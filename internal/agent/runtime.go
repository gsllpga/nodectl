// 路径: internal/agent/runtime.go
package agent

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Runtime Agent 运行时：调度采集与上报，管理信号与生命周期
type Runtime struct {
	cfg       *Config
	collector *Collector
	reporter  *Reporter
	updater   *Updater
	logDedup  *LogDedup
	cancel    context.CancelFunc
	bootID    string
}

// NewRuntime 创建运行时实例
func NewRuntime(cfg *Config, updater *Updater) *Runtime {
	return &Runtime{
		cfg:       cfg,
		collector: NewCollector(cfg.Interface),
		reporter:  NewReporter(cfg),
		updater:   updater,
		logDedup:  NewLogDedup(),
	}
}

// Run 启动 Agent 主循环（阻塞直到收到退出信号）
func (rt *Runtime) Run() error {
	// 初始化采集器
	if err := rt.collector.Init(); err != nil {
		return err
	}

	rt.bootID = readBootID()

	// 注册命令处理器
	rt.reporter.SetCommandHandler(rt.handleCommand)

	// 创建主 context
	ctx, cancel := context.WithCancel(context.Background())
	rt.cancel = cancel
	defer cancel()
	connectStartedAt := time.Now()
	postUpdatePending := rt.updater != nil && rt.updater.IsPostUpdatePending()
	postUpdateTimeout := time.Duration(0)
	if postUpdatePending {
		postUpdateTimeout = rt.updater.HealthTimeout()
	}

	// 首次连接 (无限重试直到成功或被中断)
	for {
		if err := rt.reporter.Connect(ctx); err != nil {
			log.Printf("[Agent] 首次连接失败: %v", err)
			if postUpdatePending && postUpdateTimeout > 0 && time.Since(connectStartedAt) > postUpdateTimeout {
				log.Printf("[Agent] 更新后健康检查超时（%v 内未完成首个 WS 握手），执行原地回滚...",
					postUpdateTimeout)
				if rt.updater != nil {
					rt.updater.RollbackAndReexec() // 不会返回
				}
				return fmt.Errorf("更新后健康检查超时（%v 内未完成首个 WS 握手）", postUpdateTimeout)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := rt.reporter.ReconnectWithBackoff(ctx); err != nil {
				if postUpdatePending && postUpdateTimeout > 0 && time.Since(connectStartedAt) > postUpdateTimeout {
					log.Printf("[Agent] 更新后健康检查超时（%v 内未完成首个 WS 握手），执行原地回滚...",
						postUpdateTimeout)
					if rt.updater != nil {
						rt.updater.RollbackAndReexec() // 不会返回
					}
					return fmt.Errorf("更新后健康检查超时（%v 内未完成首个 WS 握手）", postUpdateTimeout)
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
		}
		break
	}

	// 启动信号监听
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// 首次 WS 连接成功，标记健康（清除崩溃计数）
	if rt.updater != nil {
		rt.updater.MarkHealthy()
	}

	// 启动自动更新检查循环（后台 goroutine）
	if rt.updater != nil {
		go rt.updater.Run(ctx)
	}

	// 启动主循环
	pushTicker := time.NewTicker(time.Duration(rt.cfg.WSPushIntervalSec) * time.Second)
	memoryTrimTicker := time.NewTicker(2 * time.Minute) // 定期归还未使用内存给 OS
	defer pushTicker.Stop()
	defer memoryTrimTicker.Stop()

	// 启动日志（仅输出一条）
	log.Printf("[Agent] nodectl-agent %s 已启动 (install_id=%s, iface=%s, push=%ds)",
		AgentVersion, rt.cfg.InstallID, rt.collector.GetInterface(),
		rt.cfg.WSPushIntervalSec)

	for {
		select {
		case <-ctx.Done():
			rt.shutdown()
			return nil

		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				rt.reloadConfig()
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("[Agent] 收到 %v 信号，准备退出...", sig)
				cancel()
			}

		case <-pushTicker.C:
			// 采集一次数据
			if err := rt.collector.Sample(); err != nil {
				rt.logDedup.LogOrSuppress("collector:sample", "[Agent] 采集失败: %v", err)
				continue
			}

			rxRate, txRate, counterRX, counterTX := rt.collector.GetLiveSnapshot()

			err := rt.reporter.SendLiveMessage(ctx, rxRate, txRate, counterRX, counterTX, rt.bootID)
			if err != nil {
				rt.logDedup.LogOrSuppress("reporter:live", "[Agent] 实时上报失败: %v", err)
				rt.handleDisconnect(ctx)
			}

		case <-memoryTrimTicker.C:
			// 在低内存模式下主动归还空闲页，降低 RSS 常驻峰值。
			debug.FreeOSMemory()
		}
	}
}

// handleDisconnect 处理断线重连
func (rt *Runtime) handleDisconnect(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	log.Printf("[Agent] 检测到连接断开，启动重连...")
	for {
		if ctx.Err() != nil {
			return
		}
		if err := rt.reporter.ReconnectWithBackoff(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			rt.logDedup.LogOrSuppress("reporter:reconnect", "[Agent] 重连失败: %v", err)
			continue
		}
		log.Printf("[Agent] 重连成功")
		return
	}
}

// reloadConfig 重新加载配置文件 (SIGHUP)
// 注意：仅更新可动态变更的字段，网卡变更需要重启
func (rt *Runtime) reloadConfig() {
	newCfg, err := LoadConfig("")
	if err != nil {
		log.Printf("[Agent] 重新加载配置失败: %v", err)
		return
	}

	// 仅应用可安全动态变更的字段
	rt.cfg.WSPushIntervalSec = newCfg.WSPushIntervalSec
	rt.cfg.LogLevel = newCfg.LogLevel

	// 网卡变更需要重启，在此仅记录警告
	if newCfg.Interface != rt.cfg.Interface {
		log.Printf("[Agent] 网卡配置变更 (%s -> %s) 需要重启 agent 才能生效", rt.cfg.Interface, newCfg.Interface)
	}

	log.Printf("[Agent] 配置已重新加载")
}

// shutdown 优雅退出
// 顺序：collector（释放 FD）→ reporter（关闭 WS）
func (rt *Runtime) shutdown() {
	log.Printf("[Agent] 正在优雅退出...")

	// 0. 输出日志去重器的累计信息
	rt.logDedup.Flush()

	// 1. 释放采集器常驻 FD
	if err := rt.collector.Close(); err != nil {
		log.Printf("[Agent] 关闭采集器失败: %v", err)
	}

	// 2. 持久化状态
	// 2. 关闭 WebSocket 连接
	rt.reporter.Close()

	log.Printf("[Agent] 已退出")
}

// handleCommand 处理后端下发的命令
func (rt *Runtime) handleCommand(cmd ServerCommand, reply func(CommandResult)) {
	// 先回复 accepted
	reply(CommandResult{
		Type:   "accepted",
		Status: "ok",
		Stage:  "命令已接收",
	})

	switch cmd.Action {
	case "reset-links":
		rt.executeResetLinks(cmd, reply)
	case "reinstall-singbox":
		rt.executeReinstallSingbox(cmd, reply)
	case "check-agent-update":
		rt.executeCheckAgentUpdate(reply)
	case "tunnel-start":
		rt.executeTunnelStart(cmd, reply)
	case "tunnel-prepare":
		rt.executeTunnelPrepare(cmd, reply)
	case "tunnel-stop":
		rt.executeTunnelStop(reply)
	default:
		reply(CommandResult{
			Type:    "result",
			Status:  "error",
			Message: fmt.Sprintf("未知命令: %s", cmd.Action),
		})
	}
}

func readBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Sprintf("boot-%d", time.Now().UnixNano())
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return fmt.Sprintf("boot-%d", time.Now().UnixNano())
	}
	return id
}

func (rt *Runtime) executeCheckAgentUpdate(reply func(CommandResult)) {
	if rt.updater == nil {
		reply(CommandResult{Type: "result", Status: "error", Message: "更新器未初始化"})
		return
	}
	reply(CommandResult{Type: "progress", Status: "ok", Stage: "开始检查", Message: "正在检查 Agent 更新..."})
	go func() {
		if err := rt.updater.TriggerCheck(context.Background()); err != nil {
			reply(CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("检查更新失败: %v", err)})
			return
		}
		reply(CommandResult{Type: "result", Status: "ok", Message: "已触发更新检查，请查看节点日志确认结果"})
	}()
}

// deriveScriptURL 从 ws_url 推导安装脚本 URL
func (rt *Runtime) deriveScriptURL() string {
	// ws_url 形如 wss://domain:port/api/callback/traffic/ws
	panelURL := rt.cfg.WSURL
	panelURL = strings.Replace(panelURL, "wss://", "https://", 1)
	panelURL = strings.Replace(panelURL, "ws://", "http://", 1)
	if idx := strings.Index(panelURL, "/api/"); idx > 0 {
		panelURL = panelURL[:idx]
	}
	return fmt.Sprintf("%s/api/public/install-script?id=%s", panelURL, rt.cfg.InstallID)
}

// executeResetLinks 重置节点链接
// 后端下发 payload 中包含 {"protocols": ["ss", "hy2", ...]}，作为安装脚本的 CLI 参数
func (rt *Runtime) executeResetLinks(cmd ServerCommand, reply func(CommandResult)) {
	var payload struct {
		Protocols []string          `json:"protocols"`
		Tunnel    *tunnelCmdPayload `json:"tunnel,omitempty"`
	}
	if len(cmd.Payload) > 0 {
		json.Unmarshal(cmd.Payload, &payload)
	}
	if len(payload.Protocols) == 0 {
		reply(CommandResult{Type: "result", Status: "error", Message: "未收到协议列表，无法重置"})
		return
	}

	scriptURL := rt.deriveScriptURL()
	protoArgs := strings.Join(payload.Protocols, " ")
	shellCmd := fmt.Sprintf(`export SKIP_AGENT_INSTALL=1; curl -fsSL "%s" | bash -s -- %s`, scriptURL, protoArgs)

	if err := rt.runStreamingScript(shellCmd, "重置链接", reply); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("重置链接失败: %v", err)})
		return
	}
	if err := rt.refreshTunnelAfterCoreChange(payload.Tunnel, reply); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Message: "重置链接完成"})
}

// executeReinstallSingbox 重新安装 sing-box（复用安装脚本，同样从 payload 读取协议）
func (rt *Runtime) executeReinstallSingbox(cmd ServerCommand, reply func(CommandResult)) {
	var payload struct {
		Protocols []string          `json:"protocols"`
		Tunnel    *tunnelCmdPayload `json:"tunnel,omitempty"`
	}
	if len(cmd.Payload) > 0 {
		json.Unmarshal(cmd.Payload, &payload)
	}
	if len(payload.Protocols) == 0 {
		reply(CommandResult{Type: "result", Status: "error", Message: "未收到协议列表，无法重新安装"})
		return
	}

	scriptURL := rt.deriveScriptURL()
	protoArgs := strings.Join(payload.Protocols, " ")
	shellCmd := fmt.Sprintf(`export SKIP_AGENT_INSTALL=1; curl -fsSL "%s" | bash -s -- %s`, scriptURL, protoArgs)

	if err := rt.runStreamingScript(shellCmd, "重新安装", reply); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("重新安装失败: %v", err)})
		return
	}
	if err := rt.refreshTunnelAfterCoreChange(payload.Tunnel, reply); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Message: "重新安装完成"})
}

type tunnelRoutePayload struct {
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

type tunnelCmdPayload struct {
	BaseDomain  string               `json:"base_domain"`
	TunnelToken string               `json:"tunnel_token"`
	TunnelID    string               `json:"tunnel_id"`
	Routes      []tunnelRoutePayload `json:"routes"`
}

func parseTunnelPayload(cmd ServerCommand) (tunnelCmdPayload, error) {
	var payload tunnelCmdPayload
	if len(cmd.Payload) > 0 {
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return payload, err
		}
	}
	payload.BaseDomain = strings.TrimSpace(payload.BaseDomain)
	payload.TunnelToken = strings.TrimSpace(payload.TunnelToken)
	filtered := make([]tunnelRoutePayload, 0, len(payload.Routes))
	for _, r := range payload.Routes {
		r.Protocol = strings.TrimSpace(r.Protocol)
		r.Hostname = strings.TrimSpace(r.Hostname)
		r.Service = strings.TrimSpace(r.Service)
		if r.Hostname == "" || r.Service == "" {
			continue
		}
		filtered = append(filtered, r)
	}
	payload.Routes = filtered
	if payload.TunnelToken == "" {
		return payload, fmt.Errorf("缺少 tunnel token")
	}
	if len(payload.Routes) == 0 {
		return payload, fmt.Errorf("缺少可用 tunnel 路由")
	}
	return payload, nil
}

func renderTunnelConfigYAML(tunnelID, credPath string, routes []tunnelRoutePayload) string {
	var b strings.Builder
	b.WriteString("# NodeCTL Tunnel Config\n")
	b.WriteString("# Generated by nodectl-agent\n")
	b.WriteString("tunnel: ")
	b.WriteString(tunnelID)
	b.WriteString("\n")
	b.WriteString("credentials-file: ")
	b.WriteString(credPath)
	b.WriteString("\n\n")
	b.WriteString("ingress:\n")
	for _, r := range routes {
		b.WriteString("  - hostname: ")
		b.WriteString(r.Hostname)
		b.WriteString("\n")
		b.WriteString("    service: ")
		b.WriteString(r.Service)
		b.WriteString("\n")
		// 对 https:// 后端（sing-box TLS 协议使用自签证书），需要跳过证书验证
		if strings.HasPrefix(strings.ToLower(r.Service), "https://") {
			b.WriteString("    originRequest:\n")
			b.WriteString("      noTLSVerify: true\n")
		}
	}
	b.WriteString("  - service: http_status:404\n")
	return b.String()
}

func installCloudflaredCommand() string {
	return `if command -v cloudflared >/dev/null 2>&1; then
  echo "[cloudflared] already installed: $(cloudflared version 2>/dev/null || echo unknown)"
else
  echo "[cloudflared] not found, installing..."
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) FILE="cloudflared-linux-amd64" ;;
    aarch64|arm64) FILE="cloudflared-linux-arm64" ;;
    armv7l|armv7) FILE="cloudflared-linux-arm" ;;
    i386|i686) FILE="cloudflared-linux-386" ;;
    *) echo "[cloudflared] unsupported arch: $ARCH"; exit 1 ;;
  esac
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/${FILE}"
  TMP="/tmp/cloudflared.nodectl"
  echo "[cloudflared] downloading from $URL ..."
  curl -fsSL "$URL" -o "$TMP" || { echo "[cloudflared] download failed"; exit 1; }
  install -m 0755 "$TMP" /usr/local/bin/cloudflared
  rm -f "$TMP"
  echo "[cloudflared] installed: $(cloudflared version 2>/dev/null || echo unknown)"
fi`
}

func (rt *Runtime) applyTunnelConfig(payload tunnelCmdPayload, reply func(CommandResult)) error {
	configDir := "/etc/nodectl-tunnel"
	configPath := filepath.Join(configDir, "config.yml")
	credPath := filepath.Join(configDir, "credentials.json")
	servicePath := "/etc/systemd/system/nodectl-tunnel.service"

	reply(CommandResult{Type: "progress", Stage: "写入 tunnel 配置文件..."})
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 从 Token 解码凭据并写入凭据文件
	tunnelID, err := decodeTunnelTokenToCredFile(payload.TunnelToken, payload.TunnelID, credPath)
	if err != nil {
		return fmt.Errorf("解析 tunnel 凭据失败: %w", err)
	}

	// 生成完整的 named tunnel config（包含 tunnel UUID、凭据路径和 ingress 规则）
	configContent := renderTunnelConfigYAML(tunnelID, credPath, payload.Routes)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("写入 config.yml 失败: %w", err)
	}

	// 使用 credentials file 模式（非 token 模式）
	// 关键区别：token 模式下 cloudflared 从 Cloudflare API 获取 ingress 路由规则（忽略本地 config.yml 的 ingress），
	// 而 credentials file 模式下 cloudflared 使用本地 config.yml 中的 ingress 规则。
	logDir := "/var/log/nodectl-tunnel"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("[Agent] 创建 cloudflared 日志目录失败: %v", err)
	}
	serviceContent := `[Unit]
Description=NodeCTL cloudflared tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /var/log/nodectl-tunnel
ExecStart=/usr/local/bin/cloudflared --config /etc/nodectl-tunnel/config.yml --loglevel info --logfile /var/log/nodectl-tunnel/cloudflared.log tunnel --no-autoupdate run
Restart=always
RestartSec=3
User=root
StandardOutput=append:/var/log/nodectl-tunnel/cloudflared-stdout.log
StandardError=append:/var/log/nodectl-tunnel/cloudflared-stderr.log

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("写入 systemd 服务失败: %w", err)
	}

	// 清理旧版 tunnel.env（不再需要）
	os.Remove(filepath.Join(configDir, "tunnel.env"))

	return nil
}

// decodeTunnelTokenToCredFile 从 Tunnel Token 解码凭据并写入 JSON 文件
// Token 格式: base64({"a":"<account_tag>","t":"<tunnel_id>","s":"<secret_base64>"})
// 返回解析到的 Tunnel ID
func decodeTunnelTokenToCredFile(tokenStr, tunnelIDHint, credPath string) (string, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return "", fmt.Errorf("tunnel token 为空")
	}

	// 尝试多种 base64 编码方式解码
	var decoded []byte
	var decErr error
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, decErr = enc.DecodeString(tokenStr)
		if decErr == nil && len(decoded) > 0 && decoded[0] == '{' {
			break
		}
	}
	if len(decoded) == 0 || decoded[0] != '{' {
		return "", fmt.Errorf("base64 解码 tunnel token 失败: %v", decErr)
	}

	var tokenData struct {
		AccountTag   string `json:"a"`
		TunnelID     string `json:"t"`
		TunnelSecret string `json:"s"`
	}
	if err := json.Unmarshal(decoded, &tokenData); err != nil {
		return "", fmt.Errorf("解析 tunnel token JSON 失败: %v", err)
	}

	tunnelID := strings.TrimSpace(tokenData.TunnelID)
	if tunnelID == "" {
		tunnelID = strings.TrimSpace(tunnelIDHint)
	}
	if tunnelID == "" {
		return "", fmt.Errorf("无法从 token 中提取 Tunnel ID")
	}

	// 构造 cloudflared 凭据 JSON
	cred := map[string]string{
		"AccountTag":   tokenData.AccountTag,
		"TunnelID":     tunnelID,
		"TunnelSecret": tokenData.TunnelSecret,
	}
	credJSON, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化凭据失败: %v", err)
	}
	if err := os.WriteFile(credPath, credJSON, 0600); err != nil {
		return "", fmt.Errorf("写入凭据文件失败: %w", err)
	}

	log.Printf("[Agent] tunnel 凭据已写入: %s (tunnel_id=%s)", credPath, tunnelID)
	return tunnelID, nil
}

// executeTunnelPrepare 仅安装并下发配置，不自动删除已安装组件
func (rt *Runtime) executeTunnelPrepare(cmd ServerCommand, reply func(CommandResult)) {
	payload, err := parseTunnelPayload(cmd)
	if err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: "tunnel 参数错误: " + err.Error()})
		return
	}

	if err := rt.applyTunnelConfig(payload, reply); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}

	rt.execStreamingScript(installCloudflaredCommand(), "安装 cloudflared", reply)
}

// executeTunnelStart 启动节点 tunnel（若未安装则先安装）
func (rt *Runtime) executeTunnelStart(cmd ServerCommand, reply func(CommandResult)) {
	payload, err := parseTunnelPayload(cmd)
	if err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: "tunnel 参数错误: " + err.Error()})
		return
	}

	log.Printf("[Agent] tunnel-start: 收到 %d 条路由, tunnel_id=%s", len(payload.Routes), payload.TunnelID)
	for _, r := range payload.Routes {
		log.Printf("[Agent] tunnel-start: 路由 %s -> %s", r.Hostname, r.Service)
	}

	if err := rt.applyTunnelConfig(payload, reply); err != nil {
		log.Printf("[Agent] tunnel-start: 配置写入失败: %v", err)
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}
	log.Printf("[Agent] tunnel-start: 配置文件已写入")

	// 安装 cloudflared（不使用 exit 0，后续命令一定会执行）
	installCmd := installCloudflaredCommand()
	if err := rt.runStreamingScript(installCmd, "安装 cloudflared", reply); err != nil {
		log.Printf("[Agent] tunnel-start: cloudflared 安装失败: %v", err)
		reply(CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("cloudflared 安装失败: %v", err)})
		return
	}

	// 启动 systemd 服务（独立脚本，避免被 installCmd 的 exit 影响）
	startCmd := `echo "[tunnel] daemon-reload..."
systemctl daemon-reload
echo "[tunnel] enabling service..."
systemctl enable nodectl-tunnel.service
echo "[tunnel] restarting service..."
systemctl restart nodectl-tunnel.service
sleep 2
echo "[tunnel] checking service status..."
if systemctl is-active --quiet nodectl-tunnel.service; then
  echo "[tunnel] ✅ nodectl-tunnel.service is running (PID: $(systemctl show -p MainPID nodectl-tunnel.service --value))"
else
  echo "[tunnel] ❌ nodectl-tunnel.service failed to start"
  echo "[tunnel] --- service status ---"
  systemctl status nodectl-tunnel.service --no-pager 2>&1 || true
  echo "[tunnel] --- last 20 log lines ---"
  cat /var/log/nodectl-tunnel/cloudflared.log 2>/dev/null | tail -20 || journalctl -u nodectl-tunnel.service -n 20 --no-pager 2>/dev/null || true
fi`
	if err := rt.runStreamingScript(startCmd, "启动 tunnel 服务", reply); err != nil {
		log.Printf("[Agent] tunnel-start: 服务启动失败: %v", err)
		reply(CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("tunnel 服务启动失败: %v", err)})
		return
	}

	log.Printf("[Agent] tunnel-start: 完成")
	reply(CommandResult{Type: "result", Status: "ok", Message: "启动 tunnel完成"})
}

// executeTunnelStop 停止节点 tunnel（不删除已安装组件和配置）
func (rt *Runtime) executeTunnelStop(reply func(CommandResult)) {
	log.Printf("[Agent] tunnel-stop: 开始停止 tunnel 服务")
	shellCmd := `echo "[tunnel] stopping service..."
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q 'nodectl-tunnel.service'; then
  systemctl stop nodectl-tunnel.service
  sleep 1
  if systemctl is-active --quiet nodectl-tunnel.service; then
    echo "[tunnel] ⚠️ service still running after stop"
  else
    echo "[tunnel] ✅ nodectl-tunnel 已停止"
  fi
else
  echo "[tunnel] 未检测到 nodectl-tunnel.service"
fi`
	rt.execStreamingScript(shellCmd, "停止 tunnel", reply)
	log.Printf("[Agent] tunnel-stop: 完成")
}

func (rt *Runtime) refreshTunnelAfterCoreChange(payload *tunnelCmdPayload, reply func(CommandResult)) error {
	if payload == nil || strings.TrimSpace(payload.TunnelToken) == "" || len(payload.Routes) == 0 {
		return nil
	}

	log.Printf("[Agent] tunnel-refresh: 刷新 Tunnel 配置")
	reply(CommandResult{Type: "progress", Stage: "正在刷新 Tunnel 配置..."})
	if err := rt.applyTunnelConfig(*payload, reply); err != nil {
		log.Printf("[Agent] tunnel-refresh: 配置写入失败: %v", err)
		return fmt.Errorf("刷新 Tunnel 配置失败: %w", err)
	}

	// 先确保 cloudflared 已安装
	installCmd := installCloudflaredCommand()
	if err := rt.runStreamingScript(installCmd, "安装 cloudflared", reply); err != nil {
		log.Printf("[Agent] tunnel-refresh: cloudflared 安装失败: %v", err)
		return fmt.Errorf("cloudflared 安装失败: %w", err)
	}

	restartCmd := `echo "[tunnel] refreshing service..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable nodectl-tunnel.service
  systemctl restart nodectl-tunnel.service
  sleep 2
  if systemctl is-active --quiet nodectl-tunnel.service; then
    echo "[tunnel] ✅ nodectl-tunnel 已刷新 (PID: $(systemctl show -p MainPID nodectl-tunnel.service --value))"
  else
    echo "[tunnel] ❌ 刷新后服务未运行"
    systemctl status nodectl-tunnel.service --no-pager 2>&1 || true
  fi
else
  echo "[tunnel] 未检测到 systemctl，已跳过 tunnel 服务重启"
fi`
	if err := rt.runStreamingScript(restartCmd, "刷新 tunnel", reply); err != nil {
		log.Printf("[Agent] tunnel-refresh: 服务刷新失败: %v", err)
		return fmt.Errorf("刷新 Tunnel 服务失败: %w", err)
	}
	log.Printf("[Agent] tunnel-refresh: 完成")
	return nil
}

// execStreamingScript 执行 shell 命令并逐行流式回传输出
// 每行作为一个 progress 消息发送，最后发送 result
// 使用 sync.WaitGroup 确保 scanner goroutine 读完所有输出后再发送最终结果
func (rt *Runtime) execStreamingScript(shellCmd string, label string, reply func(CommandResult)) {
	if err := rt.runStreamingScript(shellCmd, label, reply); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("脚本执行完毕但退出码非零: %v", err)})
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Message: fmt.Sprintf("%s完成", label)})
}

func (rt *Runtime) runStreamingScript(shellCmd string, label string, reply func(CommandResult)) error {
	reply(CommandResult{Type: "progress", Stage: fmt.Sprintf("正在执行%s脚本...", label)})
	// 仅记录脚本前 200 字符到日志，避免巨大脚本刷屏
	scriptPreview := shellCmd
	if len(scriptPreview) > 200 {
		scriptPreview = scriptPreview[:200] + "..."
	}
	log.Printf("[Agent] 执行%s: %s", label, scriptPreview)

	cmd := exec.Command("/bin/sh", "-c", shellCmd)

	// 合并 stdout+stderr 到一个管道（有意为之，便于流式回传完整输出）
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		log.Printf("[Agent] %s脚本启动失败: %v", label, err)
		return fmt.Errorf("启动脚本失败: %v", err)
	}

	// 使用 WaitGroup 等待 scanner goroutine 完成，替代 time.Sleep hack
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 64*1024), 256*1024)
		for scanner.Scan() {
			line := scanner.Text()
			// 脚本输出同时写入 agent 日志和 WebSocket 回传
			log.Printf("[Agent] [%s] %s", label, line)
			reply(CommandResult{Type: "progress", Stage: line})
		}
	}()

	// 等待脚本执行结束
	err := cmd.Wait()
	pw.Close()

	// 等待 scanner goroutine 读完所有剩余输出
	wg.Wait()

	if err != nil {
		log.Printf("[Agent] %s脚本退出码非零: %v", label, err)
	} else {
		log.Printf("[Agent] %s脚本执行成功", label)
	}
	return err
}
