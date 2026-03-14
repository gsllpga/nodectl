// 路径: internal/agent/singbox/manager.go
// sing-box 子进程生命周期管理器
// 负责启动、停止、重启 sing-box，以及崩溃自动重启和日志捕获
package singbox

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessStatus sing-box 进程状态
type ProcessStatus struct {
	Running    bool      `json:"running"`
	PID        int       `json:"pid,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	RestartCnt int       `json:"restart_count"`
	LastError  string    `json:"last_error,omitempty"`
}

// Manager sing-box 进程管理器
type Manager struct {
	mu sync.RWMutex

	// 配置
	binaryPath string
	configPath string
	logPath    string
	pidPath    string

	// 子进程
	cmd    *exec.Cmd
	cancel context.CancelFunc

	// 状态
	running    bool
	pid        int
	startedAt  time.Time
	restartCnt int
	lastError  string

	// 配置管理器
	config    *ConfigManager
	installer *Installer

	// 自动重启控制
	maxRestarts    int           // 最大连续重启次数
	restartDelay   time.Duration // 重启间隔
	restartCounter int           // 连续崩溃计数器（非正常退出时+1，正常运行一段时间后清零）
}

// NewManager 创建 sing-box 管理器
func NewManager() *Manager {
	return &Manager{
		binaryPath:   DefaultBinaryPath,
		configPath:   DefaultConfigPath,
		logPath:      "/var/log/nodectl-agent/singbox.log",
		pidPath:      filepath.Join(DefaultWorkDir, "singbox.pid"),
		config:       NewConfigManager(),
		installer:    NewInstaller(""),
		maxRestarts:  5,
		restartDelay: 3 * time.Second,
	}
}

// NewManagerWithConfig 使用指定配置创建管理器
func NewManagerWithConfig(config *ConfigManager, installer *Installer) *Manager {
	m := NewManager()
	if config != nil {
		m.config = config
		m.configPath = config.GetConfigPath()
	}
	if installer != nil {
		m.installer = installer
		m.binaryPath = installer.GetBinaryPath()
	}
	return m
}

// GetConfigManager 返回配置管理器
func (m *Manager) GetConfigManager() *ConfigManager {
	return m.config
}

// GetInstaller 返回安装器
func (m *Manager) GetInstaller() *Installer {
	return m.installer
}

// Start 启动 sing-box 子进程
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("sing-box 已在运行 (PID=%d)", m.pid)
	}

	// 确保 sing-box 已安装
	if !m.installer.IsInstalled() {
		return fmt.Errorf("sing-box 二进制不存在: %s，请先安装", m.binaryPath)
	}

	// 确保配置文件存在
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		return fmt.Errorf("sing-box 配置文件不存在: %s，请先生成配置", m.configPath)
	}

	return m.startProcess(ctx)
}

// startProcess 内部启动逻辑（调用者须持有锁）
func (m *Manager) startProcess(ctx context.Context) error {
	// 创建子 context 用于管理进程生命周期
	procCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// 构造命令: sing-box run -c config.json
	cmd := exec.CommandContext(procCtx, m.binaryPath, "run", "-c", m.configPath)

	// 设置日志输出
	logWriter, err := m.openLogWriter()
	if err != nil {
		cancel()
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	cmd.Stdout = logWriter

	// 🆕 同时将 stderr 捕获到管道，便于回写 Agent 日志诊断启动失败原因
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		if closer, ok := logWriter.(io.Closer); ok {
			closer.Close()
		}
		return fmt.Errorf("创建 stderr 管道失败: %w", err)
	}

	// 启动子进程
	if err := cmd.Start(); err != nil {
		cancel()
		if closer, ok := logWriter.(io.Closer); ok {
			closer.Close()
		}
		m.lastError = err.Error()
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}

	// 🆕 启动 stderr 读取协程：将 sing-box 的错误输出回写到 Agent 日志和日志文件
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 64*1024), 256*1024)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[SingBox:stderr] %s", line)
			// 同时写入日志文件
			if logWriter != nil {
				fmt.Fprintf(logWriter, "[stderr] %s\n", line)
			}
		}
	}()

	m.cmd = cmd
	m.running = true
	m.pid = cmd.Process.Pid
	m.startedAt = time.Now()
	m.lastError = ""

	// 保存 PID 文件
	m.savePID()

	log.Printf("[SingBox] sing-box 已启动 (PID=%d, config=%s)", m.pid, m.configPath)

	// 启动监控协程
	go m.watchProcess(ctx, cmd, logWriter)

	return nil
}

// Stop 停止 sing-box 子进程
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopProcess()
}

// stopProcess 内部停止逻辑（调用者须持有锁）
func (m *Manager) stopProcess() error {
	if !m.running || m.cmd == nil {
		return nil
	}

	log.Printf("[SingBox] 正在停止 sing-box (PID=%d)...", m.pid)

	// 取消 context 触发进程终止
	if m.cancel != nil {
		m.cancel()
	}

	// 等待进程退出（最多 10 秒）
	done := make(chan struct{})
	go func() {
		if m.cmd.Process != nil {
			m.cmd.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		// 正常退出
	case <-time.After(10 * time.Second):
		// 超时强杀
		if m.cmd.Process != nil {
			log.Printf("[SingBox] sing-box 停止超时，强制终止 (PID=%d)", m.pid)
			m.cmd.Process.Kill()
		}
	}

	m.running = false
	m.cmd = nil
	m.removePID()

	log.Printf("[SingBox] sing-box 已停止")
	return nil
}

// Restart 重启 sing-box 子进程
func (m *Manager) Restart(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 先停止
	if err := m.stopProcess(); err != nil {
		log.Printf("[SingBox] 停止 sing-box 出错: %v", err)
	}

	// 等待一小段时间确保端口释放
	time.Sleep(500 * time.Millisecond)

	// 重新启动
	m.restartCnt++
	return m.startProcess(ctx)
}

// ReloadConfig 重新生成配置并重启
func (m *Manager) ReloadConfig(ctx context.Context) error {
	// 重新生成 sing-box 配置
	if err := m.config.GenerateAndSave(); err != nil {
		return fmt.Errorf("重新生成配置失败: %w", err)
	}

	// 保存协议缓存
	if err := m.config.SaveToCache(); err != nil {
		log.Printf("[SingBox] 保存协议缓存失败: %v", err)
	}

	// 重启 sing-box
	return m.Restart(ctx)
}

// Status 获取 sing-box 运行状态
func (m *Manager) Status() ProcessStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ProcessStatus{
		Running:    m.running,
		PID:        m.pid,
		StartedAt:  m.startedAt,
		RestartCnt: m.restartCnt,
		LastError:  m.lastError,
	}
}

// IsRunning 检查 sing-box 是否在运行
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// --- 内部方法 ---

// watchProcess 监控 sing-box 子进程，异常退出时自动重启
func (m *Manager) watchProcess(ctx context.Context, cmd *exec.Cmd, logWriter io.Writer) {
	// 等待进程退出
	err := cmd.Wait()

	// 关闭日志文件
	if closer, ok := logWriter.(io.Closer); ok {
		closer.Close()
	}

	m.mu.Lock()
	m.running = false
	m.removePID()

	if err != nil {
		m.lastError = err.Error()
		log.Printf("[SingBox] sing-box 异常退出 (PID=%d): %v", m.pid, err)
	} else {
		log.Printf("[SingBox] sing-box 正常退出 (PID=%d)", m.pid)
	}

	// 检查是否需要自动重启
	if ctx.Err() != nil {
		// 上下文已取消（用户主动停止），不重启
		m.mu.Unlock()
		return
	}

	// 检查连续崩溃次数
	m.restartCounter++
	if m.restartCounter > m.maxRestarts {
		log.Printf("[SingBox] 连续崩溃次数已达上限 (%d)，停止自动重启", m.maxRestarts)
		m.mu.Unlock()
		return
	}

	log.Printf("[SingBox] %v 后自动重启 (第 %d 次)...", m.restartDelay, m.restartCounter)
	m.mu.Unlock()

	// 等待一段时间后重启
	select {
	case <-ctx.Done():
		return
	case <-time.After(m.restartDelay):
	}

	m.mu.Lock()
	if err := m.startProcess(ctx); err != nil {
		log.Printf("[SingBox] 自动重启失败: %v", err)
		m.lastError = fmt.Sprintf("自动重启失败: %v", err)
	} else {
		m.restartCnt++
		// 启动成功，10 秒后若仍在运行则清零崩溃计数
		go func() {
			time.Sleep(10 * time.Second)
			m.mu.Lock()
			if m.running {
				m.restartCounter = 0
			}
			m.mu.Unlock()
		}()
	}
	m.mu.Unlock()
}

// openLogWriter 打开日志文件
func (m *Manager) openLogWriter() (io.Writer, error) {
	if dir := filepath.Dir(m.logPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(m.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// savePID 保存子进程 PID 到文件
func (m *Manager) savePID() {
	if m.pid <= 0 {
		return
	}
	if dir := filepath.Dir(m.pidPath); dir != "" {
		os.MkdirAll(dir, 0755)
	}
	os.WriteFile(m.pidPath, []byte(strconv.Itoa(m.pid)), 0644)
}

// removePID 删除 PID 文件
func (m *Manager) removePID() {
	os.Remove(m.pidPath)
}

// Shutdown 优雅关闭（供 Runtime.shutdown() 调用）
func (m *Manager) Shutdown() {
	if err := m.Stop(); err != nil {
		log.Printf("[SingBox] 关闭 sing-box 失败: %v", err)
	}
}

// PortConflict 端口冲突信息
type PortConflict struct {
	Protocol string // 协议名称（如 "ss", "hy2"）
	Port     int    // 冲突端口
	Network  string // "tcp" / "udp"
	Reason   string // 冲突原因描述
}

// CheckPortConflicts 检测协议配置中的端口冲突问题
// 返回两类冲突：
// 1. 协议之间的端口重复（同一端口被多个协议使用）
// 2. 端口被系统其他进程占用
func CheckPortConflicts(pc *ProtocolConfig) []PortConflict {
	var conflicts []PortConflict

	// 1. 收集所有启用协议的端口
	type protoPort struct {
		protocol string
		port     int
		networks []string // tcp, udp, or both
	}

	var protoPorts []protoPort
	enabledList := pc.EnabledProtocolList()

	for _, proto := range enabledList {
		port := getProtoPort(pc, proto)
		if port <= 0 {
			continue
		}
		nets := getProtoNetworks(proto)
		protoPorts = append(protoPorts, protoPort{protocol: proto, port: port, networks: nets})
	}

	// 2. 检测协议之间的端口重复
	portUsageMap := make(map[string][]string) // "tcp:8388" -> ["ss", "socks5"]
	for _, pp := range protoPorts {
		for _, n := range pp.networks {
			key := fmt.Sprintf("%s:%d", n, pp.port)
			portUsageMap[key] = append(portUsageMap[key], pp.protocol)
		}
	}
	for key, protos := range portUsageMap {
		if len(protos) > 1 {
			parts := strings.SplitN(key, ":", 2)
			network := parts[0]
			port, _ := strconv.Atoi(parts[1])
			conflicts = append(conflicts, PortConflict{
				Protocol: strings.Join(protos, ", "),
				Port:     port,
				Network:  network,
				Reason:   fmt.Sprintf("端口 %d/%s 被多个协议共用: [%s]", port, strings.ToUpper(network), strings.Join(protos, ", ")),
			})
		}
	}

	// 3. 检测端口是否被系统其他进程占用
	checkedPorts := make(map[string]bool)
	for _, pp := range protoPorts {
		for _, n := range pp.networks {
			key := fmt.Sprintf("%s:%d", n, pp.port)
			if checkedPorts[key] {
				continue
			}
			checkedPorts[key] = true

			if isPortInUse(n, pp.port) {
				conflicts = append(conflicts, PortConflict{
					Protocol: pp.protocol,
					Port:     pp.port,
					Network:  n,
					Reason:   fmt.Sprintf("端口 %d/%s (协议 %s) 已被系统其他进程占用", pp.port, strings.ToUpper(n), pp.protocol),
				})
			}
		}
	}

	return conflicts
}

// getProtoPort 获取协议的端口号
func getProtoPort(pc *ProtocolConfig, proto string) int {
	switch proto {
	case ProtoSS:
		return pc.SS.Port
	case ProtoHY2:
		return pc.HY2.Port
	case ProtoTUIC:
		return pc.TUIC.Port
	case ProtoReality:
		return pc.Reality.Port
	case ProtoSocks5:
		return pc.Socks5.Port
	case ProtoTrojan:
		return pc.Trojan.Port
	case ProtoAnyTLS:
		return pc.AnyTLS.Port
	case ProtoVmessTCP:
		return pc.VMess.TCPPort
	case ProtoVmessWS:
		return pc.VMess.WSPort
	case ProtoVmessHTTP:
		return pc.VMess.HTTPPort
	case ProtoVmessQUIC:
		return pc.VMess.QUICPort
	case ProtoVmessWST:
		return pc.VMess.WSTPort
	case ProtoVmessHUT:
		return pc.VMess.HUTPort
	case ProtoVlessWST:
		return pc.VlessTLS.WSTPort
	case ProtoVlessHUT:
		return pc.VlessTLS.HUTPort
	case ProtoTrojanWST:
		return pc.TrojanTLS.WSTPort
	case ProtoTrojanHUT:
		return pc.TrojanTLS.HUTPort
	default:
		return 0
	}
}

// getProtoNetworks 返回协议使用的网络类型
func getProtoNetworks(proto string) []string {
	switch proto {
	case ProtoHY2, ProtoTUIC, ProtoVmessQUIC:
		return []string{"udp"}
	default:
		return []string{"tcp"}
	}
}

// isPortInUse 检测指定端口是否被占用
func isPortInUse(network string, port int) bool {
	addr := fmt.Sprintf(":%d", port)
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return true // 端口被占用
		}
		ln.Close()
		return false
	case "udp":
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return true // 端口被占用
		}
		conn.Close()
		return false
	default:
		return false
	}
}

// StartAndVerify 启动 sing-box 并等待一段时间验证是否存活
// 返回：启动错误 或 验证失败错误
// healthCheckDuration: 启动后等待多久来验证进程存活（推荐 2-3 秒）
func (m *Manager) StartAndVerify(ctx context.Context, healthCheckDuration time.Duration) error {
	if err := m.Start(ctx); err != nil {
		return err
	}

	// 等待一段时间，检测 sing-box 是否快速退出（如端口冲突、配置错误等）
	time.Sleep(healthCheckDuration)

	m.mu.RLock()
	running := m.running
	lastErr := m.lastError
	m.mu.RUnlock()

	if !running {
		errMsg := "sing-box 启动后立即退出"
		if lastErr != "" {
			errMsg = fmt.Sprintf("sing-box 启动后立即退出: %s", lastErr)
		}
		return fmt.Errorf(errMsg)
	}

	return nil
}

// FormatPortConflictsMessage 将端口冲突列表格式化为人类可读的消息
func FormatPortConflictsMessage(conflicts []PortConflict) string {
	if len(conflicts) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️ 检测到 %d 个端口冲突问题:\n", len(conflicts)))
	for i, c := range conflicts {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, c.Reason))
	}
	return sb.String()
}
