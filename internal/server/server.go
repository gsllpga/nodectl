// 路径: internal/server/server.go
package server

import (
	"crypto/tls"
	"embed"
	"html/template"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"nodectl/internal/logger"
	"nodectl/internal/middleware"
	"nodectl/internal/service"
)

// tmpl 设为包级全局变量，供同包下的 handlers.go 使用渲染页面
var tmpl *template.Template

// restartChan 用于接收重启信号的通道
var restartChan = make(chan bool)

type serverLogWriter struct{}

type httpWarnDedupState struct {
	lastLogged time.Time
	suppressed int
}

type httpWarnDedup struct {
	mu      sync.Mutex
	window  time.Duration
	records map[string]*httpWarnDedupState
}

func newHTTPWarnDedup(window time.Duration) *httpWarnDedup {
	return &httpWarnDedup{
		window:  window,
		records: make(map[string]*httpWarnDedupState),
	}
}

func (d *httpWarnDedup) ShouldLog(key string, now time.Time) (shouldLog bool, suppressedCount int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rec, ok := d.records[key]
	if !ok {
		d.records[key] = &httpWarnDedupState{lastLogged: now}
		return true, 0
	}

	if now.Sub(rec.lastLogged) < d.window {
		rec.suppressed++
		return false, 0
	}

	suppressedCount = rec.suppressed
	rec.suppressed = 0
	rec.lastLogged = now
	return true, suppressedCount
}

// serverLogIPRe 匹配 Go HTTP 内部错误日志中的 IP:Port 格式
var serverLogIPRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+|\[?[0-9a-fA-F:]+\]?:\d+)`)
var serverWarnDedup = newHTTPWarnDedup(15 * time.Second)

func remoteHostOnly(ipPort string) string {
	ipPort = strings.TrimSpace(ipPort)
	if ipPort == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(ipPort)
	if err != nil {
		return strings.Trim(ipPort, "[]")
	}

	return strings.Trim(host, "[]")
}

func classifyHTTPServerWarning(msg string) (reason, securityHint string) {
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "tls handshake error") && strings.Contains(lower, "client sent an http request to an https server"):
		return "客户端向 HTTPS 端口发送了 HTTP 明文请求", "常见于端口探测或客户端协议配置错误，不代表已绕过登录鉴权"
	case strings.Contains(lower, "tls handshake error") && strings.Contains(lower, "first record does not look like a tls handshake"):
		return "收到非 TLS 握手数据", "常见于扫描器探测或客户端连错端口"
	case strings.Contains(lower, "tls handshake error"):
		return "TLS 握手失败", "可能是扫描、证书不受信任或协议不匹配"
	case strings.Contains(lower, "malformed http request"):
		return "收到畸形 HTTP 请求", "常见于扫描器或异常客户端"
	default:
		return "HTTP 连接异常", "请结合 message 字段排查"
	}
}

func (w *serverLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		reason, hint := classifyHTTPServerWarning(msg)
		ip := ""
		hostOnly := ""
		if m := serverLogIPRe.FindString(msg); m != "" {
			ip = m
			hostOnly = remoteHostOnly(m)
		}

		dedupKey := reason + "|" + hostOnly
		if hostOnly == "" {
			dedupKey = reason + "|" + msg
		}

		shouldLog, suppressedCount := serverWarnDedup.ShouldLog(dedupKey, time.Now())
		if !shouldLog {
			return len(p), nil
		}

		if suppressedCount > 0 {
			if hostOnly != "" {
				logger.Log.Warn("HTTP 服务告警重复已抑制", "reason", reason, "ip", hostOnly, "suppressed_count", suppressedCount, "window", "15s")
			} else {
				logger.Log.Warn("HTTP 服务告警重复已抑制", "reason", reason, "suppressed_count", suppressedCount, "window", "15s")
			}
		}

		if ip != "" {
			logger.Log.Warn("HTTP 服务告警", "message", msg, "reason", reason, "security_hint", hint, "ip", ip)
		} else {
			logger.Log.Warn("HTTP 服务告警", "message", msg, "reason", reason, "security_hint", hint)
		}
	}
	return len(p), nil
}

// TriggerRestart 触发服务器重启逻辑 (供 handlers.go 调用)
// 功能：向 restartChan 发送信号，通知主循环关闭当前 Server 实例
func TriggerRestart() {
	restartChan <- true
}

// ------------------- [中间件包装函数] -------------------

// withSecure 仅强制 HTTPS (用于登录页、订阅链接、公开接口)
func withSecure(h http.HandlerFunc) http.HandlerFunc {
	return middleware.ForceHTTPS(h)
}

// withAuthAndSecure 强制 HTTPS + 登录鉴权 (用于后台管理接口)
// 功能：保护核心 API，必须登录且在安全协议下才能访问
func withAuthAndSecure(h http.HandlerFunc) http.HandlerFunc {
	return middleware.ForceHTTPS(middleware.Auth(h))
}

// ------------------- [服务器启动逻辑] -------------------

// Start 启动核心网络服务器，支持自动检测证书并在 8080 端口热切换 HTTP/HTTPS
// 功能：初始化依赖组件，注册所有路由，并通过死循环守护 HTTP 服务的生命周期
func Start(tmplFS embed.FS) {
	// 1. 初始化各类服务组件
	service.InitGeoIP()       // 初始化 GeoIP 数据库
	service.InitCertManager() // 初始化证书目录
	//避免空指针报错
	service.InitMihomo()
	service.StartOfflineNotifyLoop()
	if err := middleware.ReloadLoginRateLimitConfigFromDB(); err != nil {
		logger.Log.Warn("加载登录IP限流配置失败，已使用默认策略", "error", err)
	}
	// 2. 预编译解析模板
	tmpl = template.Must(template.ParseFS(tmplFS, "templates/*.html", "templates/components/*.html"))

	// 3. 创建路由器并注册所有路由 (只需执行一次，避免重复注册引发 panic)
	mux := http.NewServeMux()

	// ========== A. 页面路由 (Page Routes) ==========
	mux.HandleFunc("/login", withSecure(loginHandler))   // 登录页
	mux.HandleFunc("/", withAuthAndSecure(indexHandler)) // 首页
	mux.HandleFunc("/logout", withSecure(logoutHandler)) // 退出

	// ========== B. 管理员 API (需登录 + 保护) ==========
	// 基础与设置
	mux.HandleFunc("/api/change-password", withAuthAndSecure(apiChangePassword))
	mux.HandleFunc("/api/reset-jwt", withAuthAndSecure(apiResetJWT))
	mux.HandleFunc("/api/get-settings", withAuthAndSecure(apiGetSettings))
	mux.HandleFunc("/api/update-settings", withAuthAndSecure(apiUpdateSettings))

	// 节点管理
	mux.HandleFunc("/api/get-nodes", withAuthAndSecure(apiGetNodes))
	mux.HandleFunc("/api/offline-notify/settings", withAuthAndSecure(apiGetOfflineNotifySettings))
	mux.HandleFunc("/api/offline-notify/update", withAuthAndSecure(apiUpdateOfflineNotifySetting))
	mux.HandleFunc("/api/add-node", withAuthAndSecure(apiAddNode))
	mux.HandleFunc("/api/update-node", withAuthAndSecure(apiUpdateNode))
	mux.HandleFunc("/api/delete-node", withAuthAndSecure(apiDeleteNode))
	mux.HandleFunc("/api/reorder-nodes", withAuthAndSecure(apiReorderNodes))

	// 证书与重启 (关键接口)
	mux.HandleFunc("/api/save-cert", withAuthAndSecure(apiSaveCert))    // 手动上传证书
	mux.HandleFunc("/api/apply-cert", withAuthAndSecure(apiApplyCert))  // 申请证书
	mux.HandleFunc("/api/cert-logs", withAuthAndSecure(apiGetCertLogs)) // 拉取实时申请日志
	mux.HandleFunc("/api/restart", withAuthAndSecure(apiRestartCore))   // 热重启核心

	// Clash 与规则管理
	mux.HandleFunc("/api/clash/settings", withAuthAndSecure(apiGetClashSettings))
	mux.HandleFunc("/api/clash/save", withAuthAndSecure(apiSaveClashSettings))
	mux.HandleFunc("/api/clash/custom-modules/save", withAuthAndSecure(apiSaveCustomClashModules))
	mux.HandleFunc("/api/custom-rules/get", withAuthAndSecure(apiGetCustomRules))
	mux.HandleFunc("/api/custom-rules/save", withAuthAndSecure(apiSaveCustomRules))

	// 监控与 GeoIP
	mux.HandleFunc("/api/system-monitor", withAuthAndSecure(apiGetSystemMonitor))
	mux.HandleFunc("/api/recent-logs", withAuthAndSecure(apiGetRecentLogs))
	mux.HandleFunc("/api/recent-logs/stream", withAuthAndSecure(apiStreamRecentLogs))
	mux.HandleFunc("/api/traffic/landing-nodes", withAuthAndSecure(apiGetTrafficLandingNodes))
	mux.HandleFunc("/api/traffic/series", withAuthAndSecure(apiGetTrafficSeries))
	mux.HandleFunc("/api/traffic/consumption-rank", withAuthAndSecure(apiGetTrafficConsumptionRank))
	mux.HandleFunc("/api/update-geoip", withAuthAndSecure(apiUpdateGeoIP))
	mux.HandleFunc("/api/get-geo-status", withAuthAndSecure(apiGetGeoStatus))
	// Mihomo 核心管理
	mux.HandleFunc("/api/update-mihomo", withAuthAndSecure(apiUpdateMihomo)) // 新增
	mux.HandleFunc("/api/get-mihomo-status", withAuthAndSecure(apiGetMihomoStatus))

	// ========== 数据库管理 ==========
	mux.HandleFunc("/api/db/status", withAuthAndSecure(apiGetDBStatus))
	mux.HandleFunc("/api/db/test-connection", withAuthAndSecure(apiTestDBConnection))
	mux.HandleFunc("/api/db/switch", withAuthAndSecure(apiSwitchDatabase))
	mux.HandleFunc("/api/db/migrate", withAuthAndSecure(apiMigrateDatabase))

	// ========== C. 公开/工具 路由 ==========
	mux.HandleFunc("/api/public/install-script", withSecure(apiPublicScript)) // 安装脚本
	mux.HandleFunc("/api/callback/report", withSecure(apiCallbackReport))     // 节点上报
	mux.HandleFunc("/api/callback/traffic/ws", apiCallbackTrafficWS)          // Agent WS 统一上报通道
	// 实时流量订阅 (前端 WebSocket)
	mux.HandleFunc("/api/traffic/live", withAuthAndSecure(apiTrafficLive)) // 前端实时流量订阅

	// ========== 节点控制 (Agent 命令下发) ==========
	mux.HandleFunc("/api/node/control/reset-links", withAuthAndSecure(apiNodeControlResetLinks))      // 远程重置链接
	mux.HandleFunc("/api/node/control/reinstall-singbox", withAuthAndSecure(apiNodeControlReinstall)) // 远程重装 sing-box
	mux.HandleFunc("/api/node/control/stream", withAuthAndSecure(apiNodeControlStream))               // 命令执行 SSE 流
	mux.HandleFunc("/api/node/online-status", withAuthAndSecure(apiNodeOnlineStatus))                 // 节点在线状态查询

	// 订阅接口
	mux.HandleFunc("/sub/clash", withSecure(apiSubClash))
	mux.HandleFunc("/sub/v2ray", withSecure(apiSubV2ray))
	mux.HandleFunc("/sub/raw/1", withSecure(apiSubRaw))
	mux.HandleFunc("/sub/raw/2", withSecure(apiSubRaw))
	mux.HandleFunc("/sub/rules/direct", withSecure(apiSubRuleList))
	mux.HandleFunc("/sub/rules/proxy/", withSecure(apiSubRuleList))

	// ========== 机场订阅管理 ==========
	mux.HandleFunc("/api/airport/list", withAuthAndSecure(apiAirportList))                // 获取订阅列表
	mux.HandleFunc("/api/airport/add", withAuthAndSecure(apiAirportAdd))                  // 添加订阅
	mux.HandleFunc("/api/airport/update", withAuthAndSecure(apiAirportUpdate))            // 更新订阅(同步)
	mux.HandleFunc("/api/airport/edit", withAuthAndSecure(apiAirportEdit))                // 编辑订阅(名称/URL)
	mux.HandleFunc("/api/airport/delete", withAuthAndSecure(apiAirportDelete))            // 删除订阅
	mux.HandleFunc("/api/airport/nodes", withAuthAndSecure(apiAirportNodes))              // 获取订阅下节点
	mux.HandleFunc("/api/airport/node/routing", withAuthAndSecure(apiAirportNodeRouting)) // 修改节点状态
	mux.HandleFunc("/api/airport/test-nodes", withAuthAndSecure(apiTestAirportNodes))     // 新增测速接口

	// 启动 Telegram Bot 后台服务 (不阻塞 Web 线程)
	go service.StartTelegramBot()

	// 4. 进入服务守护主循环 (实现热重启的核心逻辑)
	for {
		// 每次进入循环前，尝试加载证书
		err := service.LoadCertificate()
		certLoaded := (err == nil)

		// 实例化当前 Server，统一监听 8080 端口
		activeServer := &http.Server{
			Addr:     ":8080",
			Handler:  mux,
			ErrorLog: log.New(&serverLogWriter{}, "", 0),
		}

		// 若证书就绪，则挂载 TLS 动态获取配置
		if certLoaded {
			activeServer.TLSConfig = &tls.Config{
				GetCertificate: service.GetCertificate,
			}
		}

		// [后台协程] 监听重启信号
		// 功能：一旦接收到 TriggerRestart 发送的信号，就强制关闭当前的 Server 实例
		go func(srv *http.Server) {
			<-restartChan // 阻塞等待通道信号
			logger.Log.Info("收到重启信号，正在卸载当前网络服务...")
			if srv != nil {
				srv.Close() // 强制关闭服务，释放 8080 端口
			}
		}(activeServer)

		// [主线程] 启动服务并阻塞
		var serveErr error
		if certLoaded {
			logger.Log.Info("网络服务已启动", "mode", "HTTPS", "addr", "https://localhost:8080", "domain", service.GetCurrentCertInfo().Domain)
			serveErr = activeServer.ListenAndServeTLS("", "")
		} else {
			logger.Log.Info("网络服务已启动", "mode", "HTTP", "addr", "http://localhost:8080", "msg", "如需使用 HTTPS，请在面板上传证书")
			serveErr = activeServer.ListenAndServe()
		}

		// 拦截异常崩溃 (主动调用的 srv.Close 会返回 http.ErrServerClosed，属于正常行为)
		if serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Log.Error("服务异常崩溃退出", "error", serveErr)
			break // 严重错误(如端口占用被强杀)，跳出循环结束程序
		}

		// 走到这里说明 Server 被成功关闭了，休眠 1 秒后进入下一次 for 循环重新拉起服务
		logger.Log.Info("旧网络服务已彻底关闭，准备拉起新实例...")
		time.Sleep(1 * time.Second)
	}
}
