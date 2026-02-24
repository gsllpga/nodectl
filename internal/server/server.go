// 路径: internal/server/server.go
package server

import (
	"crypto/tls"
	"embed"
	"html/template"
	"log"
	"net/http"
	"strings"
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

func (w *serverLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		logger.Log.Warn("HTTP 服务告警", "message", msg)
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

	// ========== C. 公开/工具 路由 ==========
	mux.HandleFunc("/api/public/install-script", withSecure(apiPublicScript)) // 安装脚本
	mux.HandleFunc("/api/callback/report", withSecure(apiCallbackReport))     // 节点上报
	mux.HandleFunc("/api/callback/traffic", withSecure(apiCallbackTraffic))   // 流量信息上报接口

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
