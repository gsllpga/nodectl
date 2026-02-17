package server

import (
	"embed"
	"html/template"
	"net/http"

	"nodectl/internal/logger"
	"nodectl/internal/middleware"
	"nodectl/internal/service"
)

// tmpl 设为包级全局变量，供同包下的 handlers.go 使用
var tmpl *template.Template

// Start 启动 HTTP 服务器
func Start(tmplFS embed.FS) {
	service.InitGeoIP()
	// 1. 预编译解析模板
	tmpl = template.Must(template.ParseFS(tmplFS, "templates/*.html", "templates/components/*.html"))

	// 2. 创建独立的路游分发器
	mux := http.NewServeMux()

	// ========== 页面路由 (Page Routes) ==========
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/", middleware.Auth(indexHandler))
	mux.HandleFunc("/logout", logoutHandler)

	// ========== API 路由 (API Routes) ==========
	mux.HandleFunc("/api/change-password", middleware.Auth(apiChangePassword))
	mux.HandleFunc("/api/update-node", middleware.Auth(apiUpdateNode))
	mux.HandleFunc("/api/add-node", middleware.Auth(apiAddNode))
	mux.HandleFunc("/api/get-nodes", middleware.Auth(apiGetNodes))
	mux.HandleFunc("/api/delete-node", middleware.Auth(apiDeleteNode))
	mux.HandleFunc("/api/reorder-nodes", middleware.Auth(apiReorderNodes))
	mux.HandleFunc("/api/get-settings", middleware.Auth(apiGetSettings))
	mux.HandleFunc("/api/update-settings", middleware.Auth(apiUpdateSettings))
	mux.HandleFunc("/api/clash/settings", middleware.Auth(apiGetClashSettings))
	mux.HandleFunc("/api/clash/save", middleware.Auth(apiSaveClashSettings))
	mux.HandleFunc("/api/custom-rules/get", middleware.Auth(apiGetCustomRules))
	mux.HandleFunc("/api/custom-rules/save", middleware.Auth(apiSaveCustomRules))

	// [新增] 公开路由 (不需要 middleware.Auth)
	mux.HandleFunc("/api/public/install-script", apiPublicScript) // 获取脚本
	mux.HandleFunc("/api/callback/report", apiCallbackReport)     // 脚本上报
	// [新增] 客户端订阅接口 (公开，依靠 URL Token 鉴权)
	mux.HandleFunc("/sub/clash", apiSubClash)
	mux.HandleFunc("/sub/v2ray", apiSubV2ray)
	mux.HandleFunc("/sub/raw/1", apiSubRaw)             // 1=直连池
	mux.HandleFunc("/sub/raw/2", apiSubRaw)             // 2=落地池
	mux.HandleFunc("/sub/rules/direct", apiSubRuleList) // 自定义直连规则
	mux.HandleFunc("/sub/rules/proxy/", apiSubRuleList) // 自定义分流规则

	// [新增] GeoIP 更新接口
	mux.HandleFunc("/api/update-geoip", middleware.Auth(apiUpdateGeoIP))
	mux.HandleFunc("/api/get-geo-status", middleware.Auth(apiGetGeoStatus))

	// 3. 启动服务
	port := "8080"
	logger.Log.Info("Web 服务已启动", "地址", "http://localhost:"+port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		logger.Log.Error("Web 服务异常退出", "err", err.Error())
	}
}
