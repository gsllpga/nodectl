package server

import (
	"embed"
	"html/template"
	"net/http"

	"nodectl/internal/logger"
	"nodectl/internal/middleware"
)

// tmpl 设为包级全局变量，供同包下的 handlers.go 使用
var tmpl *template.Template

// Start 启动 HTTP 服务器
func Start(tmplFS embed.FS) {
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
	mux.HandleFunc("/api/add-node", middleware.Auth(apiAddNode))
	mux.HandleFunc("/api/get-nodes", middleware.Auth(apiGetNodes))
	mux.HandleFunc("/api/delete-node", middleware.Auth(apiDeleteNode))

	// 3. 启动服务
	port := "8080"
	logger.Log.Info("Web 服务已启动", "地址", "http://localhost:"+port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		logger.Log.Error("Web 服务异常退出", "err", err.Error())
	}
}
