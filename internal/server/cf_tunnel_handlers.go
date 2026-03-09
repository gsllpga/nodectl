// 路径: internal/server/cf_tunnel_handlers.go
// [FIX-17] Cloudflare Tunnel API Handler（独立文件，不污�?handlers.go�?
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"nodectl/internal/logger"
	"nodectl/internal/service"
)

// ------------------- [CF Tunnel 凭据测试] -------------------

// apiCFTunnelTest POST /api/cf/tunnel/test
// 测试 CF Token + Account ID + Zone 有效�?
func apiCFTunnelTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	msg, err := service.TestCFCredentials()
	if err != nil {
		logger.Log.Warn("CF 凭据测试失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("CF 凭据测试成功", "ip", getClientIP(r))
	sendJSON(w, "success", msg)
}

// ------------------- [CF Token 权限管理] -------------------

// apiCFTokenVerify POST /api/cf/token/verify
// 详细验证 Token 权限（区�?Read/Edit�?
func apiCFTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	result, err := service.VerifyCFTokenPermissions(req.Token)
	if err != nil {
		logger.Log.Warn("Token 权限验证失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	// 持久化保存最近一次校验记录
	service.SaveTokenVerifyRecord(result)

	logger.Log.Info("Token 权限验证完成", "valid", result.Valid, "all_required", result.AllRequired, "ip", getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

// apiCFTokenSave POST /api/cf/token/save
// 保存 Token 并自动发现账户信�?
func apiCFTokenSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.Token == "" {
		sendJSON(w, "error", "Token 不能为空")
		return
	}

	// 先验�?Token 有效�?
	result, err := service.VerifyCFTokenPermissions(req.Token)
	if err != nil {
		sendJSON(w, "error", "Token 验证失败: "+err.Error())
		return
	}
	if !result.Valid {
		sendJSON(w, "error", "Token 无效或已过期")
		return
	}

	// 保存 Token 和自动发现的信息
	service.SetCFConfigPublic("cf_api_key", req.Token)
	if result.AccountID != "" {
		service.SetCFConfigPublic("cf_account_id", result.AccountID)
	}
	if result.Email != "" {
		service.SetCFConfigPublic("cf_email", result.Email)
	}
	if len(result.Zones) > 0 {
		service.SetCFConfigPublic("cf_domain", result.Zones[0])
	}

	logger.Log.Info("CF Token 已保存", "account_id", result.AccountID, "ip", getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Token 已保存",
		"data":    result,
	})
}

// ------------------- [CF Tunnel 配置管理] -------------------

// apiCFTunnelSettings GET/POST /api/cf/tunnel/settings
// GET: 读取配置（token 脱敏�?
// POST: 保存配置
func apiCFTunnelSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings := service.GetCFTunnelSettings()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data":   settings,
		})

	case http.MethodPost:
		var data map[string]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			sendJSON(w, "error", "请求格式错误")
			return
		}

		if err := service.SaveCFTunnelSettings(data); err != nil {
			logger.Log.Warn("保存 CF Tunnel 配置失败", "error", err, "ip", getClientIP(r))
			sendJSON(w, "error", err.Error())
			return
		}

		logger.Log.Info("CF Tunnel 配置已保存", "ip", getClientIP(r))
		sendJSON(w, "success", "配置保存成功")

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ------------------- [cloudflared 二进制管理] -------------------

// apiCFTunnelPrepare POST /api/cf/tunnel/cloudflared/prepare
// [FIX-13] SSE 流式返回下载进度
func apiCFTunnelPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否已存在
	exists, ver := service.CheckCloudflaredBinary()
	if exists {
		sendJSON(w, "success", map[string]interface{}{
			"message": "cloudflared 已就绪",
			"version": ver,
			"exists":  true,
		})
		return
	}

	// 设置 SSE 流式响应
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "服务器不支持 SSE 流式响应")
		return
	}

	// 发送进度事�?
	sendSSE := func(eventType, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
		flusher.Flush()
	}

	sendSSE("progress", `{"percent": 0, "message": "开始下�?cloudflared..."}`)

	err := service.DownloadCloudflared(func(downloaded, total int64, percent int) {
		var msg string
		if total > 0 {
			msg = fmt.Sprintf("已下�?%.1f / %.1f MB (%d%%)",
				float64(downloaded)/1024/1024, float64(total)/1024/1024, percent)
		} else {
			msg = fmt.Sprintf("已下�?%.1f MB", float64(downloaded)/1024/1024)
		}
		data, _ := json.Marshal(map[string]interface{}{
			"percent":    percent,
			"message":    msg,
			"downloaded": downloaded,
			"total":      total,
		})
		sendSSE("progress", string(data))
	})

	if err != nil {
		logger.Log.Error("下载 cloudflared 失败", "error", err)
		data, _ := json.Marshal(map[string]interface{}{
			"message": "下载失败: " + err.Error(),
		})
		sendSSE("error", string(data))
		return
	}

	_, ver = service.CheckCloudflaredBinary()
	data, _ := json.Marshal(map[string]interface{}{
		"percent": 100,
		"message": "下载完成",
		"version": ver,
	})
	sendSSE("done", string(data))

	logger.Log.Info("cloudflared 下载完成", "version", ver, "ip", getClientIP(r))
}

// ------------------- [Tunnel CRUD] -------------------

// apiCFTunnelCreate POST /api/cf/tunnel/create
// [FIX-03] 幂等创建 Tunnel
func apiCFTunnelCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnelID, err := service.CreateCFTunnel()
	if err != nil {
		logger.Log.Error("创建 Tunnel 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("Tunnel 创建/复用成功", "tunnel_id", tunnelID, "ip", getClientIP(r))
	sendJSON(w, "success", map[string]interface{}{
		"message":   "Tunnel 创建成功",
		"tunnel_id": tunnelID,
	})
}

// apiCFTunnelDNS POST /api/cf/tunnel/dns
// 绑定子域�?CNAME
func apiCFTunnelDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.BindTunnelDNS(); err != nil {
		logger.Log.Error("绑定 DNS 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	// 同步更新远程 Ingress 规则（Token 模式�?cloudflared 依赖此配置路由流量）
	if err := service.ConfigureTunnelRemoteIngress(); err != nil {
		logger.Log.Warn("更新远程 Ingress 规则失败（非致命）", "error", err, "ip", getClientIP(r))
	}

	logger.Log.Info("Tunnel DNS 绑定成功", "ip", getClientIP(r))
	sendJSON(w, "success", "DNS 绑定成功")
}

// apiCFTunnelDelete DELETE /api/cf/tunnel/delete
// [FIX-04] 删除 Tunnel + DNS + 本地文件
func apiCFTunnelDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.DeleteCFTunnel(); err != nil {
		logger.Log.Error("删除 Tunnel 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("Tunnel 已删除", "ip", getClientIP(r))
	sendJSON(w, "success", "Tunnel 已删除")
}

// ------------------- [配置文件生成] -------------------

// apiCFTunnelConfigRender POST /api/cf/tunnel/config/render
func apiCFTunnelConfigRender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.RenderTunnelConfig(); err != nil {
		logger.Log.Error("生成 Tunnel 配置失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("Tunnel 配置文件已生成", "ip", getClientIP(r))
	sendJSON(w, "success", "配置文件已生成")
}

// ------------------- [运行控制] -------------------

// apiCFTunnelRun POST /api/cf/tunnel/run
func apiCFTunnelRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.StartCFTunnel(); err != nil {
		logger.Log.Error("启动 Tunnel 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	// [FIX-08] panel_url 智能回写
	handlePanelURLWriteback(r)

	logger.Log.Info("Tunnel 已启动", "ip", getClientIP(r))
	sendJSON(w, "success", "Tunnel 已启动")
}

// apiCFTunnelStop POST /api/cf/tunnel/stop
func apiCFTunnelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	service.StopCFTunnel()
	logger.Log.Info("Tunnel 已停止", "ip", getClientIP(r))
	sendJSON(w, "success", "Tunnel 已停止")
}

// ------------------- [状态查询] -------------------

// apiCFTunnelStatus GET /api/cf/tunnel/status
func apiCFTunnelStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	status := service.GetCFTunnelStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   status,
	})
}

// apiCFTunnelLogs GET /api/cf/tunnel/logs
func apiCFTunnelLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			lines = n
		}
	}

	logs := service.GetCFTunnelLogs(lines)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   logs,
	})
}

// ------------------- [辅助函数] -------------------

// handlePanelURLWriteback [FIX-08] panel_url 智能回写
// 仅当 panel_url 为空时自动填�?
func handlePanelURLWriteback(r *http.Request) {
	settings := service.GetCFTunnelSettings()
	subdomain := settings.TunnelSubdomain
	if subdomain == "" {
		return
	}

	currentPanelURL := service.GetCFConfigPublic("panel_url")
	if currentPanelURL == "" {
		newURL := "https://" + subdomain
		service.SetCFConfigPublic("panel_url", newURL)
		logger.Log.Info("panel_url 已自动回填", "value", newURL, "ip", getClientIP(r))
	}
}

// ------------------- [懒人模式: 自动发现] -------------------

// apiCFTunnelDetect POST /api/cf/tunnel/detect
// 通过 Token 自动发现 Account ID、域名列表等信息
func apiCFTunnelDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.Token == "" {
		req.Token = service.GetCFConfigPublic("cf_api_key")
	}

	if req.Token == "" {
		sendJSON(w, "error", "Token 不能为空")
		return
	}

	result, err := service.AutoDiscoverCFAccount(req.Token)
	if err != nil {
		logger.Log.Warn("CF 自动发现失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("CF 自动发现成功", "account_id", result.AccountID, "ip", getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

// ------------------- [懒人模式: 一键部署] -------------------

// apiCFTunnelOneClick POST /api/cf/tunnel/oneclick
// SSE 流式返回一键部署进�?
func apiCFTunnelOneClick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token      string `json:"token"`
		Subdomain  string `json:"subdomain"`
		Domain     string `json:"domain"`
		TunnelName string `json:"tunnel_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.Token == "" {
		req.Token = service.GetCFConfigPublic("cf_api_key")
	}

	if req.Token == "" {
		sendJSON(w, "error", "Token 不能为空")
		return
	}

	// 设置 SSE 流式响应
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "服务器不支持 SSE 流式响应")
		return
	}

	sendSSE := func(eventType, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
		flusher.Flush()
	}

	err := service.OneClickSetupCFTunnel(req.Token, req.Subdomain, req.Domain, req.TunnelName,
		func(p service.OneClickSetupProgress) {
			data, _ := json.Marshal(p)
			sendSSE("progress", string(data))
		},
	)

	if err != nil {
		logger.Log.Error("一键部署失败", "error", err, "ip", getClientIP(r))
		errData, _ := json.Marshal(map[string]interface{}{
			"message": "部署失败: " + err.Error(),
		})
		sendSSE("error", string(errData))
		return
	}

	// 部署成功
	settings := service.GetCFTunnelSettings()
	doneData, _ := json.Marshal(map[string]interface{}{
		"message":   "🎉 一键部署完成！",
		"panel_url": "https://" + settings.TunnelSubdomain,
		"tunnel_id": settings.TunnelID,
		"subdomain": settings.TunnelSubdomain,
	})
	sendSSE("done", string(doneData))

	logger.Log.Info("一键部署成功", "subdomain", settings.TunnelSubdomain, "ip", getClientIP(r))
}

// ------------------- [Token 校验记录] -------------------

// apiCFGetLastTokenVerify GET /api/cf/token/last-verify
// 获取最近一次 Token 权限校验记录（持久化，跨会话有效）
func apiCFGetLastTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	record := service.GetLastTokenVerifyRecord()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   record,
	})
}
