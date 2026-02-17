package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
	"nodectl/internal/version"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AppStartTime 记录后端程序启动的确切时间
var AppStartTime = time.Now()

// ------------------- [通用辅助函数] -------------------

// sendJSON 辅助函数：快速返回 JSON 格式的响应
func sendJSON(w http.ResponseWriter, status, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status, "message": message})
}

// ------------------- [页面渲染逻辑] -------------------

// loginHandler 处理登录页面渲染和表单提交
func loginHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var userConfig database.SysConfig
		var passConfig database.SysConfig
		var secretConfig database.SysConfig

		err := database.DB.Where("key = ?", "admin_username").First(&userConfig).Error
		if errors.Is(err, gorm.ErrRecordNotFound) || userConfig.Value != username {
			logger.Log.Warn("登录拦截: 用户名不存在", "username", username, "ip", clientIP, "path", reqPath)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		database.DB.Where("key = ?", "admin_password").First(&passConfig)
		err = bcrypt.CompareHashAndPassword([]byte(passConfig.Value), []byte(password))
		if err != nil {
			logger.Log.Warn("登录拦截: 密码错误", "username", username, "ip", clientIP, "path", reqPath)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		database.DB.Where("key = ?", "jwt_secret").First(&secretConfig)

		claims := jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
			"iat":      time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secretConfig.Value))
		if err != nil {
			logger.Log.Error("签发 Token 失败", "error", err, "ip", clientIP, "path", reqPath)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "系统内部错误"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "nodectl_token",
			Value:    tokenString,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			MaxAge:   86400,
			Expires:  time.Now().Add(24 * time.Hour),
			SameSite: http.SameSiteLaxMode,
		})

		logger.Log.Info("管理员登录成功", "username", username, "ip", clientIP, "path", reqPath)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// indexHandler 处理主控制台界面渲染
func indexHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	var nodes []database.NodePool
	if err := database.DB.Find(&nodes).Error; err != nil {
		logger.Log.Error("获取节点统计失败", "error", err, "ip", clientIP, "path", reqPath)
	}

	stats := map[string]int{
		"Total":   0,
		"Direct":  0,
		"Landing": 0,
		"Blocked": 0,
	}
	stats["Total"] = len(nodes)

	rawProtoCounts := make(map[string]int)

	for _, node := range nodes {
		if node.IsBlocked {
			stats["Blocked"]++
		} else {
			if node.RoutingType == 1 {
				stats["Direct"]++
			} else if node.RoutingType == 2 {
				stats["Landing"]++
			}
		}

		for protoKey := range node.Links {
			rawProtoCounts[protoKey]++
		}
	}

	type ProtoStatItem struct {
		Name  string
		Count int
	}
	var displayProtoStats []ProtoStatItem

	for _, proto := range database.SupportedProtocols {
		count := rawProtoCounts[proto]
		if count > 0 {
			displayName := strings.ToUpper(proto)
			switch proto {
			case "ss":
				displayName = "Shadowsocks"
			case "hy2":
				displayName = "Hysteria2"
			case "socks5":
				displayName = "Socks5"
			}
			displayProtoStats = append(displayProtoStats, ProtoStatItem{
				Name:  displayName,
				Count: count,
			})
		}
	}

	data := map[string]interface{}{
		"Title":      "Nodectl 总览",
		"Protocols":  database.SupportedProtocols,
		"Version":    version.Version,
		"Stats":      stats,
		"ProtoStats": displayProtoStats,
	}
	tmpl.ExecuteTemplate(w, "index.html", data)
}

// logoutHandler 处理安全退出逻辑
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-1 * time.Hour),
	})

	logger.Log.Info("管理员已安全退出", "ip", clientIP, "path", reqPath)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ------------------- [API 异步接口逻辑] -------------------

func apiUpdateNode(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UUID          string            `json:"uuid"`
		Name          string            `json:"name"`
		RoutingType   int               `json:"routing_type"`
		IsBlocked     bool              `json:"is_blocked"`
		Links         map[string]string `json:"links"`
		DisabledLinks []string          `json:"disabled_links"`
		IPV4          string            `json:"ipv4"`
		IPV6          string            `json:"ipv6"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.UUID == "" {
		logger.Log.Warn("请求缺少 UUID", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "节点 UUID 不能为空")
		return
	}

	err := service.UpdateNode(req.UUID, req.Name, req.RoutingType, req.Links, req.IsBlocked, req.DisabledLinks, req.IPV4, req.IPV6)
	if err != nil {
		logger.Log.Error("更新节点数据库失败", "error", err, "uuid", req.UUID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库更新失败")
		return
	}

	logger.Log.Info("节点更新成功", "uuid", req.UUID, "name", req.Name, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "节点更新成功")
}

func apiChangePassword(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldPassword     string `json:"old_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		logger.Log.Warn("修改密码失败: 两次密码不一致", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "两次输入的新密码不一致")
		return
	}
	if len(req.NewPassword) < 5 {
		logger.Log.Warn("修改密码失败: 密码过短", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "新密码长度不能小于 5 位")
		return
	}

	var passConfig database.SysConfig
	if err := database.DB.Where("key = ?", "admin_password").First(&passConfig).Error; err != nil {
		logger.Log.Error("修改密码失败: 找不到密码配置", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "系统错误，找不到管理员账号")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passConfig.Value), []byte(req.OldPassword)); err != nil {
		logger.Log.Warn("修改密码拦截: 旧密码验证失败", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "当前密码输入错误")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Error("新密码 Bcrypt 加密失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "密码加密失败，请稍后重试")
		return
	}

	database.DB.Model(&database.SysConfig{}).Where("key = ?", "admin_password").Update("value", string(hashedPassword))
	secureBytes := make([]byte, 32)
	if _, err := rand.Read(secureBytes); err == nil {
		newSecret := hex.EncodeToString(secureBytes)
		database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", newSecret)
		logger.Log.Info("系统级密钥 (JWT Secret) 已重置", "ip", clientIP, "path", reqPath)
	}

	logger.Log.Info("管理员密码修改成功", "ip", clientIP, "path", reqPath)

	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	sendJSON(w, "success", "密码修改成功！1.5秒后将重新跳转到登录页")
}

func apiAddNode(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name        string `json:"name"`
		RoutingType int    `json:"routing_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	node, err := service.AddNode(req.Name, req.RoutingType)
	if err != nil {
		logger.Log.Error("添加节点入库失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库写入失败")
		return
	}

	logger.Log.Info("节点添加成功", "uuid", node.UUID, "name", node.Name, "routing_type", node.RoutingType, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "节点添加成功")
}

func apiGetNodes(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodGet {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var directNodes []database.NodePool
	var landNodes []database.NodePool

	database.DB.Where("routing_type = ?", 1).Order("sort_index ASC, created_at DESC").Find(&directNodes)
	database.DB.Where("routing_type = ?", 2).Order("sort_index ASC, created_at DESC").Find(&landNodes)

	var panelURLConfig database.SysConfig
	database.DB.Where("key = ?", "panel_url").First(&panelURLConfig)

	response := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"direct_nodes": directNodes,
			"land_nodes":   landNodes,
			"panel_url":    panelURLConfig.Value,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func apiReorderNodes(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetRoutingType int      `json:"target_routing_type"`
		NodeUUIDs         []string `json:"node_uuids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	err := service.ReorderNodes(req.TargetRoutingType, req.NodeUUIDs)
	if err != nil {
		logger.Log.Error("更新排序入库失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "保存排序失败")
		return
	}

	logger.Log.Info("节点排序更新成功", "target_group", req.TargetRoutingType, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "排序已更新")
}

func apiDeleteNode(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.UUID == "" {
		logger.Log.Warn("请求缺少节点 UUID", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "缺少节点 ID")
		return
	}

	result := database.DB.Where("uuid = ?", req.UUID).Delete(&database.NodePool{})
	if result.Error != nil {
		logger.Log.Error("删除节点失败", "error", result.Error, "uuid", req.UUID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库删除失败")
		return
	}

	logger.Log.Info("节点已删除", "uuid", req.UUID, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "节点已删除")
}

func apiPublicScript(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	scriptContent, err := service.RenderInstallScript()
	if err != nil {
		logger.Log.Error("安装脚本模板渲染失败", "error", err, "ip", clientIP, "path", reqPath)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	logger.Log.Debug("成功分发安装脚本", "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(scriptContent))
}

func apiCallbackReport(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var report struct {
		InstallID string `json:"install_id"`
		Protocol  string `json:"protocol"`
		Link      string `json:"link"`
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
	}

	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		logger.Log.Warn("解析回调 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "JSON 解析失败")
		return
	}

	if report.InstallID == "" {
		logger.Log.Warn("回调请求缺少 install_id", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "缺少 install_id")
		return
	}

	var node database.NodePool
	if err := database.DB.Where("install_id = ?", report.InstallID).First(&node).Error; err != nil {
		logger.Log.Warn("收到未知节点的上报", "install_id", report.InstallID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "节点不存在")
		return
	}

	changed := false

	if report.Protocol != "" && report.Link != "" {
		if node.Links == nil {
			node.Links = make(map[string]string)
		}
		node.Links[report.Protocol] = report.Link
		changed = true
		logger.Log.Info("接收到节点协议上报", "name", node.Name, "protocol", report.Protocol, "ip", clientIP)
	}

	if report.IPv4 != "" || report.IPv6 != "" {
		if report.IPv4 != "" {
			node.IPV4 = report.IPv4
		}
		if report.IPv6 != "" {
			node.IPV6 = report.IPv6
		}

		newRegion := ""
		if node.IPV4 != "" {
			newRegion = service.GlobalGeoIP.GetCountryIsoCode(node.IPV4)
		}
		if newRegion == "" && node.IPV6 != "" {
			newRegion = service.GlobalGeoIP.GetCountryIsoCode(node.IPV6)
		}

		if newRegion != "" && newRegion != node.Region {
			node.Region = newRegion
			changed = true
			logger.Log.Info("节点地区解析更新", "name", node.Name, "region", newRegion, "ip", clientIP)
		}

		changed = true
		logger.Log.Info("接收到节点 IP 上报", "name", node.Name, "ipv4", report.IPv4, "ipv6", report.IPv6, "ip", clientIP)
	}

	if changed {
		if err := database.DB.Save(&node).Error; err != nil {
			logger.Log.Error("保存节点上报数据失败", "error", err, "name", node.Name, "ip", clientIP, "path", reqPath)
			sendJSON(w, "error", "数据库保存失败")
			return
		}
	}

	sendJSON(w, "success", "上报接收成功")
}

func apiGetSettings(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodGet {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var configs []database.SysConfig
	if err := database.DB.Where("key IN ?", []string{
		"panel_url", "sub_token", "proxy_port_ss", "proxy_port_hy2", "proxy_port_tuic",
		"proxy_port_reality", "proxy_reality_sni", "proxy_ss_method",
		"proxy_port_socks5", "proxy_socks5_user", "proxy_socks5_pass", "pref_use_emoji_flag", "sub_custom_name", "pref_ip_strategy",
	}).Find(&configs).Error; err != nil {
		logger.Log.Error("读取系统配置失败", "error", err, "ip", clientIP, "path", reqPath)
	}

	data := make(map[string]string)
	for _, c := range configs {
		data[c.Key] = c.Value
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   data,
	})
}

func apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	validKeys := map[string]bool{
		"panel_url": true, "sub_token": true, "proxy_port_ss": true, "proxy_port_hy2": true,
		"proxy_port_tuic": true, "proxy_port_reality": true, "proxy_reality_sni": true,
		"proxy_ss_method": true, "proxy_port_socks5": true, "proxy_socks5_user": true, "proxy_socks5_pass": true, "pref_use_emoji_flag": true,
		"sub_custom_name": true, "pref_ip_strategy": true,
	}

	for k, v := range req {
		if validKeys[k] {
			if err := database.DB.Model(&database.SysConfig{}).Where("key = ?", k).Update("value", v).Error; err != nil {
				logger.Log.Error("更新系统配置异常", "key", k, "error", err, "ip", clientIP, "path", reqPath)
			}
		}
	}
	logger.Log.Info("系统全局配置已更新", "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "设置已保存")
}

func apiUpdateGeoIP(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Log.Info("接收到触发更新 GeoIP 数据库的请求", "ip", clientIP, "path", reqPath)
	go func() {
		logger.Log.Info("后台线程开始更新 GeoIP 数据库...")
		if err := service.GlobalGeoIP.ForceUpdate(); err != nil {
			logger.Log.Error("GeoIP 数据库更新失败", "error", err)
		} else {
			logger.Log.Info("GeoIP 数据库更新流程圆满完成")
		}
	}()

	sendJSON(w, "success", "更新任务已在后台启动，请留意日志或稍后刷新")
}

func apiGetGeoStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	localVersion := service.GlobalGeoIP.GetLocalVersion()
	remoteVersion, errRemote := service.GlobalGeoIP.GetRemoteVersion()

	status := "unknown"
	msg := ""

	// 字符串精确比对逻辑
	if localVersion == "" {
		status = "not_found" // 数据库没有记录，视为未下载
	} else if errRemote == nil && remoteVersion != "" && remoteVersion != localVersion {
		status = "update_available" // 版本字符串不一致，提示更新
	} else if errRemote == nil && remoteVersion == localVersion {
		status = "latest" // 完全一致，已是最新
	} else {
		status = "check_failed"
	}

	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"local_version":  localVersion,
			"remote_version": remoteVersion,
			"state":          status,
			"error":          msg,
		},
	}

	if errRemote != nil {
		resp["data"].(map[string]interface{})["remote_error"] = errRemote.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func apiGetClashSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	config := service.LoadClashModulesConfig()
	customModules := service.GetCustomClashModules()
	activeModules := service.GetActiveClashModules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"builtin_modules": config.Modules,
			"custom_modules":  customModules,
			"presets":         config.Presets,
			"active_modules":  activeModules,
		},
	})
}

func apiSaveCustomClashModules(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Modules []service.ClashModuleDef `json:"modules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析自定义分流模块失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据格式错误")
		return
	}

	if err := service.SaveCustomClashModules(req.Modules); err != nil {
		logger.Log.Error("保存自定义分流模块失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "保存自定义模块失败")
		return
	}

	logger.Log.Info("自定义分流模块保存成功", "ip", clientIP, "path", reqPath, "count", len(req.Modules))
	sendJSON(w, "success", "自定义模块保存成功")
}

func apiSaveClashSettings(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Modules []string `json:"modules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据解析失败")
		return
	}

	if err := service.SaveActiveClashModules(req.Modules); err != nil {
		logger.Log.Error("保存 Clash 模块设置失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "保存失败")
		return
	}

	logger.Log.Info("Clash 模板模块设置已更新", "modules", req.Modules, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "Clash 规则组合保存成功")
}

func verifySubToken(r *http.Request) bool {
	token := r.URL.Query().Get("token")
	var config database.SysConfig
	database.DB.Where("key = ?", "sub_token").First(&config)
	return token != "" && token == config.Value
}

func getBaseURL(r *http.Request) string {
	var config database.SysConfig
	database.DB.Where("key = ?", "panel_url").First(&config)
	if config.Value != "" {
		return strings.TrimRight(config.Value, "/")
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	return fmt.Sprintf("%s://%s", scheme, host)
}

func apiSubClash(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if !verifySubToken(r) {
		logger.Log.Warn("Clash 订阅请求: Token 验证失败", "ip", clientIP, "path", reqPath)
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	baseURL := getBaseURL(r)
	token := r.URL.Query().Get("token")

	relayURL := fmt.Sprintf("%s/sub/raw/2?token=%s", baseURL, token)
	exitURL := fmt.Sprintf("%s/sub/raw/1?token=%s", baseURL, token)

	yamlContent, err := service.RenderClashConfig(relayURL, exitURL, baseURL, token)
	if err != nil {
		logger.Log.Error("生成 Clash 订阅模板失败", "error", err, "ip", clientIP, "path", reqPath)
		http.Error(w, "模板生成失败", http.StatusInternalServerError)
		return
	}

	var nameConfig database.SysConfig
	database.DB.Where("key = ?", "sub_custom_name").First(&nameConfig)
	subName := nameConfig.Value
	if subName == "" {
		subName = "NodeCTL"
	}

	logger.Log.Debug("成功下发 Clash 订阅模板", "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("profile-title", subName)

	encodedName := url.QueryEscape(subName + ".yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=utf-8''%s`, encodedName))

	w.Write([]byte(yamlContent))
}

func apiSubV2ray(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if !verifySubToken(r) {
		logger.Log.Warn("V2Ray 订阅请求: Token 验证失败", "ip", clientIP, "path", reqPath)
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	var flagConfig database.SysConfig
	database.DB.Where("key = ?", "pref_use_emoji_flag").First(&flagConfig)
	useFlag := flagConfig.Value != "false"

	b64Content, err := service.GenerateV2RaySubBase64(useFlag)
	if err != nil {
		logger.Log.Error("生成 V2Ray Base64 订阅失败", "error", err, "ip", clientIP, "path", reqPath)
		http.Error(w, "订阅生成失败", http.StatusInternalServerError)
		return
	}

	var nameConfig database.SysConfig
	database.DB.Where("key = ?", "sub_custom_name").First(&nameConfig)
	subName := nameConfig.Value
	if subName == "" {
		subName = "NodeCTL"
	}

	logger.Log.Debug("成功下发 V2Ray Base64 订阅", "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("profile-title", subName)

	encodedName := url.QueryEscape(subName + ".txt")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=utf-8''%s`, encodedName))

	w.Write([]byte(b64Content))
}

func apiSubRaw(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if !verifySubToken(r) {
		logger.Log.Warn("Raw 节点列表请求: Token 验证失败", "ip", clientIP, "path", reqPath)
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	typeStr := pathParts[len(pathParts)-1]
	routingType := 1
	if typeStr == "2" {
		routingType = 2
	}

	var flagConfig database.SysConfig
	database.DB.Where("key = ?", "pref_use_emoji_flag").First(&flagConfig)
	useFlag := flagConfig.Value != "false"

	yamlContent, err := service.GenerateRawNodesYAML(routingType, useFlag)
	if err != nil {
		logger.Log.Error("生成 Raw 节点列表失败", "error", err, "routing_type", routingType, "ip", clientIP, "path", reqPath)
		http.Error(w, "节点生成失败", http.StatusInternalServerError)
		return
	}

	logger.Log.Debug("成功下发 Raw 节点列表", "routing_type", routingType, "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write([]byte(yamlContent))
}

func apiGetCustomRules(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodGet {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	directRaw := service.GetCustomDirectRules()
	proxyRules := service.GetCustomProxyRules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"direct": directRaw,
			"proxy":  proxyRules,
		},
	})
}

func apiSaveCustomRules(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DirectRules string                    `json:"direct"`
		ProxyRules  []service.CustomProxyRule `json:"proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据解析失败")
		return
	}

	if err := service.SaveCustomDirectRules(req.DirectRules); err != nil {
		logger.Log.Error("保存自定义直连规则失败", "error", err, "ip", clientIP, "path", reqPath)
	}
	if err := service.SaveCustomProxyRules(req.ProxyRules); err != nil {
		logger.Log.Error("保存自定义分流规则失败", "error", err, "ip", clientIP, "path", reqPath)
	}

	logger.Log.Info("自定义路由规则保存成功", "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "自定义规则保存成功")
}

func apiSubRuleList(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if !verifySubToken(r) {
		logger.Log.Warn("规则列表订阅请求: Token 验证失败", "ip", clientIP, "path", reqPath)
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/sub/rules/")
	var rawContent string

	if path == "direct" {
		rawContent = service.GetCustomDirectRules()
	} else if strings.HasPrefix(path, "proxy/") {
		id := strings.TrimPrefix(path, "proxy/")
		rules := service.GetCustomProxyRules()
		for _, rule := range rules {
			if rule.ID == id {
				rawContent = rule.Content
				break
			}
		}
	}

	formattedContent := service.ParseCustomRules(rawContent)

	logger.Log.Debug("成功下发智能格式化规则集", "rule_path", path, "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Write([]byte(formattedContent))
}

// apiGetSystemMonitor 获取系统运行状态与硬件监控数据
func apiGetSystemMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取 Go 底层内存状态
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 计算运行时长
	uptime := time.Since(AppStartTime)
	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60

	uptimeStr := ""
	if days > 0 {
		uptimeStr += fmt.Sprintf("%d天 ", days)
	}
	uptimeStr += fmt.Sprintf("%d时%d分%d秒", hours, minutes, seconds)

	// 组装监控数据
	data := map[string]interface{}{
		"os_arch":       fmt.Sprintf("%s / %s", runtime.GOOS, runtime.GOARCH), // 系统和架构
		"go_version":    runtime.Version(),                                    // Go版本
		"num_cpu":       runtime.NumCPU(),                                     // 逻辑CPU核心数
		"go_max_procs":  runtime.GOMAXPROCS(0),                                // 使用的线程数
		"num_goroutine": runtime.NumGoroutine(),                               // 当前协程数量
		"num_cgo_call":  runtime.NumCgoCall(),                                 // CGO调用次数
		"start_time":    AppStartTime.Format("2006/01/02 15:04:05"),           // 启动时间
		"uptime":        uptimeStr,                                            // 运行时长
		// 内存相关 (单位均为 Bytes，前端拿到后再转换为 MB/GB)
		"heap_alloc":  m.HeapAlloc,  // 当前分配的堆内存
		"heap_sys":    m.HeapSys,    // 向系统申请的堆内存
		"heap_inuse":  m.HeapInuse,  // 正在使用的堆内存
		"sys_mem":     m.Sys,        // 向系统申请的总内存
		"total_alloc": m.TotalAlloc, // 累计分配的内存(包含已释放的)
		"stack_inuse": m.StackInuse, // 栈内存使用量
		// GC 垃圾回收状态
		"num_gc":          m.NumGC,                       // 垃圾回收次数
		"pause_total_ms":  float64(m.PauseTotalNs) / 1e6, // GC总暂停时间(毫秒)
		"gc_cpu_fraction": m.GCCPUFraction,               // GC占用CPU的时间比例
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   data,
	})
}
