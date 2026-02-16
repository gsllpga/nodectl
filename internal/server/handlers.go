package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
	"nodectl/internal/version"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ------------------- [通用辅助函数] -------------------

// sendJSON 辅助函数：快速返回 JSON 格式的响应
func sendJSON(w http.ResponseWriter, status, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status, "message": message})
}

// ------------------- [页面渲染逻辑] -------------------

// loginHandler 处理登录页面渲染和表单提交
func loginHandler(w http.ResponseWriter, r *http.Request) {
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
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		database.DB.Where("key = ?", "admin_password").First(&passConfig)
		err = bcrypt.CompareHashAndPassword([]byte(passConfig.Value), []byte(password))
		if err != nil {
			logger.Log.Warn("登录失败: 密码错误", "尝试用户名", username, "IP", r.RemoteAddr)
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
			logger.Log.Error("签发 Token 失败", "err", err.Error())
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

		logger.Log.Info("管理员登录成功", "用户名", username, "IP", r.RemoteAddr)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// indexHandler 处理主控制台界面渲染
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// SupportedProtocols 注入到模板数据中
	data := map[string]interface{}{
		"Title":     "Nodectl 总览",
		"Protocols": database.SupportedProtocols,
		"Version":   version.Version, // [新增] 将版本号传递给前端模板
	}
	tmpl.ExecuteTemplate(w, "index.html", data)
}

func apiUpdateNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 定义请求结构体
	var req struct {
		UUID          string            `json:"uuid"`
		Name          string            `json:"name"`
		RoutingType   int               `json:"routing_type"`
		IsBlocked     bool              `json:"is_blocked"`
		Links         map[string]string `json:"links"`
		DisabledLinks []string          `json:"disabled_links"`
		IPV4          string            `json:"ipv4"` // [新增] 接收 IPv4
		IPV6          string            `json:"ipv6"` // [新增] 接收 IPv6
	}

	// 解析 JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.UUID == "" {
		sendJSON(w, "error", "节点 UUID 不能为空")
		return
	}

	// [修改] 调用 Service 时传入 req.IPV4 和 req.IPV6
	err := service.UpdateNode(req.UUID, req.Name, req.RoutingType, req.Links, req.IsBlocked, req.DisabledLinks, req.IPV4, req.IPV6)
	if err != nil {
		logger.Log.Error("更新节点失败", "err", err.Error())
		sendJSON(w, "error", "数据库更新失败")
		return
	}

	logger.Log.Info("节点更新成功", "UUID", req.UUID)
	sendJSON(w, "success", "节点更新成功")
}

// logoutHandler 处理安全退出逻辑
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-1 * time.Hour),
	})
	logger.Log.Info("管理员已安全退出", "IP", r.RemoteAddr)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ------------------- [API 异步接口逻辑] -------------------

// apiChangePassword 接收 JSON 请求，处理修改密码操作
func apiChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldPassword     string `json:"old_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		sendJSON(w, "error", "两次输入的新密码不一致")
		return
	}
	if len(req.NewPassword) < 5 {
		sendJSON(w, "error", "新密码长度不能小于 5 位")
		return
	}

	var passConfig database.SysConfig
	if err := database.DB.Where("key = ?", "admin_password").First(&passConfig).Error; err != nil {
		sendJSON(w, "error", "系统错误，找不到管理员账号")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passConfig.Value), []byte(req.OldPassword)); err != nil {
		logger.Log.Warn("修改密码失败: 旧密码错误", "IP", r.RemoteAddr)
		sendJSON(w, "error", "当前密码输入错误")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Error("新密码加密失败", "err", err.Error())
		sendJSON(w, "error", "密码加密失败，请稍后重试")
		return
	}

	database.DB.Model(&database.SysConfig{}).Where("key = ?", "admin_password").Update("value", string(hashedPassword))
	secureBytes := make([]byte, 32)
	if _, err := rand.Read(secureBytes); err == nil {
		newSecret := hex.EncodeToString(secureBytes)
		database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", newSecret)
		logger.Log.Warn("管理员密码已修改，系统加密密钥已重置，所有旧会话已注销")
	}
	logger.Log.Info("管理员密码修改成功", "IP", r.RemoteAddr)

	// 强制下线当前凭证
	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	sendJSON(w, "success", "密码修改成功！1.5秒后将重新跳转到登录页")
}

// apiAddNode 接收 JSON 请求，处理新增节点操作
func apiAddNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name        string `json:"name"`
		RoutingType int    `json:"routing_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	// 调用 Service 层写入数据库
	node, err := service.AddNode(req.Name, req.RoutingType)
	if err != nil {
		logger.Log.Error("添加节点失败", "err", err.Error())
		sendJSON(w, "error", "数据库写入失败")
		return
	}

	logger.Log.Info("节点添加成功", "Name", node.Name, "RoutingType", node.RoutingType)
	sendJSON(w, "success", "节点添加成功")
}

// apiGetNodes 获取节点列表数据 (异步 API)
func apiGetNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var directNodes []database.NodePool
	var landNodes []database.NodePool

	database.DB.Where("routing_type = ?", 1).Order("sort_index ASC, created_at DESC").Find(&directNodes)
	database.DB.Where("routing_type = ?", 2).Order("sort_index ASC, created_at DESC").Find(&landNodes)

	// [新增] 顺便获取面板 URL 传给前端，供安装脚本拼接使用
	var panelURLConfig database.SysConfig
	database.DB.Where("key = ?", "panel_url").First(&panelURLConfig)

	response := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"direct_nodes": directNodes,
			"land_nodes":   landNodes,
			"panel_url":    panelURLConfig.Value, // [新增字段]
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// [新增] apiReorderNodes 处理拖拽排序和分组切换
func apiReorderNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 接收数据：目标分组 ID 和该分组内所有节点 UUID 的新顺序
	var req struct {
		TargetRoutingType int      `json:"target_routing_type"`
		NodeUUIDs         []string `json:"node_uuids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	// 调用 Service 更新顺序
	err := service.ReorderNodes(req.TargetRoutingType, req.NodeUUIDs)
	if err != nil {
		logger.Log.Error("更新排序失败", "err", err.Error())
		sendJSON(w, "error", "保存排序失败")
		return
	}

	sendJSON(w, "success", "排序已更新")
}

// apiDeleteNode 接收 JSON 请求，处理删除节点操作
func apiDeleteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 定义请求结构，只需要节点的 UUID
	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	// 简单的校验
	if req.UUID == "" {
		sendJSON(w, "error", "缺少节点 ID")
		return
	}

	// 执行物理删除 (根据 UUID 删除 NodePool 表中的记录)
	result := database.DB.Where("uuid = ?", req.UUID).Delete(&database.NodePool{})
	if result.Error != nil {
		logger.Log.Error("删除节点失败", "err", result.Error.Error())
		sendJSON(w, "error", "数据库删除失败")
		return
	}

	logger.Log.Info("节点已删除", "UUID", req.UUID)
	sendJSON(w, "success", "节点已删除")
}

// [修改] apiPublicScript 返回渲染后的安装脚本
func apiPublicScript(w http.ResponseWriter, r *http.Request) {
	// 调用 Service 层进行模板渲染 (填充端口等信息)
	scriptContent, err := service.RenderInstallScript()
	if err != nil {
		logger.Log.Error("脚本渲染失败", "err", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(scriptContent))
}

// [新增] apiCallbackReport 处理节点上报 (无需 Cookie，靠 install_id 鉴权)
func apiCallbackReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. 完整定义接收前端脚本上报的数据结构
	var report struct {
		InstallID string `json:"install_id"`
		Protocol  string `json:"protocol"`
		Link      string `json:"link"`
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
	}

	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		sendJSON(w, "error", "JSON 解析失败")
		return
	}

	if report.InstallID == "" {
		sendJSON(w, "error", "缺少 install_id")
		return
	}

	// 2. 校验并查找对应的节点
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", report.InstallID).First(&node).Error; err != nil {
		logger.Log.Warn("收到未知节点的上报", "install_id", report.InstallID)
		sendJSON(w, "error", "节点不存在")
		return
	}

	changed := false

	// 3. 处理协议和链接的上报
	if report.Protocol != "" && report.Link != "" {
		if node.Links == nil {
			node.Links = make(map[string]string)
		}
		// 将对应的协议链接存入 map 中
		node.Links[report.Protocol] = report.Link
		changed = true
		logger.Log.Info("节点协议已上报", "节点", node.Name, "协议", report.Protocol)
	}

	// 4. 处理双栈 IP 地址的上报
	if report.IPv4 != "" || report.IPv6 != "" {
		if report.IPv4 != "" {
			node.IPV4 = report.IPv4
		}
		if report.IPv6 != "" {
			node.IPV6 = report.IPv6
		}

		// [新增] 自动解析 Region
		// 优先使用 IPv4 解析，如果没有则尝试 IPv6
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
			logger.Log.Info("节点地区已更新", "节点", node.Name, "地区", newRegion)
		}

		changed = true
		logger.Log.Info("节点 IP 已更新", "节点", node.Name, "IPv4", report.IPv4, "IPv6", report.IPv6)
	}

	// 5. 保存回数据库
	if changed {
		// 使用 Save 会全量更新，能确保 JSON(Links map) 字段正确被序列化保存
		if err := database.DB.Save(&node).Error; err != nil {
			logger.Log.Error("保存节点上报数据失败", "err", err.Error())
			sendJSON(w, "error", "数据库保存失败")
			return
		}
	}

	sendJSON(w, "success", "上报接收成功")
}

// [新增] apiGetSettings 获取全局节点代理设置
func apiGetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var configs []database.SysConfig
	// [修改] 在 IN 查询列表中加入 "sub_token"
	database.DB.Where("key IN ?", []string{
		"panel_url", "sub_token", "proxy_port_ss", "proxy_port_hy2", "proxy_port_tuic",
		"proxy_port_reality", "proxy_reality_sni", "proxy_ss_method",
		"proxy_port_socks5", "proxy_socks5_user", "proxy_socks5_pass",
	}).Find(&configs)

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

// [新增] apiUpdateSettings 保存全局节点代理设置
func apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	// [修改] 在白名单中加入 "sub_token"
	validKeys := map[string]bool{
		"panel_url": true, "sub_token": true, "proxy_port_ss": true, "proxy_port_hy2": true,
		"proxy_port_tuic": true, "proxy_port_reality": true, "proxy_reality_sni": true,
		"proxy_ss_method": true, "proxy_port_socks5": true, "proxy_socks5_user": true, "proxy_socks5_pass": true,
	}

	for k, v := range req {
		if validKeys[k] {
			database.DB.Model(&database.SysConfig{}).Where("key = ?", k).Update("value", v)
		}
	}
	sendJSON(w, "success", "设置已保存")
}

// [新增] apiUpdateGeoIP 处理 GeoIP 数据库更新请求
func apiUpdateGeoIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		logger.Log.Info("后台开始更新 GeoIP 数据库...")
		if err := service.GlobalGeoIP.ForceUpdate(); err != nil {
			logger.Log.Error("GeoIP 数据库更新失败", "err", err.Error())
		} else {
			logger.Log.Info("GeoIP 数据库更新成功")
		}
	}()

	sendJSON(w, "success", "更新任务已在后台启动，请留意日志或稍后刷新")
}

// 在 internal/server/handlers.go 中添加：

// [新增] apiGetGeoStatus 获取 GeoIP 数据库状态
func apiGetGeoStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	localTime, errLocal := service.GlobalGeoIP.GetLocalDBTime()
	remoteTime, errRemote := service.GlobalGeoIP.CheckRemoteDBTime()

	status := "unknown"
	msg := ""

	// 简单的状态判断逻辑
	if errLocal != nil {
		status = "not_found" // 本地无文件
	} else if errRemote == nil && remoteTime.After(localTime.Add(24*time.Hour)) {
		// 远程时间比本地时间晚 24 小时以上，认为有更新
		status = "update_available"
	} else if errRemote == nil {
		status = "latest"
	} else {
		status = "check_failed" // 远程检查失败
	}

	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"local_time":  localTime.Format("2006-01-02"),
			"remote_time": remoteTime.Format("2006-01-02"),
			"state":       status, // latest, update_available, not_found, check_failed
			"error":       msg,
		},
	}

	// 如果获取远程时间失败，把错误带上，但如果本地有文件，不影响使用
	if errRemote != nil {
		resp["data"].(map[string]interface{})["remote_error"] = errRemote.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
