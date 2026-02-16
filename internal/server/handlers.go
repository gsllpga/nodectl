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
	data := map[string]interface{}{"Title": "Nodectl 总览"}
	tmpl.ExecuteTemplate(w, "index.html", data)
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

	// 按时间倒序查询
	database.DB.Where("routing_type = ?", 1).Order("created_at DESC").Find(&directNodes)
	database.DB.Where("routing_type = ?", 2).Order("created_at DESC").Find(&landNodes)

	// 构建返回的 JSON 结构
	response := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"direct_nodes": directNodes,
			"land_nodes":   landNodes,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
