package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/middleware"
	"nodectl/internal/service"
	"nodectl/internal/version"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AppStartTime 记录后端程序启动的确切时间
var AppStartTime = time.Now()

// ------------------- [通用辅助函数] -------------------

// getClientIP 从请求中提取真实客户端 IP（支持反向代理场景）
// 优先级: X-Real-IP > X-Forwarded-For 第一个 > RemoteAddr
func getClientIP(r *http.Request) string {
	// 1. 优先使用 X-Real-IP（Nginx 常用）
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	// 2. 其次取 X-Forwarded-For 的第一个 IP（多级代理场景）
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.Split(xff, ",")[0]); ip != "" {
			return ip
		}
	}
	// 3. 兜底使用 RemoteAddr，并去掉端口号
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		// 处理 IPv6 带方括号的情况 [::1]:port
		if bracketIdx := strings.LastIndex(ip, "]"); bracketIdx != -1 {
			return strings.Trim(ip[:bracketIdx+1], "[]")
		}
		return ip[:idx]
	}
	return ip
}

// sendJSON 辅助函数：智能返回 JSON 响应
// payload 可以是 string (作为 message) 或 map (作为数据合并)
func sendJSON(w http.ResponseWriter, status string, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")

	// 1. 初始化基础响应结构
	response := map[string]interface{}{
		"status": status,
	}

	// 2. 根据 payload 的类型智能处理
	switch v := payload.(type) {
	case string:
		// 如果传入的是字符串，自动放入 "message" 字段 (兼容旧代码)
		response["message"] = v
	case map[string]interface{}:
		// 如果传入的是 Map，将其字段合并到顶层 JSON 中
		for k, val := range v {
			response[k] = val
		}
	default:
		// 其他情况作为 data 字段返回
		response["data"] = v
	}

	json.NewEncoder(w).Encode(response)
}

func parseConfigListValue(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "<empty>" {
		return nil
	}

	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		var arr []string
		if err := json.Unmarshal([]byte(raw), &arr); err == nil {
			out := make([]string, 0, len(arr))
			for _, v := range arr {
				v = strings.TrimSpace(v)
				if v != "" {
					out = append(out, v)
				}
			}
			return out
		}
	}

	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.Trim(strings.TrimSpace(p), `"`)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func summarizeListDelta(oldList, newList []string) (added []string, removed []string, reordered bool) {
	oldSet := make(map[string]struct{}, len(oldList))
	newSet := make(map[string]struct{}, len(newList))

	for _, v := range oldList {
		if v != "" {
			oldSet[v] = struct{}{}
		}
	}
	for _, v := range newList {
		if v != "" {
			newSet[v] = struct{}{}
		}
	}

	for _, v := range newList {
		if _, ok := oldSet[v]; !ok {
			added = append(added, v)
		}
	}
	for _, v := range oldList {
		if _, ok := newSet[v]; !ok {
			removed = append(removed, v)
		}
	}

	if len(added) == 0 && len(removed) == 0 && strings.Join(oldList, ",") != strings.Join(newList, ",") {
		reordered = true
	}

	return added, removed, reordered
}

func normalizeCustomRuleLines(raw string) []string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}

	return out
}

func diffCustomRuleLines(oldLines, newLines []string) (added []string, removed []string) {
	oldSet := make(map[string]struct{}, len(oldLines))
	newSet := make(map[string]struct{}, len(newLines))

	for _, v := range oldLines {
		oldSet[v] = struct{}{}
	}
	for _, v := range newLines {
		newSet[v] = struct{}{}
	}

	for _, v := range newLines {
		if _, ok := oldSet[v]; !ok {
			added = append(added, v)
		}
	}
	for _, v := range oldLines {
		if _, ok := newSet[v]; !ok {
			removed = append(removed, v)
		}
	}

	return added, removed
}

func limitJoinedValues(values []string, max int) string {
	if len(values) == 0 {
		return ""
	}
	if max <= 0 || len(values) <= max {
		return strings.Join(values, ",")
	}
	return strings.Join(values[:max], ",") + fmt.Sprintf(" 等%d项", len(values))
}

func customGroupName(rule service.CustomProxyRule) string {
	name := strings.TrimSpace(rule.Name)
	if name != "" {
		return name
	}
	if strings.TrimSpace(rule.ID) != "" {
		return rule.ID
	}
	return "未命名分组"
}

func airportRoutingTypeLabel(rt int) string {
	switch rt {
	case 1:
		return "直连"
	case 2:
		return "落地"
	default:
		return "禁用"
	}
}

func nodeRoutingTypeLabel(rt int) string {
	switch rt {
	case 1:
		return "直连"
	case 2:
		return "落地"
	default:
		return "未知"
	}
}

func normalizeAuthCookieTTLMode(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "1d", "3d", "7d", "never":
		return raw
	default:
		return "1d"
	}
}

func loadAuthCookieTTLMode() string {
	var cfg database.SysConfig
	if err := database.DB.Where("key = ?", "auth_cookie_ttl_mode").First(&cfg).Error; err != nil {
		return "1d"
	}
	return normalizeAuthCookieTTLMode(cfg.Value)
}

func resolveAuthCookieTTL(mode string) (expiresAt time.Time, maxAge int, persistent bool) {
	now := time.Now()
	switch normalizeAuthCookieTTLMode(mode) {
	case "3d":
		return now.Add(72 * time.Hour), 72 * 3600, true
	case "7d":
		return now.Add(7 * 24 * time.Hour), 7 * 24 * 3600, true
	case "never":
		return now.AddDate(20, 0, 0), 20 * 365 * 24 * 3600, true
	default:
		return now.Add(24 * time.Hour), 24 * 3600, true
	}
}

// ------------------- [页面渲染逻辑] -------------------

// loginHandler 处理登录页面渲染和表单提交
func loginHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	reqPath := r.URL.Path

	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		allowed, _, retryAfter := middleware.CheckLoginAttemptAllowed(clientIP)
		if !allowed {
			logger.Log.Warn("登录拦截: IP短期限流生效",
				"ip", clientIP,
				"path", reqPath,
				"retry_after_sec", int(retryAfter.Seconds()),
			)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录尝试次数过多，请稍后再试"})
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		var userConfig database.SysConfig
		var passConfig database.SysConfig
		var secretConfig database.SysConfig

		err := database.DB.Where("key = ?", "admin_username").First(&userConfig).Error
		if errors.Is(err, gorm.ErrRecordNotFound) || userConfig.Value != username {
			blocked, remaining, blockAfter := middleware.RecordLoginFailure(clientIP)
			if blocked {
				logger.Log.Warn("登录拦截: 用户名不存在且IP已短期封禁",
					"username", username,
					"ip", clientIP,
					"path", reqPath,
					"retry_after_sec", int(blockAfter.Seconds()),
				)
				tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录尝试次数过多，请稍后再试"})
				return
			}
			logger.Log.Warn("登录拦截: 用户名不存在", "username", username, "ip", clientIP, "path", reqPath, "remaining_attempts", remaining)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		database.DB.Where("key = ?", "admin_password").First(&passConfig)
		err = bcrypt.CompareHashAndPassword([]byte(passConfig.Value), []byte(password))
		if err != nil {
			blocked, remaining, blockAfter := middleware.RecordLoginFailure(clientIP)
			if blocked {
				logger.Log.Warn("登录拦截: 密码错误且IP已短期封禁",
					"username", username,
					"ip", clientIP,
					"path", reqPath,
					"retry_after_sec", int(blockAfter.Seconds()),
				)
				tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录尝试次数过多，请稍后再试"})
				return
			}
			logger.Log.Warn("登录拦截: 密码错误", "username", username, "ip", clientIP, "path", reqPath, "remaining_attempts", remaining)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		middleware.ClearLoginFailureRecord(clientIP)

		database.DB.Where("key = ?", "jwt_secret").First(&secretConfig)
		ttlMode := loadAuthCookieTTLMode()
		expireAt, maxAge, persistent := resolveAuthCookieTTL(ttlMode)

		claims := jwt.MapClaims{
			"username": username,
			"iat":      time.Now().Unix(),
		}
		if persistent {
			claims["exp"] = expireAt.Unix()
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
			MaxAge:   maxAge,
			Expires:  expireAt,
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
			case "trojan":
				displayName = "Trojan"
			case "vmess_tcp":
				displayName = "VMess-TCP"
			case "vmess_ws":
				displayName = "VMess-WS"
			case "vmess_http":
				displayName = "VMess-HTTP"
			case "vmess_quic":
				displayName = "VMess-QUIC"
			case "vmess_wst":
				displayName = "VMess-WS-TLS"
			case "vmess_hut":
				displayName = "VMess-HU-TLS"
			case "vless_wst":
				displayName = "VLESS-WS-TLS"
			case "vless_hut":
				displayName = "VLESS-HU-TLS"
			case "trojan_wst":
				displayName = "Trojan-WS-TLS"
			case "trojan_hut":
				displayName = "Trojan-HU-TLS"
			}
			displayProtoStats = append(displayProtoStats, ProtoStatItem{
				Name:  displayName,
				Count: count,
			})
		}
	}

	data := map[string]interface{}{
		"Title":      "Nodectl控制台",
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

// apiUpdateNode 更新节点信息
// 功能：接收前端请求，更新节点的基础信息和协议链接，包含演示模式下对内置节点核心资产的保护与专业提示
func apiUpdateNode(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	var req struct {
		database.NodePool
		// Add backwards compatibility explicitly if needed, but since we embedded NodePool, it has IPMode and LinkIPModes
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "无效的数据格式")
		return
	}

	// 2. 先从数据库查出真实存在的节点 (确保拿到主键 ID 和 原有数据)
	var targetNode database.NodePool
	if err := database.DB.First(&targetNode, "uuid = ?", req.UUID).Error; err != nil {
		logger.Log.Warn("更新失败: 节点不存在", "uuid", req.UUID, "ip", clientIP)
		sendJSON(w, "error", "节点不存在")
		return
	}

	// 记录更新前快照，用于输出精确变更日志
	oldNode := targetNode
	oldNode.Links = make(map[string]string, len(targetNode.Links))
	for k, v := range targetNode.Links {
		oldNode.Links[k] = v
	}
	oldNode.LinkIPModes = make(map[string]int, len(targetNode.LinkIPModes))
	for k, v := range targetNode.LinkIPModes {
		oldNode.LinkIPModes[k] = v
	}
	oldNode.DisabledLinks = append([]string(nil), targetNode.DisabledLinks...)

	demoPath := filepath.Join("data", "debug", "demo")
	if _, err := os.Stat(demoPath); err == nil {
		// 判定条件：节点创建时间早于程序启动时间 (内置节点)
		if targetNode.CreatedAt.Before(AppStartTime) {

			// 保护 1: 禁止修改或删除 IPv4 和 IPv6
			if targetNode.IPV4 != req.IPV4 || targetNode.IPV6 != req.IPV6 {
				logger.Log.Warn("演示模式拦截: 尝试修改或删除内置节点 IP", "uuid", req.UUID, "ip", clientIP)
				sendJSON(w, "error", "【演示模式保护】禁止修改或清空。如需体验修改功能，请新建节点。")
				return
			}

			// 保护 2: 禁止删除、清空或修改已有的协议链接
			for protoKey, oldVal := range targetNode.Links {
				newVal, exists := req.Links[protoKey]

				// 如果前端传来的数据中没有这个协议，或者内容为空，说明尝试删除
				if !exists || newVal == "" {
					logger.Log.Warn("演示模式拦截: 尝试删除内置节点协议", "uuid", req.UUID, "protocol", protoKey, "ip", clientIP)
					// [优化] 更专业的提示语
					sendJSON(w, "error", "【演示模式保护】内置预设节点的基础协议配置已被锁定，禁止删除。")
					return
				}

				// 如果前端传来的值与数据库原有值不同 (并且排除了系统占位符 "__KEEP_EXISTING__")，说明尝试修改
				if newVal != oldVal && newVal != "__KEEP_EXISTING__" {
					logger.Log.Warn("演示模式拦截: 尝试修改内置节点协议内容", "uuid", req.UUID, "protocol", protoKey, "ip", clientIP)
					sendJSON(w, "error", "【演示模式保护】禁止修改内容。如需体验完整编辑功能，请新建节点。")
					return
				}
			}
		}
	}
	// ---------------- [新增：演示模式严密保护逻辑 结束] ----------------

	// 3. 将前端请求的基础字段更新到数据库对象上
	targetNode.Name = req.Name
	targetNode.RoutingType = req.RoutingType
	targetNode.IsBlocked = req.IsBlocked
	targetNode.DisabledLinks = req.DisabledLinks
	targetNode.IPV4 = req.IPV4
	targetNode.IPV6 = req.IPV6
	targetNode.IPMode = req.IPMode
	targetNode.ResetDay = req.ResetDay
	targetNode.TrafficLimit = req.TrafficLimit

	// 4. 安全检查：判断是否处于安全环境
	isSecure := service.CheckRequestSecure(r)
	if !isSecure {
		var config database.SysConfig
		database.DB.Where("key = ?", "sys_force_http").First(&config)
		if config.Value == "true" {
			isSecure = true // 用户选择忽略风险，允许在 HTTP 下编辑
		}
	}

	// 5. 根据安全状态执行智能合并或全量覆盖
	if !isSecure {
		safeLinks := make(map[string]string)
		safeLinkIPModes := make(map[string]int)

		for k, v := range req.Links {
			if v == "__KEEP_EXISTING__" {
				if oldVal, ok := targetNode.Links[k]; ok {
					safeLinks[k] = oldVal
					// also keep existing ip mode
					if oldMode, mok := targetNode.LinkIPModes[k]; mok {
						safeLinkIPModes[k] = oldMode
					}
				}
			} else {
				if _, exists := targetNode.Links[k]; exists {
					safeLinks[k] = targetNode.Links[k]
				} else {
					safeLinks[k] = v
				}
				// allow updating link ip mode even if link value is safe-guarded
				if newMode, ok := req.LinkIPModes[k]; ok {
					safeLinkIPModes[k] = newMode
				}
			}
		}
		targetNode.Links = safeLinks
		targetNode.LinkIPModes = safeLinkIPModes
	} else {
		safeLinks := make(map[string]string)
		safeLinkIPModes := make(map[string]int)

		for k, v := range req.Links {
			if v == "__KEEP_EXISTING__" {
				if oldVal, ok := targetNode.Links[k]; ok {
					safeLinks[k] = oldVal
					if oldMode, mok := targetNode.LinkIPModes[k]; mok {
						safeLinkIPModes[k] = oldMode
					}
				}
			} else {
				safeLinks[k] = v
				if newMode, ok := req.LinkIPModes[k]; ok {
					safeLinkIPModes[k] = newMode
				}
			}
		}
		targetNode.Links = safeLinks
		targetNode.LinkIPModes = safeLinkIPModes
	}

	// 6. 保存更新
	if err := database.DB.Save(&targetNode).Error; err != nil {
		logger.Log.Error("更新节点数据库失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库更新失败")
		return
	}

	changedDetails := make([]string, 0)
	if oldNode.Name != targetNode.Name {
		changedDetails = append(changedDetails, fmt.Sprintf("name: %s -> %s", oldNode.Name, targetNode.Name))
	}
	if oldNode.RoutingType != targetNode.RoutingType {
		changedDetails = append(changedDetails, fmt.Sprintf("routing_type: %d -> %d", oldNode.RoutingType, targetNode.RoutingType))
	}
	if oldNode.IsBlocked != targetNode.IsBlocked {
		changedDetails = append(changedDetails, fmt.Sprintf("is_blocked: %t -> %t", oldNode.IsBlocked, targetNode.IsBlocked))
	}
	if oldNode.IPV4 != targetNode.IPV4 {
		changedDetails = append(changedDetails, fmt.Sprintf("ipv4: %s -> %s", oldNode.IPV4, targetNode.IPV4))
	}
	if oldNode.IPV6 != targetNode.IPV6 {
		changedDetails = append(changedDetails, fmt.Sprintf("ipv6: %s -> %s", oldNode.IPV6, targetNode.IPV6))
	}
	if oldNode.IPMode != targetNode.IPMode {
		changedDetails = append(changedDetails, fmt.Sprintf("ip_mode: %d -> %d", oldNode.IPMode, targetNode.IPMode))
	}
	if oldNode.ResetDay != targetNode.ResetDay {
		changedDetails = append(changedDetails, fmt.Sprintf("reset_day: %d -> %d", oldNode.ResetDay, targetNode.ResetDay))
	}
	if oldNode.TrafficLimit != targetNode.TrafficLimit {
		changedDetails = append(changedDetails, fmt.Sprintf("traffic_limit: %d -> %d", oldNode.TrafficLimit, targetNode.TrafficLimit))
	}

	oldDisabledSet := make(map[string]struct{}, len(oldNode.DisabledLinks))
	for _, p := range oldNode.DisabledLinks {
		oldDisabledSet[p] = struct{}{}
	}
	newDisabledSet := make(map[string]struct{}, len(targetNode.DisabledLinks))
	for _, p := range targetNode.DisabledLinks {
		newDisabledSet[p] = struct{}{}
	}
	addedDisabled := make([]string, 0)
	removedDisabled := make([]string, 0)
	for p := range newDisabledSet {
		if _, ok := oldDisabledSet[p]; !ok {
			addedDisabled = append(addedDisabled, p)
		}
	}
	for p := range oldDisabledSet {
		if _, ok := newDisabledSet[p]; !ok {
			removedDisabled = append(removedDisabled, p)
		}
	}
	if len(addedDisabled) > 0 {
		sort.Strings(addedDisabled)
		changedDetails = append(changedDetails, fmt.Sprintf("disabled_links_add: %s", strings.Join(addedDisabled, ",")))
	}
	if len(removedDisabled) > 0 {
		sort.Strings(removedDisabled)
		changedDetails = append(changedDetails, fmt.Sprintf("disabled_links_remove: %s", strings.Join(removedDisabled, ",")))
	}

	protoSet := make(map[string]struct{})
	for p := range oldNode.Links {
		protoSet[p] = struct{}{}
	}
	for p := range targetNode.Links {
		protoSet[p] = struct{}{}
	}
	protos := make([]string, 0, len(protoSet))
	for p := range protoSet {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, p := range protos {
		oldVal, oldOK := oldNode.Links[p]
		newVal, newOK := targetNode.Links[p]
		switch {
		case !oldOK && newOK:
			changedDetails = append(changedDetails, fmt.Sprintf("links[%s]: added", p))
		case oldOK && !newOK:
			changedDetails = append(changedDetails, fmt.Sprintf("links[%s]: removed", p))
		case oldOK && newOK && oldVal != newVal:
			changedDetails = append(changedDetails, fmt.Sprintf("links[%s]: updated", p))
		}
	}

	ipModeProtoSet := make(map[string]struct{})
	for p := range oldNode.LinkIPModes {
		ipModeProtoSet[p] = struct{}{}
	}
	for p := range targetNode.LinkIPModes {
		ipModeProtoSet[p] = struct{}{}
	}
	ipModeProtos := make([]string, 0, len(ipModeProtoSet))
	for p := range ipModeProtoSet {
		ipModeProtos = append(ipModeProtos, p)
	}
	sort.Strings(ipModeProtos)
	for _, p := range ipModeProtos {
		oldMode, oldOK := oldNode.LinkIPModes[p]
		newMode, newOK := targetNode.LinkIPModes[p]
		switch {
		case !oldOK && newOK:
			changedDetails = append(changedDetails, fmt.Sprintf("link_ip_modes[%s]: add %d", p, newMode))
		case oldOK && !newOK:
			changedDetails = append(changedDetails, fmt.Sprintf("link_ip_modes[%s]: removed", p))
		case oldOK && newOK && oldMode != newMode:
			changedDetails = append(changedDetails, fmt.Sprintf("link_ip_modes[%s]: %d -> %d", p, oldMode, newMode))
		}
	}

	if len(changedDetails) == 0 {
		// 前端存在自动保存场景，无字段变化时不写日志，避免产生重复噪声
	} else {
		logger.Log.Info("节点更新成功",
			"name", targetNode.Name,
			"uuid", targetNode.UUID,
			"changed_count", len(changedDetails),
			"changes", strings.Join(changedDetails, " | "),
			"ip", clientIP,
			"path", reqPath,
		)
	}
	sendJSON(w, "success", "更新成功")
}

func apiChangePassword(w http.ResponseWriter, r *http.Request) {

	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	demoPath := filepath.Join("data", "debug", "demo")
	if _, err := os.Stat(demoPath); err == nil {
		// 如果 demo 文件存在 (不报 err)，说明开启了演示模式
		logger.Log.Warn("尝试在演示模式下修改密码，已被拦截", "ip", r.RemoteAddr)
		sendJSON(w, "error", "演示模式已开启，禁止修改密码")
		return
	}

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

	// 修改密码时同时重置 JWT 密钥，强制所有设备下线
	secureBytes := make([]byte, 32)
	if _, err := rand.Read(secureBytes); err == nil {
		newSecret := hex.EncodeToString(secureBytes)
		database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", newSecret)
		logger.Log.Info("系统级密钥 (JWT Secret) 已重置", "ip", clientIP, "path", reqPath)
	} else {
		logger.Log.Error("生成新密钥失败", "error", err, "ip", clientIP, "path", reqPath)
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

func apiResetJWT(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	demoPath := filepath.Join("data", "debug", "demo")
	if _, err := os.Stat(demoPath); err == nil {
		logger.Log.Warn("尝试在演示模式下重置JWT密钥，已被拦截", "ip", r.RemoteAddr)
		sendJSON(w, "error", "演示模式已开启，禁止重置密钥")
		return
	}

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	secureBytes := make([]byte, 32)
	if _, err := rand.Read(secureBytes); err == nil {
		newSecret := hex.EncodeToString(secureBytes)
		database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", newSecret)
		logger.Log.Info("系统级密钥 (JWT Secret) 已手动重置", "ip", clientIP, "path", reqPath)
	} else {
		logger.Log.Error("生成新密钥失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "生成新密钥失败，请稍后重试")
		return
	}

	// 清除当前用户的 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	sendJSON(w, "success", "JWT 密钥重置成功！所有设备已下线，请重新登录")
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
		ResetDay    int    `json:"reset_day"`
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

	if req.ResetDay > 0 {
		if err := database.DB.Model(&database.NodePool{}).Where("uuid = ?", node.UUID).Update("reset_day", req.ResetDay).Error; err != nil {
			logger.Log.Error("补充更新重置日失败", "uuid", node.UUID, "error", err)
			// 即使这个失败了，节点也算创建成功，只记录日志即可
		}
	}

	logger.Log.Info("节点添加成功", "uuid", node.UUID, "name", node.Name, "routing_type", node.RoutingType, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "节点添加成功")
}

// apiGetNodes 获取所有节点列表
func apiGetNodes(w http.ResponseWriter, r *http.Request) {
	// 1. 从数据库查询所有节点，按 SortIndex 排序
	var nodes []database.NodePool
	if err := database.DB.Order("sort_index ASC").Find(&nodes).Error; err != nil {
		logger.Log.Error("获取节点列表失败", "error", err)
		sendJSON(w, "error", "获取节点数据失败")
		return
	}

	// 2. 安全检查：判断是否处于安全环境 (HTTPS 协议 或 用户开启了强制 HTTP)
	isSecure := service.CheckRequestSecure(r)
	if !isSecure {
		var config database.SysConfig
		database.DB.Where("key = ?", "sys_force_http").First(&config)
		if config.Value == "true" {
			isSecure = true // 用户选择忽略风险，视为安全
		}
	}

	// 如果依然不安全，则脱敏(隐藏)真实链接
	if !isSecure {
		for i := range nodes {
			maskedLinks := make(map[string]string)
			for k := range nodes[i].Links {
				maskedLinks[k] = "🔒 安全保护: 仅 HTTPS 可见"
			}
			nodes[i].Links = maskedLinks
		}
	}

	// 3. [核心修复] 将节点分类为直连和落地，适配前端展示需求
	var directNodes []database.NodePool
	var landNodes []database.NodePool

	for _, node := range nodes {
		if node.RoutingType == 1 {
			directNodes = append(directNodes, node)
		} else if node.RoutingType == 2 {
			landNodes = append(landNodes, node)
		}
	}

	// 确保空切片序列化为 [] 而不是 null
	if directNodes == nil {
		directNodes = []database.NodePool{}
	}
	if landNodes == nil {
		landNodes = []database.NodePool{}
	}

	// 获取面板地址 (前端复制链接时需要)
	var config database.SysConfig
	database.DB.Where("key = ?", "panel_url").First(&config)

	// 4. 返回结构化数据
	sendJSON(w, "success", map[string]interface{}{
		"data": map[string]interface{}{
			"direct_nodes": directNodes,
			"land_nodes":   landNodes,
			"panel_url":    config.Value,
		},
	})
}

// apiGetOfflineNotifySettings 获取节点离线通知设置列表
func apiGetOfflineNotifySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var nodes []database.NodePool
	if err := database.DB.Select("uuid", "name", "install_id", "offline_notify_enabled", "offline_notify_grace_sec", "offline_last_notify_at", "sort_index", "updated_at").
		Order("sort_index ASC, updated_at DESC").
		Find(&nodes).Error; err != nil {
		sendJSON(w, "error", "读取离线通知配置失败")
		return
	}

	items := make([]map[string]interface{}, 0, len(nodes))
	for _, n := range nodes {
		grace := service.NormalizeNodeOfflineGraceSec(n.OfflineNotifyGraceSec)
		item := map[string]interface{}{
			"uuid":                     n.UUID,
			"install_id":               n.InstallID,
			"name":                     n.Name,
			"offline_notify_enabled":   n.OfflineNotifyEnabled,
			"offline_notify_grace_sec": grace,
			"online":                   service.IsNodeOnline(n.InstallID),
		}
		if n.OfflineLastNotifyAt != nil && !n.OfflineLastNotifyAt.IsZero() {
			item["offline_last_notify_at"] = n.OfflineLastNotifyAt.Format("2006-01-02 15:04:05")
		} else {
			item["offline_last_notify_at"] = "-"
		}
		items = append(items, item)
	}

	sendJSON(w, "success", map[string]interface{}{"nodes": items})
}

// apiUpdateOfflineNotifySetting 更新单个节点离线通知设置
func apiUpdateOfflineNotifySetting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UUID                  string `json:"uuid"`
		OfflineNotifyEnabled  *bool  `json:"offline_notify_enabled"`
		OfflineNotifyGraceSec *int   `json:"offline_notify_grace_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}
	req.UUID = strings.TrimSpace(req.UUID)
	if req.UUID == "" {
		sendJSON(w, "error", "缺少节点 UUID")
		return
	}

	updates := map[string]interface{}{}
	if req.OfflineNotifyEnabled != nil {
		updates["offline_notify_enabled"] = *req.OfflineNotifyEnabled
	}
	if req.OfflineNotifyGraceSec != nil {
		updates["offline_notify_grace_sec"] = service.NormalizeNodeOfflineGraceSec(*req.OfflineNotifyGraceSec)
	}
	if len(updates) == 0 {
		sendJSON(w, "error", "没有可更新的字段")
		return
	}

	res := database.DB.Model(&database.NodePool{}).Where("uuid = ?", req.UUID).Updates(updates)
	if res.Error != nil {
		sendJSON(w, "error", "更新失败")
		return
	}
	if res.RowsAffected == 0 {
		sendJSON(w, "error", "节点不存在")
		return
	}

	if req.OfflineNotifyEnabled != nil {
		var node database.NodePool
		if err := database.DB.Select("install_id").Where("uuid = ?", req.UUID).First(&node).Error; err == nil {
			service.OnNodeConnectionStatusChanged(node.InstallID, service.IsNodeOnline(node.InstallID))
		}
	}

	sendJSON(w, "success", "设置已更新")
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

	if len(req.NodeUUIDs) == 0 {
		sendJSON(w, "success", "排序已更新")
		return
	}

	var oldNodes []database.NodePool
	if err := database.DB.Select("uuid", "name", "routing_type", "sort_index").Where("uuid IN ?", req.NodeUUIDs).Find(&oldNodes).Error; err != nil {
		logger.Log.Error("读取重排前节点状态失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "保存排序失败")
		return
	}

	oldByUUID := make(map[string]database.NodePool, len(oldNodes))
	for _, n := range oldNodes {
		oldByUUID[n.UUID] = n
	}

	movedDetails := make([]string, 0)
	for _, uuid := range req.NodeUUIDs {
		if old, ok := oldByUUID[uuid]; ok && old.RoutingType != req.TargetRoutingType {
			name := strings.TrimSpace(old.Name)
			if name == "" {
				name = old.UUID
			}
			movedDetails = append(movedDetails, fmt.Sprintf("节点 %s；节点类型 由 %s 改为 %s", name, nodeRoutingTypeLabel(old.RoutingType), nodeRoutingTypeLabel(req.TargetRoutingType)))
		}
	}

	oldOrder := append([]string(nil), req.NodeUUIDs...)
	sort.Slice(oldOrder, func(i, j int) bool {
		li, lok := oldByUUID[oldOrder[i]]
		lj, rok := oldByUUID[oldOrder[j]]
		if !lok && !rok {
			return oldOrder[i] < oldOrder[j]
		}
		if !lok {
			return false
		}
		if !rok {
			return true
		}
		if li.SortIndex == lj.SortIndex {
			return li.UUID < lj.UUID
		}
		return li.SortIndex < lj.SortIndex
	})

	orderChanged := false
	if len(oldOrder) == len(req.NodeUUIDs) {
		for i := range req.NodeUUIDs {
			if req.NodeUUIDs[i] != oldOrder[i] {
				orderChanged = true
				break
			}
		}
	}

	err := service.ReorderNodes(req.TargetRoutingType, req.NodeUUIDs)
	if err != nil {
		logger.Log.Error("更新排序入库失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "保存排序失败")
		return
	}

	if len(movedDetails) > 0 {
		logger.Log.Info("节点更新成功",
			"changed_count", len(movedDetails),
			"changes", strings.Join(movedDetails, " | "),
			"target_group", req.TargetRoutingType,
			"ip", clientIP,
			"path", reqPath,
		)
	} else if orderChanged {
		logger.Log.Info("节点排序更新成功", "target_group", req.TargetRoutingType, "ip", clientIP, "path", reqPath)
	}

	sendJSON(w, "success", "排序已更新")
}

// apiDeleteNode 处理节点删除请求
// 功能：验证请求参数并从数据库中删除指定 UUID 的节点，支持演示模式下对内置节点的保护与专业拦截提示
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

	// 先查询目标节点，便于后续日志记录 name
	var targetNode database.NodePool
	if err := database.DB.Where("uuid = ?", req.UUID).First(&targetNode).Error; err != nil {
		logger.Log.Warn("删除拦截: 节点不存在", "uuid", req.UUID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "节点不存在")
		return
	}

	// 检查是否处于演示模式 (存在 data/debug/demo 文件)
	demoPath := filepath.Join("data", "debug", "demo")
	if _, err := os.Stat(demoPath); err == nil {
		if targetNode.CreatedAt.Before(AppStartTime) {
			logger.Log.Warn("尝试在演示模式下删除初始节点，已被拦截", "uuid", req.UUID, "name", targetNode.Name, "ip", clientIP)
			sendJSON(w, "error", "【演示模式保护】禁止删除。您可自由测试并删除您自行创建的节点。")
			return
		}
	}

	// 1. 显式删除关联的流量统计数据（不依赖外键级联）
	if err := database.DB.Where("node_uuid = ?", req.UUID).Delete(&database.NodeTrafficStat{}).Error; err != nil {
		logger.Log.Error("删除节点流量数据失败", "error", err, "uuid", req.UUID)
		// 不阻断，继续删除节点本身
	}

	// 2. 删除节点记录
	result := database.DB.Where("uuid = ?", req.UUID).Delete(&database.NodePool{})
	if result.Error != nil {
		logger.Log.Error("删除节点失败", "error", result.Error, "uuid", req.UUID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库删除失败")
		return
	}

	// 3. 清理内存中的实时状态（Agent 连接、流量缓存、前端订阅）
	service.CleanupNodeState(targetNode.InstallID, targetNode.UUID)

	logger.Log.Info("节点已删除", "uuid", req.UUID, "name", targetNode.Name, "ip", clientIP, "path", reqPath)
	sendJSON(w, "success", "节点已删除")
}

func apiPublicScript(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	// 1. 获取 URL 中的 id 参数
	installID := r.URL.Query().Get("id")
	if installID == "" {
		logger.Log.Warn("安装脚本请求被拦截", "reason", "缺少安装ID", "ip", clientIP)
		http.Error(w, "Missing InstallID", http.StatusBadRequest)
		return
	}

	// 2. 验证 ID 是否有效节点
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		logger.Log.Warn("安装脚本请求被拦截", "reason", "无效的安装ID", "id", installID, "ip", clientIP)
		http.Error(w, "Invalid InstallID", http.StatusForbidden)
		return
	}

	// 传递查出来的 node 对象给模板渲染函数
	scriptContent, err := service.RenderInstallScript(node)
	if err != nil {
		logger.Log.Error("安装脚本模板渲染失败", "error", err, "ip", clientIP, "path", reqPath)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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
		"proxy_port_reality", "proxy_ss_method",
		"proxy_port_socks5", "proxy_socks5_user", "proxy_socks5_pass", "proxy_socks5_random_auth", "pref_use_emoji_flag", "pref_force_protocol_prefix", "sub_custom_name", "pref_ip_strategy", "pref_default_install_protocols",
		"sys_force_http", "sys_log_level", "cf_email", "cf_api_key", "cf_domain", "cf_auto_renew", "airport_filter_invalid", "pref_speed_test_mode", "pref_speed_test_file_size", "pref_traffic_stats_retention_days",
		"auth_cookie_ttl_mode", "login_ip_retry_window_sec", "login_ip_max_retries", "login_ip_block_ttl_sec",
		"tg_bot_enabled", "tg_bot_token", "tg_bot_whitelist", "tg_bot_register_commands", "clash_proxies_update_interval", "clash_rules_update_interval", "clash_public_rules_update_interval",
		// 新增协议与内核优化配置
		"proxy_port_trojan", "proxy_hy2_sni", "proxy_tuic_sni", "proxy_enable_bbr",
		// VMess 族
		"proxy_port_vmess_tcp", "proxy_port_vmess_ws", "proxy_port_vmess_http", "proxy_port_vmess_quic",
		"proxy_port_vmess_wst", "proxy_port_vmess_hut",
		// VLESS-TLS 族
		"proxy_port_vless_wst", "proxy_port_vless_hut",
		// Trojan-TLS 族
		"proxy_port_trojan_wst", "proxy_port_trojan_hut",
		"proxy_tls_transport_path", "proxy_vmess_tls_sni", "proxy_vless_tls_sni", "proxy_trojan_tls_sni",
	}).Find(&configs).Error; err != nil {
		logger.Log.Error("读取系统配置失败", "error", err, "ip", clientIP, "path", reqPath)
	}

	data := make(map[string]string)
	for _, c := range configs {
		if (c.Key == "cf_api_key" || c.Key == "tg_bot_token") && c.Value != "" {
			data[c.Key] = "********"
		} else {
			data[c.Key] = c.Value
		}
	}

	// 获取当前证书的解析信息
	certInfo := service.GetCurrentCertInfo()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"data":      data,
		"cert_info": certInfo,
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
		"proxy_port_tuic": true, "proxy_port_reality": true,
		"proxy_ss_method": true, "proxy_port_socks5": true, "proxy_socks5_user": true, "proxy_socks5_pass": true, "proxy_socks5_random_auth": true, "pref_use_emoji_flag": true, "pref_force_protocol_prefix": true,
		"sub_custom_name": true, "pref_ip_strategy": true, "pref_default_install_protocols": true,
		"sys_force_http": true, "sys_log_level": true, "cf_email": true, "cf_api_key": true, "cf_domain": true, "cf_auto_renew": true,
		"airport_filter_invalid": true, "pref_speed_test_mode": true, "pref_speed_test_file_size": true, "pref_traffic_stats_retention_days": true,
		"auth_cookie_ttl_mode": true, "login_ip_retry_window_sec": true, "login_ip_max_retries": true, "login_ip_block_ttl_sec": true,
		"tg_bot_enabled": true, "tg_bot_token": true, "tg_bot_whitelist": true, "tg_bot_register_commands": true,
		"clash_proxies_update_interval": true, "clash_rules_update_interval": true, "clash_public_rules_update_interval": true,
		// 新增协议与内核优化配置
		"proxy_port_trojan": true,
		"proxy_hy2_sni":     true, "proxy_tuic_sni": true, "proxy_enable_bbr": true,
		// VMess 族
		"proxy_port_vmess_tcp": true, "proxy_port_vmess_ws": true, "proxy_port_vmess_http": true, "proxy_port_vmess_quic": true,
		"proxy_port_vmess_wst": true, "proxy_port_vmess_hut": true,
		// VLESS-TLS 族
		"proxy_port_vless_wst": true, "proxy_port_vless_hut": true,
		// Trojan-TLS 族
		"proxy_port_trojan_wst": true, "proxy_port_trojan_hut": true,
		"proxy_tls_transport_path": true,
		"proxy_vmess_tls_sni":      true, "proxy_vless_tls_sni": true, "proxy_trojan_tls_sni": true,
	}

	needRestartTgBot := false
	needRefreshLoginRateLimit := false
	changedDetails := make([]string, 0)

	maskValue := func(key, val string) string {
		if key == "cf_api_key" || key == "tg_bot_token" {
			if val == "" {
				return "<empty>"
			}
			return "********"
		}
		if val == "" {
			return "<empty>"
		}
		return val
	}

	for k, v := range req {
		if validKeys[k] {
			if (k == "cf_api_key" || k == "tg_bot_token") && v == "********" {
				continue
			}

			var oldConfig database.SysConfig
			oldValue := ""
			if err := database.DB.Where("key = ?", k).First(&oldConfig).Error; err == nil {
				oldValue = oldConfig.Value
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				logger.Log.Error("读取旧配置值失败", "key", k, "error", err, "ip", clientIP, "path", reqPath)
			}

			if k == "sys_log_level" {
				v = strings.ToLower(strings.TrimSpace(v))
				if v == "" {
					v = "info"
				}
				if oldValue == v {
					continue
				}
				if !logger.SetLevel(v) {
					logger.Log.Warn("收到非法日志等级配置，已拒绝更新", "value", v, "ip", clientIP, "path", reqPath)
					sendJSON(w, "error", "日志等级无效，仅支持: debug / info / warn / error")
					return
				}
			}

			if k == "pref_traffic_stats_retention_days" {
				v = strings.TrimSpace(v)
				days, err := strconv.Atoi(v)
				if err != nil || days < 1 || days > 3650 {
					sendJSON(w, "error", "流量记录保留天数无效，仅支持 1-3650 天")
					return
				}
				v = strconv.Itoa(days)
			}

			if k == "auth_cookie_ttl_mode" {
				v = normalizeAuthCookieTTLMode(v)
			}

			if k == "login_ip_retry_window_sec" {
				v = strings.TrimSpace(v)
				sec, err := strconv.Atoi(v)
				if err != nil || sec < 30 || sec > 86400 {
					sendJSON(w, "error", "登录失败计数窗口无效，仅支持 30-86400 秒")
					return
				}
				v = strconv.Itoa(sec)
			}

			if k == "login_ip_max_retries" {
				v = strings.TrimSpace(v)
				count, err := strconv.Atoi(v)
				if err != nil || count < 1 || count > 100 {
					sendJSON(w, "error", "登录最大重试次数无效，仅支持 1-100 次")
					return
				}
				v = strconv.Itoa(count)
			}

			if k == "login_ip_block_ttl_sec" {
				v = strings.TrimSpace(v)
				sec, err := strconv.Atoi(v)
				if err != nil || sec < 30 || sec > 86400 {
					sendJSON(w, "error", "登录封禁时长无效，仅支持 30-86400 秒")
					return
				}
				v = strconv.Itoa(sec)
			}

			if k != "sys_log_level" && oldValue == v {
				continue
			}

			if k == "tg_bot_enabled" || k == "tg_bot_token" || k == "tg_bot_whitelist" || k == "tg_bot_register_commands" {
				if oldConfig.Value != v {
					needRestartTgBot = true
				}
			}

			if k == "login_ip_retry_window_sec" || k == "login_ip_max_retries" || k == "login_ip_block_ttl_sec" {
				if oldConfig.Value != v {
					needRefreshLoginRateLimit = true
				}
			}

			// 强制公共规则更新间隔最小为 86400
			if k == "clash_public_rules_update_interval" {
				intVal, err := strconv.Atoi(v)
				if err != nil || intVal < 86400 {
					v = "86400"
				}
			}

			if err := database.DB.Model(&database.SysConfig{}).Where("key = ?", k).Update("value", v).Error; err != nil {
				logger.Log.Error("更新系统配置异常", "key", k, "error", err, "ip", clientIP, "path", reqPath)
				continue
			}

			if k == "pref_default_install_protocols" {
				added, removed, reordered := summarizeListDelta(parseConfigListValue(oldValue), parseConfigListValue(v))
				if len(added) > 0 {
					changedDetails = append(changedDetails, "默认安装协议新增: "+strings.Join(added, ","))
				}
				if len(removed) > 0 {
					changedDetails = append(changedDetails, "默认安装协议删除: "+strings.Join(removed, ","))
				}
				if reordered {
					changedDetails = append(changedDetails, "默认安装协议: 仅顺序变化")
				}
				if len(added) == 0 && len(removed) == 0 && !reordered {
					changedDetails = append(changedDetails, "默认安装协议: 无有效变化")
				}
			} else {
				changedDetails = append(changedDetails, fmt.Sprintf("%s: %s -> %s", k, maskValue(k, oldValue), maskValue(k, v)))
			}
		}
	}

	if needRestartTgBot {
		go service.RestartTelegramBot()
	}

	if needRefreshLoginRateLimit {
		if err := middleware.ReloadLoginRateLimitConfigFromDB(); err != nil {
			logger.Log.Error("热更新登录IP限流配置失败", "error", err, "ip", clientIP, "path", reqPath)
		}
	}

	if len(changedDetails) == 0 {
		logger.Log.Info("系统设置保存完成，但未检测到配置变更", "ip", clientIP, "path", reqPath)
		sendJSON(w, "success", "设置无变化")
		return
	}

	logger.Log.Info("系统全局配置已更新",
		"changed_count", len(changedDetails),
		"changes", strings.Join(changedDetails, " | "),
		"ip", clientIP,
		"path", reqPath,
	)
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

	oldModules := service.GetActiveClashModules()

	if err := service.SaveActiveClashModules(req.Modules); err != nil {
		logger.Log.Error("保存 Clash 模块设置失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "保存失败")
		return
	}

	oldSet := make(map[string]struct{}, len(oldModules))
	for _, m := range oldModules {
		oldSet[m] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(req.Modules))
	for _, m := range req.Modules {
		newSet[m] = struct{}{}
	}
	added := make([]string, 0)
	removed := make([]string, 0)
	for m := range newSet {
		if _, ok := oldSet[m]; !ok {
			added = append(added, m)
		}
	}
	for m := range oldSet {
		if _, ok := newSet[m]; !ok {
			removed = append(removed, m)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	oldOrder := strings.Join(oldModules, ",")
	newOrder := strings.Join(req.Modules, ",")
	reordered := oldOrder != newOrder && len(added) == 0 && len(removed) == 0

	changeSummary := make([]string, 0)
	if len(added) > 0 {
		changeSummary = append(changeSummary, "新增规则集: "+strings.Join(added, ","))
	}
	if len(removed) > 0 {
		changeSummary = append(changeSummary, "移除规则集: "+strings.Join(removed, ","))
	}
	if reordered {
		changeSummary = append(changeSummary, "仅顺序变化")
	}
	if len(changeSummary) == 0 {
		changeSummary = append(changeSummary, "无变化")
	}

	logger.Log.Info("Clash 模板模块设置已更新",
		"changed", strings.Join(changeSummary, " | "),
		"before_count", len(oldModules),
		"after_count", len(req.Modules),
		"ip", clientIP,
		"path", reqPath,
	)
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
	clientIP := getClientIP(r)
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

	logger.Log.Info("成功下发 Clash 订阅模板", "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("profile-title", subName)

	if userinfo := service.GetSubscriptionUserinfo(); userinfo != "" {
		w.Header().Set("Subscription-Userinfo", userinfo)
	}

	encodedName := url.QueryEscape(subName)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=utf-8''%s`, encodedName))

	w.Write([]byte(yamlContent))
}

func apiSubV2ray(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
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

	logger.Log.Info("成功下发 V2Ray Base64 订阅", "ip", clientIP, "path", reqPath)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("profile-title", subName)

	if userinfo := service.GetSubscriptionUserinfo(); userinfo != "" {
		w.Header().Set("Subscription-Userinfo", userinfo)
	}

	encodedName := url.QueryEscape(subName)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=utf-8''%s`, encodedName))

	w.Write([]byte(b64Content))
}

func apiSubRaw(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
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
	directIcon := service.GetCustomDirectIcon()
	proxyRules := service.GetCustomProxyRules()

	groupNames := make([]string, 0, len(proxyRules))
	for _, rule := range proxyRules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			name = strings.TrimSpace(rule.ID)
		}
		if name == "" {
			name = "未命名分组"
		}
		groupNames = append(groupNames, name)
	}
	groupNamesText := "无分流组"
	if len(groupNames) > 0 {
		groupNamesText = strings.Join(groupNames, ",")
	}

	logger.Log.Debug("获取自定义分流规则："+groupNamesText,
		"ip", clientIP,
		"path", reqPath,
		"direct_rules_len", len(strings.TrimSpace(directRaw)),
		"proxy_group_count", len(proxyRules),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"direct":      directRaw,
			"direct_icon": directIcon,
			"proxy":       proxyRules,
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

	oldDirectRules := service.GetCustomDirectRules()
	oldDirectIcon := service.GetCustomDirectIcon()
	oldProxyRules := service.GetCustomProxyRules()

	var req struct {
		DirectRules string                    `json:"direct"`
		DirectIcon  string                    `json:"direct_icon"`
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
	if err := service.SaveCustomDirectIcon(req.DirectIcon); err != nil {
		logger.Log.Error("保存自定义直连图标失败", "error", err, "ip", clientIP, "path", reqPath)
	}
	if err := service.SaveCustomProxyRules(req.ProxyRules); err != nil {
		logger.Log.Error("保存自定义分流规则失败", "error", err, "ip", clientIP, "path", reqPath)
	}

	changedDetails := make([]string, 0)

	oldDirectLines := normalizeCustomRuleLines(oldDirectRules)
	newDirectLines := normalizeCustomRuleLines(req.DirectRules)
	addedDirect, removedDirect := diffCustomRuleLines(oldDirectLines, newDirectLines)
	if strings.TrimSpace(oldDirectIcon) != strings.TrimSpace(req.DirectIcon) {
		changedDetails = append(changedDetails, fmt.Sprintf("全局直连 图标 %s -> %s", strings.TrimSpace(oldDirectIcon), strings.TrimSpace(req.DirectIcon)))
	}
	if len(addedDirect) > 0 {
		changedDetails = append(changedDetails, "全局直连 添加 "+limitJoinedValues(addedDirect, 8))
	}
	if len(removedDirect) > 0 {
		changedDetails = append(changedDetails, "全局直连 删除 "+limitJoinedValues(removedDirect, 8))
	}

	oldByID := make(map[string]service.CustomProxyRule, len(oldProxyRules))
	newByID := make(map[string]service.CustomProxyRule, len(req.ProxyRules))
	for _, rule := range oldProxyRules {
		if id := strings.TrimSpace(rule.ID); id != "" {
			oldByID[id] = rule
		}
	}
	for _, rule := range req.ProxyRules {
		if id := strings.TrimSpace(rule.ID); id != "" {
			newByID[id] = rule
		}
	}

	for id, oldRule := range oldByID {
		if _, ok := newByID[id]; !ok {
			changedDetails = append(changedDetails, fmt.Sprintf("删除策略组 %s", customGroupName(oldRule)))
		}
	}

	for id, newRule := range newByID {
		if _, ok := oldByID[id]; !ok {
			changedDetails = append(changedDetails, fmt.Sprintf("新建策略组 %s", customGroupName(newRule)))
		}
	}

	for _, newRule := range req.ProxyRules {
		oldRule, ok := oldByID[strings.TrimSpace(newRule.ID)]

		if !ok {
			added := normalizeCustomRuleLines(newRule.Content)
			if len(added) > 0 {
				changedDetails = append(changedDetails, fmt.Sprintf("%s 添加 %s", customGroupName(newRule), limitJoinedValues(added, 8)))
			}
			continue
		}

		groupOld := customGroupName(oldRule)
		groupNew := customGroupName(newRule)
		if strings.TrimSpace(oldRule.Name) != strings.TrimSpace(newRule.Name) {
			changedDetails = append(changedDetails, fmt.Sprintf("策略组重命名 %s -> %s", groupOld, groupNew))
		}
		if strings.TrimSpace(oldRule.Icon) != strings.TrimSpace(newRule.Icon) {
			changedDetails = append(changedDetails, fmt.Sprintf("策略组 %s 图标 %s -> %s", groupNew, strings.TrimSpace(oldRule.Icon), strings.TrimSpace(newRule.Icon)))
		}

		added, removed := diffCustomRuleLines(normalizeCustomRuleLines(oldRule.Content), normalizeCustomRuleLines(newRule.Content))
		group := groupNew
		if len(added) > 0 {
			changedDetails = append(changedDetails, fmt.Sprintf("%s 添加 %s", group, limitJoinedValues(added, 8)))
		}
		if len(removed) > 0 {
			changedDetails = append(changedDetails, fmt.Sprintf("%s 删除 %s", group, limitJoinedValues(removed, 8)))
		}
	}

	if len(changedDetails) == 0 {
		logger.Log.Info("自定义分流规则保存成功(无规则变化)", "ip", clientIP, "path", reqPath)
	} else {
		logger.Log.Info("自定义分流规则已更新",
			"changed_count", len(changedDetails),
			"changes", strings.Join(changedDetails, " | "),
			"ip", clientIP,
			"path", reqPath,
		)
	}
	sendJSON(w, "success", "自定义规则保存成功")
}

func apiSubRuleList(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	reqPath := r.URL.Path

	if !verifySubToken(r) {
		logger.Log.Warn("规则列表订阅请求: Token 验证失败", "ip", clientIP, "path", reqPath)
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/sub/rules/")
	var rawContent string
	groupName := "未知规则组"

	if path == "direct" {
		rawContent = service.GetCustomDirectRules()
		groupName = "全局直连"
	} else if strings.HasPrefix(path, "proxy/") {
		id := strings.TrimPrefix(path, "proxy/")
		rules := service.GetCustomProxyRules()
		for _, rule := range rules {
			if rule.ID == id {
				rawContent = rule.Content
				name := strings.TrimSpace(rule.Name)
				if name == "" {
					name = id
				}
				groupName = name
				break
			}
		}
		if strings.TrimSpace(rawContent) == "" {
			groupName = id
		}
	}

	logger.Log.Debug("获取自定义分流规则："+groupName,
		"ip", clientIP,
		"path", reqPath,
		"rules_len", len(strings.TrimSpace(rawContent)),
	)

	formattedContent := service.ParseCustomRules(rawContent)

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

// apiSaveCert 处理用户手动上传证书
func apiSaveCert(w http.ResponseWriter, r *http.Request) {
	// 限制上传大小为 10MB
	r.ParseMultipartForm(10 << 20)

	// 读取 .crt / .pem 文件
	fileCrt, _, err := r.FormFile("cert_file")
	if err != nil {
		sendJSON(w, "error", "缺少证书文件 (.crt/.pem)")
		return
	}
	defer fileCrt.Close()
	crtBytes, _ := io.ReadAll(fileCrt)

	// 读取 .key 文件
	fileKey, _, err := r.FormFile("key_file")
	if err != nil {
		sendJSON(w, "error", "缺少私钥文件 (.key / .pem)")
		return
	}
	defer fileKey.Close()
	keyBytes, _ := io.ReadAll(fileKey)

	// 调用 service 层的保存逻辑
	if err := service.SaveUploadedCert(crtBytes, keyBytes); err != nil {
		logger.Log.Error("保存证书失败", "error", err)
		sendJSON(w, "error", "证书保存失败: "+err.Error())
		return
	}

	sendJSON(w, "success", "证书已更新，请重启程序以生效")
}

// apiApplyCert 处理 Cloudflare 自动申请证书请求
func apiApplyCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email  string `json:"email"`
		ApiKey string `json:"api_key"`
		Domain string `json:"domain"`
	}
	// 解析 JSON body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "参数解析失败")
		return
	}

	if req.ApiKey == "********" {
		var keyConf database.SysConfig
		database.DB.Where("key = ?", "cf_api_key").First(&keyConf)
		req.ApiKey = keyConf.Value
	}

	if req.Email == "" || req.ApiKey == "" || req.Domain == "" {
		sendJSON(w, "error", "请填写完整的 Cloudflare 信息")
		return
	}

	// 调用 service 层的申请逻辑
	if err := service.ApplyCloudflareCert(req.Email, req.ApiKey, req.Domain); err != nil {
		logger.Log.Error("证书申请失败", "error", err)
		sendJSON(w, "error", "申请失败: "+err.Error())
		return
	}

	sendJSON(w, "success", "证书申请任务已提交")
}

// apiRestartCore 处理前端下发的重启核心请求
// 功能：返回成功响应后，异步触发系统的热重启逻辑
func apiRestartCore(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Log.Info("接收到面板核心重启请求", "ip", clientIP)

	// 必须先给前端返回成功的 JSON，否则直接重启会导致前端请求 Pending 并报错
	sendJSON(w, "success", "系统核心即将重启，面板可能会短暂断开连接...")

	// 延迟 1 秒后触发重启，确保 HTTP 响应已经发送给前端
	go func() {
		time.Sleep(1 * time.Second)
		TriggerRestart() // 调用 server.go 中的重启触发器
	}()
}

// apiGetCertLogs 获取证书申请的实时日志供前端黑框展示
func apiGetCertLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sendJSON(w, "success", service.GetCertLogs())
}

// apiGetRecentLogs 获取最近系统日志（含中文解读）
func apiGetRecentLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 120
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}

	logs, err := service.GetRecentLogs(limit)
	if err != nil {
		logger.Log.Error("读取最近日志失败", "error", err)
		sendJSON(w, "error", "读取日志失败，请检查日志文件是否存在")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"logs": logs,
	})
}

// apiStreamRecentLogs 通过 SSE 持续推送最近日志（含中文解读）
func apiStreamRecentLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming Unsupported", http.StatusInternalServerError)
		return
	}

	limit := 120
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ctx := r.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastFingerprint := ""
	sendLogs := func(force bool) {
		logs, err := service.GetRecentLogs(limit)
		if err != nil {
			payload, _ := json.Marshal(map[string]interface{}{
				"status":  "error",
				"message": "读取日志失败，请检查日志文件是否存在",
			})
			fmt.Fprintf(w, "event: logs\ndata: %s\n\n", payload)
			flusher.Flush()
			return
		}

		fingerprint := buildRecentLogFingerprint(logs)
		if !force && fingerprint == lastFingerprint {
			return
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"status": "success",
			"logs":   logs,
		})
		fmt.Fprintf(w, "event: logs\ndata: %s\n\n", payload)
		flusher.Flush()
		lastFingerprint = fingerprint
	}

	sendLogs(true)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendLogs(false)
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func buildRecentLogFingerprint(logs []service.RecentLogEntry) string {
	if len(logs) == 0 {
		return "empty"
	}
	head := logs[0]
	return fmt.Sprintf("%d|%s|%s|%s", len(logs), head.Time, head.Level, head.Raw)
}

// ------------------- [机场订阅相关 API] -------------------

// apiAirportList 获取订阅源列表
func apiAirportList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var subs []database.AirportSub
	if err := database.DB.Order("updated_at DESC").Find(&subs).Error; err != nil {
		logger.Log.Error("获取机场订阅列表失败", "error", err)
		sendJSON(w, "error", "获取列表失败")
		return
	}

	sendJSON(w, "success", subs)
}

// apiAirportAdd 添加新订阅
func apiAirportAdd(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("添加机场订阅失败: JSON 解析异常", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "格式错误")
		return
	}

	if req.URL == "" {
		logger.Log.Warn("添加机场订阅失败: 缺少订阅链接", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "订阅链接不能为空")
		return
	}

	if req.Name == "" {
		fetchedName := service.FetchSubscriptionName(req.URL)
		if fetchedName != "" {
			req.Name = fetchedName
		} else {
			req.Name = "未命名订阅 " + time.Now().Format("01-02 15:04")
		}
	}

	sub := database.AirportSub{
		Name: req.Name,
		URL:  req.URL,
	}

	if err := database.DB.Create(&sub).Error; err != nil {
		logger.Log.Error("添加机场订阅失败", "error", err, "name", req.Name, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库写入失败")
		return
	}

	// 自动触发一次同步
	syncStatus := "成功"
	if err := service.SyncAirportSubscription(sub.ID); err != nil {
		syncStatus = "失败"
		logger.Log.Error("添加后自动同步机场订阅失败", "id", sub.ID, "name", sub.Name, "error", err, "ip", clientIP, "path", reqPath)
	}

	logger.Log.Info("机场订阅已添加",
		"id", sub.ID,
		"name", sub.Name,
		"changes", fmt.Sprintf("新增订阅 %s | 自动同步 %s", sub.Name, syncStatus),
		"ip", clientIP,
		"path", reqPath,
	)

	sendJSON(w, "success", map[string]interface{}{
		"message": "添加成功",
		"id":      sub.ID,
	})
}

// apiAirportUpdate 手动更新订阅
func apiAirportUpdate(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("更新机场订阅失败: JSON 解析异常", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "格式错误")
		return
	}
	if req.ID == "" {
		logger.Log.Warn("更新机场订阅失败: 缺少订阅ID", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "缺少订阅ID")
		return
	}

	var sub database.AirportSub
	if err := database.DB.Where("id = ?", req.ID).First(&sub).Error; err != nil {
		logger.Log.Warn("更新机场订阅失败: 订阅不存在", "id", req.ID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "订阅不存在")
		return
	}

	logger.Log.Info("手动触发机场订阅同步", "id", sub.ID, "name", sub.Name, "changes", "手动同步 "+sub.Name, "ip", clientIP, "path", reqPath)

	// 调用 service 层逻辑进行同步 (包含保留状态逻辑)
	if err := service.SyncAirportSubscription(req.ID); err != nil {
		logger.Log.Error("更新订阅失败", "id", sub.ID, "name", sub.Name, "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "更新失败: "+err.Error())
		return
	}

	logger.Log.Info("机场订阅同步成功", "id", sub.ID, "name", sub.Name, "changes", "同步订阅 "+sub.Name, "ip", clientIP, "path", reqPath)

	sendJSON(w, "success", "订阅已更新")
}

// apiAirportDelete 删除订阅
func apiAirportDelete(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("删除机场订阅失败: JSON 解析异常", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "格式错误")
		return
	}

	var sub database.AirportSub
	if err := database.DB.Where("id = ?", req.ID).First(&sub).Error; err != nil {
		logger.Log.Warn("删除机场订阅失败: 订阅不存在", "id", req.ID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "订阅不存在")
		return
	}
	var nodeCount int64
	database.DB.Model(&database.AirportNode{}).Where("sub_id = ?", req.ID).Count(&nodeCount)

	if err := service.DeleteAirportSubscription(req.ID); err != nil {
		logger.Log.Error("删除机场订阅失败", "id", req.ID, "name", sub.Name, "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "删除失败: "+err.Error())
		return
	}

	logger.Log.Info("机场订阅已删除",
		"id", sub.ID,
		"name", sub.Name,
		"changes", fmt.Sprintf("删除订阅 %s | 清理节点 %d 个", sub.Name, nodeCount),
		"ip", clientIP,
		"path", reqPath,
	)

	sendJSON(w, "success", "删除成功")
}

// apiAirportNodes 获取指定订阅的节点列表
func apiAirportNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	subID := r.URL.Query().Get("id")
	if subID == "" {
		sendJSON(w, "error", "缺少订阅ID")
		return
	}

	var nodes []database.AirportNode
	// 按启用状态(倒序, 启用在前) -> 原始索引(正序) 排序
	if err := database.DB.Where("sub_id = ?", subID).
		Order("routing_type DESC, original_index ASC").
		Find(&nodes).Error; err != nil {
		sendJSON(w, "error", "获取节点失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"nodes": nodes,
	})
}

// apiAirportNodeRouting 修改单个节点的路由策略 (三态切换)
func apiAirportNodeRouting(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID          string `json:"id"`
		RoutingType int    `json:"routing_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("修改机场节点状态失败: JSON 解析异常", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "格式错误")
		return
	}

	var oldNode database.AirportNode
	if err := database.DB.Where("id = ?", req.ID).First(&oldNode).Error; err != nil {
		logger.Log.Warn("修改机场节点状态失败: 节点不存在", "id", req.ID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "节点不存在")
		return
	}

	// 0=禁用, 1=直连, 2=落地
	if err := database.DB.Model(&database.AirportNode{}).
		Where("id = ?", req.ID).
		Update("routing_type", req.RoutingType).Error; err != nil {

		logger.Log.Error("修改机场节点状态失败", "id", req.ID, "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库更新失败")
		return
	}

	if oldNode.RoutingType != req.RoutingType {
		logger.Log.Info("机场订阅节点状态已更新",
			"id", oldNode.ID,
			"sub_id", oldNode.SubID,
			"name", oldNode.Name,
			"changes", fmt.Sprintf("节点 %s 状态 %s -> %s", oldNode.Name, airportRoutingTypeLabel(oldNode.RoutingType), airportRoutingTypeLabel(req.RoutingType)),
			"ip", clientIP,
			"path", reqPath,
		)
	}

	sendJSON(w, "success", "状态已更新")
}

// apiAirportEdit 编辑订阅信息 (名称和URL)
func apiAirportEdit(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("编辑机场订阅失败: JSON 解析异常", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "格式错误")
		return
	}

	if req.ID == "" {
		logger.Log.Warn("编辑机场订阅失败: 缺少订阅ID", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "订阅ID不能为空")
		return
	}

	var oldSub database.AirportSub
	if err := database.DB.Where("id = ?", req.ID).First(&oldSub).Error; err != nil {
		logger.Log.Warn("编辑机场订阅失败: 订阅不存在", "id", req.ID, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "订阅不存在")
		return
	}

	// 准备更新的数据
	updates := make(map[string]interface{})
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.URL != "" {
		updates["url"] = req.URL
	}

	if len(updates) == 0 {
		sendJSON(w, "error", "没有检测到变更内容")
		return
	}

	// 执行数据库更新
	if err := database.DB.Model(&database.AirportSub{}).Where("id = ?", req.ID).Updates(updates).Error; err != nil {
		logger.Log.Error("编辑机场订阅失败", "id", req.ID, "name", oldSub.Name, "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "数据库更新失败")
		return
	}

	changed := make([]string, 0, 2)
	if req.Name != "" && req.Name != oldSub.Name {
		changed = append(changed, fmt.Sprintf("订阅名称 %s -> %s", oldSub.Name, req.Name))
	}
	if req.URL != "" && req.URL != oldSub.URL {
		changed = append(changed, "订阅链接已更新")
	}
	if len(changed) == 0 {
		changed = append(changed, "提交编辑但无有效变化")
	}

	logger.Log.Info("机场订阅信息已修改",
		"id", req.ID,
		"name", oldSub.Name,
		"changes", strings.Join(changed, " | "),
		"ip", clientIP,
		"path", reqPath,
	)
	sendJSON(w, "success", "修改成功")
}

// apiUpdateMihomo 触发 Mihomo 核心更新/下载
func apiUpdateMihomo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Log.Info("后台线程开始更新 Mihomo 核心...")
	go func() {
		if err := service.GlobalMihomo.ForceUpdate(); err != nil {
			logger.Log.Error("Mihomo 核心更新失败", "error", err)
		}
	}()

	sendJSON(w, "success", "更新任务已在后台启动，请稍后刷新查看状态")
}

// apiGetMihomoStatus 获取 Mihomo 核心状态
func apiGetMihomoStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	localVersion := service.GlobalMihomo.GetLocalVersion()
	remoteVersion, _, _, errRemote := service.GlobalMihomo.GetRemoteVersion()

	status := "unknown"
	if localVersion == "" {
		status = "not_found"
	} else if errRemote == nil && remoteVersion != "" && remoteVersion != localVersion {
		status = "update_available"
	} else if errRemote == nil && remoteVersion == localVersion {
		status = "latest"
	} else {
		status = "check_failed"
	}

	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"local_version":  localVersion,
			"remote_version": remoteVersion,
			"state":          status,
		},
	}

	if errRemote != nil {
		resp["data"].(map[string]interface{})["remote_error"] = errRemote.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// apiTestAirportNodes 流式处理节点测速请求 (Server-Sent Events)
func apiTestAirportNodes(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	// 1. 设置 SSE 必需的响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	subID := r.URL.Query().Get("sub_id")
	nodeID := r.URL.Query().Get("node_id")
	subName := "全部订阅"

	var nodes []database.AirportNode
	if subID != "" {
		var sub database.AirportSub
		if err := database.DB.Where("id = ?", subID).First(&sub).Error; err == nil {
			subName = sub.Name
		} else {
			subName = subID
		}
		database.DB.Where("sub_id = ?", subID).Find(&nodes)
	} else if nodeID != "" {
		database.DB.Where("id = ?", nodeID).Find(&nodes)
		if len(nodes) > 0 {
			var sub database.AirportSub
			if err := database.DB.Where("id = ?", nodes[0].SubID).First(&sub).Error; err == nil {
				subName = sub.Name
			} else {
				subName = nodes[0].SubID
			}
		}
	}

	if len(nodes) == 0 {
		logger.Log.Warn("机场节点测速失败: 未找到可测速节点", "sub_id", subID, "node_id", nodeID, "ip", clientIP, "path", reqPath)
		fmt.Fprintf(w, "data: %s\n\n", `{"node_id": "all", "type": "error", "text": "未找到需要测试的节点"}`)
		flusher.Flush()
		return
	}

	if !service.GlobalMihomo.IsCoreReady() {
		logger.Log.Warn("机场节点测速失败: Mihomo 核心未就绪", "sub_id", subID, "node_id", nodeID, "ip", clientIP, "path", reqPath)
		fmt.Fprintf(w, "data: %s\n\n", `{"node_id": "all", "type": "error", "text": "请先在设置中下载 Mihomo 核心"}`)
		flusher.Flush()
		return
	}

	scope := "全部节点"
	if nodeID != "" {
		scope = "单节点"
	} else if subID != "" {
		scope = "订阅全部节点"
	}
	logger.Log.Info("机场节点测速开始",
		"sub_id", subID,
		"sub_name", subName,
		"node_id", nodeID,
		"node_count", len(nodes),
		"changes", fmt.Sprintf("订阅名称 %s | 测速范围 %s | 节点数 %d", subName, scope, len(nodes)),
		"ip", clientIP,
		"path", reqPath,
	)

	// 2. 利用 r.Context() 感知客户端断开连接
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	resultChan := make(chan service.SpeedTestResult)

	// 3. 异步启动测速任务
	go service.GlobalMihomo.RunBatchTest(ctx, nodes, resultChan)

	// 4. 死循环监听管道，来一个结果发一个给前端 (流式推送)
	resultCount := 0
	errorCount := 0
	for res := range resultChan {
		resultCount++
		if strings.EqualFold(res.Type, "error") {
			errorCount++
		}
		data, _ := json.Marshal(res)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush() // 立即把缓冲区数据推给前端
	}

	logger.Log.Info("机场节点测速结束",
		"sub_id", subID,
		"sub_name", subName,
		"node_id", nodeID,
		"result_count", resultCount,
		"error_count", errorCount,
		"changes", fmt.Sprintf("订阅名称 %s | 测速结束 | 返回结果 %d 条 | 错误 %d 条", subName, resultCount, errorCount),
		"ip", clientIP,
		"path", reqPath,
	)
}

// apiGetTrafficLandingNodes 返回用于流量统计的落地节点列表
func apiGetTrafficLandingNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes, err := service.GetTrafficLandingNodes()
	if err != nil {
		logger.Log.Error("查询流量统计节点列表失败", "error", err)
		sendJSON(w, "error", "读取节点列表失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"nodes": nodes,
	})
}

// apiGetTrafficSeries 查询节点流量时序统计（支持总量/增量、1h/2h）
func apiGetTrafficSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeUUID := strings.TrimSpace(r.URL.Query().Get("node_uuid"))
	hours := 24
	if raw := strings.TrimSpace(r.URL.Query().Get("hours")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			hours = parsed
		}
	}

	intervalHours := 1
	if raw := strings.TrimSpace(r.URL.Query().Get("interval_hours")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			intervalHours = parsed
		}
	}

	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	rankDate := strings.TrimSpace(r.URL.Query().Get("date"))
	rawPoints := false
	if raw := strings.TrimSpace(r.URL.Query().Get("raw")); raw != "" {
		rawPoints = raw == "1" || strings.EqualFold(raw, "true")
	}

	result, err := service.QueryTrafficSeries(service.TrafficSeriesOptions{
		NodeUUID:      nodeUUID,
		Hours:         hours,
		IntervalHours: intervalHours,
		Mode:          mode,
		Date:          rankDate,
		Raw:           rawPoints,
	})
	if err != nil {
		logger.Log.Warn("查询流量统计数据失败", "error", err, "node_uuid", nodeUUID, "date", rankDate)
		sendJSON(w, "error", "查询流量统计失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"series": result,
	})
}

// apiGetTrafficConsumptionRank 返回节点流量消耗排行榜（支持按日期查询）
func apiGetTrafficConsumptionRank(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	rankDate := strings.TrimSpace(r.URL.Query().Get("date"))

	rank, err := service.GetTrafficConsumptionRank(limit, rankDate)
	if err != nil {
		logger.Log.Warn("查询流量消耗排行失败", "error", err, "date", rankDate)
		sendJSON(w, "error", "读取流量消耗排行失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"rank": rank,
	})
}

// apiCallbackTrafficWS Agent WebSocket 统一上报通道
// 路由: /api/callback/traffic/ws
// 无需登录鉴权 (Agent 通过 install_id 身份识别)
func apiCallbackTrafficWS(w http.ResponseWriter, r *http.Request) {
	service.HandleAgentWS(w, r)
}

// apiTrafficLive 前端实时流量订阅 (WebSocket)
// 路由: /api/traffic/live?node_uuid=...
// 需要登录鉴权
func apiTrafficLive(w http.ResponseWriter, r *http.Request) {
	service.HandleTrafficLive(w, r)
}

// ------------------- [节点控制接口] -------------------

// apiNodeControlResetLinks 远程重置节点链接（异步下发 + 返回 command_id）
// 路由: POST /api/node/control/reset-links
// 请求体: { "uuid": "节点UUID" }
func apiNodeControlResetLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, "error", "仅支持 POST 请求")
		return
	}

	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UUID == "" {
		sendJSON(w, "error", "参数错误: uuid 不能为空")
		return
	}

	// 查找节点
	var node database.NodePool
	if err := database.DB.Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	// 检查节点是否在线
	if !service.IsNodeOnline(node.InstallID) {
		sendJSON(w, "error", "节点不在线，无法执行命令")
		return
	}

	// 从数据库中已有链接提取协议列表
	protocols := make([]string, 0, len(node.Links))
	for proto := range node.Links {
		protocols = append(protocols, proto)
	}
	if len(protocols) == 0 {
		sendJSON(w, "error", "该节点没有已知协议信息，无法重置")
		return
	}

	// 将协议列表作为 payload 下发给 agent（异步，不等待结果）
	payload := map[string]interface{}{
		"protocols": protocols,
	}

	commandID, err := service.FireCommandToNode(node.InstallID, "reset-links", payload)
	if err != nil {
		logger.Log.Error("重置链接命令下发失败", "uuid", req.UUID, "error", err)
		sendJSON(w, "error", fmt.Sprintf("命令下发失败: %v", err))
		return
	}

	logger.Log.Info("重置链接命令已下发", "uuid", req.UUID, "command_id", commandID)
	sendJSON(w, "success", map[string]interface{}{
		"command_id": commandID,
		"message":    "命令已下发，正在执行...",
	})
}

// apiNodeControlReinstall 远程重新安装节点 sing-box（异步下发 + 返回 command_id）
// 路由: POST /api/node/control/reinstall-singbox
// 请求体: { "uuid": "节点UUID" }
func apiNodeControlReinstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, "error", "仅支持 POST 请求")
		return
	}

	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UUID == "" {
		sendJSON(w, "error", "参数错误: uuid 不能为空")
		return
	}

	// 查找节点
	var node database.NodePool
	if err := database.DB.Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	// 检查节点是否在线
	if !service.IsNodeOnline(node.InstallID) {
		sendJSON(w, "error", "节点不在线，无法执行命令")
		return
	}

	// 从数据库中已有链接提取协议列表
	protocols := make([]string, 0, len(node.Links))
	for proto := range node.Links {
		protocols = append(protocols, proto)
	}
	if len(protocols) == 0 {
		sendJSON(w, "error", "该节点没有已知协议信息，无法重装")
		return
	}

	// 将协议列表作为 payload 下发给 agent（异步，不等待结果）
	payload := map[string]interface{}{
		"protocols": protocols,
	}

	commandID, err := service.FireCommandToNode(node.InstallID, "reinstall-singbox", payload)
	if err != nil {
		logger.Log.Error("重装 sing-box 命令下发失败", "uuid", req.UUID, "error", err)
		sendJSON(w, "error", fmt.Sprintf("命令下发失败: %v", err))
		return
	}

	logger.Log.Info("重装 sing-box 命令已下发", "uuid", req.UUID, "command_id", commandID)
	sendJSON(w, "success", map[string]interface{}{
		"command_id": commandID,
		"message":    "命令已下发，正在执行...",
	})
}

// apiNodeOnlineStatus 查询节点在线状态
// 路由: GET /api/node/online-status?uuid=...
func apiNodeOnlineStatus(w http.ResponseWriter, r *http.Request) {
	nodeUUID := strings.TrimSpace(r.URL.Query().Get("uuid"))

	if nodeUUID == "" {
		// 返回所有节点状态
		var nodes []database.NodePool
		database.DB.Find(&nodes)

		statusList := make([]map[string]interface{}, 0, len(nodes))
		for _, node := range nodes {
			online := service.IsNodeOnline(node.InstallID)
			item := map[string]interface{}{
				"uuid":   node.UUID,
				"name":   node.Name,
				"online": online,
			}
			if live := service.GetNodeLiveState(node.InstallID); live != nil {
				item["rx_rate_bps"] = live.RXRateBps
				item["tx_rate_bps"] = live.TXRateBps
				item["last_live_at"] = live.LastLiveAt.Unix()
				if live.AgentVersion != "" {
					item["agent_version"] = live.AgentVersion
				}
			}
			statusList = append(statusList, item)
		}
		sendJSON(w, "success", map[string]interface{}{
			"nodes": statusList,
		})
		return
	}

	// 查询单个节点
	var node database.NodePool
	if err := database.DB.Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	online := service.IsNodeOnline(node.InstallID)
	result := map[string]interface{}{
		"uuid":   node.UUID,
		"name":   node.Name,
		"online": online,
	}
	if live := service.GetNodeLiveState(node.InstallID); live != nil {
		result["rx_rate_bps"] = live.RXRateBps
		result["tx_rate_bps"] = live.TXRateBps
		result["last_live_at"] = live.LastLiveAt.Unix()
		if live.AgentVersion != "" {
			result["agent_version"] = live.AgentVersion
		}
	}
	sendJSON(w, "success", result)
}

// apiNodeControlStream 命令执行日志 SSE 流式推送
// 路由: GET /api/node/control/stream?command_id=xxx
func apiNodeControlStream(w http.ResponseWriter, r *http.Request) {
	commandID := strings.TrimSpace(r.URL.Query().Get("command_id"))
	if commandID == "" {
		http.Error(w, "缺少 command_id 参数", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "不支持 SSE", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	history, ch, done, unsub := service.SubscribeCommandLog(commandID)
	defer unsub()

	// 如果命令不存在
	if history == nil && ch == nil {
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]string{
			"type": "error", "message": "命令不存在或已过期",
		}))
		flusher.Flush()
		return
	}

	// 先发送历史条目
	for _, entry := range history {
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(entry))
		flusher.Flush()
	}

	// 如果命令已完成，直接结束
	if done {
		return
	}

	// 实时订阅
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(entry))
			flusher.Flush()
			if entry.Type == "result" {
				return
			}
		}
	}
}

// mustJSON 辅助：序列化为 JSON 字符串，出错时返回空对象
func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ------------------- [数据库管理 API] -------------------

// apiGetDBStatus 获取当前数据库的状态信息
func apiGetDBStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	status := database.GetDBStatus()
	cfg := database.GetCurrentDBConfig()

	sendJSON(w, "success", map[string]interface{}{
		"data":   status,
		"config": cfg,
	})
}

// apiTestDBConnection 测试 PostgreSQL 数据库连接
func apiTestDBConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.Host == "" || req.User == "" || req.DBName == "" {
		sendJSON(w, "error", "主机地址、用户名和数据库名不能为空")
		return
	}

	cfg := database.DBConfig{
		Type:     "postgres",
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		DBName:   req.DBName,
		SSLMode:  req.SSLMode,
	}

	version, err := database.TestPostgresConnection(cfg)
	if err != nil {
		logger.Log.Warn("PostgreSQL 连接测试失败", "host", req.Host, "error", err)
		sendJSON(w, "error", "连接失败: "+err.Error())
		return
	}

	logger.Log.Info("PostgreSQL 连接测试成功", "host", req.Host, "version", version)
	sendJSON(w, "success", map[string]interface{}{
		"message": "连接成功",
		"version": version,
	})
}

// apiSwitchDatabase 切换数据库引擎
func apiSwitchDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.Type != "sqlite" && req.Type != "postgres" {
		sendJSON(w, "error", "不支持的数据库类型")
		return
	}

	cfg := database.DBConfig{
		Type:     req.Type,
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		DBName:   req.DBName,
		SSLMode:  req.SSLMode,
	}

	// 如果切换到 postgres，先验证连接参数
	if req.Type == "postgres" {
		if req.Host == "" || req.User == "" || req.DBName == "" {
			sendJSON(w, "error", "PostgreSQL 连接参数不完整")
			return
		}
		if _, err := database.TestPostgresConnection(cfg); err != nil {
			sendJSON(w, "error", "PostgreSQL 连接验证失败: "+err.Error())
			return
		}
	}

	if err := database.SwitchDatabase(cfg); err != nil {
		logger.Log.Error("切换数据库失败", "type", req.Type, "error", err)
		sendJSON(w, "error", "切换失败: "+err.Error())
		return
	}

	logger.Log.Info("数据库已成功切换", "type", req.Type)
	sendJSON(w, "success", "数据库已成功切换为 "+req.Type)
}

// apiMigrateDatabase 从 SQLite 迁移数据到 PostgreSQL
func apiMigrateDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.Host == "" || req.User == "" || req.DBName == "" {
		sendJSON(w, "error", "PostgreSQL 连接参数不完整")
		return
	}

	pgCfg := database.DBConfig{
		Type:     "postgres",
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		DBName:   req.DBName,
		SSLMode:  req.SSLMode,
	}

	// 先测试连接
	if _, err := database.TestPostgresConnection(pgCfg); err != nil {
		sendJSON(w, "error", "PostgreSQL 连接失败: "+err.Error())
		return
	}

	// 执行迁移
	if err := database.MigrateToPostgres(pgCfg); err != nil {
		logger.Log.Error("数据迁移失败", "error", err)
		sendJSON(w, "error", "迁移失败: "+err.Error())
		return
	}

	logger.Log.Info("数据迁移成功: SQLite → PostgreSQL")
	sendJSON(w, "success", "数据迁移成功！所有数据已从 SQLite 复制到 PostgreSQL。")
}
