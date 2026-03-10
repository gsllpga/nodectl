package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
)

// ------------------- [节点管理 API] -------------------

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

func apiAddNode(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name         string `json:"name"`
		RoutingType  int    `json:"routing_type"`
		ResetDay     int    `json:"reset_day"`
		TrafficLimit int64  `json:"traffic_limit"`
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

	// 补充更新 reset_day 和 traffic_limit
	updates := map[string]interface{}{}
	if req.ResetDay > 0 {
		updates["reset_day"] = req.ResetDay
	}
	if req.TrafficLimit > 0 {
		updates["traffic_limit"] = req.TrafficLimit
	}
	if len(updates) > 0 {
		if err := database.DB.Model(&database.NodePool{}).Where("uuid = ?", node.UUID).Updates(updates).Error; err != nil {
			logger.Log.Error("补充更新节点属性失败", "uuid", node.UUID, "error", err)
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

// apiGetTunnelNodeSettings 获取节点 tunnel 设置列表
func apiGetTunnelNodeSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var nodes []database.NodePool
	if err := database.DB.Select("uuid", "name", "install_id", "tunnel_enabled", "tunnel_id", "tunnel_domain", "region", "sort_index", "updated_at").
		Order("sort_index ASC, updated_at DESC").
		Find(&nodes).Error; err != nil {
		sendJSON(w, "error", "读取 tunnel 节点配置失败")
		return
	}

	items := make([]map[string]interface{}, 0, len(nodes))
	for _, n := range nodes {
		supported := getSupportedTunnelProtocolsForNode(n)
		item := map[string]interface{}{
			"uuid":                       n.UUID,
			"install_id":                 n.InstallID,
			"name":                       n.Name,
			"region":                     n.Region,
			"tunnel_enabled":             n.TunnelEnabled,
			"tunnel_id":                  strings.TrimSpace(n.TunnelID),
			"tunnel_domain":              strings.TrimSpace(n.TunnelDomain),
			"online":                     service.IsNodeOnline(n.InstallID),
			"supported_tunnel_protocols": supported,
		}
		items = append(items, item)
	}

	sendJSON(w, "success", map[string]interface{}{"nodes": items})
}

// apiUpdateTunnelNodeSetting 更新单个节点 tunnel 设置
func apiUpdateTunnelNodeSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UUID          string `json:"uuid"`
		TunnelEnabled *bool  `json:"tunnel_enabled"`
		TunnelID      string `json:"tunnel_id"`
		TunnelDomain  string `json:"tunnel_domain"`
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

	var node database.NodePool
	if err := database.DB.Select("uuid", "name", "install_id", "links", "disabled_links", "tunnel_enabled", "tunnel_id", "tunnel_domain").Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	updates := map[string]interface{}{}
	if strings.TrimSpace(req.TunnelID) != "" {
		updates["tunnel_id"] = strings.TrimSpace(req.TunnelID)
	}
	if req.TunnelEnabled != nil {
		updates["tunnel_enabled"] = *req.TunnelEnabled
		if *req.TunnelEnabled {
			supported := getSupportedTunnelProtocolsForNode(node)
			if len(supported) == 0 {
				sendJSON(w, "error", "该节点暂无可通过 Tunnel 加速的协议。")
				return
			}
			if strings.TrimSpace(service.GetCFConfigPublic("cf_tunnel_token")) == "" {
				sendJSON(w, "error", "未配置 Tunnel Token，请先在 Cloudflare Tunnel 页面完成创建")
				return
			}
			domain := strings.TrimSpace(req.TunnelDomain)
			if domain == "" {
				domain = strings.TrimSpace(node.TunnelDomain)
			}
			if domain == "" {
				generated, err := generateNodeTunnelDomain(req.UUID)
				if err != nil {
					sendJSON(w, "error", err.Error())
					return
				}
				domain = generated
			}
			updates["tunnel_domain"] = domain
			if _, ok := updates["tunnel_id"]; !ok {
				tunnelID := strings.TrimSpace(node.TunnelID)
				if tunnelID == "" {
					tunnelID = strings.TrimSpace(service.GetCFConfigPublic("cf_tunnel_id"))
				}
				if tunnelID != "" {
					updates["tunnel_id"] = tunnelID
				}
			}
		} else if strings.TrimSpace(req.TunnelDomain) != "" {
			updates["tunnel_domain"] = strings.TrimSpace(req.TunnelDomain)
		}
	} else if strings.TrimSpace(req.TunnelDomain) != "" {
		updates["tunnel_domain"] = strings.TrimSpace(req.TunnelDomain)
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

	if err := database.DB.Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "success", "设置已更新")
		return
	}

	resp := map[string]interface{}{
		"message": "设置已更新",
	}

	if req.TunnelEnabled != nil {
		if service.IsNodeOnline(node.InstallID) {
			if *req.TunnelEnabled {
				payload, err := buildNodeTunnelCommandPayload(node)
				if err != nil {
					sendJSON(w, "error", err.Error())
					return
				}
				commandID, err := service.FireCommandToNode(node.InstallID, "tunnel-start", payload)
				if err != nil {
					sendJSON(w, "error", fmt.Sprintf("隧道启动命令下发失败: %v", err))
					return
				}
				resp["command_id"] = commandID
				resp["message"] = "设置已更新，已下发 tunnel 启动命令"
			} else {
				commandID, err := service.FireCommandToNode(node.InstallID, "tunnel-stop", map[string]interface{}{})
				if err != nil {
					sendJSON(w, "error", fmt.Sprintf("隧道停止命令下发失败: %v", err))
					return
				}
				resp["command_id"] = commandID
				resp["message"] = "设置已更新，已下发 tunnel 停止命令"
			}
		} else {
			if *req.TunnelEnabled {
				resp["message"] = "设置已更新（节点离线，未下发启动命令）"
			} else {
				resp["message"] = "设置已更新（节点离线，未下发停止命令）"
			}
		}
	}

	sendJSON(w, "success", resp)
}

// apiNodeControlTunnelStart 远程启动节点 tunnel
func apiNodeControlTunnelStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, "error", "仅支持 POST 请求")
		return
	}

	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.UUID) == "" {
		sendJSON(w, "error", "参数错误: uuid 不能为空")
		return
	}

	var node database.NodePool
	if err := database.DB.Where("uuid = ?", strings.TrimSpace(req.UUID)).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}
	if !service.IsNodeOnline(node.InstallID) {
		sendJSON(w, "error", "节点不在线，无法执行命令")
		return
	}
	if !node.TunnelEnabled {
		sendJSON(w, "error", "当前节点未启用 tunnel")
		return
	}

	payload, err := buildNodeTunnelCommandPayload(node)
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	commandID, err := service.FireCommandToNode(node.InstallID, "tunnel-start", payload)
	if err != nil {
		sendJSON(w, "error", fmt.Sprintf("命令下发失败: %v", err))
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"command_id": commandID,
		"message":    "启动命令已下发",
	})
}

// apiNodeControlTunnelStop 远程停止节点 tunnel
func apiNodeControlTunnelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, "error", "仅支持 POST 请求")
		return
	}

	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.UUID) == "" {
		sendJSON(w, "error", "参数错误: uuid 不能为空")
		return
	}

	var node database.NodePool
	if err := database.DB.Where("uuid = ?", strings.TrimSpace(req.UUID)).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}
	if !service.IsNodeOnline(node.InstallID) {
		sendJSON(w, "error", "节点不在线，无法执行命令")
		return
	}

	commandID, err := service.FireCommandToNode(node.InstallID, "tunnel-stop", map[string]interface{}{})
	if err != nil {
		sendJSON(w, "error", fmt.Sprintf("命令下发失败: %v", err))
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"command_id": commandID,
		"message":    "停止命令已下发",
	})
}

// apiDeleteTunnelNode 删除（或解绑）节点 tunnel
func apiDeleteTunnelNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UUID string `json:"uuid"`
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

	var node database.NodePool
	if err := database.DB.Select("uuid", "install_id", "tunnel_enabled", "tunnel_id", "tunnel_domain").Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	tunnelID := strings.TrimSpace(node.TunnelID)
	shared := false
	if tunnelID != "" {
		var usedByOthers int64
		database.DB.Model(&database.NodePool{}).
			Where("uuid <> ? AND tunnel_id = ?", node.UUID, tunnelID).
			Count(&usedByOthers)
		shared = usedByOthers > 0
		if !shared {
			if err := service.DeleteCFTunnelByID(tunnelID); err != nil {
				sendJSON(w, "error", err.Error())
				return
			}
		}
	}

	updates := map[string]interface{}{
		"tunnel_enabled": false,
		"tunnel_id":      "",
		"tunnel_domain":  "",
	}
	if err := database.DB.Model(&database.NodePool{}).Where("uuid = ?", node.UUID).Updates(updates).Error; err != nil {
		sendJSON(w, "error", "清理节点 tunnel 设置失败")
		return
	}

	resp := map[string]interface{}{}
	if service.IsNodeOnline(node.InstallID) {
		if commandID, err := service.FireCommandToNode(node.InstallID, "tunnel-stop", map[string]interface{}{}); err == nil {
			resp["command_id"] = commandID
		}
	}

	if tunnelID == "" {
		resp["message"] = "节点未绑定 Tunnel，已清理本地配置"
	} else if shared {
		resp["message"] = "已解绑当前节点（该 Tunnel 仍被其他节点使用，未删除远端）"
	} else {
		resp["message"] = "已删除远端 Tunnel 并清理节点配置"
	}

	sendJSON(w, "success", resp)
}

func generateNodeTunnelDomain(nodeUUID string) (string, error) {
	rootDomain := ""
	var cfg database.SysConfig
	if err := database.DB.Where("key = ?", "cf_domain").First(&cfg).Error; err == nil {
		rootDomain = strings.TrimSpace(cfg.Value)
	}
	if rootDomain == "" {
		return "", fmt.Errorf("未配置 Cloudflare 根域名，请先在 Token 管理中保存域名")
	}

	for i := 0; i < 8; i++ {
		prefix, err := generateRandomAlphaNum(6)
		if err != nil {
			return "", err
		}
		domain := strings.ToLower(prefix) + "." + rootDomain

		var count int64
		database.DB.Model(&database.NodePool{}).
			Where("tunnel_domain = ? AND uuid <> ?", domain, nodeUUID).
			Count(&count)
		if count == 0 {
			return domain, nil
		}
	}

	return "", fmt.Errorf("生成 tunnel 域名前缀失败，请重试")
}

func buildNodeTunnelCommandPayload(node database.NodePool) (map[string]interface{}, error) {
	baseDomain := strings.TrimSpace(node.TunnelDomain)
	if baseDomain == "" {
		return nil, fmt.Errorf("当前节点未配置 tunnel 域名")
	}

	tunnelToken := strings.TrimSpace(service.GetCFConfigPublic("cf_tunnel_token"))
	if tunnelToken == "" {
		return nil, fmt.Errorf("未配置 tunnel token，请先在 Cloudflare Tunnel 页面完成创建")
	}

	portMap := loadProxyPortMap()
	routes := make([]map[string]string, 0)

	for proto := range node.Links {
		if sliceContains(node.DisabledLinks, proto) {
			continue
		}
		if !isTunnelCompatibleProtocol(proto) {
			continue
		}
		port, ok := portMap[proto]
		if !ok || port <= 0 {
			continue
		}

		host := buildTunnelHostForProtocol(baseDomain, proto)
		if err := service.EnsureCFTunnelDNSHost(host); err != nil {
			return nil, fmt.Errorf("绑定 tunnel DNS 失败(%s): %w", host, err)
		}

		routes = append(routes, map[string]string{
			"protocol": proto,
			"hostname": host,
			"service":  "http://127.0.0.1:" + strconv.Itoa(port),
		})
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("该节点暂无可通过 Tunnel 加速的协议。")
	}

	payload := map[string]interface{}{
		"base_domain":  baseDomain,
		"tunnel_token": tunnelToken,
		"routes":       routes,
	}
	return payload, nil
}

func loadProxyPortMap() map[string]int {
	keyByProto := map[string]string{
		"vmess_ws":   "proxy_port_vmess_ws",
		"vmess_http": "proxy_port_vmess_http",
		"vmess_wst":  "proxy_port_vmess_wst",
		"vmess_hut":  "proxy_port_vmess_hut",
		"vless_wst":  "proxy_port_vless_wst",
		"vless_hut":  "proxy_port_vless_hut",
		"trojan_wst": "proxy_port_trojan_wst",
		"trojan_hut": "proxy_port_trojan_hut",
	}

	keys := make([]string, 0, len(keyByProto))
	for _, key := range keyByProto {
		keys = append(keys, key)
	}

	var cfgs []database.SysConfig
	database.DB.Where("key IN ?", keys).Find(&cfgs)
	valueByKey := make(map[string]string, len(cfgs))
	for _, c := range cfgs {
		valueByKey[c.Key] = strings.TrimSpace(c.Value)
	}

	defaultPort := map[string]int{
		"proxy_port_vmess_ws":   20009,
		"proxy_port_vmess_http": 20010,
		"proxy_port_vmess_wst":  20012,
		"proxy_port_vmess_hut":  20014,
		"proxy_port_vless_wst":  20015,
		"proxy_port_vless_hut":  20017,
		"proxy_port_trojan_wst": 20018,
		"proxy_port_trojan_hut": 20020,
	}

	ports := make(map[string]int, len(keyByProto))
	for proto, key := range keyByProto {
		if p, err := strconv.Atoi(valueByKey[key]); err == nil && p > 0 {
			ports[proto] = p
			continue
		}
		ports[proto] = defaultPort[key]
	}

	return ports
}

func buildTunnelHostForProtocol(baseDomain, protocol string) string {
	base := strings.TrimSpace(strings.TrimSuffix(baseDomain, "."))
	if base == "" {
		return ""
	}
	prefix := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(protocol), "_", "-"))
	if prefix == "" {
		return base
	}
	return prefix + "." + base
}

func isTunnelCompatibleProtocol(protocol string) bool {
	switch strings.TrimSpace(protocol) {
	case "vmess_ws", "vmess_http", "vmess_wst", "vmess_hut", "vless_wst", "vless_hut", "trojan_wst", "trojan_hut":
		return true
	default:
		return false
	}
}

func getSupportedTunnelProtocolsForNode(node database.NodePool) []string {
	if len(node.Links) == 0 {
		return []string{}
	}
	protos := make([]string, 0)
	for proto := range node.Links {
		if sliceContains(node.DisabledLinks, proto) {
			continue
		}
		if isTunnelCompatibleProtocol(proto) {
			protos = append(protos, proto)
		}
	}
	sort.Strings(protos)
	return protos
}

func sliceContains(items []string, target string) bool {
	t := strings.TrimSpace(target)
	for _, item := range items {
		if strings.TrimSpace(item) == t {
			return true
		}
	}
	return false
}

func generateRandomAlphaNum(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	if length <= 0 {
		return "", fmt.Errorf("invalid random length")
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
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

// ------------------- [公开接口与回调] -------------------

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

	resp := map[string]interface{}{
		"command_id": commandID,
		"message":    "命令已下发，正在执行...",
	}

	if node.TunnelEnabled {
		if tunnelPayload, e := buildNodeTunnelCommandPayload(node); e == nil {
			if tunnelCmdID, e2 := service.FireCommandToNode(node.InstallID, "tunnel-prepare", tunnelPayload); e2 == nil {
				resp["tunnel_command_id"] = tunnelCmdID
			}
		}
	}

	logger.Log.Info("重置链接命令已下发", "uuid", req.UUID, "command_id", commandID)
	sendJSON(w, "success", resp)
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

	resp := map[string]interface{}{
		"command_id": commandID,
		"message":    "命令已下发，正在执行...",
	}

	if node.TunnelEnabled {
		if tunnelPayload, e := buildNodeTunnelCommandPayload(node); e == nil {
			if tunnelCmdID, e2 := service.FireCommandToNode(node.InstallID, "tunnel-prepare", tunnelPayload); e2 == nil {
				resp["tunnel_command_id"] = tunnelCmdID
			}
		}
	}

	logger.Log.Info("重装 sing-box 命令已下发", "uuid", req.UUID, "command_id", commandID)
	sendJSON(w, "success", resp)
}

// apiNodeControlCheckAgentUpdate 远程触发 Agent 主动检查更新（异步下发 + 返回 command_id）
// 路由: POST /api/node/control/check-agent-update
// 请求体: { "uuid": "节点UUID" }
func apiNodeControlCheckAgentUpdate(w http.ResponseWriter, r *http.Request) {
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

	var node database.NodePool
	if err := database.DB.Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	if !service.IsNodeOnline(node.InstallID) {
		sendJSON(w, "error", "节点不在线，无法执行命令")
		return
	}

	commandID, err := service.FireCommandToNode(node.InstallID, "check-agent-update", map[string]interface{}{})
	if err != nil {
		logger.Log.Error("Agent 检查更新命令下发失败", "uuid", req.UUID, "error", err)
		sendJSON(w, "error", fmt.Sprintf("命令下发失败: %v", err))
		return
	}

	logger.Log.Info("Agent 检查更新命令已下发", "uuid", req.UUID, "command_id", commandID)
	sendJSON(w, "success", map[string]interface{}{
		"command_id": commandID,
		"message":    "命令已下发，Agent 正在检查更新",
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
