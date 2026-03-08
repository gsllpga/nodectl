// 路径: internal/service/traffic_live.go
// WebSocket 实时流量中枢：Agent 上报 + 前端订阅
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	"nhooyr.io/websocket"
)

// ============================================================
//  通用辅助函数
// ============================================================

// getClientIP 从请求中提取真实客户端 IP（支持反向代理场景）
func getClientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.Split(xff, ",")[0]); ip != "" {
			return ip
		}
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		if bracketIdx := strings.LastIndex(ip, "]"); bracketIdx != -1 {
			return strings.Trim(ip[:bracketIdx+1], "[]")
		}
		return ip[:idx]
	}
	return ip
}

// ============================================================
//  数据结构
// ============================================================

// AgentTrafficMsg Agent 上报的动态 JSON 消息
type AgentTrafficMsg struct {
	InstallID string `json:"install_id"`
	TS        int64  `json:"ts"`
	RXRateBps int64  `json:"rx_rate_bps"`
	TXRateBps int64  `json:"tx_rate_bps"`
	// 可选字段：仅快照消息包含
	RXBytes      *int64 `json:"rx_bytes,omitempty"`
	TXBytes      *int64 `json:"tx_bytes,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"` // 仅快照消息携带
}

// NodeLiveState 节点实时内存态
type NodeLiveState struct {
	InstallID    string    `json:"install_id"`
	NodeUUID     string    `json:"node_uuid"`
	RXRateBps    int64     `json:"rx_rate_bps"`
	TXRateBps    int64     `json:"tx_rate_bps"`
	LastLiveAt   time.Time `json:"last_live_at"`
	AgentVersion string    `json:"agent_version,omitempty"` // Agent 上报的版本号
}

// FrontendPushMsg 推送给前端的实时消息
type FrontendPushMsg struct {
	InstallID  string `json:"install_id"`
	NodeUUID   string `json:"node_uuid"`
	RXRateBps  int64  `json:"rx_rate_bps"`
	TXRateBps  int64  `json:"tx_rate_bps"`
	LastLiveAt int64  `json:"last_live_at"` // Unix 秒
	Offline    bool   `json:"offline"`
}

// ============================================================
//  全局 Hub（生命周期在路由器外，热重启不丢失）
// ============================================================

// AgentCommand 后端→Agent 下发命令结构
type AgentCommand struct {
	Type      string      `json:"type"`       // 固定 "command"
	CommandID string      `json:"command_id"` // 幂等键
	Action    string      `json:"action"`     // "reset-links" / "reinstall-singbox"
	Payload   interface{} `json:"payload,omitempty"`
}

// AgentCommandResult Agent 回传命令执行结果
type AgentCommandResult struct {
	Type      string `json:"type"` // "accepted" / "progress" / "result"
	CommandID string `json:"command_id"`
	Status    string `json:"status,omitempty"` // "ok" / "error"
	Message   string `json:"message,omitempty"`
	Stage     string `json:"stage,omitempty"` // 执行阶段描述
}

// TrafficHub 实时流量中枢：管理 Agent 连接与前端订阅
// CommandLogEntry 命令日志条目
type CommandLogEntry struct {
	Type    string `json:"type"`              // "progress" / "result"
	Message string `json:"message,omitempty"` // 日志内容
	Status  string `json:"status,omitempty"`  // result 时: "ok" / "error"
}

// CommandLog 单个命令的日志记录
type CommandLog struct {
	mu      sync.Mutex
	entries []CommandLogEntry
	done    bool                              // 是否已收到 result
	subs    map[chan CommandLogEntry]struct{} // SSE 订阅者
}

type TrafficHub struct {
	mu sync.RWMutex

	// install_id → 实时内存态
	nodes map[string]*NodeLiveState

	// install_id → install_id 到 node_uuid 的映射缓存
	idCache map[string]string

	// 前端订阅者：node_uuid → [subscriber channels]
	subscribers map[string]map[chan FrontendPushMsg]struct{}
	subMu       sync.Mutex

	// Agent 活跃连接：install_id → websocket.Conn（用于命令下发）
	agentConns map[string]*websocket.Conn
	agentMu    sync.RWMutex

	// 命令结果回调通道：command_id → channel
	cmdResults map[string]chan AgentCommandResult
	cmdMu      sync.Mutex

	// 命令日志：command_id → CommandLog（供 SSE 流式推送）
	cmdLogs map[string]*CommandLog
	logMu   sync.Mutex
}

// globalHub 全局单例（在 for 循环外持有生命周期）
var globalHub *TrafficHub
var hubOnce sync.Once

// GetTrafficHub 返回全局 TrafficHub 单例
func GetTrafficHub() *TrafficHub {
	hubOnce.Do(func() {
		globalHub = &TrafficHub{
			nodes:       make(map[string]*NodeLiveState),
			idCache:     make(map[string]string),
			subscribers: make(map[string]map[chan FrontendPushMsg]struct{}),
			agentConns:  make(map[string]*websocket.Conn),
			cmdResults:  make(map[string]chan AgentCommandResult),
			cmdLogs:     make(map[string]*CommandLog),
		}
	})
	return globalHub
}

// ============================================================
//  install_id → node_uuid 缓存
// ============================================================

func (h *TrafficHub) resolveNodeUUID(installID string) string {
	h.mu.RLock()
	if uuid, ok := h.idCache[installID]; ok {
		h.mu.RUnlock()
		return uuid
	}
	h.mu.RUnlock()

	// 查库
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		return ""
	}

	h.mu.Lock()
	h.idCache[installID] = node.UUID
	h.mu.Unlock()

	return node.UUID
}

func (h *TrafficHub) resolveNodeNameByInstallID(installID string) string {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return ""
	}

	var node database.NodePool
	if err := database.DB.Select("name").Where("install_id = ?", installID).First(&node).Error; err != nil {
		return ""
	}

	return strings.TrimSpace(node.Name)
}

func (h *TrafficHub) resolveNodeNameByIP(ip string) string {
	ip = strings.TrimSpace(strings.Trim(ip, "[]"))
	if ip == "" {
		return ""
	}

	var node database.NodePool
	if err := database.DB.Select("name").Where("ipv4 = ? OR ipv6 = ?", ip, ip).First(&node).Error; err != nil {
		return ""
	}

	return strings.TrimSpace(node.Name)
}

// ============================================================
//  Agent 上报处理 (WS Server Handler)
// ============================================================

// HandleAgentWS 处理 Agent 的 WebSocket 上报连接
// 路由: /api/callback/traffic/ws
// 支持双向通信：Agent→后端上报流量，后端→Agent下发命令
func HandleAgentWS(w http.ResponseWriter, r *http.Request) {
	hub := GetTrafficHub()
	clientIP := getClientIP(r)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:   []string{"nodectl-agent"},
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		logger.Log.Error("Agent WS 握手失败", "error", err, "ip", clientIP)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")

	logger.Log.Info("Agent WS 握手成功，等待身份识别", "ip", clientIP)

	ctx := r.Context()

	// 首个消息用于识别 install_id 并注册连接
	var agentInstallID string

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			nodeName := ""
			if agentInstallID != "" {
				nodeName = hub.resolveNodeNameByInstallID(agentInstallID)
			}
			// 正常关闭或网络断开
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				logger.Log.Info("Agent WS 正常断开", "ip", clientIP, "install_id", agentInstallID, "node_name", nodeName)
			} else {
				logger.Log.Warn("Agent WS 读取异常", "error", err, "ip", clientIP, "install_id", agentInstallID, "node_name", nodeName)
			}
			// 注销 Agent 连接
			if agentInstallID != "" {
				hub.agentMu.Lock()
				delete(hub.agentConns, agentInstallID)
				hub.agentMu.Unlock()
				OnNodeConnectionStatusChanged(agentInstallID, false)
			}
			return
		}

		// 使用轻量 peek 结构体替代 map[string]interface{} 判断消息类型（P2-server 优化）
		var peek struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &peek); err != nil {
			logger.Log.Warn("Agent WS 消息解析失败", "error", err, "ip", clientIP)
			continue
		}

		// 如果包含 type 字段且为命令结果类型，按命令结果处理
		if peek.Type == "accepted" || peek.Type == "progress" || peek.Type == "result" {
			var cmdResult AgentCommandResult
			json.Unmarshal(data, &cmdResult)

			// 写入命令日志并通知 SSE 订阅者
			hub.appendCommandLog(cmdResult)

			hub.cmdMu.Lock()
			if ch, exists := hub.cmdResults[cmdResult.CommandID]; exists {
				select {
				case ch <- cmdResult:
				default:
				}
				// result 类型表示执行完毕，清理通道
				if cmdResult.Type == "result" {
					delete(hub.cmdResults, cmdResult.CommandID)
				}
			}
			hub.cmdMu.Unlock()
			continue
		}

		// 否则按流量上报处理
		var msg AgentTrafficMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			logger.Log.Warn("Agent WS 流量消息解析失败", "error", err, "ip", clientIP)
			continue
		}

		installID := strings.TrimSpace(msg.InstallID)
		if installID == "" {
			continue
		}

		// 首次识别到 install_id 时注册连接
		if agentInstallID == "" {
			agentInstallID = installID
			hub.agentMu.Lock()
			hub.agentConns[installID] = conn
			hub.agentMu.Unlock()
			OnNodeConnectionStatusChanged(agentInstallID, true)

			nodeName := hub.resolveNodeNameByInstallID(installID)
			if nodeName == "" {
				nodeName = hub.resolveNodeNameByIP(clientIP)
			}
			logger.Log.Info("Agent WS 已连接",
				"ip", clientIP,
				"install_id", installID,
				"node_name", nodeName,
			)
		}

		// 解析 node_uuid
		nodeUUID := hub.resolveNodeUUID(installID)
		if nodeUUID == "" {
			logger.Log.Warn("Agent WS 未知节点",
				"install_id", installID,
				"ip", clientIP,
				"node_name_by_ip", hub.resolveNodeNameByIP(clientIP),
			)
			continue
		}

		// 更新内存态
		hub.mu.Lock()
		state, exists := hub.nodes[installID]
		if !exists {
			state = &NodeLiveState{
				InstallID: installID,
				NodeUUID:  nodeUUID,
			}
			hub.nodes[installID] = state
		}
		state.RXRateBps = msg.RXRateBps
		state.TXRateBps = msg.TXRateBps
		state.LastLiveAt = time.Now()
		// 更新 agent 版本（若快照消息携带）
		if msg.AgentVersion != "" {
			state.AgentVersion = msg.AgentVersion
		}
		hub.mu.Unlock()

		// 若包含累计字段 → 快照消息处理
		if msg.RXBytes != nil && msg.TXBytes != nil {
			// 持久化 agent_version 到 NodePool（仅版本变更时更新，避免重复写库）
			if msg.AgentVersion != "" {
				go func(iid, newVer string) {
					var node database.NodePool
					if err := database.DB.Select("name", "agent_version").Where("install_id = ?", iid).First(&node).Error; err != nil {
						return
					}
					oldVer := node.AgentVersion
					nodeName := strings.TrimSpace(node.Name)
					if nodeName == "" {
						nodeName = "unknown"
					}
					if oldVer != newVer {
						database.DB.Model(&database.NodePool{}).Where("install_id = ?", iid).Update("agent_version", newVer)
						if oldVer == "" {
							logger.Log.Info("Agent 版本已记录",
								"event", "agent_version_init",
								"install_id", iid,
								"node_name", nodeName,
								"agent_version", newVer)
						} else {
							logger.Log.Info("Agent 版本已更新",
								"event", "agent_auto_updated",
								"install_id", iid,
								"node_name", nodeName,
								"old_version", oldVer,
								"new_version", newVer)
						}
					}
				}(installID, msg.AgentVersion)
			}

			go func(iid string, rx, tx int64) {
				if _, err := SaveNodeTrafficReport(iid, rx, tx, time.Now()); err != nil {
					logger.Log.Error("WS 快照写入失败", "install_id", iid, "error", err)
				}
			}(installID, *msg.RXBytes, *msg.TXBytes)
		}

		// 转发给前端订阅者
		pushMsg := FrontendPushMsg{
			InstallID:  installID,
			NodeUUID:   nodeUUID,
			RXRateBps:  msg.RXRateBps,
			TXRateBps:  msg.TXRateBps,
			LastLiveAt: time.Now().Unix(),
			Offline:    false,
		}
		hub.broadcast(nodeUUID, pushMsg)
	}
}

// ============================================================
//  前端订阅 (WS Server Handler)
// ============================================================

// HandleTrafficLive 处理前端的实时流量订阅连接
// 路由: /api/traffic/live?node_uuid=...
// 若不传 node_uuid，则订阅所有节点
func HandleTrafficLive(w http.ResponseWriter, r *http.Request) {
	hub := GetTrafficHub()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		logger.Log.Error("前端 Live WS 握手失败", "error", err, "ip", r.RemoteAddr)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")

	ctx := r.Context()

	// 必须持续读取以处理客户端 close / ping 帧
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	nodeUUID := strings.TrimSpace(r.URL.Query().Get("node_uuid"))

	// 订阅 key：空字符串表示订阅全部
	subKey := nodeUUID
	if subKey == "" {
		subKey = "__all__"
	}

	// 创建订阅通道
	ch := make(chan FrontendPushMsg, 64)
	hub.subscribe(subKey, ch)
	defer hub.unsubscribe(subKey, ch)

	sendSnapshot := func() error {
		hub.mu.RLock()
		defer hub.mu.RUnlock()

		for _, state := range hub.nodes {
			if nodeUUID != "" && state.NodeUUID != nodeUUID {
				continue
			}

			isOffline := !IsNodeOnline(state.InstallID)
			outRX := state.RXRateBps
			outTX := state.TXRateBps
			if isOffline {
				outRX = 0
				outTX = 0
			}

			initMsg := FrontendPushMsg{
				InstallID:  state.InstallID,
				NodeUUID:   state.NodeUUID,
				RXRateBps:  outRX,
				TXRateBps:  outTX,
				LastLiveAt: state.LastLiveAt.Unix(),
				Offline:    isOffline,
			}

			data, _ := json.Marshal(initMsg)
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				return err
			}
		}

		return nil
	}

	// 先推送当前快照（让前端立即看到最新状态）
	if err := sendSnapshot(); err != nil {
		return
	}

	// 周期推送快照：由后端统一判定离线，避免前端自行计时
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// 持续推送
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sendSnapshot(); err != nil {
				return
			}
		case msg, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
				cancel()
				return
			}
			cancel()
		}
	}
}

// ============================================================
//  Hub 内部方法
// ============================================================

// subscribe 注册前端订阅
func (h *TrafficHub) subscribe(key string, ch chan FrontendPushMsg) {
	h.subMu.Lock()
	defer h.subMu.Unlock()

	if h.subscribers[key] == nil {
		h.subscribers[key] = make(map[chan FrontendPushMsg]struct{})
	}
	h.subscribers[key][ch] = struct{}{}
}

// unsubscribe 注销前端订阅
func (h *TrafficHub) unsubscribe(key string, ch chan FrontendPushMsg) {
	h.subMu.Lock()
	defer h.subMu.Unlock()

	if subs, ok := h.subscribers[key]; ok {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(h.subscribers, key)
		}
	}
	close(ch)
}

// broadcast 向对应节点的前端订阅者广播消息
func (h *TrafficHub) broadcast(nodeUUID string, msg FrontendPushMsg) {
	h.subMu.Lock()
	defer h.subMu.Unlock()

	// 推送给订阅了具体节点的前端
	if subs, ok := h.subscribers[nodeUUID]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
				// 通道满了，跳过（避免阻塞）
			}
		}
	}

	// 推送给订阅了全部节点的前端
	if subs, ok := h.subscribers["__all__"]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

// GetNodeLiveState 获取节点实时状态（供其他模块使用）
func GetNodeLiveState(installID string) *NodeLiveState {
	hub := GetTrafficHub()
	hub.mu.RLock()
	defer hub.mu.RUnlock()

	if state, ok := hub.nodes[installID]; ok {
		copied := *state
		return &copied
	}
	return nil
}

// GetAllNodeLiveStates 获取所有节点实时状态
func GetAllNodeLiveStates() map[string]*NodeLiveState {
	hub := GetTrafficHub()
	hub.mu.RLock()
	defer hub.mu.RUnlock()

	result := make(map[string]*NodeLiveState, len(hub.nodes))
	for k, v := range hub.nodes {
		copied := *v
		result[k] = &copied
	}
	return result
}

// ============================================================
//  命令下发
// ============================================================

// DispatchCommandToNode 向指定节点下发命令，等待结果（带超时）
// 返回执行结果；若节点不在线或超时返回 error
func DispatchCommandToNode(installID string, action string, payload interface{}, timeout time.Duration) (*AgentCommandResult, error) {
	hub := GetTrafficHub()

	// 检查 Agent 是否在线
	hub.agentMu.RLock()
	conn, online := hub.agentConns[installID]
	hub.agentMu.RUnlock()
	if !online || conn == nil {
		return nil, fmt.Errorf("节点 %s 不在线", installID)
	}

	// 生成唯一命令 ID
	commandID := fmt.Sprintf("cmd-%s-%d", installID, time.Now().UnixNano())

	cmd := AgentCommand{
		Type:      "command",
		CommandID: commandID,
		Action:    action,
		Payload:   payload,
	}

	// 注册结果通道
	resultCh := make(chan AgentCommandResult, 8)
	hub.cmdMu.Lock()
	hub.cmdResults[commandID] = resultCh
	hub.cmdMu.Unlock()

	// 清理函数
	defer func() {
		hub.cmdMu.Lock()
		delete(hub.cmdResults, commandID)
		hub.cmdMu.Unlock()
	}()

	// 发送命令到 Agent
	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("命令序列化失败: %w", err)
	}

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer writeCancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		return nil, fmt.Errorf("命令发送失败: %w", err)
	}

	logger.Log.Info("命令已下发", "install_id", installID, "action", action, "command_id", commandID)

	// 等待最终结果（type=result）或超时
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case result := <-resultCh:
			if result.Type == "result" {
				return &result, nil
			}
			// accepted / progress 类型继续等待
			logger.Log.Info("命令执行中", "command_id", commandID, "type", result.Type, "stage", result.Stage)
		case <-timer.C:
			return nil, fmt.Errorf("命令执行超时 (%v)", timeout)
		}
	}
}

// IsNodeOnline 检查节点是否有活跃 Agent 连接
func IsNodeOnline(installID string) bool {
	hub := GetTrafficHub()
	hub.agentMu.RLock()
	defer hub.agentMu.RUnlock()
	_, ok := hub.agentConns[installID]
	return ok
}

// CleanupNodeState 删除节点时清理内存中的所有关联状态
func CleanupNodeState(installID string, nodeUUID string) {
	hub := GetTrafficHub()

	// 清理实时流量状态 + ID缓存
	hub.mu.Lock()
	delete(hub.nodes, installID)
	delete(hub.idCache, installID)
	hub.mu.Unlock()

	// 关闭并清理 Agent WS 连接
	hub.agentMu.Lock()
	if conn, ok := hub.agentConns[installID]; ok && conn != nil {
		conn.Close(websocket.StatusGoingAway, "节点已删除")
		delete(hub.agentConns, installID)
	}
	hub.agentMu.Unlock()

	// 关闭该节点的所有前端订阅者
	hub.subMu.Lock()
	if subs, ok := hub.subscribers[nodeUUID]; ok {
		for ch := range subs {
			close(ch)
		}
		delete(hub.subscribers, nodeUUID)
	}
	hub.subMu.Unlock()

	logger.Log.Info("已清理节点内存状态", "install_id", installID, "node_uuid", nodeUUID)
}

// ============================================================
//  命令日志 & SSE 流式推送
// ============================================================

// FireCommandToNode 异步下发命令，立即返回 commandID（不等待结果）
func FireCommandToNode(installID string, action string, payload interface{}) (string, error) {
	hub := GetTrafficHub()

	hub.agentMu.RLock()
	conn, online := hub.agentConns[installID]
	hub.agentMu.RUnlock()
	if !online || conn == nil {
		return "", fmt.Errorf("节点 %s 不在线", installID)
	}

	commandID := fmt.Sprintf("cmd-%s-%d", installID, time.Now().UnixNano())

	cmd := AgentCommand{
		Type:      "command",
		CommandID: commandID,
		Action:    action,
		Payload:   payload,
	}

	// 预创建命令日志（SSE 订阅者可能在命令结果到来之前就连接）
	hub.logMu.Lock()
	hub.cmdLogs[commandID] = &CommandLog{
		entries: make([]CommandLogEntry, 0, 64),
		subs:    make(map[chan CommandLogEntry]struct{}),
	}
	hub.logMu.Unlock()

	data, err := json.Marshal(cmd)
	if err != nil {
		return "", fmt.Errorf("命令序列化失败: %w", err)
	}

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer writeCancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		return "", fmt.Errorf("命令发送失败: %w", err)
	}

	logger.Log.Info("命令已异步下发", "install_id", installID, "action", action, "command_id", commandID)

	// 5 分钟后自动清理日志
	go func() {
		time.Sleep(5 * time.Minute)
		hub.logMu.Lock()
		delete(hub.cmdLogs, commandID)
		hub.logMu.Unlock()
	}()

	return commandID, nil
}

// appendCommandLog 将命令结果追加到日志并通知 SSE 订阅者
func (hub *TrafficHub) appendCommandLog(result AgentCommandResult) {
	hub.logMu.Lock()
	cmdLog, exists := hub.cmdLogs[result.CommandID]
	hub.logMu.Unlock()

	if !exists {
		return
	}

	entry := CommandLogEntry{
		Type: result.Type,
	}
	if result.Type == "progress" {
		entry.Message = result.Stage
	} else if result.Type == "result" {
		entry.Status = result.Status
		entry.Message = result.Message
	} else if result.Type == "accepted" {
		entry.Message = "命令已接收"
	}

	cmdLog.mu.Lock()
	cmdLog.entries = append(cmdLog.entries, entry)
	if result.Type == "result" {
		cmdLog.done = true
	}
	// 通知所有 SSE 订阅者
	for ch := range cmdLog.subs {
		select {
		case ch <- entry:
		default:
		}
	}
	cmdLog.mu.Unlock()
}

// SubscribeCommandLog 订阅命令日志流
// 返回: 历史条目切片, 实时通道, 是否已完成, 取消订阅函数
func SubscribeCommandLog(commandID string) ([]CommandLogEntry, chan CommandLogEntry, bool, func()) {
	hub := GetTrafficHub()

	hub.logMu.Lock()
	cmdLog, exists := hub.cmdLogs[commandID]
	hub.logMu.Unlock()

	if !exists {
		return nil, nil, false, func() {}
	}

	ch := make(chan CommandLogEntry, 64)

	cmdLog.mu.Lock()
	history := make([]CommandLogEntry, len(cmdLog.entries))
	copy(history, cmdLog.entries)
	done := cmdLog.done
	if !done {
		cmdLog.subs[ch] = struct{}{}
	}
	cmdLog.mu.Unlock()

	unsub := func() {
		cmdLog.mu.Lock()
		delete(cmdLog.subs, ch)
		cmdLog.mu.Unlock()
	}

	return history, ch, done, unsub
}
