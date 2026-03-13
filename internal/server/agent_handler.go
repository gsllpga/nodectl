// 路径: internal/server/agent_handler.go
// Agent 相关后端 API：初始化配置、二进制下载、新版极简安装脚本、协议重置
// 对应改造任务 task-05-backend-api.md
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
	"nodectl/internal/version"
)

// ============================================================
//  5.1 Agent 初始化配置 API
// ============================================================

// apiAgentInitConfig 获取 Agent 初始化配置
// GET /api/agent/init-config?install_id={INSTALL_ID}
// Agent 首次启动时从后端拉取协议配置
func apiAgentInitConfig(w http.ResponseWriter, r *http.Request) {
	installID := strings.TrimSpace(r.URL.Query().Get("install_id"))
	if installID == "" {
		sendJSON(w, "error", "install_id is required")
		return
	}

	// 验证 install_id 是否存在
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		logger.Log.Warn("Agent init-config: 无效的 install_id", "install_id", installID, "ip", getClientIP(r))
		sendJSON(w, "error", "node not found")
		return
	}

	// 读取面板 URL
	panelURL := loadSysConfigValue("panel_url")

	// 构造协议配置（从节点当前链接推导启用的协议列表）
	enabledProtocols := make([]string, 0)
	if node.Links != nil {
		disabledSet := make(map[string]bool)
		for _, d := range node.DisabledLinks {
			disabledSet[d] = true
		}
		for proto := range node.Links {
			if !disabledSet[proto] {
				enabledProtocols = append(enabledProtocols, proto)
			}
		}
	}

	// 构造 ws_url
	wsURL := ""
	if panelURL != "" {
		wsScheme := "wss"
		if strings.HasPrefix(panelURL, "http://") {
			wsScheme = "ws"
		}
		host := strings.TrimPrefix(strings.TrimPrefix(panelURL, "https://"), "http://")
		host = strings.TrimRight(host, "/")
		wsURL = fmt.Sprintf("%s://%s/api/callback/traffic/ws", wsScheme, host)
	}

	sendJSON(w, "success", map[string]interface{}{
		"data": map[string]interface{}{
			"protocols": map[string]interface{}{
				"enabled": enabledProtocols,
			},
			"panel_url": panelURL,
			"ws_url":    wsURL,
		},
	})
}

// ============================================================
//  5.2 Agent 下载接口
// ============================================================

// apiDownloadAgent 代理 Agent 二进制下载
// GET /api/public/download/agent?arch={amd64|arm64}&channel={stable|alpha}
// 安装脚本通过此接口下载与面板版本匹配的 Agent 二进制
func apiDownloadAgent(w http.ResponseWriter, r *http.Request) {
	arch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if arch == "" {
		arch = "amd64"
	}
	channel := strings.TrimSpace(r.URL.Query().Get("channel"))
	if channel == "" {
		channel = string(version.GetChannel())
	}

	// 验证架构参数
	validArchs := map[string]bool{"amd64": true, "arm64": true, "armv7": true, "386": true}
	if !validArchs[arch] {
		http.Error(w, "invalid arch, must be one of: amd64, arm64, armv7, 386", http.StatusBadRequest)
		return
	}

	// 验证渠道参数
	if channel != "stable" && channel != "alpha" && channel != "dev" {
		channel = string(version.GetChannel())
	}

	// 获取 GitHub 仓库信息
	githubRepo := loadSysConfigValue("github_repo")
	if githubRepo == "" {
		githubRepo = "NodeCTL/nodectl" // 默认仓库
	}

	// 获取最新 Agent 版本号
	agentVersion := getLatestAgentVersion(channel)
	if agentVersion == "" {
		http.Error(w, "unable to determine agent version", http.StatusInternalServerError)
		return
	}

	// 构造文件名（与 GitHub Actions 工作流保持一致）
	// 工作流中 Agent 文件名格式：nodectl-agent-{goos}-{goarch}-{AGENT_VERSION}
	//   - release-main.yml:   AGENT_VERSION="v0.2.0"       → nodectl-agent-linux-amd64-v0.2.0
	//   - release-alpha.yml:  AGENT_VERSION="v0.2.0-alpha"  → nodectl-agent-linux-amd64-v0.2.0-alpha
	// 注意：alpha 后缀是版本号的一部分，不是额外追加到文件名末尾的
	filename := fmt.Sprintf("nodectl-agent-linux-%s-%s", arch, agentVersion)

	// 构造 Release Tag（使用面板版本号，因为 Agent 二进制附在面板的 Release 中）
	// 工作流中 Release Tag：
	//   - release-main.yml:  tag_name = "v0.4.0"        （面板版本号，无后缀）
	//   - release-alpha.yml: tag_name = "v0.4.0-alpha"   （面板版本号 + -alpha 后缀）
	releaseTag := getPanelReleaseTag(channel)

	// GitHub Release 下载 URL
	downloadURL := fmt.Sprintf(
		"https://github.com/%s/releases/download/%s/%s",
		githubRepo, releaseTag, filename,
	)

	logger.Log.Info("Agent 下载重定向",
		"arch", arch,
		"channel", channel,
		"version", agentVersion,
		"url", downloadURL,
		"ip", getClientIP(r),
	)

	// 重定向到 GitHub Release
	http.Redirect(w, r, downloadURL, http.StatusFound)
}

// ============================================================
//  5.3 新版极简安装脚本 API
// ============================================================

// apiNewInstallScript 新版极简安装脚本生成接口
// GET /api/public/new-install-script?id={INSTALL_ID}
// 生成约 50 行的 bash 脚本，仅负责：下载 agent → 写配置 → 注册系统服务
func apiNewInstallScript(w http.ResponseWriter, r *http.Request) {
	installID := strings.TrimSpace(r.URL.Query().Get("id"))
	if installID == "" {
		logger.Log.Warn("新版安装脚本请求被拦截", "reason", "缺少安装ID", "ip", getClientIP(r))
		http.Error(w, "Missing InstallID", http.StatusBadRequest)
		return
	}

	// 验证 ID 是否有效节点
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		logger.Log.Warn("新版安装脚本请求被拦截", "reason", "无效的安装ID", "id", installID, "ip", getClientIP(r))
		http.Error(w, "Invalid InstallID", http.StatusForbidden)
		return
	}

	// 获取面板 URL
	panelURL := loadSysConfigValue("panel_url")
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	panelURL = getPanelURLForScript(panelURL, r.Host, isSecure)

	// 生成新版极简安装脚本
	script := generateMinimalInstallScript(installID, panelURL)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// ============================================================
//  5.5 协议重置接口扩展
// ============================================================

// apiResetProtocol 协议重置接口（面板调用 → 通过 WS 下发命令到 Agent）
// POST /api/callback/reset-protocol
// 支持单协议/多协议重置，以及 disable/enable 操作
func apiResetProtocol(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		InstallID string   `json:"install_id"`
		Protocols []string `json:"protocols"`
		Action    string   `json:"action"` // reset / disable / enable
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "invalid request body")
		return
	}

	installID := strings.TrimSpace(req.InstallID)
	if installID == "" {
		sendJSON(w, "error", "install_id is required")
		return
	}

	if len(req.Protocols) == 0 {
		sendJSON(w, "error", "protocols list is required")
		return
	}

	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = "reset"
	}
	if action != "reset" && action != "disable" && action != "enable" {
		sendJSON(w, "error", "invalid action, must be reset/disable/enable")
		return
	}

	// 验证节点存在
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		sendJSON(w, "error", "node not found")
		return
	}

	// 根据 action 分发处理
	switch action {
	case "reset":
		// 通过 WebSocket 通道下发 reset-links 命令到 Agent
		payload := map[string]interface{}{
			"protocols": req.Protocols,
		}
		commandID, err := service.FireCommandToNode(installID, "reset-links", payload)
		if err != nil {
			sendJSON(w, "error", fmt.Sprintf("命令下发失败: %v", err))
			return
		}
		sendJSON(w, "success", map[string]interface{}{
			"message":    "reset command sent",
			"command_id": commandID,
		})

	case "disable":
		// 更新数据库中节点的 disabled_links
		disabledSet := make(map[string]bool)
		for _, d := range node.DisabledLinks {
			disabledSet[d] = true
		}
		for _, proto := range req.Protocols {
			disabledSet[proto] = true
		}
		newDisabled := make([]string, 0, len(disabledSet))
		for k := range disabledSet {
			newDisabled = append(newDisabled, k)
		}
		if err := database.DB.Model(&database.NodePool{}).Where("install_id = ?", installID).
			Update("disabled_links", newDisabled).Error; err != nil {
			sendJSON(w, "error", fmt.Sprintf("更新失败: %v", err))
			return
		}
		sendJSON(w, "success", "protocols disabled")

	case "enable":
		// 从 disabled_links 中移除指定协议
		enableSet := make(map[string]bool)
		for _, p := range req.Protocols {
			enableSet[p] = true
		}
		newDisabled := make([]string, 0)
		for _, d := range node.DisabledLinks {
			if !enableSet[d] {
				newDisabled = append(newDisabled, d)
			}
		}
		if err := database.DB.Model(&database.NodePool{}).Where("install_id = ?", installID).
			Update("disabled_links", newDisabled).Error; err != nil {
			sendJSON(w, "error", fmt.Sprintf("更新失败: %v", err))
			return
		}
		sendJSON(w, "success", "protocols enabled")
	}
}

// ============================================================
//  辅助函数
// ============================================================

// loadSysConfigValue 从 sys_config 表读取单个配置值
func loadSysConfigValue(key string) string {
	var cfg database.SysConfig
	if err := database.DB.Where("key = ?", key).First(&cfg).Error; err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Value)
}

// getLatestAgentVersion 获取最新 Agent 版本号
// 优先从数据库配置读取，否则使用面板版本号推导
func getLatestAgentVersion(channel string) string {
	// 方案 1：从数据库配置读取
	versionKey := "agent_version_" + channel
	if v := loadSysConfigValue(versionKey); v != "" {
		return v
	}

	// 方案 2：使用面板当前版本推导（面板和 Agent 可能版本不同步，使用固定值）
	// 读取 GitHub Action 中注入的 agent_version
	if v := loadSysConfigValue("agent_version"); v != "" {
		return v
	}

	// 方案 3：使用面板版本作为回退
	return version.Version
}

// getPanelReleaseTag 根据渠道使用面板版本号生成 GitHub Release Tag
// 因为 Agent 二进制文件附在面板的 Release 中发布，所以 tag 必须是面板版本号
// 工作流规则：
//   - release-main.yml:  tag = version.Version（如 "v0.4.0"）
//   - release-alpha.yml: tag = version.Version（如 "v0.4.0-alpha"，编译时已注入含 -alpha 的版本号）
func getPanelReleaseTag(channel string) string {
	panelVer := version.Version

	if channel == "alpha" {
		// Alpha 渠道：面板版本号应已包含 -alpha 后缀（编译时通过 ldflags 注入）
		// 但为安全起见做兜底处理
		if !strings.HasSuffix(panelVer, "-alpha") {
			return panelVer + "-alpha"
		}
		return panelVer
	}
	// Stable 渠道：面板版本号无后缀
	return strings.TrimSuffix(panelVer, "-alpha")
}
