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

	"golang.org/x/mod/semver"
)

const (
	agentReleaseLatestAPI   = "https://api.github.com/repos/hobin66/nodectl/releases/latest"
	agentStartupCheckDelay  = 15 * time.Second
	agentStartupCheckWindow = 60 * time.Second
)

var (
	agentStartupUpdateOnce sync.Once
)

// StartAgentStartupSilentUpdateCheck 启动时静默检查一次 Agent 版本并按需下发更新命令。
// 设计目标：
// 1) 不阻塞主流程（异步执行）
// 2) 只在进程生命周期内执行一次
// 3) 仅对在线节点且版本落后的 Agent 下发 check-agent-update
// 4) 全程写日志，便于审计追踪
func StartAgentStartupSilentUpdateCheck() {
	agentStartupUpdateOnce.Do(func() {
		go func() {
			logger.Log.Info("启动静默 Agent 更新检查任务已创建", "delay", agentStartupCheckDelay.String())

			timer := time.NewTimer(agentStartupCheckDelay)
			defer timer.Stop()

			select {
			case <-timer.C:
			case <-context.Background().Done():
				return
			}

			enabled, err := isStartupSilentAgentUpdateEnabled()
			if err != nil {
				logger.Log.Warn("读取启动静默 Agent 更新开关失败，按关闭处理", "error", err)
				return
			}
			if !enabled {
				logger.Log.Info("启动静默 Agent 更新检查已关闭，跳过执行", "config_key", "agent_startup_silent_update_enabled")
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), agentStartupCheckWindow)
			defer cancel()

			if err := runAgentStartupSilentUpdateCheck(ctx); err != nil {
				logger.Log.Warn("启动静默 Agent 更新检查失败", "error", err)
			}
		}()
	})
}

func runAgentStartupSilentUpdateCheck(ctx context.Context) (retErr error) {
	var (
		latestVersion string
		nodes         []database.NodePool
	)

	defer func() {
		// 显式释放临时内存引用，避免长生命周期 goroutine 持有大对象
		latestVersion = ""
		for i := range nodes {
			nodes[i] = database.NodePool{}
		}
		nodes = nil
	}()

	latestVersion, err := fetchLatestAgentVersionFromGitHub(ctx)
	if err != nil {
		return fmt.Errorf("获取 GitHub 最新 Agent 版本失败: %w", err)
	}

	logger.Log.Info("启动静默 Agent 更新检查开始",
		"latest_version", latestVersion,
		"source", "github_releases_latest",
		"delay_applied_sec", int(agentStartupCheckDelay/time.Second),
	)

	if err := database.DB.Select("uuid", "install_id", "name", "agent_version").Find(&nodes).Error; err != nil {
		return fmt.Errorf("查询节点列表失败: %w", err)
	}

	total := len(nodes)
	if total == 0 {
		logger.Log.Info("启动静默 Agent 更新检查结束", "total_nodes", 0, "triggered", 0, "skipped", 0)
		return nil
	}

	triggered := 0
	skipped := 0
	latest := normalizeSemver(latestVersion)
	if !semver.IsValid(latest) {
		return fmt.Errorf("远端版本号无效: %s", latestVersion)
	}

	for _, node := range nodes {
		installID := strings.TrimSpace(node.InstallID)
		nodeName := strings.TrimSpace(node.Name)
		if nodeName == "" {
			nodeName = "unknown"
		}

		dbVerRaw := strings.TrimSpace(node.AgentVersion)
		dbVer := normalizeSemver(dbVerRaw)

		// 版本未知/无效：不冒进触发，记录日志后跳过
		if dbVer == "" || !semver.IsValid(dbVer) {
			skipped++
			logger.Log.Debug("启动静默 Agent 更新检查跳过：数据库版本无效",
				"install_id", installID,
				"node_name", nodeName,
				"db_agent_version", dbVerRaw,
				"latest_version", latestVersion,
			)
			continue
		}

		// 已是最新或更高（比如测试版）
		if semver.Compare(dbVer, latest) >= 0 {
			skipped++
			continue
		}

		// 仅对在线节点下发静默命令
		if !IsNodeOnline(installID) {
			skipped++
			logger.Log.Debug("启动静默 Agent 更新检查跳过：节点离线",
				"install_id", installID,
				"node_name", nodeName,
				"db_agent_version", dbVerRaw,
				"latest_version", latestVersion,
			)
			continue
		}

		commandID, fireErr := FireCommandToNode(installID, "check-agent-update", map[string]interface{}{})
		if fireErr != nil {
			skipped++
			logger.Log.Warn("启动静默 Agent 更新检查下发失败",
				"install_id", installID,
				"node_name", nodeName,
				"db_agent_version", dbVerRaw,
				"latest_version", latestVersion,
				"error", fireErr,
			)
			continue
		}

		triggered++
		logger.Log.Info("启动静默 Agent 更新命令已下发",
			"event", "agent_startup_silent_update_triggered",
			"install_id", installID,
			"node_name", nodeName,
			"db_agent_version", dbVerRaw,
			"latest_version", latestVersion,
			"command_id", commandID,
			"silent", true,
		)
	}

	logger.Log.Info("启动静默 Agent 更新检查结束",
		"total_nodes", total,
		"triggered", triggered,
		"skipped", skipped,
		"latest_version", latestVersion,
	)

	return nil
}

func fetchLatestAgentVersionFromGitHub(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentReleaseLatestAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "nodectl-core-agent-startup-check")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api status not ok: %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	// 优先使用 tag_name
	if v := normalizeSemver(release.TagName); v != "" && semver.IsValid(v) {
		return v, nil
	}

	// 兜底：从资产名中提取 nodectl-agent-linux-*-vX.Y.Z
	for _, a := range release.Assets {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			continue
		}
		if idx := strings.LastIndex(name, "-v"); idx > 0 {
			candidate := normalizeSemver(name[idx+1:])
			if semver.IsValid(candidate) {
				return candidate, nil
			}
		}
	}

	return "", fmt.Errorf("无法从 GitHub release 中解析 Agent 版本")
}

func normalizeSemver(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	return s
}

func isStartupSilentAgentUpdateEnabled() (bool, error) {
	var cfg database.SysConfig
	if err := database.DB.Select("value").Where("key = ?", "agent_startup_silent_update_enabled").First(&cfg).Error; err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(cfg.Value), "true"), nil
}
