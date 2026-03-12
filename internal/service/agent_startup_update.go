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
//  1. 不阻塞主流程（异步执行）
//  2. 只在进程生命周期内执行一次
//  3. 先从 GitHub 获取最新版本，与数据库中各节点的版本号比较，
//     若版本号一致则不下发更新检查命令（避免无谓的命令下发）
//  4. 仅对在线节点且版本落后的 Agent 下发 check-agent-update
//  5. 汇总式日志输出，不逐节点打印
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

	latest := normalizeSemver(latestVersion)
	if !semver.IsValid(latest) {
		return fmt.Errorf("远端版本号无效: %s", latestVersion)
	}

	if err := database.DB.Select("uuid", "install_id", "name", "agent_version").Find(&nodes).Error; err != nil {
		return fmt.Errorf("查询节点列表失败: %w", err)
	}

	total := len(nodes)
	if total == 0 {
		logger.Log.Info("启动静默 Agent 更新检查完成：无节点", "latest_version", latestVersion)
		return nil
	}

	// ── 第一轮：纯版本号比较，筛选出需要更新的节点 ──
	type needUpdateNode struct {
		InstallID string
		Name      string
		DBVersion string
	}
	var needUpdate []needUpdateNode
	skippedUpToDate := 0
	skippedInvalid := 0

	for _, node := range nodes {
		installID := strings.TrimSpace(node.InstallID)
		nodeName := strings.TrimSpace(node.Name)
		if nodeName == "" {
			nodeName = "unknown"
		}

		dbVerRaw := strings.TrimSpace(node.AgentVersion)
		dbVer := normalizeSemver(dbVerRaw)

		// 版本未知/无效：不冒进触发，跳过
		if dbVer == "" || !semver.IsValid(dbVer) {
			skippedInvalid++
			continue
		}

		// 数据库版本 >= 远端最新版本：已是最新，无需下发
		if semver.Compare(dbVer, latest) >= 0 {
			skippedUpToDate++
			continue
		}

		needUpdate = append(needUpdate, needUpdateNode{
			InstallID: installID,
			Name:      nodeName,
			DBVersion: dbVerRaw,
		})
	}

	// 所有节点版本均已是最新，直接结束，不下发任何命令
	if len(needUpdate) == 0 {
		logger.Log.Info("启动静默 Agent 更新检查完成：所有节点版本均已是最新",
			"latest_version", latestVersion,
			"total_nodes", total,
			"up_to_date", skippedUpToDate,
			"version_invalid", skippedInvalid,
		)
		return nil
	}

	// ── 第二轮：仅对版本落后且在线的节点下发更新命令 ──
	triggered := 0
	skippedOffline := 0
	skippedFireErr := 0

	for _, n := range needUpdate {
		if !IsNodeOnline(n.InstallID) {
			skippedOffline++
			continue
		}

		_, fireErr := FireCommandToNode(n.InstallID, "check-agent-update", map[string]interface{}{})
		if fireErr != nil {
			skippedFireErr++
			logger.Log.Debug("启动静默 Agent 更新命令下发失败",
				"install_id", n.InstallID,
				"node_name", n.Name,
				"error", fireErr,
			)
			continue
		}

		triggered++
	}

	// ── 汇总日志：一行显示所有统计 ──
	logger.Log.Info("启动静默 Agent 更新检查完成",
		"latest_version", latestVersion,
		"total_nodes", total,
		"need_update", len(needUpdate),
		"triggered", triggered,
		"skipped_up_to_date", skippedUpToDate,
		"skipped_offline", skippedOffline,
		"skipped_version_invalid", skippedInvalid,
		"skipped_fire_error", skippedFireErr,
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
