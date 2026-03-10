// 路径: internal/agent/updater.go
//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// GitHub 仓库坐标（编译期可通过 ldflags 覆盖）
var (
	UpdateRepoOwner = "hobin66"
	UpdateRepoName  = "nodectl"
)

const (
	// 检查更新周期
	updateCheckInterval = 6 * time.Hour
	// 启动后随机抖动上限，避免大量 agent 同时请求 GitHub
	updateInitialJitter = 10 * time.Minute
	// 下载缓冲大小（低内存）
	downloadBufSize = 64 * 1024 // 64 KiB
	// 健康检查超时（新版启动后在此时间内完成 WS 握手即为健康）
	healthCheckTimeout = 30 * time.Second
	// 崩溃循环阈值：连续 N 次在 healthCheckTimeout 内退出则锁定
	maxCrashCount = 3
	// HTTP 请求超时
	httpTimeout = 60 * time.Second
	// 产物文件名正则（匹配 nodectl-agent-linux-amd64-v1.4.2）
	assetPattern = `^nodectl-agent-linux-%s-(v\d+\.\d+\.\d+.*)$`
)

// updateState 更新状态持久化结构体
type updateState struct {
	CrashCount    int    `json:"crash_count"`              // 连续崩溃次数
	Locked        bool   `json:"locked"`                   // 是否锁定更新
	LockedVersion string `json:"locked_version,omitempty"` // 锁定时的版本号（出现新版后解锁）
	LastCheck     int64  `json:"last_check,omitempty"`     // 上次检查时间戳
}

// Updater Agent 自动更新器（仅 Linux）
type Updater struct {
	mu       sync.Mutex
	selfPath string       // 当前二进制绝对路径
	stateDir string       // 状态文件目录
	client   *http.Client // 复用 HTTP client
	state    updateState  // 更新状态
}

// NewUpdater 创建更新器实例
func NewUpdater() (*Updater, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取自身路径失败: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return nil, fmt.Errorf("解析符号链接失败: %w", err)
	}

	stateDir := filepath.Dir(selfPath)

	u := &Updater{
		selfPath: selfPath,
		stateDir: stateDir,
		client: &http.Client{
			Timeout: httpTimeout,
		},
	}

	// 加载持久化更新状态
	u.loadState()

	return u, nil
}

// statePath 返回状态文件路径
func (u *Updater) statePath() string {
	return filepath.Join(u.stateDir, ".update_state.json")
}

// loadState 加载更新状态
func (u *Updater) loadState() {
	data, err := os.ReadFile(u.statePath())
	if err != nil {
		return // 文件不存在时使用零值
	}
	json.Unmarshal(data, &u.state)
}

// saveState 持久化更新状态
func (u *Updater) saveState() {
	data, _ := json.Marshal(&u.state)
	tmp := u.statePath() + ".tmp"
	if f, err := os.Create(tmp); err == nil {
		f.Write(data)
		f.Sync()
		f.Close()
		os.Rename(tmp, u.statePath())
	}
}

// RecordStartup 记录启动事件（供 main.go 调用，用于崩溃循环检测）
// 返回 true 表示需要回滚（崩溃次数已达上限）
func (u *Updater) RecordStartup() bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	bakPath := u.selfPath + ".bak"

	// 检查是否存在 .bak 文件（说明刚刚经历了更新）
	if _, err := os.Stat(bakPath); err != nil {
		// 没有 .bak 文件，不是更新后启动，重置计数器
		if u.state.CrashCount > 0 {
			u.state.CrashCount = 0
			u.saveState()
		}
		return false
	}

	// 存在 .bak 文件 → 更新后启动，递增崩溃计数
	u.state.CrashCount++
	u.saveState()

	if u.state.CrashCount >= maxCrashCount {
		log.Printf("[Updater] 连续崩溃 %d 次，执行回滚...", u.state.CrashCount)
		if err := os.Rename(bakPath, u.selfPath); err != nil {
			log.Printf("[Updater] 回滚失败: %v", err)
			return false
		}
		u.state.Locked = true
		u.state.LockedVersion = AgentVersion
		u.state.CrashCount = 0
		u.saveState()
		log.Printf("[Updater] 已回滚并锁定版本 %s，将不再自动更新此版本", AgentVersion)
		return true // 通知 main.go 需要重启（使用回滚后的二进制）
	}

	return false
}

// MarkHealthy 标记启动成功（WS 首次握手后调用）
// 清除崩溃计数并删除 .bak 文件
func (u *Updater) MarkHealthy() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.state.CrashCount > 0 {
		u.state.CrashCount = 0
		u.saveState()
	}

	// 删除 .bak 文件（更新确认成功）
	bakPath := u.selfPath + ".bak"
	os.Remove(bakPath)
}

// Run 启动更新检查循环（阻塞，应在独立 goroutine 中运行）
func (u *Updater) Run(ctx context.Context) {
	// dev 版本不检查更新
	if AgentVersion == "dev" || AgentVersion == "" {
		log.Printf("[Updater] dev 版本，跳过自动更新")
		return
	}

	// 启动后随机抖动 0~10min
	jitter := time.Duration(time.Now().UnixNano()%int64(updateInitialJitter/time.Millisecond)) * time.Millisecond
	log.Printf("[Updater] 首次检查将在 %v 后开始", jitter.Round(time.Second))

	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}

	// 首次立即检查一次
	u.checkAndUpdate(ctx)

	ticker := time.NewTicker(updateCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.checkAndUpdate(ctx)
		}
	}
}

// TriggerCheck 手动触发一次更新检查（供远程命令调用）
func (u *Updater) TriggerCheck(ctx context.Context) error {
	if AgentVersion == "dev" || AgentVersion == "" {
		return fmt.Errorf("dev 版本不支持更新检查")
	}
	u.checkAndUpdate(ctx)
	return nil
}

// IsPostUpdatePending 返回当前是否处于“更新后待健康确认”阶段（存在 .bak）
func (u *Updater) IsPostUpdatePending() bool {
	bakPath := u.selfPath + ".bak"
	_, err := os.Stat(bakPath)
	return err == nil
}

// HealthTimeout 返回更新后首个 WS 握手健康检查超时时间
func (u *Updater) HealthTimeout() time.Duration {
	return healthCheckTimeout
}

// checkAndUpdate 执行一次完整的检查和更新流程
func (u *Updater) checkAndUpdate(ctx context.Context) {
	if !u.mu.TryLock() {
		return // 另一个更新流程正在进行
	}
	defer u.mu.Unlock()

	// 检查是否锁定
	if u.state.Locked {
		log.Printf("[Updater] 更新已锁定（锁定版本: %s），跳过检查", u.state.LockedVersion)
		return
	}

	log.Printf("[Updater] 开始检查更新 (当前版本: %s)", AgentVersion)

	// 1. 查询 latest release
	targetVersion, downloadURL, sha256URL, err := u.findLatestAgentRelease(ctx)
	if err != nil {
		log.Printf("[Updater] 检查更新失败: %v", err)
		return
	}

	// 2. 版本比较
	localVer := AgentVersion
	if !strings.HasPrefix(localVer, "v") {
		localVer = "v" + localVer
	}
	if !semver.IsValid(localVer) {
		log.Printf("[Updater] 本地版本号无效: %s，跳过更新", AgentVersion)
		return
	}
	if !semver.IsValid(targetVersion) {
		log.Printf("[Updater] 远端版本号无效: %s，跳过更新", targetVersion)
		return
	}

	// 仅正式版触发（跳过 prerelease）
	if semver.Prerelease(targetVersion) != "" {
		log.Printf("[Updater] 远端为预发布版本 %s，跳过", targetVersion)
		return
	}

	if semver.Compare(targetVersion, localVer) <= 0 {
		log.Printf("[Updater] 已是最新版本 (%s >= %s)", localVer, targetVersion)
		u.state.LastCheck = time.Now().Unix()
		u.saveState()
		return
	}

	// 3. 如果锁定的版本与新版不同，解锁
	if u.state.Locked && u.state.LockedVersion != targetVersion {
		log.Printf("[Updater] 检测到新版本 %s（锁定版本为 %s），解除锁定", targetVersion, u.state.LockedVersion)
		u.state.Locked = false
		u.state.LockedVersion = ""
		u.saveState()
	}

	log.Printf("[Updater] 发现新版本: %s → %s，开始更新", localVer, targetVersion)

	// 4. 下载 sha256 校验文件
	expectedHash, err := u.downloadSHA256(ctx, sha256URL)
	if err != nil {
		log.Printf("[Updater] 下载 SHA256 文件失败: %v", err)
		return
	}

	// 5. 流式下载二进制 + 边下载边计算哈希
	tmpPath := u.selfPath + ".new.tmp"
	actualHash, err := u.downloadBinary(ctx, downloadURL, tmpPath)
	if err != nil {
		log.Printf("[Updater] 下载二进制失败: %v", err)
		os.Remove(tmpPath)
		return
	}

	// 6. 校验哈希
	if actualHash != expectedHash {
		log.Printf("[Updater] SHA256 校验失败: 预期 %s, 实际 %s", expectedHash, actualHash)
		os.Remove(tmpPath)
		return
	}
	log.Printf("[Updater] SHA256 校验通过")

	// 7. staging: 设置可执行权限
	if err := os.Chmod(tmpPath, 0755); err != nil {
		log.Printf("[Updater] chmod 失败: %v", err)
		os.Remove(tmpPath)
		return
	}

	// 8. staging → switching: 原子切换
	newPath := u.selfPath + ".new"
	if err := os.Rename(tmpPath, newPath); err != nil {
		log.Printf("[Updater] staging 重命名失败: %v", err)
		os.Remove(tmpPath)
		return
	}

	bakPath := u.selfPath + ".bak"
	// 清理可能存在的旧 .bak
	os.Remove(bakPath)

	// agent → agent.bak
	if err := os.Rename(u.selfPath, bakPath); err != nil {
		log.Printf("[Updater] 备份当前版本失败: %v", err)
		// 恢复 .new 文件
		os.Rename(newPath, tmpPath)
		os.Remove(tmpPath)
		return
	}

	// agent.new → agent
	if err := os.Rename(newPath, u.selfPath); err != nil {
		log.Printf("[Updater] 切换新版本失败: %v", err)
		// 回滚
		os.Rename(bakPath, u.selfPath)
		return
	}

	// 9. 重置崩溃计数器（新的更新周期开始）
	u.state.CrashCount = 0
	u.state.LastCheck = time.Now().Unix()
	u.saveState()

	log.Printf("[Updater] 更新完成 %s → %s，将通过 systemd 自动重启生效", localVer, targetVersion)

	// 10. 退出进程，依赖 systemd 自动重启以加载新二进制
	// 使用 SIGTERM 让 runtime 优雅退出
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(os.Interrupt)
}

// ============================================================
//  GitHub API 交互
// ============================================================

// ghRelease GitHub Release API 响应（仅需要的字段）
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// ghAsset GitHub Release Asset
type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// findLatestAgentRelease 查询最新 release 并匹配当前架构的 agent 产物
// 返回: 目标版本号、二进制下载 URL、sha256 下载 URL
func (u *Updater) findLatestAgentRelease(ctx context.Context) (version, binaryURL, sha256URL string, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", UpdateRepoOwner, UpdateRepoName)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", fmt.Sprintf("nodectl-agent/%s", AgentVersion))

	resp, err := u.client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("请求 GitHub API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("GitHub API 返回 %d", resp.StatusCode)
	}

	// 限制读取体积（防止异常响应撑爆内存）
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", "", "", fmt.Errorf("读取响应失败: %w", err)
	}

	var release ghRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", "", "", fmt.Errorf("解析 release JSON 失败: %w", err)
	}

	// 构造匹配模式: nodectl-agent-linux-amd64-v1.4.2
	arch := runtime.GOARCH
	pattern := regexp.MustCompile(fmt.Sprintf(assetPattern, regexp.QuoteMeta(arch)))

	var matchedAsset *ghAsset
	var matchedVersion string

	for i := range release.Assets {
		asset := &release.Assets[i]
		if strings.HasSuffix(asset.Name, ".sha256") {
			continue
		}
		matches := pattern.FindStringSubmatch(asset.Name)
		if matches != nil && len(matches) >= 2 {
			matchedAsset = asset
			matchedVersion = matches[1] // 提取版本号
			break
		}
	}

	if matchedAsset == nil {
		return "", "", "", fmt.Errorf("未找到匹配 %s 架构的 agent 产物", arch)
	}

	// 查找对应的 .sha256 文件
	sha256Name := matchedAsset.Name + ".sha256"
	var sha256Asset *ghAsset
	for i := range release.Assets {
		if release.Assets[i].Name == sha256Name {
			sha256Asset = &release.Assets[i]
			break
		}
	}

	if sha256Asset == nil {
		return "", "", "", fmt.Errorf("未找到 SHA256 校验文件: %s", sha256Name)
	}

	return matchedVersion, matchedAsset.BrowserDownloadURL, sha256Asset.BrowserDownloadURL, nil
}

// downloadSHA256 下载 .sha256 文件并提取哈希值
func (u *Updater) downloadSHA256(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("nodectl-agent/%s", AgentVersion))

	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载 SHA256 文件返回 %d", resp.StatusCode)
	}

	// sha256 文件很小，限制 1KiB
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}

	// 格式: "<hash>  <filename>\n" 或 "<hash> <filename>\n"
	line := strings.TrimSpace(string(data))
	parts := strings.Fields(line)
	if len(parts) < 1 {
		return "", fmt.Errorf("SHA256 文件格式异常: %q", line)
	}

	hash := strings.ToLower(parts[0])
	if len(hash) != 64 {
		return "", fmt.Errorf("SHA256 哈希长度异常: %d", len(hash))
	}

	return hash, nil
}

// downloadBinary 流式下载二进制文件并同时计算 SHA256
// 返回计算出的哈希（小写 hex）
func (u *Updater) downloadBinary(ctx context.Context, url string, destPath string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("nodectl-agent/%s", AgentVersion))

	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载二进制文件返回 %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer f.Close()

	// 使用 TeeReader 边下载边计算哈希
	hasher := sha256.New()
	reader := io.TeeReader(resp.Body, hasher)

	buf := make([]byte, downloadBufSize)
	if _, err := io.CopyBuffer(f, reader, buf); err != nil {
		return "", fmt.Errorf("下载写入失败: %w", err)
	}

	// fsync 确保落盘
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("fsync 失败: %w", err)
	}

	hash := hex.EncodeToString(hasher.Sum(nil))
	return hash, nil
}
