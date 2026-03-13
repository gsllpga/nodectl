// 路径: internal/agent/singbox/manager.go
// sing-box 子进程生命周期管理器
// 负责启动、停止、重启 sing-box，以及崩溃自动重启和日志捕获
package singbox

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ProcessStatus sing-box 进程状态
type ProcessStatus struct {
	Running    bool      `json:"running"`
	PID        int       `json:"pid,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	RestartCnt int       `json:"restart_count"`
	LastError  string    `json:"last_error,omitempty"`
}

// Manager sing-box 进程管理器
type Manager struct {
	mu sync.RWMutex

	// 配置
	binaryPath string
	configPath string
	logPath    string
	pidPath    string

	// 子进程
	cmd    *exec.Cmd
	cancel context.CancelFunc

	// 状态
	running    bool
	pid        int
	startedAt  time.Time
	restartCnt int
	lastError  string

	// 配置管理器
	config    *ConfigManager
	installer *Installer

	// 自动重启控制
	maxRestarts    int           // 最大连续重启次数
	restartDelay   time.Duration // 重启间隔
	restartCounter int           // 连续崩溃计数器（非正常退出时+1，正常运行一段时间后清零）
}

// NewManager 创建 sing-box 管理器
func NewManager() *Manager {
	return &Manager{
		binaryPath:   DefaultBinaryPath,
		configPath:   DefaultConfigPath,
		logPath:      "/var/log/nodectl-agent/singbox.log",
		pidPath:      filepath.Join(DefaultWorkDir, "singbox.pid"),
		config:       NewConfigManager(),
		installer:    NewInstaller(""),
		maxRestarts:  5,
		restartDelay: 3 * time.Second,
	}
}

// NewManagerWithConfig 使用指定配置创建管理器
func NewManagerWithConfig(config *ConfigManager, installer *Installer) *Manager {
	m := NewManager()
	if config != nil {
		m.config = config
		m.configPath = config.GetConfigPath()
	}
	if installer != nil {
		m.installer = installer
		m.binaryPath = installer.GetBinaryPath()
	}
	return m
}

// GetConfigManager 返回配置管理器
func (m *Manager) GetConfigManager() *ConfigManager {
	return m.config
}

// GetInstaller 返回安装器
func (m *Manager) GetInstaller() *Installer {
	return m.installer
}

// Start 启动 sing-box 子进程
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("sing-box 已在运行 (PID=%d)", m.pid)
	}

	// 确保 sing-box 已安装
	if !m.installer.IsInstalled() {
		return fmt.Errorf("sing-box 二进制不存在: %s，请先安装", m.binaryPath)
	}

	// 确保配置文件存在
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		return fmt.Errorf("sing-box 配置文件不存在: %s，请先生成配置", m.configPath)
	}

	return m.startProcess(ctx)
}

// startProcess 内部启动逻辑（调用者须持有锁）
func (m *Manager) startProcess(ctx context.Context) error {
	// 创建子 context 用于管理进程生命周期
	procCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// 构造命令: sing-box run -c config.json
	cmd := exec.CommandContext(procCtx, m.binaryPath, "run", "-c", m.configPath)

	// 设置日志输出
	logWriter, err := m.openLogWriter()
	if err != nil {
		cancel()
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	cmd.Stdout = logWriter
	cmd.Stderr = logWriter

	// 启动子进程
	if err := cmd.Start(); err != nil {
		cancel()
		if closer, ok := logWriter.(io.Closer); ok {
			closer.Close()
		}
		m.lastError = err.Error()
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}

	m.cmd = cmd
	m.running = true
	m.pid = cmd.Process.Pid
	m.startedAt = time.Now()
	m.lastError = ""

	// 保存 PID 文件
	m.savePID()

	log.Printf("[SingBox] sing-box 已启动 (PID=%d, config=%s)", m.pid, m.configPath)

	// 启动监控协程
	go m.watchProcess(ctx, cmd, logWriter)

	return nil
}

// Stop 停止 sing-box 子进程
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopProcess()
}

// stopProcess 内部停止逻辑（调用者须持有锁）
func (m *Manager) stopProcess() error {
	if !m.running || m.cmd == nil {
		return nil
	}

	log.Printf("[SingBox] 正在停止 sing-box (PID=%d)...", m.pid)

	// 取消 context 触发进程终止
	if m.cancel != nil {
		m.cancel()
	}

	// 等待进程退出（最多 10 秒）
	done := make(chan struct{})
	go func() {
		if m.cmd.Process != nil {
			m.cmd.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		// 正常退出
	case <-time.After(10 * time.Second):
		// 超时强杀
		if m.cmd.Process != nil {
			log.Printf("[SingBox] sing-box 停止超时，强制终止 (PID=%d)", m.pid)
			m.cmd.Process.Kill()
		}
	}

	m.running = false
	m.cmd = nil
	m.removePID()

	log.Printf("[SingBox] sing-box 已停止")
	return nil
}

// Restart 重启 sing-box 子进程
func (m *Manager) Restart(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 先停止
	if err := m.stopProcess(); err != nil {
		log.Printf("[SingBox] 停止 sing-box 出错: %v", err)
	}

	// 等待一小段时间确保端口释放
	time.Sleep(500 * time.Millisecond)

	// 重新启动
	m.restartCnt++
	return m.startProcess(ctx)
}

// ReloadConfig 重新生成配置并重启
func (m *Manager) ReloadConfig(ctx context.Context) error {
	// 重新生成 sing-box 配置
	if err := m.config.GenerateAndSave(); err != nil {
		return fmt.Errorf("重新生成配置失败: %w", err)
	}

	// 保存协议缓存
	if err := m.config.SaveToCache(); err != nil {
		log.Printf("[SingBox] 保存协议缓存失败: %v", err)
	}

	// 重启 sing-box
	return m.Restart(ctx)
}

// Status 获取 sing-box 运行状态
func (m *Manager) Status() ProcessStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ProcessStatus{
		Running:    m.running,
		PID:        m.pid,
		StartedAt:  m.startedAt,
		RestartCnt: m.restartCnt,
		LastError:  m.lastError,
	}
}

// IsRunning 检查 sing-box 是否在运行
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// --- 内部方法 ---

// watchProcess 监控 sing-box 子进程，异常退出时自动重启
func (m *Manager) watchProcess(ctx context.Context, cmd *exec.Cmd, logWriter io.Writer) {
	// 等待进程退出
	err := cmd.Wait()

	// 关闭日志文件
	if closer, ok := logWriter.(io.Closer); ok {
		closer.Close()
	}

	m.mu.Lock()
	m.running = false
	m.removePID()

	if err != nil {
		m.lastError = err.Error()
		log.Printf("[SingBox] sing-box 异常退出 (PID=%d): %v", m.pid, err)
	} else {
		log.Printf("[SingBox] sing-box 正常退出 (PID=%d)", m.pid)
	}

	// 检查是否需要自动重启
	if ctx.Err() != nil {
		// 上下文已取消（用户主动停止），不重启
		m.mu.Unlock()
		return
	}

	// 检查连续崩溃次数
	m.restartCounter++
	if m.restartCounter > m.maxRestarts {
		log.Printf("[SingBox] 连续崩溃次数已达上限 (%d)，停止自动重启", m.maxRestarts)
		m.mu.Unlock()
		return
	}

	log.Printf("[SingBox] %v 后自动重启 (第 %d 次)...", m.restartDelay, m.restartCounter)
	m.mu.Unlock()

	// 等待一段时间后重启
	select {
	case <-ctx.Done():
		return
	case <-time.After(m.restartDelay):
	}

	m.mu.Lock()
	if err := m.startProcess(ctx); err != nil {
		log.Printf("[SingBox] 自动重启失败: %v", err)
		m.lastError = fmt.Sprintf("自动重启失败: %v", err)
	} else {
		m.restartCnt++
		// 启动成功，10 秒后若仍在运行则清零崩溃计数
		go func() {
			time.Sleep(10 * time.Second)
			m.mu.Lock()
			if m.running {
				m.restartCounter = 0
			}
			m.mu.Unlock()
		}()
	}
	m.mu.Unlock()
}

// openLogWriter 打开日志文件
func (m *Manager) openLogWriter() (io.Writer, error) {
	if dir := filepath.Dir(m.logPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(m.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// savePID 保存子进程 PID 到文件
func (m *Manager) savePID() {
	if m.pid <= 0 {
		return
	}
	if dir := filepath.Dir(m.pidPath); dir != "" {
		os.MkdirAll(dir, 0755)
	}
	os.WriteFile(m.pidPath, []byte(strconv.Itoa(m.pid)), 0644)
}

// removePID 删除 PID 文件
func (m *Manager) removePID() {
	os.Remove(m.pidPath)
}

// Shutdown 优雅关闭（供 Runtime.shutdown() 调用）
func (m *Manager) Shutdown() {
	if err := m.Stop(); err != nil {
		log.Printf("[SingBox] 关闭 sing-box 失败: %v", err)
	}
}
