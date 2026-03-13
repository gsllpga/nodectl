// 路径: internal/agent/migrate.go
// 旧版安装迁移模块
// Agent 首次启动时检测旧版路径并迁移文件到新版标准路径
package agent

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// 旧版路径（由 singbox.tpl 安装脚本管理）
const (
	OldSingBoxBinary    = "/usr/local/bin/sing-box"
	OldSingBoxConfig    = "/etc/sing-box/config.json"
	OldSingBoxCachePath = "/etc/sing-box/.config_cache"
	OldCertPath         = "/etc/sing-box/cert.pem"
	OldKeyPath          = "/etc/sing-box/private.key"
)

// 新版路径
const (
	NewSingBoxBinary = "/var/lib/nodectl-agent/sing-box"
	NewSingBoxConfig = "/var/lib/nodectl-agent/singbox-config.json"
	NewProtocolsPath = "/var/lib/nodectl-agent/protocols.json"
	NewCertPath      = "/var/lib/nodectl-agent/certs/fullchain.pem"
	NewKeyPath       = "/var/lib/nodectl-agent/certs/privkey.pem"
)

// MigrationResult 迁移结果
type MigrationResult struct {
	Migrated       bool   // 是否执行了迁移
	BinaryMigrated bool   // sing-box 二进制是否迁移
	ConfigMigrated bool   // sing-box 配置是否迁移
	CertMigrated   bool   // 证书是否迁移
	CacheMigrated  bool   // 协议缓存是否迁移
	OldSvcDisabled bool   // 旧服务是否已禁用
	Error          string // 迁移过程中的非致命错误
}

// RunMigration 执行旧版安装迁移检测和文件迁移
// 调用时机：Agent 首次启动时（Runtime.Run 内部）
func RunMigration() *MigrationResult {
	result := &MigrationResult{}

	// 检查新版路径是否已存在配置（如果已有则跳过迁移）
	if fileExists(NewSingBoxConfig) {
		log.Printf("[Migration] 新版配置已存在 (%s)，跳过迁移", NewSingBoxConfig)
		return result
	}

	// 检查旧版路径是否存在
	if !fileExists(OldSingBoxConfig) {
		log.Printf("[Migration] 未检测到旧版安装路径，无需迁移")
		return result
	}

	log.Printf("[Migration] 检测到旧版安装，开始迁移...")
	result.Migrated = true

	// 1. 确保新版目录存在
	dirs := []string{
		"/var/lib/nodectl-agent",
		"/var/lib/nodectl-agent/certs",
		"/var/log/nodectl-agent",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			result.Error = fmt.Sprintf("创建目录失败 %s: %v", dir, err)
			log.Printf("[Migration] %s", result.Error)
			return result
		}
	}

	// 2. 迁移 sing-box 二进制
	if fileExists(OldSingBoxBinary) && !fileExists(NewSingBoxBinary) {
		if err := copyFile(OldSingBoxBinary, NewSingBoxBinary); err != nil {
			log.Printf("[Migration] 迁移 sing-box 二进制失败: %v", err)
			result.Error += fmt.Sprintf("binary: %v; ", err)
		} else {
			os.Chmod(NewSingBoxBinary, 0755)
			result.BinaryMigrated = true
			log.Printf("[Migration] sing-box 二进制已迁移: %s -> %s", OldSingBoxBinary, NewSingBoxBinary)
		}
	}

	// 3. 迁移 sing-box 配置
	if fileExists(OldSingBoxConfig) && !fileExists(NewSingBoxConfig) {
		if err := copyFile(OldSingBoxConfig, NewSingBoxConfig); err != nil {
			log.Printf("[Migration] 迁移 sing-box 配置失败: %v", err)
			result.Error += fmt.Sprintf("config: %v; ", err)
		} else {
			result.ConfigMigrated = true
			log.Printf("[Migration] sing-box 配置已迁移: %s -> %s", OldSingBoxConfig, NewSingBoxConfig)
		}
	}

	// 4. 迁移协议缓存
	if fileExists(OldSingBoxCachePath) && !fileExists(NewProtocolsPath) {
		if err := copyFile(OldSingBoxCachePath, NewProtocolsPath); err != nil {
			log.Printf("[Migration] 迁移协议缓存失败: %v", err)
			result.Error += fmt.Sprintf("cache: %v; ", err)
		} else {
			result.CacheMigrated = true
			log.Printf("[Migration] 协议缓存已迁移: %s -> %s", OldSingBoxCachePath, NewProtocolsPath)
		}
	}

	// 5. 迁移证书
	if fileExists(OldCertPath) && !fileExists(NewCertPath) {
		if err := copyFile(OldCertPath, NewCertPath); err != nil {
			log.Printf("[Migration] 迁移证书失败: %v", err)
		} else {
			result.CertMigrated = true
			log.Printf("[Migration] 证书已迁移: %s -> %s", OldCertPath, NewCertPath)
		}
	}
	if fileExists(OldKeyPath) && !fileExists(NewKeyPath) {
		if err := copyFile(OldKeyPath, NewKeyPath); err != nil {
			log.Printf("[Migration] 迁移私钥失败: %v", err)
		} else {
			os.Chmod(NewKeyPath, 0600)
			log.Printf("[Migration] 私钥已迁移: %s -> %s", OldKeyPath, NewKeyPath)
		}
	}

	// 6. 停止并禁用旧版 sing-box 服务（不删除文件，保留回滚能力）
	result.OldSvcDisabled = disableOldSingBoxService()

	log.Printf("[Migration] 迁移完成: binary=%v, config=%v, cert=%v, cache=%v, old_svc_disabled=%v",
		result.BinaryMigrated, result.ConfigMigrated, result.CertMigrated, result.CacheMigrated, result.OldSvcDisabled)

	return result
}

// disableOldSingBoxService 停止并禁用旧版 sing-box 独立系统服务
func disableOldSingBoxService() bool {
	disabled := false

	// 尝试 systemd
	if _, err := exec.LookPath("systemctl"); err == nil {
		// 停止服务
		exec.Command("systemctl", "stop", "sing-box").Run()
		// 禁用服务
		if err := exec.Command("systemctl", "disable", "sing-box").Run(); err == nil {
			disabled = true
			log.Printf("[Migration] 已禁用 systemd sing-box 服务")
		}
	}

	// 尝试 OpenRC
	if _, err := exec.LookPath("rc-service"); err == nil {
		exec.Command("rc-service", "sing-box", "stop").Run()
		if err := exec.Command("rc-update", "del", "sing-box", "default").Run(); err == nil {
			disabled = true
			log.Printf("[Migration] 已禁用 OpenRC sing-box 服务")
		}
	}

	return disabled
}

// fileExists 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// copyFile 复制文件（保留权限）
func copyFile(src, dst string) error {
	// 确保目标目录存在
	if dir := filepath.Dir(dst); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("获取源文件信息失败: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("创建目标文件失败: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("复制文件内容失败: %w", err)
	}

	return nil
}
