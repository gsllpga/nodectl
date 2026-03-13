// 路径: internal/agent/singbox/installer.go
// sing-box 二进制下载/安装器
// 从 GitHub Release 下载 sing-box 并安装到工作目录
package singbox

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// DefaultBinaryPath sing-box 二进制默认安装路径
	DefaultBinaryPath = "/var/lib/nodectl-agent/sing-box"

	// SingBoxGitHubRepo GitHub Release 下载 URL 模板
	// 格式: https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}.tar.gz
	SingBoxGitHubRepo = "https://github.com/SagerNet/sing-box/releases"

	// DefaultSingBoxVersion 默认安装版本
	DefaultSingBoxVersion = "1.11.8"
)

// Installer sing-box 安装器
type Installer struct {
	binaryPath string // sing-box 二进制安装路径
	version    string // 目标版本
}

// NewInstaller 创建安装器
func NewInstaller(binaryPath string) *Installer {
	if binaryPath == "" {
		binaryPath = DefaultBinaryPath
	}
	return &Installer{
		binaryPath: binaryPath,
		version:    DefaultSingBoxVersion,
	}
}

// SetVersion 设置目标版本
func (i *Installer) SetVersion(version string) {
	i.version = strings.TrimPrefix(version, "v")
}

// GetBinaryPath 返回二进制文件路径
func (i *Installer) GetBinaryPath() string {
	return i.binaryPath
}

// IsInstalled 检查 sing-box 是否已安装
func (i *Installer) IsInstalled() bool {
	_, err := os.Stat(i.binaryPath)
	return err == nil
}

// GetVersion 获取已安装的 sing-box 版本
func (i *Installer) GetVersion() (string, error) {
	if !i.IsInstalled() {
		return "", fmt.Errorf("sing-box 未安装")
	}

	cmd := exec.Command(i.binaryPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("获取 sing-box 版本失败: %w", err)
	}

	// 输出格式: "sing-box version 1.x.x\n..."
	line := strings.Split(string(output), "\n")[0]
	parts := strings.Fields(line)
	if len(parts) >= 3 {
		return parts[2], nil
	}

	return strings.TrimSpace(string(output)), nil
}

// NeedUpdate 检查是否需要更新
func (i *Installer) NeedUpdate(latestVersion string) bool {
	currentVersion, err := i.GetVersion()
	if err != nil {
		return true // 获取不到版本信息，需要安装
	}

	latestVersion = strings.TrimPrefix(latestVersion, "v")
	return currentVersion != latestVersion
}

// Download 下载并安装 sing-box 二进制
func (i *Installer) Download(ctx context.Context) error {
	arch := detectArch()
	if arch == "" {
		return fmt.Errorf("不支持的系统架构: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	version := i.version
	if version == "" {
		version = DefaultSingBoxVersion
	}

	// 构造下载 URL
	// 格式: sing-box-{version}-linux-{arch}.tar.gz
	filename := fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", version, arch)
	downloadURL := fmt.Sprintf("%s/download/v%s/%s", SingBoxGitHubRepo, version, filename)

	log.Printf("[SingBox] 下载 sing-box v%s (%s): %s", version, arch, downloadURL)

	// 确保目标目录存在
	if dir := filepath.Dir(i.binaryPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	// 下载到临时文件
	tmpFile, err := os.CreateTemp("", "sing-box-*.tar.gz")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if err := downloadFile(ctx, downloadURL, tmpFile); err != nil {
		return fmt.Errorf("下载 sing-box 失败: %w", err)
	}

	// 从 tar.gz 中提取 sing-box 二进制
	if _, err := tmpFile.Seek(0, 0); err != nil {
		return fmt.Errorf("重置文件指针失败: %w", err)
	}

	if err := extractSingBox(tmpFile, i.binaryPath, version, arch); err != nil {
		return fmt.Errorf("解压 sing-box 失败: %w", err)
	}

	// 设置可执行权限
	if err := os.Chmod(i.binaryPath, 0755); err != nil {
		return fmt.Errorf("设置执行权限失败: %w", err)
	}

	log.Printf("[SingBox] sing-box v%s 安装完成: %s", version, i.binaryPath)
	return nil
}

// Verify 验证二进制文件完整性（执行 sing-box version 确认可运行）
func (i *Installer) Verify() error {
	if !i.IsInstalled() {
		return fmt.Errorf("sing-box 二进制不存在: %s", i.binaryPath)
	}

	version, err := i.GetVersion()
	if err != nil {
		return fmt.Errorf("sing-box 二进制验证失败: %w", err)
	}

	log.Printf("[SingBox] 验证通过: sing-box v%s", version)
	return nil
}

// EnsureInstalled 确保 sing-box 已安装，若不存在则下载
func (i *Installer) EnsureInstalled(ctx context.Context) error {
	if i.IsInstalled() {
		if err := i.Verify(); err == nil {
			return nil
		}
		log.Printf("[SingBox] 已安装的 sing-box 验证失败，重新下载")
	}
	return i.Download(ctx)
}

// --- 内部辅助函数 ---

// detectArch 检测系统架构并映射到 sing-box 发布文件名使用的架构标识
func detectArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7"
	case "386":
		return "386"
	default:
		return ""
	}
}

// downloadFile 使用 HTTP GET 下载文件
func downloadFile(ctx context.Context, url string, dst *os.File) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 5 * time.Minute, // 下载大文件给足时间
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	written, err := io.Copy(dst, resp.Body)
	if err != nil {
		return err
	}

	log.Printf("[SingBox] 下载完成: %d bytes", written)
	return nil
}

// extractSingBox 从 tar.gz 归档中提取 sing-box 二进制文件
// sing-box 发布归档结构: sing-box-{version}-linux-{arch}/sing-box
func extractSingBox(archive io.Reader, destPath, version, arch string) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("解压 gzip 失败: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	// 在 tar.gz 中查找 sing-box 二进制
	// 路径格式: sing-box-{version}-linux-{arch}/sing-box
	targetName := fmt.Sprintf("sing-box-%s-linux-%s/sing-box", version, arch)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar 条目失败: %w", err)
		}

		// 精确匹配或以 /sing-box 结尾（兼容不同版本格式）
		if header.Name == targetName || strings.HasSuffix(header.Name, "/sing-box") {
			if header.Typeflag != tar.TypeReg {
				continue
			}

			out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("创建目标文件失败: %w", err)
			}
			defer out.Close()

			if _, err := io.Copy(out, tr); err != nil {
				return fmt.Errorf("写入二进制失败: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("归档中未找到 sing-box 二进制 (查找: %s)", targetName)
}
