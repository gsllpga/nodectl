package service

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// GlobalGeoIP 全局实例
var GlobalGeoIP *GeoService

type GeoService struct {
	db   *geoip2.Reader
	mu   sync.RWMutex // 读写锁，防止更新时读取崩溃
	path string
	url  string
}

// InitGeoIP 初始化 GeoIP 服务
func InitGeoIP() {
	// [修改] 路径改为 data/geo/GeoLite2-Country.mmdb
	dbPath := filepath.Join("data", "geo", "GeoLite2-Country.mmdb")
	downloadURL := "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

	svc := &GeoService{
		path: dbPath,
		url:  downloadURL,
	}

	// 尝试加载，如果不存在则自动下载
	if err := svc.Reload(); err != nil {
		slog.Error("GeoIP 初始化失败 (如果是首次运行，可能正在下载中，请稍后在设置中手动更新)", "err", err)
	}

	GlobalGeoIP = svc
}

// Reload 重新加载/下载数据库
func (s *GeoService) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 如果旧数据库已打开，先关闭
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}

	// 2. 确保存放目录存在
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 3. 检查文件是否存在，不存在则下载
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		slog.Info("GeoIP 数据库不存在，开始下载...", "url", s.url)
		if err := downloadFile(s.path, s.url); err != nil {
			return err
		}
	}

	// 4. 打开数据库
	db, err := geoip2.Open(s.path)
	if err != nil {
		return fmt.Errorf("打开 GeoIP 数据库失败: %w", err)
	}

	s.db = db
	slog.Info("GeoIP 服务加载成功", "path", s.path)
	return nil
}

// ForceUpdate 强制重新下载并加载
func (s *GeoService) ForceUpdate() error {
	s.mu.Lock()
	// 注意：这里只做下载前的准备，具体的锁在 reload 中也会用到，所以要小心死锁。
	// 简单的做法是：先下载到临时文件，下载成功后再获取锁进行替换。

	// 这里为了简化，先解锁进行下载（因为下载耗时），下载完成后再加锁替换
	s.mu.Unlock()

	slog.Info("开始强制更新 GeoIP 数据库...")
	tempPath := s.path + ".update"

	// 1. 下载到临时位置
	if err := downloadFile(tempPath, s.url); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}

	// 2. 重新加锁进行文件替换和重载
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		s.db.Close()
	}

	// 替换文件
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("文件替换失败: %w", err)
	}

	// 重新打开
	db, err := geoip2.Open(s.path)
	if err != nil {
		return fmt.Errorf("重载数据库失败: %w", err)
	}
	s.db = db
	slog.Info("GeoIP 数据库更新完成")
	return nil
}

// GetCountryIsoCode 获取国家 ISO 代码 (线程安全)
func (s *GeoService) GetCountryIsoCode(ipStr string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || ipStr == "" {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	record, err := s.db.Country(ip)
	if err != nil {
		return ""
	}

	return record.Country.IsoCode
}

// downloadFile 通用下载函数
func downloadFile(filepath string, url string) error {
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// 在 internal/service/geo.go 中添加：

// GetLocalDBTime 获取本地数据库文件的修改时间
func (s *GeoService) GetLocalDBTime() (time.Time, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// CheckRemoteDBTime 检查远程文件的 Last-Modified 时间
func (s *GeoService) CheckRemoteDBTime() (time.Time, error) {
	// P3TERX/GeoLite.mmdb 仓库的最新 Release API 地址
	apiURL := "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return time.Time{}, err
	}

	// GitHub API 强制要求设置 User-Agent，否则会拒绝请求 (403 Forbidden)
	req.Header.Set("User-Agent", "NodeCTL-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("GitHub API 请求失败: %s", resp.Status)
	}

	// 定义一个简单的结构体来提取 JSON 中的发布时间
	var release struct {
		PublishedAt time.Time `json:"published_at"`
	}

	// 解析 JSON
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return time.Time{}, fmt.Errorf("API 响应解析失败: %v", err)
	}

	return release.PublishedAt, nil
}
