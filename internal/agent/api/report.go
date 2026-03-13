// 路径: internal/agent/api/report.go
// 节点信息上报模块
// 负责向后端上报节点上线信息、协议链接等
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"nodectl/internal/agent/links"
	"nodectl/internal/agent/singbox"
)

// NodeReport 节点上线上报的数据结构
type NodeReport struct {
	InstallID string       `json:"install_id"`
	Hostname  string       `json:"hostname"`
	PublicIP  string       `json:"public_ip"`
	Protocols []string     `json:"protocols"` // 已启用协议列表
	Links     []links.Link `json:"links"`     // 所有协议链接
	Timestamp int64        `json:"timestamp"`
}

// Reporter 节点信息上报器
type Reporter struct {
	reportURL string // 后端上报地址（如 https://panel.example.com/api/callback/report）
	installID string
	client    *http.Client
}

// NewReporter 创建上报器
// reportURL: 后端上报接口地址
// installID: 节点唯一标识
func NewReporter(reportURL, installID string) *Reporter {
	return &Reporter{
		reportURL: reportURL,
		installID: installID,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ReportNodeOnline 上报节点上线信息（包含协议和链接）
func (r *Reporter) ReportNodeOnline(ctx context.Context, publicIP string, config *singbox.ProtocolConfig) error {
	hostname, _ := os.Hostname()

	// 生成链接
	gen := links.NewGenerator(publicIP, getSuffix(config), config)
	allLinks := gen.GenerateAll()

	report := NodeReport{
		InstallID: r.installID,
		Hostname:  hostname,
		PublicIP:  publicIP,
		Protocols: config.EnabledProtocolList(),
		Links:     allLinks,
		Timestamp: time.Now().Unix(),
	}

	return r.sendReport(ctx, "node-online", report)
}

// ReportLinksUpdate 上报链接更新（协议重置后调用）
func (r *Reporter) ReportLinksUpdate(ctx context.Context, publicIP string, config *singbox.ProtocolConfig, resetProtocols []string) error {
	// 生成链接
	gen := links.NewGenerator(publicIP, getSuffix(config), config)
	allLinks := gen.GenerateAll()

	payload := map[string]any{
		"install_id":      r.installID,
		"reset_protocols": resetProtocols,
		"protocols":       config.EnabledProtocolList(),
		"links":           allLinks,
		"timestamp":       time.Now().Unix(),
	}

	return r.sendReport(ctx, "links-update", payload)
}

// sendReport 发送上报请求到后端
func (r *Reporter) sendReport(ctx context.Context, action string, payload any) error {
	if r.reportURL == "" {
		log.Printf("[API] 上报地址为空，跳过上报 (action=%s)", action)
		return nil
	}

	body := map[string]any{
		"action":  action,
		"payload": payload,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("序列化上报数据失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.reportURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("创建上报请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("发送上报请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 读取并丢弃响应体（释放连接）
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("上报失败: HTTP %d", resp.StatusCode)
	}

	log.Printf("[API] 上报成功: action=%s, status=%d", action, resp.StatusCode)
	return nil
}

// DeriveReportURL 从 ws_url 推导上报接口 URL
// ws_url 格式: wss://domain:port/api/callback/traffic/ws
// 返回: https://domain:port/api/callback/report
func DeriveReportURL(wsURL string) string {
	reportURL := wsURL
	reportURL = strings.Replace(reportURL, "wss://", "https://", 1)
	reportURL = strings.Replace(reportURL, "ws://", "http://", 1)
	if idx := strings.Index(reportURL, "/api/"); idx > 0 {
		reportURL = reportURL[:idx]
	}
	return reportURL + "/api/callback/report"
}

// getSuffix 获取节点名称后缀
func getSuffix(config *singbox.ProtocolConfig) string {
	if config.HostSuffix != "" {
		return config.HostSuffix
	}
	hostname, _ := os.Hostname()
	if hostname != "" {
		return hostname
	}
	return ""
}

// GetPublicIP 获取节点公网 IP
func GetPublicIP() string {
	urls := []string{
		"https://api.ipify.org",
		"https://ipinfo.io/ip",
		"https://ifconfig.me",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}
