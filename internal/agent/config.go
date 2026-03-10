// 路径: internal/agent/config.go
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DefaultConfigPath 默认配置文件路径
const DefaultConfigPath = "/etc/nodectl-agent/config.json"

// Config Agent 配置结构体，从 /etc/nodectl-agent/config.json 读取
type Config struct {
	InstallID         string `json:"install_id"`           // 节点唯一标识 (12位)
	WSURL             string `json:"ws_url"`               // WebSocket 上报地址
	WSPushIntervalSec int    `json:"ws_push_interval_sec"` // 实时速率推送间隔 (默认 2 秒)
	Interface         string `json:"interface"`            // 网卡名称 ("auto" 自动检测)
	LogLevel          string `json:"log_level"`            // 日志等级
}

// LoadConfig 从指定路径加载配置文件
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败 [%s]: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 校验必要字段
	if strings.TrimSpace(cfg.InstallID) == "" {
		return nil, fmt.Errorf("配置项 install_id 不能为空")
	}
	if strings.TrimSpace(cfg.WSURL) == "" {
		return nil, fmt.Errorf("配置项 ws_url 不能为空")
	}

	// 应用默认值
	if cfg.WSPushIntervalSec <= 0 {
		cfg.WSPushIntervalSec = 2
	}
	if strings.TrimSpace(cfg.Interface) == "" {
		cfg.Interface = "auto"
	}
	if strings.TrimSpace(cfg.LogLevel) == "" {
		cfg.LogLevel = "info"
	}

	return &cfg, nil
}
