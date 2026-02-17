package service

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"nodectl/internal/database"
	"regexp"
	"strings"
	"text/template"
)

//go:embed clash_meta.tpl
var ClashTemplateStr string

// RuleModule 定义前端展示和后端判断的规则模块
type RuleModule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

// [修复] 补全所有的 18 个分流模块
var SupportedClashModules = []RuleModule{
	{ID: "XiaoHongShu", Name: "小红书", Icon: "📕"},
	{ID: "DouYin", Name: "抖音", Icon: "🎵"},
	{ID: "BiliBili", Name: "BiliBili", Icon: "📺"},
	{ID: "Steam", Name: "Steam", Icon: "🎮"},
	{ID: "Apple", Name: "Apple", Icon: "🍎"},
	{ID: "Microsoft", Name: "Microsoft", Icon: "🪟"},
	{ID: "Telegram", Name: "Telegram", Icon: "✈️"},
	{ID: "Discord", Name: "Discord", Icon: "💬"},
	{ID: "Spotify", Name: "Spotify", Icon: "🎧"},
	{ID: "TikTok", Name: "TikTok", Icon: "📱"},
	{ID: "YouTube", Name: "YouTube", Icon: "▶️"},
	{ID: "Netflix", Name: "Netflix", Icon: "🎬"},
	{ID: "Google", Name: "Google", Icon: "🔍"},
	{ID: "GoogleFCM", Name: "GoogleFCM", Icon: "🔔"},
	{ID: "Facebook", Name: "Facebook", Icon: "📘"},
	{ID: "OpenAI", Name: "OpenAI", Icon: "🤖"},
	{ID: "GitHub", Name: "GitHub", Icon: "🐙"},
	{ID: "Twitter", Name: "Twitter(X)", Icon: "🐦"},
}

// [修改 internal/service/clash.go 中的结构体]
type ClashTemplateData struct {
	RelaySubURL   string          // 中转节点订阅链接
	ExitSubURL    string          // 落地节点订阅链接
	Modules       map[string]bool // 用户启用的规则模块
	BaseURL       string
	Token         string
	CustomProxies []CustomProxyRule // [新增] 多组自定义分流
}

// GetActiveClashModules 从数据库获取用户保存的启用的模块
func GetActiveClashModules() []string {
	var conf database.SysConfig
	err := database.DB.Where("key = ?", "clash_active_modules").First(&conf).Error
	if err != nil || conf.Value == "" {
		return []string{}
	}
	return strings.Split(conf.Value, ",")
}

// SaveActiveClashModules 保存用户选择的模块
func SaveActiveClashModules(modules []string) error {
	val := strings.Join(modules, ",")

	err := database.DB.Where(database.SysConfig{Key: "clash_active_modules"}).
		Assign(database.SysConfig{Value: val}).
		FirstOrCreate(&database.SysConfig{}).Error

	return err
}

// RenderClashConfig 最终生成用户的 YAML 配置
func RenderClashConfig(relayURL, exitURL, baseURL, token string) (string, error) {
	activeMods := GetActiveClashModules()
	modMap := make(map[string]bool)
	for _, m := range activeMods {
		modMap[m] = true
	}

	data := ClashTemplateData{
		RelaySubURL:   relayURL,
		ExitSubURL:    exitURL,
		Modules:       modMap,
		BaseURL:       baseURL,
		Token:         token,
		CustomProxies: GetCustomProxyRules(), // [新增] 获取多组分流规则
	}

	tmpl, err := template.New("clash").Parse(ClashTemplateStr)
	if err != nil {
		return "", fmt.Errorf("解析 Clash 模板失败: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染 Clash 模板失败: %v", err)
	}

	// [修复] 绝对安全的空行清理逻辑
	// 步骤 1: 将只有空格或制表符的“假空行”清理干净，变为纯粹的换行符
	re1 := regexp.MustCompile(`(?m)^[ \t]+$`)
	step1 := re1.ReplaceAllString(buf.String(), "")

	// 步骤 2: 将连续 3 个及以上的纯换行符，压缩为 2 个换行符 (保留一个正常空隙)
	// 这样绝对不会吃掉带有文字行的前置缩进
	re2 := regexp.MustCompile(`(\r?\n){3,}`)
	cleanYAML := re2.ReplaceAllString(step1, "\n\n")

	return cleanYAML, nil
}

// ---------------------------------------------------------
// 自定义规则处理逻辑 (智能识别 IP/CIDR 与 域名)
// ---------------------------------------------------------

// ParseCustomRules 自动解析原生文本，输出 Clash Classical 规范规则
func ParseCustomRules(raw string) string {
	var result []string
	// 统一换行符并逐行解析
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 1. 保留注释
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			result = append(result, line)
			continue
		}

		// 2. 如果用户手动写了规范格式 (包含逗号)，直接放行
		if strings.Contains(line, ",") {
			result = append(result, line)
			continue
		}

		// [修复] 清洗协议头: 剥离 http:// 或 https://
		if idx := strings.Index(line, "://"); idx != -1 {
			line = line[idx+3:]
		}

		// 3. 智能判断是 IP 还是 域名
		if isIPOrCIDR(line) {
			// 如果是没有掩码的纯 IP，自动补全掩码
			if !strings.Contains(line, "/") {
				if strings.Contains(line, ":") {
					line += "/128" // IPv6
				} else {
					line += "/32" // IPv4
				}
			}
			result = append(result, "IP-CIDR,"+line)
		} else {
			// [修复] 清洗路径: 剥离域名后面的路径 (如 github.com/xxx -> github.com)
			if idx := strings.Index(line, "/"); idx != -1 {
				line = line[:idx]
			}
			result = append(result, "DOMAIN-SUFFIX,"+line)
		}
	}

	return strings.Join(result, "\n")
}

// isIPOrCIDR 判断字符串是否为合法的 IP 或 CIDR
func isIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}

// CustomProxyRule 定义自定义分流出站的结构
type CustomProxyRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// GetCustomProxyRules 从数据库获取自定义分流规则列表
func GetCustomProxyRules() []CustomProxyRule {
	var conf database.SysConfig
	database.DB.Where("key = ?", "clash_custom_proxy_rules").First(&conf)

	var rules []CustomProxyRule
	if conf.Value != "" {
		json.Unmarshal([]byte(conf.Value), &rules)
	}
	return rules
}

// SaveCustomProxyRules 保存自定义分流规则列表
func SaveCustomProxyRules(rules []CustomProxyRule) error {
	data, _ := json.Marshal(rules)
	return database.DB.Where(database.SysConfig{Key: "clash_custom_proxy_rules"}).
		Assign(database.SysConfig{Value: string(data)}).
		FirstOrCreate(&database.SysConfig{}).Error
}

// GetCustomDirectRules 获取直连规则文本
func GetCustomDirectRules() string {
	var conf database.SysConfig
	database.DB.Where("key = ?", "clash_custom_direct_raw").First(&conf)
	return conf.Value
}

// SaveCustomDirectRules 保存直连规则文本
func SaveCustomDirectRules(content string) error {
	return database.DB.Where(database.SysConfig{Key: "clash_custom_direct_raw"}).
		Assign(database.SysConfig{Value: content}).
		FirstOrCreate(&database.SysConfig{}).Error
}
