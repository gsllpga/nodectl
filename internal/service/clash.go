package service

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"text/template"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	"gorm.io/gorm"
)

//go:embed clash_meta.tpl
var ClashTemplateStr string

//go:embed clash_modules.tpl
var ClashModulesJSON []byte

// ClashModuleDef 分流模块终极定义 (完美适配 GitMetaio mrs 架构)
type ClashModuleDef struct {
	Name       string   `json:"name"`
	Icon       string   `json:"icon"`
	URL        string   `json:"url,omitempty"`         // 用于用户自定义的 classical YAML 规则
	DomainURL  string   `json:"domain_url,omitempty"`  // 用于 GitMetaio 的 Domain.mrs
	IPURL      string   `json:"ip_url,omitempty"`      // 用于 GitMetaio 的 IP.mrs
	ExtraRules []string `json:"extra_rules,omitempty"` // 用于挂载 PROCESS-PATH 等附加规则
}

type ClashPresetDef struct {
	Name    string   `json:"name"`
	Desc    string   `json:"desc"`
	Modules []string `json:"modules"`
}

type ClashModulesConfig struct {
	Modules []ClashModuleDef `json:"modules"`
	Presets []ClashPresetDef `json:"presets"`
}

// LoadClashModulesConfig 读取内置 JSON 模板
func LoadClashModulesConfig() ClashModulesConfig {
	var config ClashModulesConfig
	if err := json.Unmarshal(ClashModulesJSON, &config); err != nil {
		logger.Log.Error("解析内置 clash_modules.tpl 失败", "error", err)
	}
	return config
}

func GetCustomClashModules() []ClashModuleDef {
	var conf database.SysConfig
	err := database.DB.Where("key = ?", "clash_custom_modules").First(&conf).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Log.Warn("读取自定义分流模块数据库异常", "error", err)
	}

	var modules []ClashModuleDef
	if conf.Value != "" && conf.Value != "[]" {
		if err := json.Unmarshal([]byte(conf.Value), &modules); err != nil {
			logger.Log.Error("反序列化自定义分流模块失败", "error", err, "raw_data", conf.Value)
		}
	}
	return modules
}

func SaveCustomClashModules(modules []ClashModuleDef) error {
	data, err := json.Marshal(modules)
	if err != nil {
		logger.Log.Error("序列化自定义分流模块失败", "error", err)
		return err
	}

	err = database.DB.Where(database.SysConfig{Key: "clash_custom_modules"}).
		Assign(database.SysConfig{Value: string(data)}).
		FirstOrCreate(&database.SysConfig{}).Error

	if err != nil {
		logger.Log.Error("保存自定义分流模块入库失败", "error", err)
		return err
	}

	logger.Log.Info("自定义分流模块已落库", "count", len(modules))
	return nil
}

func GetActiveClashModules() []string {
	var conf database.SysConfig
	database.DB.Where("key = ?", "clash_active_modules").First(&conf)
	if conf.Value == "" {
		return []string{}
	}
	return strings.Split(conf.Value, ",")
}

func SaveActiveClashModules(modules []string) error {
	val := strings.Join(modules, ",")
	return database.DB.Where(database.SysConfig{Key: "clash_active_modules"}).
		Assign(database.SysConfig{Value: val}).
		FirstOrCreate(&database.SysConfig{}).Error
}

// ---------------------------------------------------------
// Clash 模板渲染逻辑
// ---------------------------------------------------------

type ClashTemplateData struct {
	RelaySubURL   string
	ExitSubURL    string
	BaseURL       string
	Token         string
	ActiveModules []ClashModuleDef
	CustomProxies []CustomProxyRule
}

func RenderClashConfig(relayURL, exitURL, baseURL, token string) (string, error) {
	activeNames := GetActiveClashModules()
	activeMap := make(map[string]bool)
	for _, n := range activeNames {
		activeMap[n] = true
	}

	builtin := LoadClashModulesConfig().Modules
	custom := GetCustomClashModules()
	allModules := append(builtin, custom...)

	var finalActiveMods []ClashModuleDef
	for _, m := range allModules {
		if activeMap[m.Name] {
			finalActiveMods = append(finalActiveMods, m)
		}
	}

	data := ClashTemplateData{
		RelaySubURL:   relayURL,
		ExitSubURL:    exitURL,
		ActiveModules: finalActiveMods,
		BaseURL:       baseURL,
		Token:         token,
		CustomProxies: GetCustomProxyRules(),
	}

	tmpl, err := template.New("clash").Parse(ClashTemplateStr)
	if err != nil {
		return "", fmt.Errorf("解析 Clash 模板失败: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染 Clash 模板失败: %v", err)
	}

	re1 := regexp.MustCompile(`(?m)^[ \t]+$`)
	step1 := re1.ReplaceAllString(buf.String(), "")
	re2 := regexp.MustCompile(`(\r?\n){3,}`)
	return re2.ReplaceAllString(step1, "\n\n"), nil
}

// ---------------------------------------------------------
// 自定义规则处理逻辑
// ---------------------------------------------------------

func ParseCustomRules(raw string) string {
	var result []string
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.Contains(line, ",") {
			if line != "" {
				result = append(result, line)
			}
			continue
		}
		if idx := strings.Index(line, "://"); idx != -1 {
			line = line[idx+3:]
		}
		if isIPOrCIDR(line) {
			if !strings.Contains(line, "/") {
				if strings.Contains(line, ":") {
					line += "/128"
				} else {
					line += "/32"
				}
			}
			result = append(result, "IP-CIDR,"+line)
		} else {
			if idx := strings.Index(line, "/"); idx != -1 {
				line = line[:idx]
			}
			result = append(result, "DOMAIN-SUFFIX,"+line)
		}
	}
	return strings.Join(result, "\n")
}

func isIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}

type CustomProxyRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func GetCustomProxyRules() []CustomProxyRule {
	var conf database.SysConfig
	database.DB.Where("key = ?", "clash_custom_proxy_rules").First(&conf)
	var rules []CustomProxyRule
	if conf.Value != "" {
		json.Unmarshal([]byte(conf.Value), &rules)
	}
	return rules
}

func SaveCustomProxyRules(rules []CustomProxyRule) error {
	data, _ := json.Marshal(rules)
	return database.DB.Where(database.SysConfig{Key: "clash_custom_proxy_rules"}).
		Assign(database.SysConfig{Value: string(data)}).
		FirstOrCreate(&database.SysConfig{}).Error
}

func GetCustomDirectRules() string {
	var conf database.SysConfig
	database.DB.Where("key = ?", "clash_custom_direct_raw").First(&conf)
	return conf.Value
}

func SaveCustomDirectRules(content string) error {
	return database.DB.Where(database.SysConfig{Key: "clash_custom_direct_raw"}).
		Assign(database.SysConfig{Value: content}).
		FirstOrCreate(&database.SysConfig{}).Error
}
