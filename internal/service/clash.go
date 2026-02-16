package service

import (
	"bytes"
	_ "embed"
	"fmt"
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

// SupportedClashModules 定义所有支持的按需分流模块
var SupportedClashModules = []RuleModule{
	{ID: "XiaoHongShu", Name: "小红书", Icon: "📕"},
	{ID: "DouYin", Name: "抖音", Icon: "🎵"},
	{ID: "BiliBili", Name: "BiliBili", Icon: "📺"},
	{ID: "Steam", Name: "Steam", Icon: "🎮"},
	{ID: "Telegram", Name: "Telegram", Icon: "✈️"},
	{ID: "Spotify", Name: "Spotify", Icon: "🎧"},
	{ID: "YouTube", Name: "YouTube", Icon: "▶️"},
	{ID: "Netflix", Name: "Netflix", Icon: "🎬"},
	{ID: "OpenAI", Name: "OpenAI", Icon: "🤖"},
	{ID: "GitHub", Name: "GitHub", Icon: "🐙"},
	{ID: "Twitter", Name: "Twitter(X)", Icon: "🐦"},
}

// ClashTemplateData 用于传入模板渲染的数据结构
type ClashTemplateData struct {
	RelaySubURL string          // 中转节点订阅链接
	ExitSubURL  string          // 落地节点订阅链接
	Modules     map[string]bool // 用户启用的规则模块
}

// GetActiveClashModules 从数据库获取用户保存的启用的模块
func GetActiveClashModules() []string {
	var conf database.SysConfig
	err := database.DB.Where("key = ?", "clash_active_modules").First(&conf).Error
	if err != nil || conf.Value == "" {
		return []string{} // 默认返回空或你想要的默认选中项
	}
	return strings.Split(conf.Value, ",")
}

// SaveActiveClashModules 保存用户选择的模块
func SaveActiveClashModules(modules []string) error {
	val := strings.Join(modules, ",")

	// 使用 FirstOrCreate 配合 Updates，或者直接用 Save
	// 这里用 Assign 来实现优雅的 Upsert
	err := database.DB.Where(database.SysConfig{Key: "clash_active_modules"}).
		Assign(database.SysConfig{Value: val}).
		FirstOrCreate(&database.SysConfig{}).Error

	return err
}

// RenderClashConfig 最终生成用户的 YAML 配置
func RenderClashConfig(relayURL, exitURL string) (string, error) {
	activeMods := GetActiveClashModules()
	modMap := make(map[string]bool)
	for _, m := range activeMods {
		modMap[m] = true
	}

	data := ClashTemplateData{
		RelaySubURL: relayURL,
		ExitSubURL:  exitURL,
		Modules:     modMap,
	}

	tmpl, err := template.New("clash").Parse(ClashTemplateStr)
	if err != nil {
		return "", fmt.Errorf("解析 Clash 模板失败: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染 Clash 模板失败: %v", err)
	}

	// [修改这里] 清洗模板产生的大量多余空行
	// 原理：将 3 个或以上连续的换行符（中间可能夹带空格制表符），强制压缩为 2 个换行符 (保留一个正常空行)
	re := regexp.MustCompile(`(\r?\n[ \t]*){3,}`)
	cleanYAML := re.ReplaceAllString(buf.String(), "\n\n")

	return cleanYAML, nil
}
