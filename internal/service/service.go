package service

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"nodectl/internal/database"
	"nodectl/internal/logger"
	"os"
	"path/filepath"
	"text/template"

	"gorm.io/gorm"
)

//go:embed singbox.tpl
var SingboxScriptTpl string // [修改] 改为大写开头

// GenerateRandomNodeName 生成随机节点名称 (node-4位字母数字)
func GenerateRandomNodeName() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "node-0000" // 容错备用
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return fmt.Sprintf("node-%s", string(b))
}

// AddNode 核心写入节点逻辑
func AddNode(name string, routingType int) (*database.NodePool, error) {
	// 如果用户未输入名称，则自动生成
	if name == "" {
		name = GenerateRandomNodeName()
	}

	node := &database.NodePool{
		Name:        name,
		RoutingType: routingType,             // 1:直连, 2:落地
		Links:       make(map[string]string), // 初始化空的连接 map
	}

	// 写入数据库
	if err := database.DB.Create(node).Error; err != nil {
		return nil, err
	}

	return node, nil
}

// UpdateNode 更新节点信息 (名称、路由类型、协议链接)
func UpdateNode(uuid string, name string, routingType int, links map[string]string, isBlocked bool, disabledLinks []string, ipv4, ipv6 string) error {
	var node database.NodePool

	if err := database.DB.Where("uuid = ?", uuid).First(&node).Error; err != nil {
		return err
	}

	node.Name = name
	node.RoutingType = routingType
	node.Links = links
	node.IsBlocked = isBlocked
	node.DisabledLinks = disabledLinks
	node.IPV4 = ipv4
	node.IPV6 = ipv6

	// [新增] 解析 Region
	if GlobalGeoIP != nil {
		region := ""
		if ipv4 != "" {
			region = GlobalGeoIP.GetCountryIsoCode(ipv4)
		}
		if region == "" && ipv6 != "" {
			region = GlobalGeoIP.GetCountryIsoCode(ipv6)
		}
		// 如果解析到了，就更新；如果没解析到但IP变空了，可能需要清空 region？
		// 这里策略是：只要解析出有效代码就覆盖，否则保留原样(或根据需求清空)
		if region != "" {
			node.Region = region
		}
	}

	return database.DB.Save(&node).Error
}

// [新增] ReorderNodes 批量更新节点的路由类型和排序索引
func ReorderNodes(routingType int, uuids []string) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		for index, uuid := range uuids {
			// 更新每个节点的 RoutingType (因为可能从直连拖到了落地)
			// 并更新 SortIndex 为当前数组的下标
			err := tx.Model(&database.NodePool{}).
				Where("uuid = ?", uuid).
				Updates(map[string]interface{}{
					"RoutingType": routingType, // 确保节点归属到新分组
					"SortIndex":   index,       // 更新排序
				}).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// [修改] RenderInstallScript 渲染安装脚本 (只填充静态端口配置)
func RenderInstallScript() (string, error) {
	var configs []database.SysConfig
	if err := database.DB.Find(&configs).Error; err != nil {
		return "", fmt.Errorf("读取系统配置失败: %v", err)
	}

	configMap := make(map[string]string)
	for _, c := range configs {
		configMap[c.Key] = c.Value
	}

	// 拼接出完整的 Report URL
	panelURL := configMap["panel_url"]
	reportURL := ""
	if panelURL != "" {
		reportURL = panelURL + "/api/callback/report"
	}

	data := map[string]string{
		"PortSS":      configMap["proxy_port_ss"],
		"PortHY2":     configMap["proxy_port_hy2"],
		"PortTUIC":    configMap["proxy_port_tuic"],
		"PortReality": configMap["proxy_port_reality"],
		"RealitySNI":  configMap["proxy_reality_sni"],
		"SSMethod":    configMap["proxy_ss_method"],
		"PortSocks5":  configMap["proxy_port_socks5"],
		"Socks5User":  configMap["proxy_socks5_user"],
		"Socks5Pass":  configMap["proxy_socks5_pass"],
		"ReportURL":   reportURL,
	}

	tplContent := SingboxScriptTpl // 默认使用打包在二进制里的 embed 模板

	// 定义外部调试模板的路径 (data/debug/singbox.tpl)
	debugPath := filepath.Join("data", "debug", "singbox.tpl")

	// 尝试读取外部文件
	if content, err := os.ReadFile(debugPath); err == nil {
		// 如果文件存在且有权限读取，则直接覆盖 tplContent
		tplContent = string(content)
		// 打印一条提示日志，方便你在控制台/Docker logs 中确认热更新生效
		logger.Log.Info("【调试模式】已拦截并使用外部安装模板", "path", debugPath)
	}

	// 解析最终决定的模板内容
	tmpl, err := template.New("install_script").Parse(tplContent)
	if err != nil {
		return "", fmt.Errorf("解析脚本模板失败: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染脚本失败: %v", err)
	}

	return buf.String(), nil
}
