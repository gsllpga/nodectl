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
	"strings"
	"text/template"

	"gorm.io/gorm"
)

//go:embed singbox.tpl
var SingboxScriptTpl string

// GenerateRandomNodeName 生成随机节点名称 (node-4位字母数字)
func GenerateRandomNodeName() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		logger.Log.Warn("生成随机节点名称失败，启用回退名称", "error", err)
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
		logger.Log.Error("服务层异常: 创建节点入库失败", "error", err, "node_name", name)
		return nil, err
	}
	return node, nil
}

// UpdateNode 更新节点信息 (名称、路由类型、协议链接)
func UpdateNode(uuid string, name string, routingType int, links map[string]string, isBlocked bool, disabledLinks []string, ipv4, ipv6 string) error {
	var node database.NodePool

	if err := database.DB.Where("uuid = ?", uuid).First(&node).Error; err != nil {
		logger.Log.Error("服务层异常: 更新时未找到目标节点", "error", err, "uuid", uuid)
		return err
	}

	node.Name = name
	node.RoutingType = routingType
	node.Links = links
	node.IsBlocked = isBlocked
	node.DisabledLinks = disabledLinks
	node.IPV4 = ipv4
	node.IPV6 = ipv6

	// 解析 Region
	if GlobalGeoIP != nil {
		region := ""
		if ipv4 != "" {
			region = GlobalGeoIP.GetCountryIsoCode(ipv4)
		}
		if region == "" && ipv6 != "" {
			region = GlobalGeoIP.GetCountryIsoCode(ipv6)
		}
		// 如果解析到了，就更新；如果没解析到但IP变空了，可能需要清空 region？
		// 这里策略是：只要解析出有效代码就覆盖，否则保留原样
		if region != "" {
			node.Region = region
			logger.Log.Debug("服务层: 节点 GeoIP 区域自动匹配成功", "uuid", uuid, "region", region)
		}
	}

	if err := database.DB.Save(&node).Error; err != nil {
		logger.Log.Error("服务层异常: 保存节点更新失败", "error", err, "uuid", uuid)
		return err
	}

	logger.Log.Debug("服务层: 节点数据更新成功", "uuid", uuid)
	return nil
}

// ReorderNodes 批量更新节点的路由类型和排序索引
func ReorderNodes(routingType int, uuids []string) error {
	err := database.DB.Transaction(func(tx *gorm.DB) error {
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

	if err != nil {
		logger.Log.Error("服务层异常: 批量重排节点事务提交失败", "error", err, "routing_type", routingType)
		return err
	}
	return nil
}

// generateRandomString 生成指定长度的随机字母数字字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		logger.Log.Warn("生成随机字符串失败，使用回退值", "error", err)
		return "fallback"
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// generateSocks5User 根据配置决定返回默认用户名还是随机用户名
func generateSocks5User(configMap map[string]string) string {
	if strings.EqualFold(strings.TrimSpace(configMap["proxy_socks5_random_auth"]), "true") {
		return "s5_" + generateRandomString(8)
	}
	return configMap["proxy_socks5_user"]
}

// generateSocks5Pass 根据配置决定返回默认密码还是随机密码
func generateSocks5Pass(configMap map[string]string) string {
	if strings.EqualFold(strings.TrimSpace(configMap["proxy_socks5_random_auth"]), "true") {
		return generateRandomString(16)
	}
	return configMap["proxy_socks5_pass"]
}

// RenderInstallScript 渲染安装脚本 (只填充静态端口配置)
func RenderInstallScript(node database.NodePool) (string, error) {
	var configs []database.SysConfig
	if err := database.DB.Find(&configs).Error; err != nil {
		logger.Log.Error("服务层异常: 渲染脚本时读取配置失败", "error", err)
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
		// 去除面板 URL 末尾可能存在的所有斜杠，防止拼接出双斜杠
		cleanPanelURL := strings.TrimRight(panelURL, "/")
		reportURL = cleanPanelURL + "/api/callback/report"
	}

	// 拼接 Agent WebSocket 上报地址
	agentWSURL := ""
	if panelURL != "" {
		cleanPanelURL := strings.TrimRight(panelURL, "/")
		// http → ws, https → wss
		wsURL := cleanPanelURL
		wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
		wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
		agentWSURL = wsURL + "/api/callback/traffic/ws"
	}

	// Agent 下载地址（GitHub Releases，含架构占位符供脚本 sed 替换）
	// 注意：使用 __ARCH__ 而非 ${ARCH_NAME}，避免 bash 双引号赋值时提前展开为空
	agentDownloadURL := "https://github.com/hobin66/nodectl/releases/latest/download/nodectl-agent-linux-__ARCH__"

	// Agent 配置参数（从 sys_config 读取，提供默认值）
	agentWSPushInterval := configMap["agent_ws_push_interval_sec"]
	if agentWSPushInterval == "" {
		agentWSPushInterval = "2"
	}

	// 读取可配置 SNI，提供兜底默认值
	hy2SNI := configMap["proxy_hy2_sni"]
	if hy2SNI == "" {
		hy2SNI = "www.bing.com"
	}
	tuicSNI := configMap["proxy_tuic_sni"]
	if tuicSNI == "" {
		tuicSNI = "www.bing.com"
	}
	enableBBR := configMap["proxy_enable_bbr"]
	if enableBBR == "" {
		enableBBR = "true"
	}
	portTrojan := configMap["proxy_port_trojan"]
	if portTrojan == "" {
		portTrojan = "20006"
	}
	portVmessTCP := configMap["proxy_port_vmess_tcp"]
	if portVmessTCP == "" {
		portVmessTCP = "20008"
	}
	portVmessWS := configMap["proxy_port_vmess_ws"]
	if portVmessWS == "" {
		portVmessWS = "20009"
	}
	portVmessHTTP := configMap["proxy_port_vmess_http"]
	if portVmessHTTP == "" {
		portVmessHTTP = "20010"
	}
	portVmessQUIC := configMap["proxy_port_vmess_quic"]
	if portVmessQUIC == "" {
		portVmessQUIC = "20011"
	}
	portVmessWST := configMap["proxy_port_vmess_wst"]
	if portVmessWST == "" {
		portVmessWST = "20012"
	}
	portVmessHUT := configMap["proxy_port_vmess_hut"]
	if portVmessHUT == "" {
		portVmessHUT = "20014"
	}
	portVlessWST := configMap["proxy_port_vless_wst"]
	if portVlessWST == "" {
		portVlessWST = "20015"
	}
	portVlessHUT := configMap["proxy_port_vless_hut"]
	if portVlessHUT == "" {
		portVlessHUT = "20017"
	}
	portTrojanWST := configMap["proxy_port_trojan_wst"]
	if portTrojanWST == "" {
		portTrojanWST = "20018"
	}
	portTrojanHUT := configMap["proxy_port_trojan_hut"]
	if portTrojanHUT == "" {
		portTrojanHUT = "20020"
	}
	tlsTransportPath := configMap["proxy_tls_transport_path"]
	if tlsTransportPath == "" {
		tlsTransportPath = "/ray"
	}
	vmessTLSSNI := configMap["proxy_vmess_tls_sni"]
	if vmessTLSSNI == "" {
		vmessTLSSNI = "www.bing.com"
	}
	vlessTLSSNI := configMap["proxy_vless_tls_sni"]
	if vlessTLSSNI == "" {
		vlessTLSSNI = "www.bing.com"
	}
	trojanTLSSNI := configMap["proxy_trojan_tls_sni"]
	if trojanTLSSNI == "" {
		trojanTLSSNI = "www.bing.com"
	}

	data := map[string]string{
		"PortSS":      configMap["proxy_port_ss"],
		"PortHY2":     configMap["proxy_port_hy2"],
		"PortTUIC":    configMap["proxy_port_tuic"],
		"PortReality": configMap["proxy_port_reality"],
		"RealitySNI":  vlessTLSSNI,
		"SSMethod":    configMap["proxy_ss_method"],
		"PortSocks5":  configMap["proxy_port_socks5"],
		"Socks5User":  generateSocks5User(configMap),
		"Socks5Pass":  generateSocks5Pass(configMap),
		// 新增协议端口
		"PortTrojan": portTrojan,
		// 可配置 SNI
		"HY2SNI":    hy2SNI,
		"TUICSNI":   tuicSNI,
		"TrojanSNI": trojanTLSSNI,
		// 系统优化
		"EnableBBR": enableBBR,
		// VMess 族端口
		"PortVmessTCP":  portVmessTCP,
		"PortVmessWS":   portVmessWS,
		"PortVmessHTTP": portVmessHTTP,
		"PortVmessQUIC": portVmessQUIC,
		// VMess+TLS 传输族端口
		"PortVmessWST": portVmessWST,
		"PortVmessHUT": portVmessHUT,
		// VLESS-TLS 传输族端口
		"PortVlessWST": portVlessWST,
		"PortVlessHUT": portVlessHUT,
		// Trojan-TLS 传输族端口
		"PortTrojanWST": portTrojanWST,
		"PortTrojanHUT": portTrojanHUT,
		// TLS 传输共用路径
		"TLSTransportPath": tlsTransportPath,
		"VmessTLSSNI":      vmessTLSSNI,
		"VlessTLSSNI":      vlessTLSSNI,
		"TrojanTLSSNI":     trojanTLSSNI,
		"ReportURL":        reportURL,
		// [新增] 将节点专属参数硬编码注入到脚本中
		"InstallID": node.InstallID,
		// [新增] Agent 相关模板变量
		"AgentDownloadURL":       agentDownloadURL,
		"AgentWSURL":             agentWSURL,
		"AgentWSPushIntervalSec": agentWSPushInterval,
	}

	tplContent := SingboxScriptTpl // 默认使用打包在二进制里的 embed 模板

	// 定义外部调试模板的路径 (data/debug/singbox.tpl)
	debugPath := filepath.Join("data", "debug", "singbox.tpl")

	// 尝试读取外部文件
	if content, err := os.ReadFile(debugPath); err == nil {
		tplContent = string(content)
		logger.Log.Info("【调试模式】已拦截并使用外部安装模板", "path", debugPath)
	}

	// 解析最终决定的模板内容
	tmpl, err := template.New("install_script").Parse(tplContent)
	if err != nil {
		logger.Log.Error("服务层异常: 安装脚本模板语法解析失败", "error", err)
		return "", fmt.Errorf("解析脚本模板失败: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		logger.Log.Error("服务层异常: 注入数据渲染脚本失败", "error", err)
		return "", fmt.Errorf("渲染脚本失败: %v", err)
	}

	// 统一安装脚本换行符为 LF，避免在部分环境中因 CRLF 导致 bash 解析异常
	script := strings.ReplaceAll(buf.String(), "\r\n", "\n")
	script = strings.ReplaceAll(script, "\r", "\n")

	return script, nil
}
