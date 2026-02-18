package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	"gopkg.in/yaml.v3"
)

// ClashProvider 是用于生成 0.yaml / 1.yaml 的根结构
type ClashProvider struct {
	Proxies []*ClashNode `yaml:"proxies"`
}

// GenerateRawNodesYAML 动态生成指定路由类型的节点 YAML
// routingType: 1=直连, 2=落地
func GenerateRawNodesYAML(routingType int, useFlag bool) (string, error) {
	var nodes []database.NodePool
	// 按照 SortIndex 排序获取节点
	if err := database.DB.Where("routing_type = ? AND is_blocked = ?", routingType, false).
		Order("sort_index ASC").Find(&nodes).Error; err != nil {
		logger.Log.Error("从数据库获取 Raw 节点列表失败", "error", err, "routing_type", routingType)
		return "", err
	}

	var strategyConfig database.SysConfig
	database.DB.Where("key = ?", "pref_ip_strategy").First(&strategyConfig)
	ipStrategy := strategyConfig.Value
	if ipStrategy == "" {
		ipStrategy = "ipv4_prefer"
	}

	var proxyList []*ClashNode

	for _, node := range nodes {
		ipOptions := determineIPs(node, ipStrategy)

		for proto, link := range node.Links {
			if contains(node.DisabledLinks, proto) {
				continue
			}

			// 根据 IP 策略可能生成 1 个，也可能生成 2 个(双栈)，也可能跳过(0个)
			for _, ipOpt := range ipOptions {
				baseName := fmt.Sprintf("%s-%s%s", strings.ToLower(proto), node.Name, ipOpt.Suffix)
				proxyNode := ParseProxyLink(link, baseName, node.Region, useFlag)
				if proxyNode != nil {
					if ipOpt.IP != "" {
						proxyNode.Server = ipOpt.IP // 覆盖 Clash 解析后的 Server IP
					}
					proxyList = append(proxyList, proxyNode)
				}
			}
		}
	}

	// [新增修复逻辑] ---------------------------------------------------------
	// 如果遍历完数据库后，proxyList 依然为空（说明用户没配节点，或节点都被禁用了）
	// 强制插入一个 "直连" 类型的占位节点，防止客户端报错，并实现自动直连
	if len(proxyList) == 0 {
		var name string
		if routingType == 1 {
			name = "⚠️ 无中转-自动直连"
		} else {
			name = "⚠️ 无落地-自动直连"
		}

		fallbackNode := &ClashNode{
			Name:              name,
			Type:              "direct", // 使用 direct 类型，Clash 会将其视为直连
			UDP:               true,
			ClientFingerprint: "chrome", // 随便带个指纹让它看起来更像正常节点
		}
		proxyList = append(proxyList, fallbackNode)
	}

	provider := ClashProvider{Proxies: proxyList}

	// 1. 使用 Encoder 设置缩进为 2 空格 (解决默认4空格的问题)
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&provider); err != nil {
		logger.Log.Error("YAML 序列化节点数据失败", "error", err, "routing_type", routingType)
		return "", err
	}
	encoder.Close()

	// 2. 修复 yaml.v3 的 Emoji \Uxxxxxxxx 转义以及双引号问题
	yamlStr := buf.String()

	// 正则匹配 \U0001F1ED 这种 8 位的 Unicode 逃义符并将其转换回真实的 Emoji
	re := regexp.MustCompile(`\\U([0-9A-Fa-f]{8})`)
	yamlStr = re.ReplaceAllStringFunc(yamlStr, func(s string) string {
		// s 格式为 "\U0001F1ED"，提取后面的 16 进制部分
		code, _ := strconv.ParseInt(s[2:], 16, 32)
		return string(rune(code))
	})

	logger.Log.Debug("Raw 节点 YAML 组装完成", "routing_type", routingType, "proxy_count", len(proxyList))
	return yamlStr, nil
}

// 辅助函数：检查切片是否包含某个元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GenerateV2RaySubBase64 生成通用 Base64 订阅 (包含直连和落地)
func GenerateV2RaySubBase64(useFlag bool) (string, error) {
	var nodes []database.NodePool
	// 取出直连(1)和落地(2)的节点，排除被屏蔽的
	if err := database.DB.Where("routing_type IN ? AND is_blocked = ?", []int{1, 2}, false).
		Order("sort_index ASC").Find(&nodes).Error; err != nil {
		logger.Log.Error("从数据库获取全量聚合节点失败", "error", err)
		return "", err
	}

	var strategyConfig database.SysConfig
	database.DB.Where("key = ?", "pref_ip_strategy").First(&strategyConfig)
	ipStrategy := strategyConfig.Value
	if ipStrategy == "" {
		ipStrategy = "ipv4_prefer"
	}

	var lines []string

	for _, node := range nodes {
		ipOptions := determineIPs(node, ipStrategy)

		for proto, link := range node.Links {
			if contains(node.DisabledLinks, proto) {
				continue
			}

			for _, ipOpt := range ipOptions {
				baseName := fmt.Sprintf("%s-%s%s", strings.ToLower(proto), node.Name, ipOpt.Suffix)
				finalName := baseName
				if useFlag && node.Region != "" {
					flag := getEmojiFlag(node.Region)
					finalName = fmt.Sprintf("%s %s", flag, strings.ReplaceAll(baseName, flag, ""))
				}
				finalName = strings.TrimSpace(finalName)
				safeName := strings.ReplaceAll(url.QueryEscape(finalName), "+", "%20")

				cleanLink := strings.Split(link, "#")[0]

				// 核心：使用刚才写的替换引擎，重构链接
				targetLink := ReplaceLinkIP(cleanLink, ipOpt.IP)

				lines = append(lines, fmt.Sprintf("%s#%s", targetLink, safeName))
			}
		}
	}

	// 用换行符拼接并进行 Base64 编码
	rawStr := strings.Join(lines, "\n")
	b64Str := base64.StdEncoding.EncodeToString([]byte(rawStr))

	logger.Log.Debug("V2Ray Base64 订阅组装完成", "link_count", len(lines))
	return b64Str, nil
}

type IPOption struct {
	IP     string
	Suffix string // 用于双栈分离时给节点名加后缀
}

// determineIPs 根据策略计算应该生成哪些 IP
func determineIPs(node database.NodePool, strategy string) []IPOption {
	hasV4 := node.IPV4 != ""
	hasV6 := node.IPV6 != ""

	if !hasV4 && !hasV6 {
		return []IPOption{{IP: "", Suffix: ""}} // 无IP记录，使用原链接IP
	}

	var ips []IPOption
	switch strategy {
	case "ipv4_only":
		if hasV4 {
			ips = append(ips, IPOption{IP: node.IPV4, Suffix: ""})
		}
	case "ipv6_only":
		if hasV6 {
			ips = append(ips, IPOption{IP: node.IPV6, Suffix: ""})
		}
	case "dual_stack":
		if hasV4 && hasV6 {
			ips = append(ips, IPOption{IP: node.IPV4, Suffix: "-V4"})
			ips = append(ips, IPOption{IP: node.IPV6, Suffix: "-V6"})
		} else if hasV4 {
			ips = append(ips, IPOption{IP: node.IPV4, Suffix: ""})
		} else if hasV6 {
			ips = append(ips, IPOption{IP: node.IPV6, Suffix: ""})
		}
	case "ipv6_prefer":
		if hasV6 {
			ips = append(ips, IPOption{IP: node.IPV6, Suffix: ""})
		} else if hasV4 {
			ips = append(ips, IPOption{IP: node.IPV4, Suffix: ""})
		}
	default: // ipv4_prefer
		if hasV4 {
			ips = append(ips, IPOption{IP: node.IPV4, Suffix: ""})
		} else if hasV6 {
			ips = append(ips, IPOption{IP: node.IPV6, Suffix: ""})
		}
	}
	return ips
}

// ParseProxyLink 解析链接并强制覆盖合并后的完美名称
func ParseProxyLink(link string, baseName string, region string, useFlag bool) *ClashNode {
	finalName := baseName
	if useFlag && region != "" {
		flag := getEmojiFlag(region)
		if flag != "" {
			finalName = flag + " " + finalName
		}
	}

	// 调用 links.go 里的核心解析函数
	node := ParseLinkToClashNode(link, "")
	if node != nil {
		node.Name = finalName // 直接强行覆盖为组合好的名字
	}
	return node
}

// getEmojiFlag 根据 2 位国家/地区代码智能生成 Emoji 国旗
func getEmojiFlag(region string) string {
	if len(region) != 2 {
		return ""
	}
	region = strings.ToUpper(region)
	flag := ""
	for _, char := range region {
		// A 的 ASCII 码是 65，区域指示符 A 是 127462 (0x1F1E6)
		// 127462 - 65 = 127397 (这就是精确的偏移量)
		flag += string(rune(char) + 127397)
	}
	return flag
}

// ReplaceLinkIP 安全替换标准 URI 链接中的 IP / 域名 (不破坏端口和其他参数)
func ReplaceLinkIP(link string, newIP string) string {
	if newIP == "" {
		return link
	}
	u, err := url.Parse(link)
	if err != nil || u.Host == "" {
		return link // 解析失败或极其特殊的格式，原样返回防报错
	}

	port := u.Port()
	if port != "" {
		u.Host = newIP + ":" + port
	} else {
		u.Host = newIP
	}

	return u.String()
}

// ---------------------------------------------------------
// 节点重命名引擎
// ---------------------------------------------------------

// RenameNodeLink 修改节点分享链接的名字后缀 (#name)
// 智能重命名引擎：已支持解析各种 Base64 嵌套进行安全重命名
func RenameNodeLink(link string, newName string) string {
	lowerLink := strings.ToLower(link)

	// 处理 VMess (JSON 修改并重新 Base64 编码)
	if strings.HasPrefix(lowerLink, "vmess://") {
		body := safeBase64Decode(link[8:])
		if body == "" {
			return link
		}
		var vj map[string]interface{}
		if err := json.Unmarshal([]byte(body), &vj); err == nil {
			vj["ps"] = newName
			if newBody, err := json.Marshal(vj); err == nil {
				return "vmess://" + base64.StdEncoding.EncodeToString(newBody)
			}
		}
		return link
	}

	// 处理 SSR (复杂查询参数和 Base64 编码)
	if strings.HasPrefix(lowerLink, "ssr://") {
		decoded := safeBase64Decode(link[6:])
		if decoded == "" {
			return link
		}
		// SSR 格式: host:port:protocol:method:obfs:base64pass/?obfsparam=...&remarks=base64(name)
		if strings.Contains(decoded, "remarks=") {
			parts := strings.Split(decoded, "remarks=")
			prefix := parts[0]
			suffix := parts[1]
			// 去掉旧的 remarks 值 (直到下一个 & 或结尾)
			if idx := strings.Index(suffix, "&"); idx != -1 {
				suffix = suffix[idx:]
			} else {
				suffix = ""
			}
			newDecoded := prefix + "remarks=" + base64.RawURLEncoding.EncodeToString([]byte(newName)) + suffix
			return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(newDecoded))
		}
		// 如果没有 remarks 参数，追加上去
		sep := "/?"
		if strings.Contains(decoded, "/?") {
			sep = "&"
		}
		newDecoded := decoded + sep + "remarks=" + base64.RawURLEncoding.EncodeToString([]byte(newName))
		return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(newDecoded))
	}

	// 处理 SS 纯 Base64 格式的特殊情况
	if strings.HasPrefix(lowerLink, "ss://") {
		u, err := url.Parse(link)
		if err != nil || u.Host == "" {
			encoded := strings.TrimPrefix(link, "ss://")
			hashIdx := strings.LastIndex(encoded, "#")
			if hashIdx != -1 {
				encoded = encoded[:hashIdx]
			}
			return "ss://" + encoded + "#" + url.PathEscape(newName)
		}
		u.Fragment = newName
		return u.String()
	}

	// 处理其他标准 URI 格式协议 (包含新增的 anytls)
	if strings.HasPrefix(lowerLink, "vless://") ||
		strings.HasPrefix(lowerLink, "trojan://") ||
		strings.HasPrefix(lowerLink, "hy2://") ||
		strings.HasPrefix(lowerLink, "hysteria2://") ||
		strings.HasPrefix(lowerLink, "hy://") ||
		strings.HasPrefix(lowerLink, "hysteria://") ||
		strings.HasPrefix(lowerLink, "tuic://") ||
		strings.HasPrefix(lowerLink, "socks5://") ||
		strings.HasPrefix(lowerLink, "anytls://") ||
		strings.HasPrefix(lowerLink, "http://") ||
		strings.HasPrefix(lowerLink, "https://") {
		u, err := url.Parse(link)
		if err == nil {
			u.Fragment = newName
			return u.String()
		}
	}

	return link
}
