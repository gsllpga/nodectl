package service

import (
	"bytes"
	"encoding/base64"
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
