package service

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"nodectl/internal/database"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ClashProvider 是用于生成 0.yaml / 1.yaml 的根结构
// [修复] 将原先的 map 替换为严格结构体 *ClashNode
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
		return "", err
	}

	var proxyList []*ClashNode

	for _, node := range nodes {
		for proto, link := range node.Links {
			// 如果该协议被禁用，跳过
			if contains(node.DisabledLinks, proto) {
				continue
			}

			// 构造统一的前缀名 (例如 ss-香港节点)
			baseName := fmt.Sprintf("%s-%s", strings.ToLower(proto), node.Name)

			// 调用链接解析器，返回的已经是严格结构体指针 *ClashNode
			proxyNode := ParseProxyLink(link, baseName, node.Region, useFlag)
			if proxyNode != nil {
				proxyList = append(proxyList, proxyNode)
			}
		}
	}

	provider := ClashProvider{Proxies: proxyList}

	// 1. 使用 Encoder 设置缩进为 2 空格 (解决默认4空格的问题)
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&provider); err != nil {
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

// [新增] GenerateV2RaySubBase64 生成通用 Base64 订阅 (包含直连和落地)
func GenerateV2RaySubBase64(useFlag bool) (string, error) {
	var nodes []database.NodePool
	// 取出直连(1)和落地(2)的节点，排除被屏蔽的
	if err := database.DB.Where("routing_type IN ? AND is_blocked = ?", []int{1, 2}, false).
		Order("sort_index ASC").Find(&nodes).Error; err != nil {
		return "", err
	}

	var lines []string

	for _, node := range nodes {
		for proto, link := range node.Links {
			if contains(node.DisabledLinks, proto) {
				continue
			}

			// 构造名称 (同 Clash 逻辑)
			baseName := fmt.Sprintf("%s-%s", strings.ToLower(proto), node.Name)
			finalName := baseName
			if useFlag && node.Region != "" {
				flag := getEmojiFlag(node.Region)
				finalName = fmt.Sprintf("%s %s", flag, strings.ReplaceAll(baseName, flag, ""))
			}
			finalName = strings.TrimSpace(finalName)

			// V2ray/通用格式要求节点名称附带在 # 之后，并进行 URL 编码
			// 注意：Go 的 QueryEscape 会把空格转成 +，而客户端更标准的是识别 %20
			safeName := strings.ReplaceAll(url.QueryEscape(finalName), "+", "%20")

			// 去除原始链接中可能带有的旧名称 (#xxx)
			cleanLink := strings.Split(link, "#")[0]

			lines = append(lines, fmt.Sprintf("%s#%s", cleanLink, safeName))
		}
	}

	// 用换行符拼接并进行 Base64 编码
	rawStr := strings.Join(lines, "\n")
	b64Str := base64.StdEncoding.EncodeToString([]byte(rawStr))

	return b64Str, nil
}
