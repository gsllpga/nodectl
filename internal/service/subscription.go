package service

import (
	"fmt"
	"nodectl/internal/database"
	"strings"

	"gopkg.in/yaml.v3"
)

// [修改这里] 将 map 替换为严格结构体 *ClashNode
type ClashProvider struct {
	Proxies []*ClashNode `yaml:"proxies"`
}

func GenerateRawNodesYAML(routingType int, useFlag bool) (string, error) {
	var nodes []database.NodePool
	if err := database.DB.Where("routing_type = ? AND is_blocked = ?", routingType, false).
		Order("sort_index ASC").Find(&nodes).Error; err != nil {
		return "", err
	}

	// [修改这里] 同步替换类型
	var proxyList []*ClashNode

	for _, node := range nodes {
		for proto, link := range node.Links {
			if contains(node.DisabledLinks, proto) {
				continue
			}

			baseName := fmt.Sprintf("%s-%s", strings.ToLower(proto), node.Name)

			// 现在的 proxyNode 已经是 *ClashNode 结构体类型
			proxyNode := ParseProxyLink(link, baseName, node.Region, useFlag)
			if proxyNode != nil {
				proxyList = append(proxyList, proxyNode)
			}
		}
	}

	provider := ClashProvider{Proxies: proxyList}

	yamlBytes, err := yaml.Marshal(&provider)
	if err != nil {
		return "", err
	}

	return string(yamlBytes), nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
