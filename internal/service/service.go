package service

import (
	"crypto/rand"
	"fmt"
	"nodectl/internal/database"
)

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
