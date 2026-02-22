package database

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"time"

	"nodectl/internal/logger"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// DB 全局数据库实例
var DB *gorm.DB

// ------------------- [模型定义区] -------------------

// NodePool 节点池表
type NodePool struct {
	UUID            string            `gorm:"primaryKey;column:uuid;type:varchar(36)" json:"uuid"`
	InstallID       string            `gorm:"column:install_id;type:varchar(8);uniqueIndex" json:"install_id"`
	Name            string            `gorm:"column:name" json:"name"`
	RoutingType     int               `gorm:"column:routing_type;default:1" json:"routing_type"` //路由类型
	IsBlocked       bool              `gorm:"column:is_blocked;default:false" json:"is_blocked"` // 是否屏蔽
	Links           map[string]string `gorm:"column:links;serializer:json" json:"links"`
	LinkIPModes     map[string]int    `gorm:"column:link_ip_modes;serializer:json" json:"link_ip_modes"` //协议级别的IP生成模式
	DisabledLinks   []string          `gorm:"column:disabled_links;serializer:json" json:"disabled_links"`
	IPV4            string            `gorm:"column:ipv4;type:varchar(15)" json:"ipv4"`
	IPV6            string            `gorm:"column:ipv6;type:varchar(45)" json:"ipv6"`
	Region          string            `gorm:"column:region" json:"region"`                         //存储国家信息
	IPMode          int               `gorm:"column:ip_mode;default:0" json:"ip_mode"`             // 0: 跟随系统, 1: 仅IPv4, 2: 仅IPv6, 3: 双栈
	SortIndex       int               `gorm:"column:sort_index;default:0" json:"sort_index"`       //排序
	Remark          string            `gorm:"column:remark" json:"remark"`                         //备注
	TrafficUp       int64             `gorm:"column:traffic_up;default:0" json:"traffic_up"`       // 本周期上传流量 (Bytes)
	TrafficDown     int64             `gorm:"column:traffic_down;default:0" json:"traffic_down"`   // 本周期下载流量 (Bytes)
	TrafficLimit    int64             `gorm:"column:traffic_limit;default:0" json:"traffic_limit"` // 总流量限额 (Bytes, 0表示不限制)
	ResetDay        int               `gorm:"column:reset_day;default:0" json:"reset_day"`         // 每月重置日 (1-31, 0表示不重置)
	TrafficUpdateAt *time.Time        `gorm:"column:traffic_update_at" json:"traffic_update_at"`   // 流量更新时间
	CreatedAt       time.Time         `gorm:"column:created_at" json:"created_at"`
	UpdatedAt       time.Time         `gorm:"column:updated_at" json:"updated_at"`
}

func (NodePool) TableName() string {
	return "node_pool"
}

func (n *NodePool) BeforeCreate(tx *gorm.DB) (err error) {
	if n.UUID == "" {
		n.UUID = uuid.New().String()
	}
	if n.InstallID == "" {
		n.InstallID = generateSecureRandomID(8)
	}
	return
}

func generateSecureRandomID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate secure random id: " + err.Error())
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// SysConfig 系统全局配置表 (Key-Value 设计)
type SysConfig struct {
	Key         string    `gorm:"primaryKey;column:key;type:varchar(64)" json:"key"`
	Value       string    `gorm:"column:value;type:text" json:"value"`
	Description string    `gorm:"column:description;type:varchar(255)" json:"description"`
	UpdatedAt   time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (SysConfig) TableName() string {
	return "sys_config"
}

// ------------------- 机场订阅相关模型] -------------------

// AirportSub 机场订阅源表
type AirportSub struct {
	ID        string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
	Name      string    `gorm:"type:varchar(64)" json:"name"` // 机场名称
	URL       string    `gorm:"type:text" json:"url"`         // 订阅链接
	Upload    int64     `gorm:"default:0" json:"upload"`      // 已用上行 (Bytes)
	Download  int64     `gorm:"default:0" json:"download"`    // 已用下行 (Bytes)
	Total     int64     `gorm:"default:0" json:"total"`       // 总流量 (Bytes)
	Expire    int64     `gorm:"default:0" json:"expire"`      // 到期时间戳
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (AirportSub) TableName() string {
	return "airport_subs"
}

func (s *AirportSub) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}

// AirportNode 机场节点表 (关联 AirportSub)
type AirportNode struct {
	ID            string `gorm:"primaryKey;type:varchar(36)" json:"id"`
	SubID         string `gorm:"index;type:varchar(36)" json:"sub_id"` // 外键关联 AirportSub
	Name          string `gorm:"index" json:"name"`                    // 节点名称
	Protocol      string `gorm:"type:varchar(32)" json:"protocol"`     // 协议类型 (新增)
	Link          string `gorm:"type:text" json:"link"`                // 原始链接 (vmess://, ss:// 等)
	RoutingType   int    `gorm:"default:0" json:"routing_type"`        // 0=不启用, 1=直连, 2=落地
	OriginalIndex int    `gorm:"default:0" json:"original_index"`      // 原始排序索引
}

func (AirportNode) TableName() string {
	return "airport_nodes"
}

func (n *AirportNode) BeforeCreate(tx *gorm.DB) (err error) {
	if n.ID == "" {
		n.ID = uuid.New().String()
	}
	return
}

// ------------------- 数据库初始化 -------------------

// InitDB 初始化数据库连接并同步表结构
func InitDB() {

	if err := os.MkdirAll("data", os.ModePerm); err != nil {
		logger.Log.Error("创建 data 目录失败", "err", err.Error())
		panic("目录初始化失败")
	}
	dbPath := filepath.Join("data", "nodectl.db")

	// 1. 打开 SQLite 数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		logger.Log.Error("连接 nodectl.db 失败", "err", err.Error())
		panic("数据库连接失败")
	}

	// 2. 配置 SQLite 的连接池
	sqlDB, err := db.DB()
	if err != nil {
		logger.Log.Error("获取底层 sql.DB 失败", "err", err.Error())
		panic(err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// 3. 自动迁移所有的表
	err = db.AutoMigrate(
		&NodePool{},
		&SysConfig{},
		&AirportSub{},
		&AirportNode{},
	)
	if err != nil {
		logger.Log.Error("自动同步表结构失败", "err", err.Error())
		panic("数据库表结构迁移失败")
	}

	// 4. 赋值给全局变量
	DB = db

	// 5. 调用外部模块初始化默认系统设置
	initDefaultConfigs()

	logger.Log.Info("数据库初始化成功，表结构已同步", "path", dbPath)
}
