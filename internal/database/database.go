package database

import (
	"crypto/rand"
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
	UUID        string            `gorm:"primaryKey;column:uuid;type:varchar(36)" json:"uuid"`
	InstallID   string            `gorm:"column:install_id;type:varchar(16);uniqueIndex" json:"install_id"`
	Name        string            `gorm:"column:name" json:"name"`
	RoutingType int               `gorm:"column:routing_type;default:1" json:"routing_type"` //路由类型
	Links       map[string]string `gorm:"column:links;serializer:json" json:"links"`
	IPV4        string            `gorm:"column:ipv4;type:varchar(15)" json:"ipv4"`
	IPV6        string            `gorm:"column:ipv6;type:varchar(45)" json:"ipv6"`
	Region      string            `gorm:"column:region" json:"region"`                   //存储国家信息
	SortIndex   int               `gorm:"column:sort_index;default:0" json:"sort_index"` //排序
	Remark      string            `gorm:"column:remark" json:"remark"`                   //备注
	CreatedAt   time.Time         `gorm:"column:created_at" json:"created_at"`
	UpdatedAt   time.Time         `gorm:"column:updated_at" json:"updated_at"`
}

func (NodePool) TableName() string {
	return "node_pool"
}

func (n *NodePool) BeforeCreate(tx *gorm.DB) (err error) {
	if n.UUID == "" {
		n.UUID = uuid.New().String()
	}
	if n.InstallID == "" {
		n.InstallID = generateSecureRandomID(16)
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

// ------------------- [数据库初始化] -------------------

// InitDB 初始化数据库连接并同步表结构
func InitDB() {
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
		&SysConfig{}, // 写入新的配置表
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
