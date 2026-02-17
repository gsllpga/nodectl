package database

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"nodectl/internal/logger"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SupportedProtocols 定义系统支持的节点协议列表 (全局变量，供前端和逻辑使用)
var SupportedProtocols = []string{"vless", "hy2", "socks", "tuic", "ss"}

// initDefaultConfigs 初始化默认的系统配置参数
func initDefaultConfigs() {
	// 1. 初始化普通基础设置
	initBasicSettings()

	// 2. 初始化核心安全设置 (加密密钥、默认账号密码)
	initAuthSettings()

	// 3. 初始化singbox安装脚本模板参数
	initProxySettings()
}

func initBasicSettings() {
	// 生成一个随机的 32 位 Hex 字符串作为默认的订阅 Token
	secureBytes := make([]byte, 16)
	rand.Read(secureBytes)
	defaultToken := hex.EncodeToString(secureBytes)

	defaultConfigs := []SysConfig{
		{Key: "panel_url", Value: "", Description: "面板外部访问地址"},
		{Key: "sub_token", Value: defaultToken, Description: "订阅访问 Token"},
		// [新增] 初始化 Clash 分流规则的存储 Key
		{Key: "clash_active_modules", Value: "", Description: "Clash 分流规则启用列表"},
		{Key: "pref_use_emoji_flag", Value: "true", Description: "订阅节点是否添加国旗前缀"},
		{Key: "sub_custom_name", Value: "NodeCTL", Description: "自定义订阅名称"},
		{Key: "geo_db_version", Value: "", Description: "GeoIP 数据库版本号"},
		{Key: "pref_ip_strategy", Value: "ipv4_prefer", Description: "节点IP生成策略"},
	}

	for _, config := range defaultConfigs {
		if err := DB.Where(SysConfig{Key: config.Key}).FirstOrCreate(&config).Error; err != nil {
			logger.Log.Error("初始化普通配置失败", "key", config.Key, "err", err.Error())
		}
	}
}

func initAuthSettings() {
	// 1. 初始化随机加密密钥 (JWT Secret / Session Key)
	var secretConfig SysConfig
	err := DB.Where("key = ?", "jwt_secret").First(&secretConfig).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 只有当密钥不存在时才生成
		secureBytes := make([]byte, 32)
		if _, err := rand.Read(secureBytes); err != nil {
			panic("无法生成安全随机密钥: " + err.Error())
		}
		randomSecret := hex.EncodeToString(secureBytes)

		DB.Create(&SysConfig{
			Key:         "jwt_secret",
			Value:       randomSecret,
			Description: "系统核心加密密钥 (请勿泄露)",
		})
		logger.Log.Info("已生成全新的系统加密密钥")
	}

	// 2. 初始化默认管理员账号和密码
	var adminUser SysConfig
	err = DB.Where("key = ?", "admin_username").First(&adminUser).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 生成 bcrypt 哈希密码 (默认密码设为 admin)
		defaultPassword := "admin"
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
		if err != nil {
			panic("默认密码加密失败: " + err.Error())
		}

		// 存入用户名
		DB.Create(&SysConfig{Key: "admin_username", Value: "admin", Description: "管理员登录账号"})
		// 存入密码哈希值
		DB.Create(&SysConfig{Key: "admin_password", Value: string(hashedPassword), Description: "管理员密码(Bcrypt加密)"})

		logger.Log.Warn("已创建默认管理员账号！", "用户名", "admin", "密码", "admin", "提示", "请登录后尽快修改！")
	}
}

func initProxySettings() {
	defaultConfigs := []SysConfig{
		{Key: "proxy_port_ss", Value: "20001", Description: "SS 默认监听端口"},
		{Key: "proxy_port_hy2", Value: "20002", Description: "HY2 默认监听端口"},
		{Key: "proxy_port_tuic", Value: "20003", Description: "TUIC 默认监听端口"},
		{Key: "proxy_port_reality", Value: "20004", Description: "Reality 默认监听端口"},
		{Key: "proxy_reality_sni", Value: "learn.microsoft.com", Description: "Reality 默认 SNI 域名"},
		{Key: "proxy_ss_method", Value: "aes-128-gcm", Description: "SS 默认加密方式"},
		{Key: "proxy_port_socks5", Value: "20005", Description: "Socks5 默认监听端口"},
		{Key: "proxy_socks5_user", Value: "admin", Description: "Socks5 默认用户名"},
		{Key: "proxy_socks5_pass", Value: "123456", Description: "Socks5 默认密码"},
	}

	for _, config := range defaultConfigs {
		if err := DB.Where(SysConfig{Key: config.Key}).FirstOrCreate(&config).Error; err != nil {
			logger.Log.Error("初始化代理配置失败", "key", config.Key, "err", err.Error())
		}
	}
}
