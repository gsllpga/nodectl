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
var SupportedProtocols = []string{
	"vless", "hy2", "socks5", "tuic", "ss", "trojan", "vless_h2",
	"vmess_tcp", "vmess_ws", "vmess_http", "vmess_quic",
	"vmess_wst", "vmess_h2t", "vmess_hut",
	"vless_wst", "vless_h2t", "vless_hut",
	"trojan_wst", "trojan_h2t", "trojan_hut",
}

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
		// 初始化 Clash 分流规则的存储 Key
		{Key: "clash_active_modules", Value: "", Description: "Clash 分流规则启用列表"},
		{Key: "pref_use_emoji_flag", Value: "true", Description: "订阅节点是否添加国旗前缀"},
		{Key: "sub_custom_name", Value: "NodeCTL", Description: "自定义订阅名称"},
		{Key: "geo_db_version", Value: "", Description: "GeoIP 数据库版本号"},
		{Key: "mihomo_core_version", Value: "", Description: "Mihomo 核心版本号"},
		{Key: "pref_ip_strategy", Value: "ipv4_prefer", Description: "节点IP生成策略"},
		{Key: "clash_custom_modules", Value: "[]", Description: "用户自定义的 Clash 分流模块"},
		{Key: "clash_custom_proxy_rules", Value: "[]", Description: "自定义分流策略组配置"},
		{Key: "clash_custom_direct_raw", Value: "", Description: "自定义直连规则原始文本"},
		{Key: "clash_proxies_update_interval", Value: "3600", Description: "Clash节点自动更新间隔(秒)"},
		{Key: "clash_rules_update_interval", Value: "300", Description: "Clash私有规则自动更新间隔(秒)"},
		{Key: "clash_public_rules_update_interval", Value: "86400", Description: "Clash公共规则自动更新间隔(秒)"},
		// 将 sys_force_https 改为 sys_force_http
		{Key: "sys_force_http", Value: "false", Description: "是否强制允许 HTTP (忽略安全)"},
		// Cloudflare API 配置预留
		{Key: "cf_email", Value: "", Description: "Cloudflare 账号邮箱"},
		{Key: "cf_api_key", Value: "", Description: "Cloudflare API Token"},
		{Key: "cf_domain", Value: "", Description: "证书绑定的主域名"},
		{Key: "cf_auto_renew", Value: "true", Description: "是否开启证书自动续期"},
		{Key: "airport_filter_invalid", Value: "false", Description: "是否剔除机场订阅中的无效节点"},
		{Key: "pref_speed_test_mode", Value: "ping_speed", Description: "节点测速模式"},
		{Key: "pref_speed_test_file_size", Value: "50", Description: "节点测速文件大小(MB)"},
		// Telegram Bot 配置
		{Key: "tg_bot_enabled", Value: "false", Description: "是否启用 Telegram Bot"},
		{Key: "tg_bot_token", Value: "", Description: "Telegram Bot Token"},
		{Key: "tg_bot_whitelist", Value: "", Description: "允许使用 Bot 的 TG User ID (逗号分隔)"},
		{Key: "tg_bot_register_commands", Value: "false", Description: "是否清理历史菜单并注册 /sub 指令"},
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
		{Key: "proxy_ss_method", Value: "aes-128-gcm", Description: "SS 默认加密方式"},
		{Key: "proxy_port_socks5", Value: "20005", Description: "Socks5 默认监听端口"},
		{Key: "proxy_socks5_user", Value: "admin", Description: "Socks5 默认用户名"},
		{Key: "proxy_socks5_pass", Value: "123456", Description: "Socks5 默认密码"},
		// 新增协议配置
		{Key: "proxy_port_trojan", Value: "20006", Description: "Trojan 默认监听端口"},
		{Key: "proxy_port_vless_h2", Value: "20007", Description: "VLESS-H2-Reality 默认监听端口"},
		// 可配置 SNI（原先硬编码 www.bing.com）
		{Key: "proxy_hy2_sni", Value: "www.bing.com", Description: "HY2 客户端 SNI 伪装域名"},
		{Key: "proxy_tuic_sni", Value: "www.bing.com", Description: "TUIC 客户端 SNI 伪装域名"},
		// 系统优化选项
		{Key: "proxy_enable_bbr", Value: "true", Description: "是否在安装时启用 BBR 内核加速"},
		// VMess 协议族端口
		{Key: "proxy_port_vmess_tcp", Value: "20008", Description: "VMess-TCP 默认监听端口"},
		{Key: "proxy_port_vmess_ws", Value: "20009", Description: "VMess-WS 默认监听端口"},
		{Key: "proxy_port_vmess_http", Value: "20010", Description: "VMess-HTTP 默认监听端口"},
		{Key: "proxy_port_vmess_quic", Value: "20011", Description: "VMess-QUIC 默认监听端口"},
		// VMess+TLS 传输族端口
		{Key: "proxy_port_vmess_wst", Value: "20012", Description: "VMess-WS-TLS 默认监听端口"},
		{Key: "proxy_port_vmess_h2t", Value: "20013", Description: "VMess-H2-TLS 默认监听端口"},
		{Key: "proxy_port_vmess_hut", Value: "20014", Description: "VMess-HTTPUpgrade-TLS 默认监听端口"},
		// VLESS+TLS 传输族端口
		{Key: "proxy_port_vless_wst", Value: "20015", Description: "VLESS-WS-TLS 默认监听端口"},
		{Key: "proxy_port_vless_h2t", Value: "20016", Description: "VLESS-H2-TLS 默认监听端口"},
		{Key: "proxy_port_vless_hut", Value: "20017", Description: "VLESS-HTTPUpgrade-TLS 默认监听端口"},
		// Trojan+TLS 传输族端口
		{Key: "proxy_port_trojan_wst", Value: "20018", Description: "Trojan-WS-TLS 默认监听端口"},
		{Key: "proxy_port_trojan_h2t", Value: "20019", Description: "Trojan-H2-TLS 默认监听端口"},
		{Key: "proxy_port_trojan_hut", Value: "20020", Description: "Trojan-HTTPUpgrade-TLS 默认监听端口"},
		// TLS 传输协议共用路径
		{Key: "proxy_tls_transport_path", Value: "/ray", Description: "WS/H2/HTTPUpgrade 传输协议共用路径"},
		{Key: "proxy_vmess_tls_sni", Value: "www.bing.com", Description: "VMess TLS 传输族默认客户端 SNI 伪装域名"},
		{Key: "proxy_vless_tls_sni", Value: "www.bing.com", Description: "VLESS TLS 传输族默认客户端 SNI 伪装域名"},
		{Key: "proxy_trojan_tls_sni", Value: "www.bing.com", Description: "Trojan TLS 传输族默认客户端 SNI 伪装域名"},
	}

	for _, config := range defaultConfigs {
		if err := DB.Where(SysConfig{Key: config.Key}).FirstOrCreate(&config).Error; err != nil {
			logger.Log.Error("初始化代理配置失败", "key", config.Key, "err", err.Error())
		}
	}

	// 清理已废弃配置项（改为复用 TLS 传输族默认 SNI）
	if err := DB.Where("key IN ?", []string{"proxy_reality_sni", "proxy_trojan_sni"}).Delete(&SysConfig{}).Error; err != nil {
		logger.Log.Error("清理废弃代理配置失败", "err", err.Error())
	}
}
