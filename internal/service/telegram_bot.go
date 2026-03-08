package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var (
	tgBotCancel context.CancelFunc

	offlineNotifyMu       sync.Mutex
	offlineNotifyState    = make(map[string]*offlineNotifyRuntime)
	offlineNotifyLoopOnce sync.Once
)

type offlineNotifyRuntime struct {
	initialized      bool
	online           bool
	pendingOfflineAt time.Time
	lastNotified     string // offline | online | ""
}

func NormalizeNodeOfflineGraceSec(v int) int {
	if v < 1 {
		return 180
	}
	if v > 86400 {
		return 86400
	}
	return v
}

func StartOfflineNotifyLoop() {
	offlineNotifyLoopOnce.Do(func() {
		go runOfflineNotifyLoop()
	})
}

func runOfflineNotifyLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for now := range ticker.C {
		handleOfflineNotifyTick(now)
	}
}

func handleOfflineNotifyTick(now time.Time) {
	candidates := make([]string, 0)

	offlineNotifyMu.Lock()
	for installID, st := range offlineNotifyState {
		if st == nil || !st.initialized || st.online {
			continue
		}
		if st.pendingOfflineAt.IsZero() || now.Before(st.pendingOfflineAt) {
			continue
		}
		if st.lastNotified == "offline" {
			st.pendingOfflineAt = time.Time{}
			continue
		}
		candidates = append(candidates, installID)
	}
	offlineNotifyMu.Unlock()

	for _, installID := range candidates {
		notifyOfflineIfDue(installID, now)
	}
}

func notifyOfflineIfDue(installID string, now time.Time) {
	if IsNodeOnline(installID) {
		return
	}

	node, ok := getNodeNotifyConfigByInstallID(installID)
	if !ok || !node.OfflineNotifyEnabled {
		return
	}

	if sendNodeStatusNotification(node.Name, false, now) {
		updateNodeOfflineLastNotifyAt(node.UUID, now)
	}

	offlineNotifyMu.Lock()
	st := offlineNotifyState[installID]
	if st == nil {
		st = &offlineNotifyRuntime{}
		offlineNotifyState[installID] = st
	}
	st.lastNotified = "offline"
	st.pendingOfflineAt = time.Time{}
	offlineNotifyMu.Unlock()
}

func getNodeNotifyConfigByInstallID(installID string) (database.NodePool, bool) {
	var node database.NodePool
	if err := database.DB.Select("uuid", "install_id", "name", "offline_notify_enabled", "offline_notify_grace_sec").Where("install_id = ?", installID).First(&node).Error; err != nil {
		return database.NodePool{}, false
	}
	node.OfflineNotifyGraceSec = NormalizeNodeOfflineGraceSec(node.OfflineNotifyGraceSec)
	return node, true
}

func updateNodeOfflineLastNotifyAt(nodeUUID string, at time.Time) {
	if err := database.DB.Model(&database.NodePool{}).
		Where("uuid = ?", nodeUUID).
		Update("offline_last_notify_at", at).Error; err != nil {
		logger.Log.Warn("更新节点最后通知时间失败", "uuid", nodeUUID, "error", err)
	}
}

type tgNotifyTarget struct {
	UserID     int64
	AllowNode  bool
	AllowLogin bool
}

func parseTGNotifyTargets(raw string) []tgNotifyTarget {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]tgNotifyTarget, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		entry := strings.SplitN(p, "=", 2)
		idStr := strings.TrimSpace(entry[0])
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}

		target := tgNotifyTarget{UserID: id, AllowNode: true, AllowLogin: true}

		if len(entry) == 2 {
			rest := strings.TrimSpace(entry[1])
			if rest != "" {
				metaParts := strings.Split(rest, "|")
				for i := 1; i < len(metaParts); i++ {
					meta := strings.TrimSpace(metaParts[i])
					if meta == "" {
						continue
					}
					kv := strings.SplitN(meta, "=", 2)
					if len(kv) != 2 {
						continue
					}
					k := strings.ToLower(strings.TrimSpace(kv[0]))
					v := strings.ToLower(strings.TrimSpace(kv[1]))
					allow := v == "1" || v == "true"
					switch k {
					case "node", "node_status":
						target.AllowNode = allow
					case "login", "login_notify":
						target.AllowLogin = allow
					}
				}
			}
		}

		out = append(out, target)
	}

	return out
}

func parseTGNotifyUsers(raw string) []int64 {
	targets := parseTGNotifyTargets(raw)
	out := make([]int64, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.UserID)
	}
	return out
}

func sendNodeStatusNotification(nodeName string, online bool, eventTime time.Time) bool {
	keys := []string{"tg_bot_enabled", "tg_bot_token", "tg_bot_whitelist"}
	var cfgList []database.SysConfig
	if err := database.DB.Where("key IN ?", keys).Find(&cfgList).Error; err != nil {
		logger.Log.Warn("读取 TG 通知配置失败", "error", err)
		return false
	}

	cfg := map[string]string{}
	for _, c := range cfgList {
		cfg[c.Key] = strings.TrimSpace(c.Value)
	}

	if cfg["tg_bot_enabled"] != "true" {
		return false
	}
	token := cfg["tg_bot_token"]
	if token == "" {
		return false
	}
	targets := parseTGNotifyTargets(cfg["tg_bot_whitelist"])
	users := make([]int64, 0, len(targets))
	for _, t := range targets {
		if t.AllowNode {
			users = append(users, t.UserID)
		}
	}
	if len(users) == 0 {
		return false
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		logger.Log.Warn("初始化 TG Bot 失败，无法发送节点状态通知", "error", err)
		return false
	}

	statusText := "离线"
	timeLabel := "离线时间"
	emoji := "🔴"
	if online {
		statusText = "上线"
		timeLabel = "上线时间"
		emoji = "🟢"
	}

	if strings.TrimSpace(nodeName) == "" {
		nodeName = "未命名节点"
	}

	msgText := fmt.Sprintf("%s 节点%s通知\n节点名称：%s\n%s：%s", emoji, statusText, nodeName, timeLabel, eventTime.Format("2006-01-02 15:04:05"))

	sentAny := false
	for _, uid := range users {
		msg := tgbotapi.NewMessage(uid, msgText)
		if _, err := bot.Send(msg); err != nil {
			logger.Log.Warn("发送 TG 节点状态通知失败", "user_id", uid, "node_name", nodeName, "status", statusText, "error", err)
			continue
		}
		sentAny = true
	}

	return sentAny
}

// SendAdminLoginNotification 发送后台登录通知到 TG 白名单用户
// success=true 表示登录成功；success=false 表示登录失败
func SendAdminLoginNotification(username, loginIP string, loginTime time.Time, success bool, reason string) bool {
	keys := []string{"tg_bot_enabled", "tg_bot_token", "tg_bot_whitelist", "tg_login_notify_mode", "tg_login_notify_enabled"}
	var cfgList []database.SysConfig
	if err := database.DB.Where("key IN ?", keys).Find(&cfgList).Error; err != nil {
		logger.Log.Warn("读取 TG 登录通知配置失败", "error", err)
		return false
	}

	cfg := map[string]string{}
	for _, c := range cfgList {
		cfg[c.Key] = strings.TrimSpace(c.Value)
	}

	if cfg["tg_bot_enabled"] != "true" {
		return false
	}

	mode := strings.TrimSpace(cfg["tg_login_notify_mode"])
	if mode == "" {
		// 兼容旧版本布尔配置
		if strings.TrimSpace(cfg["tg_login_notify_enabled"]) == "true" {
			mode = "all"
		} else {
			mode = "off"
		}
	}

	switch mode {
	case "off":
		return false
	case "success_only":
		if !success {
			return false
		}
	case "failure_only":
		if success {
			return false
		}
	case "all":
		// continue
	default:
		return false
	}

	if !success && strings.TrimSpace(reason) == "" {
		reason = "未知原因"
	}

	if success {
		reason = ""
	}

	token := cfg["tg_bot_token"]
	if token == "" {
		return false
	}

	targets := parseTGNotifyTargets(cfg["tg_bot_whitelist"])
	users := make([]int64, 0, len(targets))
	for _, t := range targets {
		if t.AllowLogin {
			users = append(users, t.UserID)
		}
	}
	if len(users) == 0 {
		return false
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		logger.Log.Warn("初始化 TG Bot 失败，无法发送登录通知", "error", err)
		return false
	}

	if strings.TrimSpace(username) == "" {
		username = "unknown"
	}
	if strings.TrimSpace(loginIP) == "" {
		loginIP = "unknown"
	}

	countryZh := "未知"
	if GlobalGeoIP != nil {
		if name := strings.TrimSpace(GlobalGeoIP.GetCountryNameZhCN(loginIP)); name != "" {
			countryZh = name
		}
	}

	title := "✅ 管理后台登录成功"
	timeLabel := "登录时间"
	if !success {
		title = "⚠️ 管理后台登录失败"
		timeLabel = "失败时间"
	}

	msgText := fmt.Sprintf("%s\n账号：%s\n%s：%s\n登录IP：%s\n归属地：%s", title, username, timeLabel, loginTime.Format("2006-01-02 15:04:05"), loginIP, countryZh)
	if !success {
		msgText += fmt.Sprintf("\n失败原因：%s", reason)
	}

	sentAny := false
	for _, uid := range users {
		msg := tgbotapi.NewMessage(uid, msgText)
		if _, err := bot.Send(msg); err != nil {
			logger.Log.Warn("发送 TG 登录通知失败", "user_id", uid, "username", username, "ip", loginIP, "error", err)
			continue
		}
		sentAny = true
	}

	return sentAny
}

// OnNodeConnectionStatusChanged 在节点 WS 连接状态变化时触发。
func OnNodeConnectionStatusChanged(installID string, online bool) {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return
	}

	StartOfflineNotifyLoop()
	now := time.Now()
	node, nodeFound := getNodeNotifyConfigByInstallID(installID)

	offlineNotifyMu.Lock()
	st := offlineNotifyState[installID]
	if st == nil {
		st = &offlineNotifyRuntime{}
		offlineNotifyState[installID] = st
	}
	prevOnline := st.online
	wasInitialized := st.initialized
	st.initialized = true
	st.online = online
	if online {
		st.pendingOfflineAt = time.Time{}
	} else {
		graceSec := 180
		if nodeFound {
			graceSec = NormalizeNodeOfflineGraceSec(node.OfflineNotifyGraceSec)
		}
		st.pendingOfflineAt = now.Add(time.Duration(graceSec) * time.Second)
	}
	lastNotified := st.lastNotified
	offlineNotifyMu.Unlock()

	if !nodeFound || !node.OfflineNotifyEnabled {
		return
	}

	if online && wasInitialized && !prevOnline && lastNotified == "offline" {
		if sendNodeStatusNotification(node.Name, true, now) {
			updateNodeOfflineLastNotifyAt(node.UUID, now)
		}
		offlineNotifyMu.Lock()
		if latest := offlineNotifyState[installID]; latest != nil {
			latest.lastNotified = "online"
		}
		offlineNotifyMu.Unlock()
	}
}

// StartTelegramBot 初始化并启动 Telegram Bot 监听协程
func StartTelegramBot() {
	// 等待数据库初始化完成
	time.Sleep(2 * time.Second)
	RestartTelegramBot()
}

// RestartTelegramBot 重启 Telegram Bot 服务，用于热更新配置
func RestartTelegramBot() {
	if tgBotCancel != nil {
		tgBotCancel()
		tgBotCancel = nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	tgBotCancel = cancel

	go runTelegramBot(ctx)
}

func runTelegramBot(ctx context.Context) {
	var enabledConfig database.SysConfig
	var tokenConfig database.SysConfig
	var whitelistConfig database.SysConfig
	var registerConfig database.SysConfig

	// 获取配置
	database.DB.Where("key = ?", "tg_bot_enabled").First(&enabledConfig)
	database.DB.Where("key = ?", "tg_bot_token").First(&tokenConfig)
	database.DB.Where("key = ?", "tg_bot_whitelist").First(&whitelistConfig)
	database.DB.Where("key = ?", "tg_bot_register_commands").First(&registerConfig)

	botEnabled := strings.TrimSpace(enabledConfig.Value) == "true"
	token := strings.TrimSpace(tokenConfig.Value)
	whitelist := sanitizeTgWhitelist(strings.TrimSpace(whitelistConfig.Value))
	registerCommands := strings.TrimSpace(registerConfig.Value) == "true"

	if !botEnabled {
		return
	}

	if token == "" {
		logger.Log.Warn("Telegram Bot Token 未配置，Bot 未启动")
		return
	}
	if whitelist == "" {
		logger.Log.Warn("Telegram Bot 白名单为空或无有效条目，Bot 未启动")
		return
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		logger.Log.Error("Telegram Bot 初始化失败", "error", err)
		return
	}

	// bot.Debug = true // 可选：开启调试模式

	if registerCommands {
		// 删除并重新注册主菜单指令
		deleteConfig := tgbotapi.NewDeleteMyCommands()
		if _, err := bot.Request(deleteConfig); err != nil {
			logger.Log.Warn("清除历史 TG Bot 指令失败", "error", err)
		}

		setCmdConfig := tgbotapi.NewSetMyCommands(
			tgbotapi.BotCommand{
				Command:     "sub",
				Description: "获取我的节点订阅或机场资源",
			},
		)
		if _, err := bot.Request(setCmdConfig); err != nil {
			logger.Log.Error("注册 TG Bot 指令失败", "error", err)
		}
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for {
		select {
		case <-ctx.Done():
			logger.Log.Info("检测到配置变化，正在停止旧的 Telegram Bot 服务...")
			bot.StopReceivingUpdates()
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			// 采用协程并发处理每条消息，避免因为某一条消息卡顿阻塞整体的接收队列，提升多用户并发响应速度
			go func(upd tgbotapi.Update) {
				// 处理消息 (Message)
				if upd.Message != nil {
					handleMessage(bot, upd.Message, whitelist)
				} else if upd.CallbackQuery != nil {
					handleCallbackQuery(bot, upd.CallbackQuery, whitelist)
				}
			}(update)
		}
	}
}

// sanitizeTgWhitelist 清洗白名单字符串，仅保留 ID 为纯数字的有效条目
func sanitizeTgWhitelist(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	valid := make([]string, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		entry := strings.SplitN(item, "=", 2)
		id := strings.TrimSpace(entry[0])
		if id == "" {
			continue
		}
		if _, err := strconv.ParseInt(id, 10, 64); err != nil {
			logger.Log.Warn("TG 白名单中发现无效条目，已忽略", "entry", item)
			continue
		}
		valid = append(valid, item)
	}
	return strings.Join(valid, ",")
}

// 检查用户是否在白名单中
func isUserAllowed(userID int64, whitelistStr string) bool {
	if whitelistStr == "" {
		return false // 未配置白名单时，默认拒绝所有人
	}
	whitelist := strings.Split(whitelistStr, ",")
	userIDStr := fmt.Sprintf("%d", userID)
	for _, item := range whitelist {
		parts := strings.SplitN(item, "=", 2)
		id := strings.TrimSpace(parts[0])
		if id == userIDStr {
			return true
		}
	}
	return false
}

// 获取基础面板域名和鉴权 Token
func getBaseURLAndToken() (string, string) {
	var panelURLConfig database.SysConfig
	var subTokenConfig database.SysConfig

	database.DB.Where("key = ?", "panel_url").First(&panelURLConfig)
	database.DB.Where("key = ?", "sub_token").First(&subTokenConfig)

	panelURL := strings.TrimRight(strings.TrimSpace(panelURLConfig.Value), "/")
	if panelURL == "" {
		panelURL = "https://yourdomain.com" // 默认占位
	}
	return panelURL, strings.TrimSpace(subTokenConfig.Value)
}

// 处理普通消息
func handleMessage(bot *tgbotapi.BotAPI, message *tgbotapi.Message, whitelistStr string) {
	if !message.IsCommand() {
		return // 目前只响应命令
	}

	// 白名单验证
	if !isUserAllowed(message.From.ID, whitelistStr) {
		logger.Log.Warn("未授权的 TG 用户尝试访问", "user_id", message.From.ID)
		msg := tgbotapi.NewMessage(message.Chat.ID, "⛔ 未经授权的访问。请将您的 TG ID 添加到管理员白名单中。")
		bot.Send(msg)
		return
	}

	switch message.Command() {
	case "start", "sub":
		sendSubMenu(bot, message.Chat.ID)
	default:
		msg := tgbotapi.NewMessage(message.Chat.ID, "未知命令。请发送 /sub 获取订阅菜单。")
		bot.Send(msg)
	}
}

// 发送订阅主菜单 (包含一级按钮)
func sendSubMenu(bot *tgbotapi.BotAPI, chatID int64) {
	msg := tgbotapi.NewMessage(chatID, "🚀 请选择菜单")

	// 创建 Inline Keyboard，包含一级菜单按钮
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🌐 订阅中心", "menu_sub_center"),
			tgbotapi.NewInlineKeyboardButtonData("📡 服务器列表", "menu_nodes:1"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🛡️ TG 代理", "menu_tg_proxy"),
		),
	)

	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}

// 处理点击 Inline Keyboard 回调事件
func handleCallbackQuery(bot *tgbotapi.BotAPI, callbackQuery *tgbotapi.CallbackQuery, whitelistStr string) {
	// 同样需要进行白名单验证 (防止之前的消息被转发或未授权用户点击)
	if !isUserAllowed(callbackQuery.From.ID, whitelistStr) {
		bot.Request(tgbotapi.NewCallback(callbackQuery.ID, "⛔ 未经授权"))
		return
	}

	// 响应 Telegram 提示收到回调，消除按钮顶部的 loading 状态（提速体感）
	bot.Request(tgbotapi.NewCallback(callbackQuery.ID, ""))

	data := callbackQuery.Data
	chatID := callbackQuery.Message.Chat.ID
	messageID := callbackQuery.Message.MessageID

	// 采用异步处理以提升点击按钮时的响应速度
	go func() {
		switch data {
		case "menu_sub_center":
			// 点击“订阅中心”，修改原消息，显示二级菜单
			editMsg := tgbotapi.NewEditMessageText(chatID, messageID, "👇 请选择具体的订阅格式：")
			keyboard := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("🐱 Clash 订阅", "get_sub_clash"),
					tgbotapi.NewInlineKeyboardButtonData("✌️ V2ray 订阅", "get_sub_v2ray"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("🔄 重置订阅", "reset_sub_token"),
					tgbotapi.NewInlineKeyboardButtonData("🔙 返回上级", "menu_main"),
				),
			)
			editMsg.ReplyMarkup = &keyboard
			bot.Send(editMsg)

		case "menu_main":
			// 返回主菜单
			editMsg := tgbotapi.NewEditMessageText(chatID, messageID, "🚀 请选择要获取的订阅类型：")
			keyboard := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("🌐 订阅中心", "menu_sub_center"),
					tgbotapi.NewInlineKeyboardButtonData("📡 服务器列表", "menu_nodes:1"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("🛡️ TG 代理", "menu_tg_proxy"),
				),
			)
			editMsg.ReplyMarkup = &keyboard
			bot.Send(editMsg)

		case "get_sub_clash":
			panelURL, token := getBaseURLAndToken()
			subURL := fmt.Sprintf("%s/sub/clash?token=%s", panelURL, token)
			replyText := fmt.Sprintf("✅ **您的 Clash (Mihomo) 订阅链接：**\n\n`%s`", subURL)

			msg := tgbotapi.NewMessage(chatID, replyText)
			msg.ParseMode = "Markdown"
			sentMsg, err := bot.Send(msg)
			if err == nil {
				go func(chatID int64, messageID int) {
					time.Sleep(10 * time.Second)
					deleteMsg := tgbotapi.NewDeleteMessage(chatID, messageID)
					bot.Request(deleteMsg)
				}(chatID, sentMsg.MessageID)
			}

		case "get_sub_v2ray":
			panelURL, token := getBaseURLAndToken()
			subURL := fmt.Sprintf("%s/sub/v2ray?token=%s", panelURL, token)
			replyText := fmt.Sprintf("✅ **您的 V2ray 订阅链接：**\n\n`%s`", subURL)

			msg := tgbotapi.NewMessage(chatID, replyText)
			msg.ParseMode = "Markdown"
			sentMsg, err := bot.Send(msg)
			if err == nil {
				go func(chatID int64, messageID int) {
					time.Sleep(10 * time.Second)
					deleteMsg := tgbotapi.NewDeleteMessage(chatID, messageID)
					bot.Request(deleteMsg)
				}(chatID, sentMsg.MessageID)
			}

		case "menu_tg_proxy":
			var nodes []database.NodePool
			database.DB.Where("is_blocked = ? AND ipv6 != ''", false).Find(&nodes)

			var tgProxies []string
			for _, node := range nodes {
				if link, ok := node.Links["socks5"]; ok && link != "" {
					parsedNode := ParseLinkToClashNode(link, "")
					if parsedNode != nil && parsedNode.Type == "socks5" {
						params := url.Values{}
						params.Add("server", node.IPV6)
						params.Add("port", strconv.Itoa(parsedNode.Port))
						if parsedNode.Username != "" {
							params.Add("user", parsedNode.Username)
						}
						if parsedNode.Password != "" {
							params.Add("pass", parsedNode.Password)
						}

						proxyLink := "https://t.me/socks?" + params.Encode()
						escapedName := escapeMarkdown(node.Name)
						tgProxies = append(tgProxies, fmt.Sprintf("▪️ **%s** | [👉 代理直链](%s)", escapedName, proxyLink))
					}
				}
			}

			var replyText string
			if len(tgProxies) == 0 {
				replyText = "📭 目前没有任何支持 IPv6 的 Socks5 节点。"
			} else {
				replyText = "🛡️ **可用的 TG 代理：**\n\n" + strings.Join(tgProxies, "\n")
			}

			msg := tgbotapi.NewMessage(chatID, replyText)
			msg.ParseMode = "Markdown"
			sentMsg, err := bot.Send(msg)
			if err == nil && len(tgProxies) > 0 {
				go func(cID int64, mID int) {
					time.Sleep(30 * time.Second)
					bot.Request(tgbotapi.NewDeleteMessage(cID, mID))
				}(chatID, sentMsg.MessageID)
			}

		case "reset_sub_token":
			secureBytes := make([]byte, 16)
			rand.Read(secureBytes)
			newToken := hex.EncodeToString(secureBytes)

			err := database.DB.Model(&database.SysConfig{}).Where("key = ?", "sub_token").Update("value", newToken).Error
			if err != nil {
				logger.Log.Error("TG Bot 重置 Sub Token 失败", "error", err)
				msg := tgbotapi.NewMessage(chatID, "❌ 重置订阅 Token 失败，请检查系统日志。")
				bot.Send(msg)
				return
			}

			logger.Log.Info("用户通过 TG Bot 重置了订阅 Token", "user_id", callbackQuery.From.ID)
			replyText := "✅ **订阅重置成功！**"

			msg := tgbotapi.NewMessage(chatID, replyText)
			msg.ParseMode = "Markdown"
			bot.Send(msg)

		default:
			if strings.HasPrefix(data, "menu_nodes:") {
				handleMenuNodes(bot, chatID, messageID, data)
			} else if strings.HasPrefix(data, "node_info:") {
				handleNodeInfo(bot, chatID, messageID, data)
			}
		}
	}()
}

func escapeMarkdown(text string) string {
	text = strings.ReplaceAll(text, "_", "\\_")
	text = strings.ReplaceAll(text, "*", "\\*")
	text = strings.ReplaceAll(text, "`", "\\`")
	text = strings.ReplaceAll(text, "[", "\\[")
	return text
}

func formatBytes(b int64) string {
	if b == 0 {
		return "0G"
	}
	gb := float64(b) / (1024 * 1024 * 1024)
	if gb >= 1024 {
		return fmt.Sprintf("%.2fT", gb/1024)
	}
	return fmt.Sprintf("%.2fG", gb)
}

func handleMenuNodes(bot *tgbotapi.BotAPI, chatID int64, messageID int, data string) {
	pageStr := strings.TrimPrefix(data, "menu_nodes:")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	var totalNodes int64
	database.DB.Model(&database.NodePool{}).Where("is_blocked = ?", false).Count(&totalNodes)

	if totalNodes == 0 {
		editMsg := tgbotapi.NewEditMessageText(chatID, messageID, "📭 当前没有任何节点。")
		btn := tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData("🔙 返回上级", "menu_main"))
		keyboard := tgbotapi.NewInlineKeyboardMarkup(btn)
		editMsg.ReplyMarkup = &keyboard
		bot.Send(editMsg)
		return
	}

	perPage := 12
	totalPages := int(math.Ceil(float64(totalNodes) / float64(perPage)))
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * perPage

	var nodes []database.NodePool
	// 按照流量消耗排行，一页显示12个
	database.DB.Where("is_blocked = ?", false).
		Order("(traffic_up + traffic_down) DESC").
		Limit(perPage).Offset(offset).Find(&nodes)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📊 **服务器流量排行榜 (第 %d/%d 页)**\n\n", page, totalPages))

	getStringWidth := func(s string) int {
		width := 0
		for _, r := range s {
			if r > 127 {
				width += 2
			} else {
				width += 1
			}
		}
		return width
	}

	var maxNameWidth int
	var maxUsedWidth int

	type listNodeInfo struct {
		id    string
		name  string
		used  string
		limit string
	}
	var infos []listNodeInfo

	for _, node := range nodes {
		nameWidth := getStringWidth(node.Name)
		if nameWidth > maxNameWidth {
			maxNameWidth = nameWidth
		}

		usedStr := formatBytes(node.TrafficUp + node.TrafficDown)
		usedWidth := getStringWidth(usedStr)
		if usedWidth > maxUsedWidth {
			maxUsedWidth = usedWidth
		}

		limitStr := "不限量"
		if node.TrafficLimit > 0 {
			limitStr = formatBytes(node.TrafficLimit)
		}
		infos = append(infos, listNodeInfo{node.UUID, node.Name, usedStr, limitStr})
	}

	for _, info := range infos {
		namePad := maxNameWidth - getStringWidth(info.name)
		if namePad < 0 {
			namePad = 0
		}
		paddedName := info.name + strings.Repeat(" ", namePad)

		usedPad := maxUsedWidth - getStringWidth(info.used)
		if usedPad < 0 {
			usedPad = 0
		}
		paddedUsed := strings.Repeat(" ", usedPad) + info.used

		sb.WriteString(fmt.Sprintf("`%s | %s | %s`\n", paddedName, paddedUsed, info.limit))
	}

	editMsg := tgbotapi.NewEditMessageText(chatID, messageID, sb.String())
	editMsg.ParseMode = "Markdown"

	// 构建键盘
	var keyboard [][]tgbotapi.InlineKeyboardButton

	var currentRow []tgbotapi.InlineKeyboardButton
	for i, n := range nodes {
		currentRow = append(currentRow, tgbotapi.NewInlineKeyboardButtonData(n.Name, "node_info:"+n.UUID))
		if len(currentRow) == 3 || i == len(nodes)-1 {
			keyboard = append(keyboard, currentRow)
			currentRow = nil
		}
	}

	// 翻页行
	var pageRow []tgbotapi.InlineKeyboardButton
	if page > 1 {
		pageRow = append(pageRow, tgbotapi.NewInlineKeyboardButtonData("◀️ 上一页", fmt.Sprintf("menu_nodes:%d", page-1)))
	}
	if page < totalPages {
		pageRow = append(pageRow, tgbotapi.NewInlineKeyboardButtonData("▶️ 下一页", fmt.Sprintf("menu_nodes:%d", page+1)))
	}
	if len(pageRow) > 0 {
		keyboard = append(keyboard, pageRow)
	}

	// 返回行
	keyboard = append(keyboard, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🔙 返回主菜单", "menu_main"),
	))

	kbd := tgbotapi.NewInlineKeyboardMarkup(keyboard...)
	editMsg.ReplyMarkup = &kbd
	bot.Send(editMsg)
}

func handleNodeInfo(bot *tgbotapi.BotAPI, chatID int64, messageID int, data string) {
	uuid := strings.TrimPrefix(data, "node_info:")
	var node database.NodePool
	if err := database.DB.Where("uuid = ?", uuid).First(&node).Error; err != nil {
		bot.Send(tgbotapi.NewEditMessageText(chatID, messageID, "❌ 找不到该节点信息。"))
		return
	}

	routingType := "直连节点"
	if node.RoutingType != 1 {
		routingType = "中转/落地节点"
	}

	upStr := formatBytes(node.TrafficUp)
	downStr := formatBytes(node.TrafficDown)
	usedStr := formatBytes(node.TrafficUp + node.TrafficDown)
	limitStr := "不限量"
	if node.TrafficLimit > 0 {
		limitStr = formatBytes(node.TrafficLimit)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("💻 **[%s] 的专属信息**\n\n", node.Name))
	sb.WriteString(fmt.Sprintf("▪️ **网络组：** %s\n", routingType))
	sb.WriteString(fmt.Sprintf("▪️ **已用上传：** %s\n", upStr))
	sb.WriteString(fmt.Sprintf("▪️ **已用下载：** %s\n", downStr))
	sb.WriteString(fmt.Sprintf("▪️ **总计消耗：** %s / %s\n", usedStr, limitStr))
	if node.Remark != "" {
		sb.WriteString(fmt.Sprintf("▪️ **备注：** %s\n", node.Remark))
	}

	sb.WriteString("\n🔗 **协议链接：**\n")
	hasLink := false
	for protoType, link := range node.Links {
		if link != "" {
			sb.WriteString(fmt.Sprintf("**%s**: `%s`\n", strings.ToUpper(protoType), link))
			hasLink = true
		}
	}

	if !hasLink {
		sb.WriteString("⚠️ 该节点目前没有任何协议链接。\n")
	}

	editMsg := tgbotapi.NewEditMessageText(chatID, messageID, sb.String())
	editMsg.ParseMode = "Markdown"

	keyboard := [][]tgbotapi.InlineKeyboardButton{
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔙 返回服务器列表", "menu_nodes:1"),
		),
	}

	kbd := tgbotapi.NewInlineKeyboardMarkup(keyboard...)
	editMsg.ReplyMarkup = &kbd
	bot.Send(editMsg)
}
