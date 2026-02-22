package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var (
	tgBotCancel context.CancelFunc
)

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
	whitelist := strings.TrimSpace(whitelistConfig.Value)
	registerCommands := strings.TrimSpace(registerConfig.Value) == "true"

	if !botEnabled {
		return
	}

	if token == "" || whitelist == "" {
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
			// 处理消息 (Message)
			if update.Message != nil {
				handleMessage(bot, update.Message, whitelist)
			} else if update.CallbackQuery != nil {
				handleCallbackQuery(bot, update.CallbackQuery, whitelist)
			}
		}
	}
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
	msg := tgbotapi.NewMessage(chatID, "🚀 请选择要获取的订阅类型：")

	// 创建 Inline Keyboard，包含一级菜单按钮
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🌐 订阅中心", "menu_sub_center"),
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

	// 响应 Telegram 提示收到回调，消除按钮顶部的 loading 状态
	bot.Request(tgbotapi.NewCallback(callbackQuery.ID, ""))

	data := callbackQuery.Data
	chatID := callbackQuery.Message.Chat.ID
	messageID := callbackQuery.Message.MessageID

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
	}
}
