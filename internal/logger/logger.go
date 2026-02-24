package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"gopkg.in/natefinch/lumberjack.v2"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Log 全局导出的日志实例
var Log *slog.Logger

// levelVar 支持运行时热切换日志等级
var levelVar = new(slog.LevelVar)

// parseLevel 解析日志等级字符串
func parseLevel(level string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// CurrentLevel 返回当前日志等级字符串
func CurrentLevel() string {
	current := levelVar.Level()
	switch {
	case current <= slog.LevelDebug:
		return "debug"
	case current <= slog.LevelInfo:
		return "info"
	case current <= slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}

// SetLevel 动态设置日志等级，支持热切换
func SetLevel(level string) bool {
	parsed, ok := parseLevel(level)
	if !ok {
		return false
	}

	levelVar.Set(parsed)
	if Log != nil {
		Log.Info("日志等级已更新", "level", CurrentLevel())
	}
	return true
}

// LoadPersistedLogLevel 从数据库读取已保存的日志等级
func LoadPersistedLogLevel() string {
	defaultLevel := "info"

	dbPath := filepath.Join("data", "nodectl.db")
	if _, err := os.Stat(dbPath); err != nil {
		return defaultLevel
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return defaultLevel
	}

	var cfg struct {
		Value string `gorm:"column:value"`
	}
	if err := db.Table("sys_config").Select("value").Where("key = ?", "sys_log_level").Take(&cfg).Error; err != nil {
		return defaultLevel
	}

	if cfg.Value == "" {
		return defaultLevel
	}

	return cfg.Value
}

// Init 初始化日志配置
func Init(initialLevel string) {
	parsedLevel, ok := parseLevel(initialLevel)
	if !ok {
		parsedLevel = slog.LevelInfo
	}
	levelVar.Set(parsedLevel)

	// 1. 配置文件切割
	logFile := &lumberjack.Logger{
		Filename:   filepath.Join("data", "logs", "nodectl.log"), // 日志文件的绝对或相对路径
		MaxSize:    2,                                            // 每个日志文件保存的最大尺寸 (单位: MB)，超过该大小会自动切割
		MaxBackups: 3,                                            // 系统中最多保留的旧日志文件个数
		MaxAge:     30,                                           // 保留旧日志文件的最大天数 (单位: 天)
		Compress:   true,                                         // 是否对切割后的旧日志文件进行 gzip 压缩
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)

	// 2. 配置 slog 拦截器
	opts := &slog.HandlerOptions{
		Level:     levelVar,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format("2006-01-02 15:04:05"))
			}

			if a.Key == slog.SourceKey {
				source, ok := a.Value.Any().(*slog.Source)
				if ok {
					file := filepath.ToSlash(source.File)

					if idx := strings.Index(file, "/internal/"); idx != -1 {
						file = file[idx+1:]
					} else if strings.HasSuffix(file, "main.go") {
						file = "main.go"
					} else {
						parts := strings.Split(file, "/")
						if len(parts) > 2 {
							file = strings.Join(parts[len(parts)-2:], "/")
						}
					}

					formattedSource := fmt.Sprintf("%s:%d", file, source.Line)
					return slog.String(slog.SourceKey, formattedSource)
				}
			}

			return a
		},
	}

	// 3. 实例化 Logger
	handler := slog.NewTextHandler(multiWriter, opts)
	Log = slog.New(handler)
	slog.SetDefault(Log)
	if !ok && strings.TrimSpace(initialLevel) != "" {
		Log.Warn("启动时读取到非法日志等级配置，已回退为 info", "value", initialLevel)
	}
	Log.Info("日志组件初始化完成", slog.String("模块", "logger"), slog.String("等级", CurrentLevel()))
}
