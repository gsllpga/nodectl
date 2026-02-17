package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"nodectl/internal/version"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Log 全局导出的日志实例
var Log *slog.Logger

// Init 初始化日志配置
func Init() {
	// 1. 配置文件切割
	logFile := &lumberjack.Logger{
		Filename:   filepath.Join("data", "logs", "nodectl.log"), // 日志文件的绝对或相对路径
		MaxSize:    2,                                            // 每个日志文件保存的最大尺寸 (单位: MB)，超过该大小会自动切割
		MaxBackups: 3,                                            // 系统中最多保留的旧日志文件个数
		MaxAge:     30,                                           // 保留旧日志文件的最大天数 (单位: 天)
		Compress:   true,                                         // 是否对切割后的旧日志文件进行 gzip 压缩 (强烈建议开启，节省空间)
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)

	// 2. 动态判断日志级别
	logLevel := slog.LevelDebug
	// 在正式版本中强制使用 Error 级别，禁止 Debug 和 Info 日志输出
	if version.Version != "dev" && version.Version != "" {
		logLevel = slog.LevelError
	}

	// 3. 配置 slog 拦截器
	opts := &slog.HandlerOptions{
		Level:     logLevel,
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

	// 4. 实例化 Logger
	handler := slog.NewTextHandler(multiWriter, opts)
	Log = slog.New(handler)
	slog.SetDefault(Log)

	if logLevel == slog.LevelDebug {
		Log.Info("日志组件初始化完成", slog.String("模块", "logger"), slog.String("模式", "Debug 开发模式"))
	} else {
		Log.Error("服务已启动", slog.String("模块", "logger"), slog.String("模式", "Error 生产模式"))
	}
}
