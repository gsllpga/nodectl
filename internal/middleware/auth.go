package middleware

import (
	"fmt"
	"net/http"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	"github.com/golang-jwt/jwt/v5"
)

// Auth 鉴权中间件，用于保护需要登录才能访问的路由
func Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		reqPath := r.URL.Path

		// 1. 尝试从请求中获取名为 nodectl_token 的 Cookie
		cookie, err := r.Cookie("nodectl_token")
		if err != nil {
			// 没有带 Cookie，说明没登录，重定向到登录页
			logger.Log.Warn("未授权访问拦截",
				"reason", "请求缺少 nodectl_token Cookie",
				"ip", clientIP,
				"path", reqPath,
			)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 2. 从数据库获取系统加密密钥 (JWT Secret)
		var secretConfig database.SysConfig
		if err := database.DB.Where("key = ?", "jwt_secret").First(&secretConfig).Error; err != nil {
			logger.Log.Error("鉴权系统异常",
				"reason", "无法从数据库读取 jwt_secret",
				"error", err,
				"ip", clientIP,
				"path", reqPath,
			)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 3. 解析并校验 JWT
		tokenString := cookie.Value
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 确保签名算法是我们预期的 HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				algoErr := fmt.Errorf("非法的签名算法: %v", token.Header["alg"])
				logger.Log.Warn("Token 校验警告",
					"reason", "尝试使用伪造的签名算法",
					"error", algoErr,
					"ip", clientIP,
				)
				return nil, algoErr
			}
			return []byte(secretConfig.Value), nil
		})

		if err != nil || !token.Valid {
			logger.Log.Warn("Token 校验失败",
				"reason", "Token无效或已过期",
				"error", err,
				"ip", clientIP,
				"path", reqPath,
			)
			// Token 失效或被篡改，清除失效的 Cookie 并重定向
			http.SetCookie(w, &http.Cookie{
				Name:     "nodectl_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 4. 提取 Payload 信息并记录放行日志
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			username := claims["username"]
			logger.Log.Debug("鉴权放行",
				"user", username,
				"ip", clientIP,
				"path", reqPath,
			)
		} else {
			logger.Log.Warn("Token 校验警告",
				"reason", "无法解析 Token Claims 结构",
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 5. 鉴权完全通过，执行下一个业务 Handler
		next.ServeHTTP(w, r)
	}
}
