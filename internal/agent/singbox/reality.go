// 路径: internal/agent/singbox/reality.go
// Reality 密钥对 & Short ID 生成（纯 Go 实现，替代 sing-box generate 命令）
package singbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// RealityKeyPair Reality 协议所需的 X25519 密钥对
type RealityKeyPair struct {
	PrivateKey string `json:"private_key"` // base64 编码的私钥（sing-box 格式）
	PublicKey  string `json:"public_key"`  // base64 编码的公钥（客户端配置使用）
}

// GenerateRealityKeyPair 生成 Reality 密钥对（X25519）
// sing-box 使用 base64 编码（非 hex），与 sing-box generate reality-keypair 输出一致。
func GenerateRealityKeyPair() (*RealityKeyPair, error) {
	// 生成 32 字节随机私钥
	var privateKeyBytes [32]byte
	if _, err := rand.Read(privateKeyBytes[:]); err != nil {
		return nil, fmt.Errorf("生成随机私钥失败: %w", err)
	}

	// X25519 clamping（标准做法，确保私钥符合 Curve25519 要求）
	privateKeyBytes[0] &= 248
	privateKeyBytes[31] &= 127
	privateKeyBytes[31] |= 64

	// 计算公钥 = privateKey * basePoint
	publicKeyBytes, err := curve25519.X25519(privateKeyBytes[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("计算 X25519 公钥失败: %w", err)
	}

	return &RealityKeyPair{
		PrivateKey: base64.RawStdEncoding.EncodeToString(privateKeyBytes[:]),
		PublicKey:  base64.RawStdEncoding.EncodeToString(publicKeyBytes),
	}, nil
}

// GenerateShortID 生成 Reality Short ID（8 字节随机 hex）
// 输出为 16 字符的十六进制字符串，与 sing-box generate rand --hex 8 一致。
func GenerateShortID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("生成 Short ID 失败: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateUUID 生成 UUID v4（用于 VLESS/VMess/TUIC 的 uuid 字段）
// 格式: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
func GenerateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", fmt.Errorf("生成 UUID 失败: %w", err)
	}

	// RFC 4122 version 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// GeneratePassword 生成随机密码（用于 SS/HY2/Trojan 等协议）
// 返回指定长度的 base64url 编码字符串（无填充）。
func GeneratePassword(length int) (string, error) {
	if length <= 0 {
		length = 16
	}
	// 生成足够的随机字节，base64 编码后截取
	rawLen := (length*3)/4 + 1
	bytes := make([]byte, rawLen)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("生成随机密码失败: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(bytes)
	if len(encoded) > length {
		encoded = encoded[:length]
	}
	return encoded, nil
}
