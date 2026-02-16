package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ---------------------------------------------------------
// 1. 结构体定义 (严格保证 YAML 字段的输出顺序)
// ---------------------------------------------------------

// ClashNode 统一节点结构体，利用字段声明顺序强制规范 YAML 节点的按序输出
type ClashNode struct {
	Name                 string                 `yaml:"name"`
	Type                 string                 `yaml:"type"`
	Server               string                 `yaml:"server"`
	Port                 int                    `yaml:"port"`
	Password             string                 `yaml:"password,omitempty"`
	UUID                 string                 `yaml:"uuid,omitempty"`
	Cipher               string                 `yaml:"cipher,omitempty"`
	AlterId              int                    `yaml:"alterId,omitempty"`
	Network              string                 `yaml:"network,omitempty"`
	UDP                  bool                   `yaml:"udp,omitempty"`
	TLS                  bool                   `yaml:"tls,omitempty"`
	SkipCertVerify       bool                   `yaml:"skip-cert-verify,omitempty"`
	ServerName           string                 `yaml:"servername,omitempty"`
	SNI                  string                 `yaml:"sni,omitempty"`
	ALPN                 []string               `yaml:"alpn,omitempty"`
	Flow                 string                 `yaml:"flow,omitempty"`
	PacketEncoding       string                 `yaml:"packet-encoding,omitempty"`
	RealityOpts          map[string]interface{} `yaml:"reality-opts,omitempty"`
	ClientFingerprint    string                 `yaml:"client-fingerprint,omitempty"`
	WSOpts               map[string]interface{} `yaml:"ws-opts,omitempty"`
	GRPCOpts             map[string]interface{} `yaml:"grpc-opts,omitempty"`
	H2Opts               map[string]interface{} `yaml:"h2-opts,omitempty"`
	HTTPOpts             map[string]interface{} `yaml:"http-opts,omitempty"`
	Obfs                 string                 `yaml:"obfs,omitempty"`
	ObfsPassword         string                 `yaml:"obfs-password,omitempty"`
	Ports                string                 `yaml:"ports,omitempty"`
	Up                   int                    `yaml:"up,omitempty"`
	Down                 int                    `yaml:"down,omitempty"`
	DisableSNI           bool                   `yaml:"disable-sni,omitempty"`
	CongestionController string                 `yaml:"congestion-controller,omitempty"`
	UDPRelayMode         string                 `yaml:"udp-relay-mode,omitempty"`
	ReduceRTT            bool                   `yaml:"reduce-rtt,omitempty"`
	ZeroRTT              bool                   `yaml:"zero-rtt,omitempty"`
	TFO                  bool                   `yaml:"tfo,omitempty"`
	Username             string                 `yaml:"username,omitempty"`
}

// ---------------------------------------------------------
// 2. 基础工具函数
// ---------------------------------------------------------

func getEmojiFlag(region string) string {
	if region == "" {
		return "🌐"
	}
	region = strings.ToUpper(strings.TrimSpace(region))
	if len(region) == 2 {
		const offset = 127397
		return string(rune(region[0])+offset) + string(rune(region[1])+offset)
	}
	return region
}

func safeBase64Decode(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if padding := len(s) % 4; padding > 0 {
		s += strings.Repeat("=", 4-padding)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func getBool(query url.Values, keys ...string) bool {
	for _, k := range keys {
		val := strings.ToLower(query.Get(k))
		if val == "1" || val == "true" || val == "yes" || val == "on" {
			return true
		}
	}
	return false
}

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok && val != nil {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok && val != nil {
		switch v := val.(type) {
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return 0
}

// ---------------------------------------------------------
// 3. 协议转换统一入口
// ---------------------------------------------------------

func ParseProxyLink(link, baseName, region string, useFlag bool) *ClashNode {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil
	}

	finalName := baseName
	if useFlag && region != "" {
		flag := getEmojiFlag(region)
		finalName = fmt.Sprintf("%s %s", flag, strings.ReplaceAll(baseName, flag, ""))
	}
	finalName = strings.TrimSpace(finalName)

	lowerLink := strings.ToLower(link)

	if strings.HasPrefix(lowerLink, "vmess://") {
		return parseVmess(link, finalName)
	} else if strings.HasPrefix(lowerLink, "vless://") {
		return parseVless(link, finalName)
	} else if strings.HasPrefix(lowerLink, "trojan://") {
		return parseTrojan(link, finalName)
	} else if strings.HasPrefix(lowerLink, "hy2://") || strings.HasPrefix(lowerLink, "hysteria2://") {
		return parseHysteria2(link, finalName)
	} else if strings.HasPrefix(lowerLink, "tuic://") {
		return parseTuic(link, finalName)
	} else if strings.HasPrefix(lowerLink, "ss://") {
		return parseSS(link, finalName)
	} else if strings.HasPrefix(lowerLink, "socks5://") {
		return parseSocks5(link, finalName)
	}
	return nil
}

// ---------------------------------------------------------
// 4. 各协议独立解析逻辑
// ---------------------------------------------------------

func parseVless(link, proxyName string) *ClashNode {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil
	}

	portInt, _ := strconv.Atoi(parsed.Port())
	query := parsed.Query()
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}

	node := &ClashNode{
		Name:           proxyName,
		Type:           "vless",
		Server:         parsed.Hostname(),
		Port:           portInt,
		UUID:           parsed.User.Username(),
		Network:        network,
		UDP:            true,
		TFO:            getBool(query, "fast-open"),
		SkipCertVerify: getBool(query, "insecure", "skip-cert-verify", "allowInsecure"),
		ServerName:     query.Get("sni"),
		Flow:           query.Get("flow"),
	}

	if alpn := query.Get("alpn"); alpn != "" {
		node.ALPN = strings.Split(alpn, ",")
	}

	security := query.Get("security")
	if security == "reality" {
		node.TLS = true
		node.RealityOpts = map[string]interface{}{
			"public-key": query.Get("pbk"),
			"short-id":   query.Get("sid"),
		}
		if fp := query.Get("fp"); fp != "" {
			node.ClientFingerprint = fp
		} else {
			node.ClientFingerprint = "chrome"
		}
	} else if security == "tls" || getBool(query, "tls") {
		node.TLS = true
		if fp := query.Get("fp"); fp != "" {
			node.ClientFingerprint = fp
		}
	}

	applyTransportOpts(node, network, query)
	return node
}

func parseTrojan(link, proxyName string) *ClashNode {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil
	}

	portInt, _ := strconv.Atoi(parsed.Port())
	query := parsed.Query()
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}

	node := &ClashNode{
		Name:           proxyName,
		Type:           "trojan",
		Server:         parsed.Hostname(),
		Port:           portInt,
		Password:       parsed.User.Username(),
		Network:        network,
		UDP:            true,
		TFO:            getBool(query, "fast-open"),
		SkipCertVerify: getBool(query, "insecure", "skip-cert-verify"),
		SNI:            query.Get("sni"),
	}

	if alpn := query.Get("alpn"); alpn != "" {
		node.ALPN = strings.Split(alpn, ",")
	}
	if fp := query.Get("fp"); fp != "" {
		node.ClientFingerprint = fp
	}

	if query.Get("security") == "reality" {
		node.RealityOpts = map[string]interface{}{
			"public-key": query.Get("pbk"),
			"short-id":   query.Get("sid"),
		}
	}

	applyTransportOpts(node, network, query)
	return node
}

func parseHysteria2(link, proxyName string) *ClashNode {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil
	}

	portInt, _ := strconv.Atoi(parsed.Port())
	query := parsed.Query()
	password := parsed.User.Username()
	if password == "" {
		password = query.Get("auth")
	}

	node := &ClashNode{
		Name:           proxyName,
		Type:           "hysteria2",
		Server:         parsed.Hostname(),
		Port:           portInt,
		Password:       password,
		UDP:            true,
		SkipCertVerify: getBool(query, "insecure", "skip-cert-verify", "allowInsecure"),
	}

	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("peer")
	}
	node.SNI = sni

	if alpn := query.Get("alpn"); alpn != "" {
		node.ALPN = strings.Split(alpn, ",")
	}
	if obfs := query.Get("obfs"); obfs != "" {
		node.Obfs = obfs
		node.ObfsPassword = query.Get("obfs-password")
	}
	if ports := query.Get("ports"); ports != "" {
		node.Ports = ports
	}

	up := query.Get("up")
	if up == "" {
		up = query.Get("upmbps")
	}
	if upInt, _ := strconv.Atoi(up); upInt > 0 {
		node.Up = upInt
	}

	down := query.Get("down")
	if down == "" {
		down = query.Get("downmbps")
	}
	if downInt, _ := strconv.Atoi(down); downInt > 0 {
		node.Down = downInt
	}

	return node
}

func parseTuic(link, proxyName string) *ClashNode {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil
	}

	portInt, _ := strconv.Atoi(parsed.Port())
	query := parsed.Query()
	password, _ := parsed.User.Password()

	node := &ClashNode{
		Name:                 proxyName,
		Type:                 "tuic",
		Server:               parsed.Hostname(),
		Port:                 portInt,
		UUID:                 parsed.User.Username(),
		Password:             password,
		TLS:                  true,
		UDP:                  true,
		DisableSNI:           getBool(query, "disable-sni"),
		SkipCertVerify:       getBool(query, "insecure", "skip-cert-verify", "allowInsecure") || true,
		CongestionController: query.Get("congestion_controller"),
		UDPRelayMode:         query.Get("udp-relay-mode"),
		ReduceRTT:            getBool(query, "reduce-rtt"),
		ZeroRTT:              getBool(query, "zero-rtt"),
	}

	if node.CongestionController == "" {
		node.CongestionController = "bbr"
	}
	if node.UDPRelayMode == "" {
		node.UDPRelayMode = "native"
	}

	if alpn := query.Get("alpn"); alpn != "" {
		node.ALPN = strings.Split(alpn, ",")
	} else {
		node.ALPN = []string{"h3"}
	}

	if sni := query.Get("sni"); sni != "" {
		node.SNI = sni
		node.ServerName = sni
	}

	return node
}

func parseVmess(link, proxyName string) *ClashNode {
	b64Part := link[8:]
	if idx := strings.Index(b64Part, "#"); idx != -1 {
		b64Part = b64Part[:idx]
	}

	decoded := safeBase64Decode(b64Part)
	if decoded == "" {
		return nil
	}

	var v map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil
	}

	serverAddr := getString(v, "add")
	if strings.Contains(serverAddr, ":") && !strings.HasPrefix(serverAddr, "[") {
		serverAddr = "[" + serverAddr + "]"
	}

	node := &ClashNode{
		Name:    proxyName,
		Type:    "vmess",
		Server:  serverAddr,
		Port:    getInt(v, "port"),
		UUID:    getString(v, "id"),
		AlterId: getInt(v, "aid"),
		Cipher:  getString(v, "scy"),
		UDP:     true,
	}

	if node.Cipher == "" {
		node.Cipher = "auto"
	}

	tlsVal := getString(v, "tls")
	if tlsVal != "" && strings.ToLower(tlsVal) != "none" {
		node.TLS = true
		if sni := getString(v, "sni"); sni != "" {
			node.ServerName = sni
		}
		if v["skip-cert-verify"] == true || v["insecure"] == true || getString(v, "insecure") == "1" {
			node.SkipCertVerify = true
		}
	}

	net := getString(v, "net")
	if net == "" {
		net = "tcp"
	}
	typeField := getString(v, "type")
	if typeField == "" {
		typeField = net
	}

	query := url.Values{}
	if path := getString(v, "path"); path != "" {
		query.Set("path", path)
	}
	if host := getString(v, "host"); host != "" {
		query.Set("host", host)
	} else if sni := getString(v, "sni"); sni != "" {
		query.Set("host", sni)
	}

	if net == "http" || (net == "tcp" && typeField == "http") {
		net = "http"
	}

	node.Network = net
	applyTransportOpts(node, net, query)

	return node
}

func parseSS(link, proxyName string) *ClashNode {
	body := link[5:]
	if idx := strings.Index(body, "#"); idx != -1 {
		body = body[:idx]
	}
	if idx := strings.Index(body, "?"); idx != -1 {
		body = body[:idx]
	}

	if !strings.Contains(body, "@") {
		if decoded := safeBase64Decode(body); decoded != "" {
			body = decoded
		}
	}

	if strings.Contains(body, "@") {
		parts := strings.SplitN(body, "@", 2)
		userInfo := parts[0]
		hostPart := parts[1]

		if !strings.Contains(userInfo, ":") {
			if decodedUser := safeBase64Decode(userInfo); decodedUser != "" {
				userInfo = decodedUser
			}
		}

		if strings.Contains(userInfo, ":") {
			userParts := strings.SplitN(userInfo, ":", 2)
			method := userParts[0]
			password := userParts[1]

			lastColon := strings.LastIndex(hostPart, ":")
			if lastColon != -1 {
				server := hostPart[:lastColon]
				portInt, _ := strconv.Atoi(hostPart[lastColon+1:])

				if strings.Contains(server, ":") && !strings.HasPrefix(server, "[") {
					server = "[" + server + "]"
				}

				return &ClashNode{
					Name:     proxyName,
					Type:     "ss",
					Server:   server,
					Port:     portInt,
					Cipher:   method,
					Password: password,
					UDP:      true,
				}
			}
		}
	}
	return nil
}

func parseSocks5(link, proxyName string) *ClashNode {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil
	}

	portInt, _ := strconv.Atoi(parsed.Port())
	if portInt == 0 {
		portInt = 1080
	}
	query := parsed.Query()
	password, _ := parsed.User.Password()

	node := &ClashNode{
		Name:           proxyName,
		Type:           "socks5",
		Server:         parsed.Hostname(),
		Port:           portInt,
		Username:       parsed.User.Username(),
		Password:       password,
		UDP:            true,
		SkipCertVerify: getBool(query, "insecure", "skip-cert-verify"),
	}

	if getBool(query, "tls") {
		node.TLS = true
		if sni := query.Get("sni"); sni != "" {
			node.ServerName = sni
		}
	}

	return node
}

// ---------------------------------------------------------
// 5. 通用传输层 (Transport) 参数挂载
// ---------------------------------------------------------
func applyTransportOpts(node *ClashNode, network string, query url.Values) {
	if network == "ws" {
		node.WSOpts = map[string]interface{}{
			"path":    "/",
			"headers": map[string]string{},
		}
		if p := query.Get("path"); p != "" {
			node.WSOpts["path"] = p
		}
		if h := query.Get("host"); h != "" {
			node.WSOpts["headers"].(map[string]string)["Host"] = h
		}
	} else if network == "grpc" {
		node.GRPCOpts = map[string]interface{}{
			"grpc-service-name": "",
		}
		if s := query.Get("serviceName"); s != "" {
			node.GRPCOpts["grpc-service-name"] = s
		}
	} else if network == "h2" {
		node.H2Opts = map[string]interface{}{}
		if p := query.Get("path"); p != "" {
			node.H2Opts["path"] = strings.Split(p, ",")
		} else {
			node.H2Opts["path"] = []string{"/"}
		}
		if h := query.Get("host"); h != "" {
			node.H2Opts["host"] = strings.Split(h, ",")
		}
	} else if network == "http" {
		node.HTTPOpts = map[string]interface{}{
			"method": "GET",
		}
		if p := query.Get("path"); p != "" {
			node.HTTPOpts["path"] = strings.Split(p, ",")
		} else {
			node.HTTPOpts["path"] = []string{"/"}
		}
		if h := query.Get("host"); h != "" {
			node.HTTPOpts["headers"] = map[string]interface{}{
				"Host": strings.Split(h, ","),
			}
		}
	}
}
