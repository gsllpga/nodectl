mixed-port: 7890
redir-port: 7891
tproxy-port: 1536
ipv6: true
mode: Rule
allow-lan: true
disable-keep-alive: true
geodata-mode: true
geo-auto-update: false
geo-update-interval: 24
geox-url:
  asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
experimental:
  http-headers:
    request:
      - name: "User-Agent"
        value: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36"
      - name: "Accept-Language"
        value: "en-US,en;q=0.9"
unified-delay: true
tcp-concurrent: true
log-level: silent
find-process-mode: always
global-client-fingerprint: chrome

# -------------------- 订阅提供商 --------------------
#此为地址替换识别符号，请勿更改格式
# —————————
proxy-providers:
  中转机场:
    type: http
    interval: 86400
    url: "{{.RelaySubURL}}"
    path: ./proxy_providers/clash-node.yaml
    health-check:
      enable: false
      url: https://www.gstatic.com/generate_204
      interval: 300
  落地机场:
    type: http
    interval: 86400
    url: "{{.ExitSubURL}}"
    path: ./proxy_providers/exit.yaml
    health-check:
      enable: false
      url: https://www.gstatic.com/generate_204
      interval: 300
    override:
      dialer-proxy: '💠 中转选择'
      skip-proxy: false

profile: # ← 此函数位置请勿变动！此为模块更新时备份恢复订阅变量范围 
  store-selected: true
  store-fake-ip: true

# 嗅探模块
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
    TLS:
      ports: [443, 5228, 8443]
    QUIC:
      ports: [443, 8443]
  force-domain:
    - "+.v2ex.com"
  skip-domain: # 如遇需内部通信的应用请放行该域名
    - "Mijia Cloud"
# —————————

# 网卡模块
tun:
  enable: false  # true 开 # false 默认关
  device: Meta
  stack: mixed
  dns-hijack:
    - any:53
    - tcp://any:53
  udp-timeout: 300
  auto-route: true
  strict-route: true
  auto-redirect: false
  auto-detect-interface: true

dns:
  enable: true
  ipv6: true
  listen: 0.0.0.0:1053
  enhanced-mode: redir-host
  fake-ip-range: 172.20.0.1/16
  fake-ip-filter:
    - "RULE-SET:CN_域"
    - "RULE-SET:Private_域"
    {{if .Modules.GoogleFCM}}
    - "RULE-SET:GoogleFCM_域"
    {{end}}
    - "+.3gppnetwork.org"
    - "+.xtracloud.net"
  direct-nameserver:
    - https://doh.pub/dns-query#🇨🇳 大陆&h3=false
    - https://dns.alidns.com/dns-query#🇨🇳 大陆&h3=true
  proxy-server-nameserver:
    - https://doh.pub/dns-query#🇨🇳 大陆&h3=false
    - https://dns.alidns.com/dns-query#🇨🇳 大陆&h3=true
  nameserver-policy:
    "RULE-SET:CN_域{{if .Modules.Microsoft}},Microsoft_域{{end}}{{if .Modules.Apple}},Apple_域{{end}}":
       - https://doh.pub/dns-query#🇨🇳 大陆&h3=false
       - https://dns.alidns.com/dns-query#🇨🇳 大陆&h3=true
  nameserver:
    - https://dns.google/dns-query#DNS连接&h3=true
    - https://cloudflare-dns.com/dns-query#DNS连接&h3=true

proxies:
    - {name: 🇨🇳 大陆, type: direct, udp: true}
    - {name: ⛔️ 拒绝连接, type: reject}
    - {name: 🌐 DNS_Hijack, type: dns}

# -------------------- 策略组锚点 --------------------
proxy_groups: &proxy_groups
  type: select 
  proxies: 
    - 总模式
    - 🇨🇳 大陆
    - ⛔️ 拒绝连接
  use: 
    - 中转机场
    - 落地机场

# -------------------- 策略组定义 --------------------
proxy-groups:
  - name: 总模式
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/All.svg"
    type: select
    proxies:
      - 🇨🇳 大陆
    use:
      - 中转机场
      - 落地机场

  - name: '💠 中转选择'
    type: select
    use:
      - 中转机场

  - name: 订阅更新
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Update.svg"
    type: select
    proxies:
      - 🇨🇳 大陆
      - 总模式

{{if .Modules.XiaoHongShu}}
  - name: 小红书
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/XiaoHongShu.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.DouYin}}
  - name: 抖音
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DouYin.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.BiliBili}}
  - name: BiliBili
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/BiliBili.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Steam}}
  - name: Steam
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Steam.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Apple}}
  - name: Apple
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Apple.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Microsoft}}
  - name: Microsoft
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Microsoft.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Telegram}}
  - name: Telegram
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Telegram.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Discord}}
  - name: Discord
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Discord.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Spotify}}
  - name: Spotify
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Spotify.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.TikTok}}
  - name: TikTok
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/TikTok.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.YouTube}}
  - name: YouTube
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/YouTube.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Netflix}}
  - name: Netflix
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Netflix.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Google}}
  - name: Google
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Google.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.GoogleFCM}}
  - name: GoogleFCM
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/GoogleFCM.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Facebook}}
  - name: Facebook
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Facebook.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.OpenAI}}
  - name: OpenAI
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/OpenAI.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.GitHub}}
  - name: GitHub
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/GitHub.svg"
    <<: *proxy_groups
{{end}}

{{if .Modules.Twitter}}
  - name: Twitter(X)
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Twitter.svg"
    <<: *proxy_groups
{{end}}

  # 基础核心功能策略组保留
  - name: DNS连接
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DNS.svg"
    <<: *proxy_groups

  - name: 漏网之鱼
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/HBASE-copy.svg"
    <<: *proxy_groups

  - name: 自定义出站
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/User.svg"
    type: select
    <<: *proxy_groups

rule-anchor:
  Local: &Local
    {type: file, behavior: classical, format: text}
  Classical: &Classical
    {type: http, behavior: classical, format: text, interval: 86400}
  IPCIDR: &IPCIDR
    {type: http, behavior: ipcidr, format: mrs, interval: 86400}
  Domain: &Domain
    {type: http, behavior: domain, format: mrs, interval: 86400}

# —————————

rule-providers:
  # ------ 核心基础 Providers 保留 ------
  我的直连规则:
    type: http
    behavior: classical
    format: text
    url: "直连规则订阅地址/direct.list"
    path: ./rules/direct.list
    interval: 86400
  自定义出站:
    type: http
    behavior: classical
    format: text
    url: "定义规则订阅地址/customize.list"
    path: ./rules/customize.list
    interval: 3600
  WebRTC_端/域:
    <<: *Classical
    path: ./rules/WebRTC.list
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/rules/WebRTC.list"
  CN_IP:
    <<: *IPCIDR
    path: ./rules/CN_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs"
  CN_域:
    <<: *Domain
    path: ./rules/CN_域.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs"
  No-ads-all_域:
    <<: *Domain
    path: ./rules/No-ads-all.mrs
    url: "https://anti-ad.net/mihomo.mrs"
  Private_域:
    <<: *Domain
    path: ./rules/LAN.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_Domain.mrs"
  Private_IP:
    <<: *IPCIDR
    path: ./rules/Private_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_IP.mrs"

  # ------ 动态模块 Providers ------
{{if .Modules.XiaoHongShu}}
  XiaoHongShu_域:
    <<: *Domain
    path: ./rules/XiaoHongShu.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/XiaoHongShu/XiaoHongShu_OCD_Domain.mrs"
{{end}}

{{if .Modules.DouYin}}
  DouYin_域:
    <<: *Domain
    path: ./rules/DouYin.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/DouYin/DouYin_OCD_Domain.mrs"
{{end}}

{{if .Modules.BiliBili}}
  BiliBili_域:
    <<: *Domain
    path: ./rules/BiliBili.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/BiliBili/BiliBili_OCD_Domain.mrs"
  BiliBili_IP:
    <<: *IPCIDR
    path: ./rules/BiliBili_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/BiliBili/BiliBili_OCD_IP.mrs"
{{end}}

{{if .Modules.Steam}}
  Steam_域:
    <<: *Domain
    path: ./rules/Steam.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Steam/Steam_OCD_Domain.mrs"
{{end}}

{{if .Modules.TikTok}}
  TikTok_域:
    <<: *Domain
    path: ./rules/TikTok.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/TikTok/TikTok_OCD_Domain.mrs"
{{end}}

{{if .Modules.Spotify}}
  Spotify_域:
    <<: *Domain
    path: ./rules/Spotify.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Spotify/Spotify_OCD_Domain.mrs"
  Spotify_IP:
    <<: *IPCIDR
    path: ./rules/Spotify_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Spotify/Spotify_OCD_IP.mrs"
{{end}}

{{if .Modules.Facebook}}
  Facebook_域:
    <<: *Domain
    path: ./rules/Facebook.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Facebook/Facebook_OCD_Domain.mrs"
  Facebook_IP:
    <<: *IPCIDR
    path: ./rules/Facebook_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Facebook/Facebook_OCD_IP.mrs"
{{end}}

{{if .Modules.Telegram}}
  Telegram_域:
    <<: *Domain
    path: ./rules/Telegram.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Telegram/Telegram_OCD_Domain.mrs"
  Telegram_IP:
    <<: *IPCIDR
    path: ./rules/Telegram_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Telegram/Telegram_OCD_IP.mrs"
{{end}}

{{if .Modules.YouTube}}
  YouTube_域:
    <<: *Domain
    path: ./rules/YouTube.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/YouTube/YouTube_OCD_Domain.mrs"
  YouTube_IP:
    <<: *IPCIDR
    path: ./rules/YouTube_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/YouTube/YouTube_OCD_IP.mrs"
{{end}}

{{if .Modules.Google}}
  Google_域:
    <<: *Domain
    path: ./rules/Google.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Google/Google_OCD_Domain.mrs"
  Google_IP:
    <<: *IPCIDR
    path: ./rules/Google_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Google/Google_OCD_IP.mrs"
{{end}}

{{if .Modules.GoogleFCM}}
  GoogleFCM_域:
    <<: *Domain
    path: ./rules/GoogleFCM.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GoogleFCM/GoogleFCM_OCD_Domain.mrs"
  GoogleFCM_IP:
    <<: *IPCIDR
    path: ./rules/GoogleFCM_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GoogleFCM/GoogleFCM_OCD_IP.mrs"
{{end}}

{{if .Modules.Microsoft}}
  Microsoft_域:
    <<: *Domain
    path: ./rules/Microsoft.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Microsoft/Microsoft_OCD_Domain.mrs"
{{end}}

{{if .Modules.Apple}}
  Apple_域:
    <<: *Domain
    path: ./rules/Apple.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Apple/Apple_OCD_Domain.mrs"
  Apple_IP:
    <<: *IPCIDR
    path: ./rules/Apple_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Apple/Apple_OCD_IP.mrs"
{{end}}

{{if .Modules.OpenAI}}
  OpenAI_域:
    <<: *Domain
    path: ./rules/OpenAI.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/OpenAI/OpenAI_OCD_Domain.mrs"
  OpenAI_IP:
    <<: *IPCIDR
    path: ./rules/OpenAI_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/OpenAI/OpenAI_OCD_IP.mrs"
{{end}}

{{if .Modules.Netflix}}
  Netflix_域:
    <<: *Domain
    path: ./rules/Netflix.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Netflix/Netflix_OCD_Domain.mrs"
  Netflix_IP:
    <<: *IPCIDR
    path: ./rules/Netflix_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Netflix/Netflix_OCD_IP.mrs"
{{end}}

{{if .Modules.Discord}}
  Discord_域:
    <<: *Domain
    path: ./rules/Discord.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Discord/Discord_OCD_Domain.mrs"
{{end}}

{{if .Modules.GitHub}}
  GitHub_域:
    <<: *Domain
    path: ./rules/GitHub.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GitHub/GitHub_OCD_Domain.mrs"
{{end}}

{{if .Modules.Twitter}}
  Twitter_域:
    <<: *Domain
    path: ./rules/Twitter.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Twitter/Twitter_OCD_Domain.mrs"
  Twitter_IP:
    <<: *IPCIDR
    path: ./rules/Twitter_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Twitter/Twitter_OCD_IP.mrs"
{{end}}


rules:
  # ------ 核心基础 Rules 保留 ------
  - RULE-SET,我的直连规则,🇨🇳 大陆
  - RULE-SET,自定义出站,自定义出站
  - RULE-SET,No-ads-all_域,⛔️ 拒绝连接
  - RULE-SET,WebRTC_端/域,⛔️ 拒绝连接
  - DST-PORT,53,🌐 DNS_Hijack
  - DST-PORT,853,DNS连接

  # ------ 动态模块 Rules ------
{{if .Modules.DouYin}}
  - PROCESS-PATH,com.ss.android.ugc.aweme,抖音
  - RULE-SET,DouYin_域,抖音
{{end}}

{{if .Modules.XiaoHongShu}}
  - PROCESS-PATH,com.xingin.xhs,小红书
  - RULE-SET,XiaoHongShu_域,小红书
{{end}}

{{if .Modules.BiliBili}}
  - PROCESS-PATH,tv.danmaku.bili,BiliBili
  - RULE-SET,BiliBili_域,BiliBili
  - RULE-SET,BiliBili_IP,BiliBili
{{end}}

{{if .Modules.Steam}}
  - RULE-SET,Steam_域,Steam
{{end}}

{{if .Modules.GitHub}}
  - RULE-SET,GitHub_域,GitHub
{{end}}

{{if .Modules.Discord}}
  - RULE-SET,Discord_域,Discord
{{end}}

{{if .Modules.TikTok}}
  - RULE-SET,TikTok_域,TikTok
{{end}}

{{if .Modules.Twitter}}
  - RULE-SET,Twitter_域,Twitter(X)
  - RULE-SET,Twitter_IP,Twitter(X)
{{end}}

{{if .Modules.YouTube}}
  - RULE-SET,YouTube_域,YouTube
  - RULE-SET,YouTube_IP,YouTube
{{end}}

{{if .Modules.GoogleFCM}}
  - DOMAIN-KEYWORD,mtalk.google,GoogleFCM
  - RULE-SET,GoogleFCM_域,GoogleFCM
  - RULE-SET,GoogleFCM_IP,GoogleFCM
{{end}}

{{if .Modules.Google}}
  - RULE-SET,Google_域,Google
  - RULE-SET,Google_IP,Google
{{end}}

{{if .Modules.Netflix}}
  - RULE-SET,Netflix_域,Netflix
  - RULE-SET,Netflix_IP,Netflix
{{end}}

{{if .Modules.Spotify}}
  - RULE-SET,Spotify_域,Spotify
  - RULE-SET,Spotify_IP,Spotify
{{end}}

{{if .Modules.Facebook}}
  - RULE-SET,Facebook_域,Facebook
  - RULE-SET,Facebook_IP,Facebook
{{end}}

{{if .Modules.OpenAI}}
  - RULE-SET,OpenAI_域,OpenAI
  - RULE-SET,OpenAI_IP,OpenAI
{{end}}

{{if .Modules.Apple}}
  - RULE-SET,Apple_域,Apple
  - RULE-SET,Apple_IP,Apple
{{end}}

{{if .Modules.Microsoft}}
  - RULE-SET,Microsoft_域,Microsoft
{{end}}

{{if .Modules.Telegram}}
  - RULE-SET,Telegram_域,Telegram
  - RULE-SET,Telegram_IP,Telegram
{{end}}

  # ------ 核心收尾 Rules ------
  - DOMAIN,browserleaks.com,漏网之鱼
  - RULE-SET,CN_域,🇨🇳 大陆
  - RULE-SET,CN_IP,🇨🇳 大陆
  - RULE-SET,Private_域,🇨🇳 大陆
  - RULE-SET,Private_IP,🇨🇳 大陆
  - MATCH,漏网之鱼