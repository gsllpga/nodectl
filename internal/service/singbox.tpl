#!/usr/bin/env bash
set -euo pipefail

# Shadowsocks 端口
FIXED_PORT_SS={{.PortSS}}
FIXED_PORT_HY2={{.PortHY2}}
FIXED_PORT_TUIC={{.PortTUIC}}
FIXED_PORT_REALITY={{.PortReality}}
FIXED_REALITY_SNI="{{.VlessTLSSNI}}"
FIXED_SS_METHOD="{{.SSMethod}}"
FIXED_PORT_SOCKS5={{.PortSocks5}}
FIXED_SOCKS5_USER="{{.Socks5User}}"
FIXED_SOCKS5_PASS="{{.Socks5Pass}}"
# 新增协议端口
FIXED_PORT_TROJAN={{.PortTrojan}}
FIXED_PORT_VLESS_H2={{.PortVlessH2}}
# 可配置 SNI（各协议客户端伪装域名）
FIXED_HY2_SNI="{{.HY2SNI}}"
FIXED_TUIC_SNI="{{.TUICSNI}}"
FIXED_TROJAN_SNI="{{.TrojanTLSSNI}}"
# 系统优化
FIXED_ENABLE_BBR="{{.EnableBBR}}"
# VMess 协议族端口
FIXED_PORT_VMESS_TCP={{.PortVmessTCP}}
FIXED_PORT_VMESS_WS={{.PortVmessWS}}
FIXED_PORT_VMESS_HTTP={{.PortVmessHTTP}}
FIXED_PORT_VMESS_QUIC={{.PortVmessQUIC}}
# VMess+TLS 传输族端口
FIXED_PORT_VMESS_WST={{.PortVmessWST}}
FIXED_PORT_VMESS_H2T={{.PortVmessH2T}}
FIXED_PORT_VMESS_HUT={{.PortVmessHUT}}
# VLESS+TLS 传输族端口
FIXED_PORT_VLESS_WST={{.PortVlessWST}}
FIXED_PORT_VLESS_H2T={{.PortVlessH2T}}
FIXED_PORT_VLESS_HUT={{.PortVlessHUT}}
# Trojan+TLS 传输族端口
FIXED_PORT_TROJAN_WST={{.PortTrojanWST}}
FIXED_PORT_TROJAN_H2T={{.PortTrojanH2T}}
FIXED_PORT_TROJAN_HUT={{.PortTrojanHUT}}
# TLS 传输协议共用路径
FIXED_TLS_TRANSPORT_PATH="{{.TLSTransportPath}}"
FIXED_VMESS_TLS_SNI="{{.VmessTLSSNI}}"
FIXED_VLESS_TLS_SNI="{{.VlessTLSSNI}}"
FIXED_TROJAN_TLS_SNI="{{.TrojanTLSSNI}}"
REPORT_URL="{{.ReportURL}}"
INSTALL_ID="{{.InstallID}}" # 直接由后端渲染注入
RESET_DAY="{{.ResetDay}}"
# -----------------------
# 彩色输出函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
    else
        OS_ID=""
        OS_ID_LIKE=""
    fi

    if echo "$OS_ID $OS_ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi
}

detect_os
info "SingBox安装脚本: v0.1.2"
info "检测到系统: $OS (${OS_ID:-unknown})"

# -----------------------
# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限"
        err "请使用: sudo bash -c \"\$(curl -fsSL ...)\" 或切换到 root 用户"
        exit 1
    fi
}

check_root

# -----------------------
# 安装依赖
install_deps() {
    info "安装系统依赖..."
    
    case "$OS" in
        alpine)
            apk update || { err "apk update 失败"; exit 1; }
            apk add --no-cache bash curl ca-certificates openssl openrc jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || { err "apt update 失败"; exit 1; }
            apt-get install -y curl ca-certificates openssl jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        redhat)
            yum install -y curl ca-certificates openssl jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        *)
            warn "未识别的系统类型,尝试继续..."
            ;;
    esac
    
    info "依赖安装完成"
}

install_deps

# -----------------------
# 工具函数
# 生成随机密码
rand_pass() {
    local pass
    pass=$(openssl rand -base64 16 2>/dev/null | tr -d '\n\r') || pass=$(head -c 16 /dev/urandom | base64 2>/dev/null | tr -d '\n\r')
    echo "$pass"
}

# 生成UUID
rand_uuid() {
    local uuid
    if [ -f /proc/sys/kernel/random/uuid ]; then
        uuid=$(cat /proc/sys/kernel/random/uuid)
    else
        uuid=$(openssl rand -hex 16 | awk '{print substr($0,1,8)"-"substr($0,9,4)"-"substr($0,13,4)"-"substr($0,17,4)"-"substr($0,21,12)}')
    fi
    echo "$uuid"
}

# -----------------------
# 配置节点名称后缀 (自动获取主机名)
# 直接获取机器 hostname
user_name=$(hostname)

if [[ -n "$user_name" ]]; then
    suffix="-${user_name}"
    # 将后缀写入文件，供 sb 管理脚本读取
    echo "$suffix" > /root/node_names.txt
else
    suffix=""
    rm -f /root/node_names.txt 2>/dev/null
fi

info "节点名称后缀已自动设置为: $suffix"

# -----------------------
# 选择要部署的协议
select_protocols() {
    # 初始化所有协议开关
    ENABLE_SS=false; ENABLE_HY2=false; ENABLE_TUIC=false; ENABLE_REALITY=false; ENABLE_SOCKS5=false
    ENABLE_TROJAN=false; ENABLE_VLESS_H2=false
    # VMess 族
    ENABLE_VMESS_TCP=false; ENABLE_VMESS_WS=false; ENABLE_VMESS_HTTP=false; ENABLE_VMESS_QUIC=false
    # VMess+TLS 传输族
    ENABLE_VMESS_WST=false; ENABLE_VMESS_H2T=false; ENABLE_VMESS_HUT=false
    # VLESS+TLS 传输族
    ENABLE_VLESS_WST=false; ENABLE_VLESS_H2T=false; ENABLE_VLESS_HUT=false
    # Trojan+TLS 传输族
    ENABLE_TROJAN_WST=false; ENABLE_TROJAN_H2T=false; ENABLE_TROJAN_HUT=false

    _any_enabled() {
        $ENABLE_SS || $ENABLE_HY2 || $ENABLE_TUIC || $ENABLE_REALITY || $ENABLE_SOCKS5 || \
        $ENABLE_TROJAN || $ENABLE_VLESS_H2 || \
        $ENABLE_VMESS_TCP || $ENABLE_VMESS_WS || $ENABLE_VMESS_HTTP || $ENABLE_VMESS_QUIC || \
        $ENABLE_VMESS_WST || $ENABLE_VMESS_H2T || $ENABLE_VMESS_HUT || \
        $ENABLE_VLESS_WST || $ENABLE_VLESS_H2T || $ENABLE_VLESS_HUT || \
        $ENABLE_TROJAN_WST || $ENABLE_TROJAN_H2T || $ENABLE_TROJAN_HUT
    }

    while [[ $# -gt 0 ]]; do
        arg="$1"
        arg_lower=$(echo "$arg" | tr '[:upper:]' '[:lower:]')
        case "$arg_lower" in
            --reset-day)
                if [[ -n "${2:-}" ]]; then RESET_DAY="$2"; info "-> 设定流量重置日: 每月 $RESET_DAY 号"; shift
                else warn "--reset-day 参数后面必须跟日期数字"; fi ;;
            ss|shadowsocks)         ENABLE_SS=true;         info "-> 启用 Shadowsocks" ;;
            hy2|hysteria2)          ENABLE_HY2=true;        info "-> 启用 Hysteria2" ;;
            tuic)                   ENABLE_TUIC=true;       info "-> 启用 TUIC" ;;
            vless|reality)          ENABLE_REALITY=true;    info "-> 启用 VLESS Reality" ;;
            socks5|socks)           ENABLE_SOCKS5=true;     info "-> 启用 SOCKS5" ;;
            trojan)                 ENABLE_TROJAN=true;     info "-> 启用 Trojan" ;;
            vless-h2|vless_h2|vlessh2) ENABLE_VLESS_H2=true; info "-> 启用 VLESS-H2-Reality" ;;
            vmess-tcp|vmess_tcp)    ENABLE_VMESS_TCP=true;  info "-> 启用 VMess-TCP" ;;
            vmess-ws|vmess_ws)      ENABLE_VMESS_WS=true;   info "-> 启用 VMess-WS" ;;
            vmess-http|vmess_http)  ENABLE_VMESS_HTTP=true; info "-> 启用 VMess-HTTP" ;;
            vmess-quic|vmess_quic)  ENABLE_VMESS_QUIC=true; info "-> 启用 VMess-QUIC" ;;
            vmess-wst|vmess_wst|vmess-ws-tls)   ENABLE_VMESS_WST=true;  info "-> 启用 VMess-WS-TLS" ;;
            vmess-h2t|vmess_h2t|vmess-h2-tls)   ENABLE_VMESS_H2T=true;  info "-> 启用 VMess-H2-TLS" ;;
            vmess-hut|vmess_hut|vmess-httpupgrade-tls) ENABLE_VMESS_HUT=true; info "-> 启用 VMess-HTTPUpgrade-TLS" ;;
            vless-wst|vless_wst|vless-ws-tls)   ENABLE_VLESS_WST=true;  info "-> 启用 VLESS-WS-TLS" ;;
            vless-h2t|vless_h2t|vless-h2-tls)   ENABLE_VLESS_H2T=true;  info "-> 启用 VLESS-H2-TLS" ;;
            vless-hut|vless_hut|vless-httpupgrade-tls) ENABLE_VLESS_HUT=true; info "-> 启用 VLESS-HTTPUpgrade-TLS" ;;
            trojan-wst|trojan_wst|trojan-ws-tls) ENABLE_TROJAN_WST=true; info "-> 启用 Trojan-WS-TLS" ;;
            trojan-h2t|trojan_h2t|trojan-h2-tls) ENABLE_TROJAN_H2T=true; info "-> 启用 Trojan-H2-TLS" ;;
            trojan-hut|trojan_hut|trojan-httpupgrade-tls) ENABLE_TROJAN_HUT=true; info "-> 启用 Trojan-HTTPUpgrade-TLS" ;;
            *) warn "忽略未知参数: $arg" ;;
        esac
        shift
    done

    if ! _any_enabled; then
        err "未选择任何协议,退出安装"; exit 1
    fi

    info "已选择协议:"
    $ENABLE_SS         && echo "  - Shadowsocks"
    $ENABLE_HY2        && echo "  - Hysteria2"
    $ENABLE_TUIC       && echo "  - TUIC"
    $ENABLE_REALITY    && echo "  - VLESS Reality"
    $ENABLE_SOCKS5     && echo "  - SOCKS5"
    $ENABLE_TROJAN     && echo "  - Trojan"
    $ENABLE_VLESS_H2   && echo "  - VLESS-H2-Reality"
    $ENABLE_VMESS_TCP  && echo "  - VMess-TCP"
    $ENABLE_VMESS_WS   && echo "  - VMess-WS"
    $ENABLE_VMESS_HTTP && echo "  - VMess-HTTP"
    $ENABLE_VMESS_QUIC && echo "  - VMess-QUIC"
    $ENABLE_VMESS_WST  && echo "  - VMess-WS-TLS"
    $ENABLE_VMESS_H2T  && echo "  - VMess-H2-TLS"
    $ENABLE_VMESS_HUT  && echo "  - VMess-HTTPUpgrade-TLS"
    $ENABLE_VLESS_WST  && echo "  - VLESS-WS-TLS"
    $ENABLE_VLESS_H2T  && echo "  - VLESS-H2-TLS"
    $ENABLE_VLESS_HUT  && echo "  - VLESS-HTTPUpgrade-TLS"
    $ENABLE_TROJAN_WST && echo "  - Trojan-WS-TLS"
    $ENABLE_TROJAN_H2T && echo "  - Trojan-H2-TLS"
    $ENABLE_TROJAN_HUT && echo "  - Trojan-HTTPUpgrade-TLS"

    mkdir -p /etc/sing-box
    cat > /etc/sing-box/.protocols <<EOF
ENABLE_SS=$ENABLE_SS
ENABLE_HY2=$ENABLE_HY2
ENABLE_TUIC=$ENABLE_TUIC
ENABLE_REALITY=$ENABLE_REALITY
ENABLE_SOCKS5=$ENABLE_SOCKS5
ENABLE_TROJAN=$ENABLE_TROJAN
ENABLE_VLESS_H2=$ENABLE_VLESS_H2
ENABLE_VMESS_TCP=$ENABLE_VMESS_TCP
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
ENABLE_VMESS_HTTP=$ENABLE_VMESS_HTTP
ENABLE_VMESS_QUIC=$ENABLE_VMESS_QUIC
ENABLE_VMESS_WST=$ENABLE_VMESS_WST
ENABLE_VMESS_H2T=$ENABLE_VMESS_H2T
ENABLE_VMESS_HUT=$ENABLE_VMESS_HUT
ENABLE_VLESS_WST=$ENABLE_VLESS_WST
ENABLE_VLESS_H2T=$ENABLE_VLESS_H2T
ENABLE_VLESS_HUT=$ENABLE_VLESS_HUT
ENABLE_TROJAN_WST=$ENABLE_TROJAN_WST
ENABLE_TROJAN_H2T=$ENABLE_TROJAN_H2T
ENABLE_TROJAN_HUT=$ENABLE_TROJAN_HUT
EOF
    export ENABLE_SS ENABLE_HY2 ENABLE_TUIC ENABLE_REALITY ENABLE_SOCKS5 \
           ENABLE_TROJAN ENABLE_VLESS_H2 \
           ENABLE_VMESS_TCP ENABLE_VMESS_WS ENABLE_VMESS_HTTP ENABLE_VMESS_QUIC \
           ENABLE_VMESS_WST ENABLE_VMESS_H2T ENABLE_VMESS_HUT \
           ENABLE_VLESS_WST ENABLE_VLESS_H2T ENABLE_VLESS_HUT \
           ENABLE_TROJAN_WST ENABLE_TROJAN_H2T ENABLE_TROJAN_HUT
}

# 创建配置目录
mkdir -p /etc/sing-box
select_protocols "$@"

# -----------------------
# 配置 SS 加密方式 (直接读取顶部配置)
select_ss_method() {
    # 直接使用顶部定义的变量
    SS_METHOD="$FIXED_SS_METHOD"
    
    # 如果启用 SS，打印一下提示
    if $ENABLE_SS; then
        info "SS 加密方式已设置为: $SS_METHOD"
    fi
    
    # 导出变量供后续使用
    export SS_METHOD
}

# 调用函数
select_ss_method

# -----------------------
# 在获取公网 IP 之前，询问连接ip和sni配置
# echo ""
# echo "请输入节点连接 IP 或 DDNS域名(留空默认出口IP):"
# read -r CUSTOM_IP
# CUSTOM_IP="$(echo "$CUSTOM_IP" | tr -d '[:space:]')"

# 修改为默认使用出口IP
CUSTOM_IP=""

# 直接使用开头定义的SNI域名
REALITY_SNI="$FIXED_REALITY_SNI"

# 将用户选择写入缓存
mkdir -p /etc/sing-box
# preserve existing cache if any (append/overwrite relevant keys)
# 最简单直接：在后面 create_config 也会写入 .config_cache，先写初始值以便中间步骤可读取
echo "CUSTOM_IP=$CUSTOM_IP" > /etc/sing-box/.config_cache.tmp || true
echo "REALITY_SNI=$REALITY_SNI" >> /etc/sing-box/.config_cache.tmp || true
# 保留其他可能已有的缓存条目（若存在老的 .config_cache），把新临时与旧文件合并（保新值覆盖旧值）
if [ -f /etc/sing-box/.config_cache ]; then
    # 将旧文件中不在新文件内的行追加
    awk 'FNR==NR{a[$1]=1;next} {split($0,k,"="); if(!(k[1] in a)) print $0}' /etc/sing-box/.config_cache.tmp /etc/sing-box/.config_cache >> /etc/sing-box/.config_cache.tmp2 || true
    mv /etc/sing-box/.config_cache.tmp2 /etc/sing-box/.config_cache.tmp || true
fi
mv /etc/sing-box/.config_cache.tmp /etc/sing-box/.config_cache || true

# -----------------------
# 配置端口和密码
get_config() {
    info "开始配置端口和密码..."
    
    # --- Shadowsocks ---
    if $ENABLE_SS; then
        # 直接使用顶部定义的变量
        PORT_SS="$FIXED_PORT_SS"
        # 密码依然保留随机生成(也可以按需改成固定)
        PSK_SS=$(rand_pass)
        
    fi

    # --- Hysteria2 ---
    if $ENABLE_HY2; then
        PORT_HY2="$FIXED_PORT_HY2"
        PSK_HY2=$(rand_pass)
        
    fi

    # --- TUIC ---
    if $ENABLE_TUIC; then
        PORT_TUIC="$FIXED_PORT_TUIC"
        PSK_TUIC=$(rand_pass)
        UUID_TUIC=$(rand_uuid)
        
    fi

    # --- Reality ---
    if $ENABLE_REALITY; then
        PORT_REALITY="$FIXED_PORT_REALITY"
        UUID=$(rand_uuid)
        
    fi

    # --- SOCKS5 ---
    if $ENABLE_SOCKS5; then
        PORT_SOCKS5="$FIXED_PORT_SOCKS5"
        USER_SOCKS5="$FIXED_SOCKS5_USER"
        PASS_SOCKS5="$FIXED_SOCKS5_PASS"
    fi

    # --- Trojan ---
    if $ENABLE_TROJAN; then
        PORT_TROJAN="$FIXED_PORT_TROJAN"
        PSK_TROJAN=$(rand_pass)
    fi

    # --- VLESS-H2-Reality ---
    if $ENABLE_VLESS_H2; then
        PORT_VLESS_H2="$FIXED_PORT_VLESS_H2"
        UUID_VLESS_H2=$(rand_uuid)
    fi

    # --- VMess 族 共用 UUID ---
    if $ENABLE_VMESS_TCP || $ENABLE_VMESS_WS || $ENABLE_VMESS_HTTP || $ENABLE_VMESS_QUIC || \
       $ENABLE_VMESS_WST || $ENABLE_VMESS_H2T || $ENABLE_VMESS_HUT; then
        UUID_VMESS=$(rand_uuid)
        PATH_TRANSPORT="${FIXED_TLS_TRANSPORT_PATH:-/ray}"
    fi
    $ENABLE_VMESS_TCP  && PORT_VMESS_TCP="$FIXED_PORT_VMESS_TCP"
    $ENABLE_VMESS_WS   && PORT_VMESS_WS="$FIXED_PORT_VMESS_WS"
    $ENABLE_VMESS_HTTP && PORT_VMESS_HTTP="$FIXED_PORT_VMESS_HTTP"
    $ENABLE_VMESS_QUIC && PORT_VMESS_QUIC="$FIXED_PORT_VMESS_QUIC"
    $ENABLE_VMESS_WST  && PORT_VMESS_WST="$FIXED_PORT_VMESS_WST"
    $ENABLE_VMESS_H2T  && PORT_VMESS_H2T="$FIXED_PORT_VMESS_H2T"
    $ENABLE_VMESS_HUT  && PORT_VMESS_HUT="$FIXED_PORT_VMESS_HUT"

    # --- VLESS-TLS 传输族 共用 UUID ---
    if $ENABLE_VLESS_WST || $ENABLE_VLESS_H2T || $ENABLE_VLESS_HUT; then
        UUID_VLESS_TLS=$(rand_uuid)
        PATH_TRANSPORT="${FIXED_TLS_TRANSPORT_PATH:-/ray}"
    fi
    $ENABLE_VLESS_WST  && PORT_VLESS_WST="$FIXED_PORT_VLESS_WST"
    $ENABLE_VLESS_H2T  && PORT_VLESS_H2T="$FIXED_PORT_VLESS_H2T"
    $ENABLE_VLESS_HUT  && PORT_VLESS_HUT="$FIXED_PORT_VLESS_HUT"

    # --- Trojan-TLS 传输族 共用 PSK ---
    if $ENABLE_TROJAN_WST || $ENABLE_TROJAN_H2T || $ENABLE_TROJAN_HUT; then
        PSK_TROJAN_TLS=$(rand_pass)
        PATH_TRANSPORT="${FIXED_TLS_TRANSPORT_PATH:-/ray}"
    fi
    $ENABLE_TROJAN_WST && PORT_TROJAN_WST="$FIXED_PORT_TROJAN_WST"
    $ENABLE_TROJAN_H2T && PORT_TROJAN_H2T="$FIXED_PORT_TROJAN_H2T"
    $ENABLE_TROJAN_HUT && PORT_TROJAN_HUT="$FIXED_PORT_TROJAN_HUT"
}

get_config

# -----------------------
# 安装 sing-box
install_singbox() {
    info "开始安装 sing-box..."

    if command -v sing-box >/dev/null 2>&1; then
        CURRENT_VERSION=$(sing-box version 2>/dev/null | head -1 || echo "unknown")
        warn "检测到已安装 sing-box: $CURRENT_VERSION"
        read -p "是否重新安装?(y/N): " REINSTALL
        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            info "跳过 sing-box 安装"
            return 0
        fi
    fi

    case "$OS" in
        alpine)
            info "使用 Edge 仓库安装 sing-box"
            apk update || { err "apk update 失败"; exit 1; }
            apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box || {
                err "sing-box 安装失败"
                exit 1
            }
            ;;
        debian|redhat)
            bash <(curl -fsSL https://sing-box.app/install.sh) || {
                err "sing-box 安装失败"
                exit 1
            }
            ;;
        *)
            err "未支持的系统,无法安装 sing-box"
            exit 1
            ;;
    esac

    if ! command -v sing-box >/dev/null 2>&1; then
        err "sing-box 安装后未找到可执行文件"
        exit 1
    fi

    INSTALLED_VERSION=$(sing-box version 2>/dev/null | head -1 || echo "unknown")
    info "sing-box 安装成功: $INSTALLED_VERSION"
}

install_singbox

# -----------------------
# 生成 Reality 密钥对（必须在 sing-box 安装之后）
generate_reality_keys() {
    if ! $ENABLE_REALITY && ! $ENABLE_VLESS_H2; then
        info "跳过 Reality 密钥生成（未选择 Reality 或 VLESS-H2-Reality 协议）"
        return 0
    fi
    
    info "生成 Reality 密钥对..."
    
    if ! command -v sing-box >/dev/null 2>&1; then
        err "sing-box 未安装，无法生成 Reality 密钥"
        exit 1
    fi
    
    REALITY_KEYS=$(sing-box generate reality-keypair 2>&1) || {
        err "生成 Reality 密钥失败"
        exit 1
    }
    
    REALITY_PK=$(echo "$REALITY_KEYS" | grep "PrivateKey" | awk '{print $NF}' | tr -d '\r')
    REALITY_PUB=$(echo "$REALITY_KEYS" | grep "PublicKey" | awk '{print $NF}' | tr -d '\r')
    REALITY_SID=$(sing-box generate rand 8 --hex 2>&1) || {
        err "生成 Reality ShortID 失败"
        exit 1
    }
    
    if [ -z "$REALITY_PK" ] || [ -z "$REALITY_PUB" ] || [ -z "$REALITY_SID" ]; then
        err "Reality 密钥生成结果为空"
        exit 1
    fi
    
    mkdir -p /etc/sing-box
    echo -n "$REALITY_PUB" > /etc/sing-box/.reality_pub
    echo -n "$REALITY_SID" > /etc/sing-box/.reality_sid
    
    info "Reality 密钥已生成"
}

generate_reality_keys

# -----------------------
# 生成 HY2/TUIC 自签证书(仅在需要时)
generate_cert() {
    if ! $ENABLE_HY2 && ! $ENABLE_TUIC && ! $ENABLE_TROJAN && \
       ! $ENABLE_VMESS_QUIC && ! $ENABLE_VMESS_WST && ! $ENABLE_VMESS_H2T && ! $ENABLE_VMESS_HUT && \
       ! $ENABLE_VLESS_WST && ! $ENABLE_VLESS_H2T && ! $ENABLE_VLESS_HUT && \
       ! $ENABLE_TROJAN_WST && ! $ENABLE_TROJAN_H2T && ! $ENABLE_TROJAN_HUT; then
        info "跳过证书生成(未选择需要 TLS 证书的协议)"
        return 0
    fi
    
    info "生成内置应用自签证书(HY2/TUIC/Trojan)..."
    mkdir -p /etc/sing-box/certs
    
    if [ ! -f /etc/sing-box/certs/fullchain.pem ] || [ ! -f /etc/sing-box/certs/privkey.pem ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
          -keyout /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -days 3650 \
          -subj "/CN=www.bing.com" || {
            err "证书生成失败"
            exit 1
        }
        info "证书已生成"
    else
        info "证书已存在"
    fi
}

generate_cert

# -----------------------
# 生成配置文件
CONFIG_PATH="/etc/sing-box/config.json"

create_config() {
    info "生成配置文件: $CONFIG_PATH"

    mkdir -p "$(dirname "$CONFIG_PATH")"

    # 构建 inbounds 内容（使用临时文件避免字符串处理问题）
    local TEMP_INBOUNDS="/tmp/singbox_inbounds_$$.json"
    > "$TEMP_INBOUNDS"
    
    local need_comma=false
    
    if $ENABLE_SS; then
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_SS'
    {
      "type": "shadowsocks",
      "listen": "::",
      "listen_port": PORT_SS_PLACEHOLDER,
      "method": "METHOD_SS_PLACEHOLDER",
      "password": "PSK_SS_PLACEHOLDER",
      "tag": "ss-in"
    }
INBOUND_SS
        sed -i "s|PORT_SS_PLACEHOLDER|$PORT_SS|g" "$TEMP_INBOUNDS"
        sed -i "s|METHOD_SS_PLACEHOLDER|$SS_METHOD|g" "$TEMP_INBOUNDS"
        sed -i "s|PSK_SS_PLACEHOLDER|$PSK_SS|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi
    
    if $ENABLE_HY2; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_HY2'
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": PORT_HY2_PLACEHOLDER,
      "users": [
        {
          "password": "PSK_HY2_PLACEHOLDER"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
INBOUND_HY2
        sed -i "s|PORT_HY2_PLACEHOLDER|$PORT_HY2|g" "$TEMP_INBOUNDS"
        sed -i "s|PSK_HY2_PLACEHOLDER|$PSK_HY2|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi
    
    if $ENABLE_TUIC; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_TUIC'
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": PORT_TUIC_PLACEHOLDER,
      "users": [
        {
          "uuid": "UUID_TUIC_PLACEHOLDER",
          "password": "PSK_TUIC_PLACEHOLDER"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
INBOUND_TUIC
        sed -i "s|PORT_TUIC_PLACEHOLDER|$PORT_TUIC|g" "$TEMP_INBOUNDS"
        sed -i "s|UUID_TUIC_PLACEHOLDER|$UUID_TUIC|g" "$TEMP_INBOUNDS"
        sed -i "s|PSK_TUIC_PLACEHOLDER|$PSK_TUIC|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi
    
    if $ENABLE_REALITY; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_REALITY'
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": PORT_REALITY_PLACEHOLDER,
      "users": [
        {
          "uuid": "UUID_REALITY_PLACEHOLDER",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "REALITY_SNI_PLACEHOLDER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "REALITY_SNI_PLACEHOLDER",
            "server_port": 443
          },
          "private_key": "REALITY_PK_PLACEHOLDER",
          "short_id": ["REALITY_SID_PLACEHOLDER"]
        }
      }
    }

INBOUND_REALITY
        sed -i "s|PORT_REALITY_PLACEHOLDER|$PORT_REALITY|g" "$TEMP_INBOUNDS"
        sed -i "s|UUID_REALITY_PLACEHOLDER|$UUID|g" "$TEMP_INBOUNDS"
        sed -i "s|REALITY_PK_PLACEHOLDER|$REALITY_PK|g" "$TEMP_INBOUNDS"
        sed -i "s|REALITY_SID_PLACEHOLDER|$REALITY_SID|g" "$TEMP_INBOUNDS"
        sed -i "s|REALITY_SNI_PLACEHOLDER|$REALITY_SNI|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    if $ENABLE_SOCKS5; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_SOCKS5'
    {
    "type": "socks",
    "tag": "socks-in",
    "listen": "::",
    "listen_port": PORT_SOCKS5_PLACEHOLDER,
    "users": [
        {
        "username": "USER_SOCKS5_PLACEHOLDER",
        "password": "PASS_SOCKS5_PLACEHOLDER"
        }
    ]
    }

INBOUND_SOCKS5
        sed -i "s|PORT_SOCKS5_PLACEHOLDER|$PORT_SOCKS5|g" "$TEMP_INBOUNDS"
        sed -i "s|USER_SOCKS5_PLACEHOLDER|$USER_SOCKS5|g" "$TEMP_INBOUNDS"
        sed -i "s|PASS_SOCKS5_PLACEHOLDER|$PASS_SOCKS5|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    if $ENABLE_TROJAN; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_TROJAN'
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": PORT_TROJAN_PLACEHOLDER,
      "users": [
        {
          "password": "PSK_TROJAN_PLACEHOLDER"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
INBOUND_TROJAN
        sed -i "s|PORT_TROJAN_PLACEHOLDER|$PORT_TROJAN|g" "$TEMP_INBOUNDS"
        sed -i "s|PSK_TROJAN_PLACEHOLDER|$PSK_TROJAN|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    if $ENABLE_VLESS_H2; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VLESS_H2'
    {
      "type": "vless",
      "tag": "vless-h2-in",
      "listen": "::",
      "listen_port": PORT_VLESS_H2_PLACEHOLDER,
      "users": [
        {
          "uuid": "UUID_VLESS_H2_PLACEHOLDER"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "VLESS_H2_SNI_PLACEHOLDER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "VLESS_H2_SNI_PLACEHOLDER",
            "server_port": 443
          },
          "private_key": "VLESS_H2_PK_PLACEHOLDER",
          "short_id": ["VLESS_H2_SID_PLACEHOLDER"]
        }
      },
      "transport": {
        "type": "http"
      }
    }
INBOUND_VLESS_H2
        sed -i "s|PORT_VLESS_H2_PLACEHOLDER|$PORT_VLESS_H2|g" "$TEMP_INBOUNDS"
        sed -i "s|UUID_VLESS_H2_PLACEHOLDER|$UUID_VLESS_H2|g" "$TEMP_INBOUNDS"
        sed -i "s|VLESS_H2_PK_PLACEHOLDER|$REALITY_PK|g" "$TEMP_INBOUNDS"
        sed -i "s|VLESS_H2_SID_PLACEHOLDER|$REALITY_SID|g" "$TEMP_INBOUNDS"
        sed -i "s|VLESS_H2_SNI_PLACEHOLDER|$REALITY_SNI|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-TCP ---
    if $ENABLE_VMESS_TCP; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_TCP'
    {
      "type": "vmess", "tag": "vmess-tcp-in",
      "listen": "::", "listen_port": PORT_VMESS_TCP_PH,
      "users": [{"uuid": "UUID_VMESS_PH", "alterId": 0}]
    }
INBOUND_VMESS_TCP
        sed -i "s|PORT_VMESS_TCP_PH|$PORT_VMESS_TCP|g; s|UUID_VMESS_PH|$UUID_VMESS|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-WS ---
    if $ENABLE_VMESS_WS; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_WS'
    {
      "type": "vmess", "tag": "vmess-ws-in",
      "listen": "::", "listen_port": PORT_VMESS_WS_PH,
      "users": [{"uuid": "UUID_VMESS_PH2", "alterId": 0}],
      "transport": {"type": "ws", "path": "PATH_TP_PH", "early_data_header_name": "Sec-WebSocket-Protocol"}
    }
INBOUND_VMESS_WS
        sed -i "s|PORT_VMESS_WS_PH|$PORT_VMESS_WS|g; s|UUID_VMESS_PH2|$UUID_VMESS|g; s|PATH_TP_PH|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-HTTP ---
    if $ENABLE_VMESS_HTTP; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_HTTP'
    {
      "type": "vmess", "tag": "vmess-http-in",
      "listen": "::", "listen_port": PORT_VMESS_HTTP_PH,
      "users": [{"uuid": "UUID_VMESS_PH3", "alterId": 0}],
      "transport": {"type": "http", "path": "PATH_TP_PH2"}
    }
INBOUND_VMESS_HTTP
        sed -i "s|PORT_VMESS_HTTP_PH|$PORT_VMESS_HTTP|g; s|UUID_VMESS_PH3|$UUID_VMESS|g; s|PATH_TP_PH2|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-QUIC (需要TLS) ---
    if $ENABLE_VMESS_QUIC; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_QUIC'
    {
      "type": "vmess", "tag": "vmess-quic-in",
      "listen": "::", "listen_port": PORT_VMESS_QUIC_PH,
      "users": [{"uuid": "UUID_VMESS_PH4", "alterId": 0}],
      "tls": {"enabled": true, "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "quic"}
    }
INBOUND_VMESS_QUIC
        sed -i "s|PORT_VMESS_QUIC_PH|$PORT_VMESS_QUIC|g; s|UUID_VMESS_PH4|$UUID_VMESS|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-WS-TLS ---
    if $ENABLE_VMESS_WST; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_WST'
    {
      "type": "vmess", "tag": "vmess-wst-in",
      "listen": "::", "listen_port": PORT_VMESS_WST_PH,
      "users": [{"uuid": "UUID_VMESS_PH5", "alterId": 0}],
      "tls": {"enabled": true,
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "ws", "path": "PATH_TP_PH3", "early_data_header_name": "Sec-WebSocket-Protocol"}
    }
INBOUND_VMESS_WST
        sed -i "s|PORT_VMESS_WST_PH|$PORT_VMESS_WST|g; s|UUID_VMESS_PH5|$UUID_VMESS|g; s|PATH_TP_PH3|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-H2-TLS ---
    if $ENABLE_VMESS_H2T; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_H2T'
    {
      "type": "vmess", "tag": "vmess-h2t-in",
      "listen": "::", "listen_port": PORT_VMESS_H2T_PH,
      "users": [{"uuid": "UUID_VMESS_PH6", "alterId": 0}],
      "tls": {"enabled": true, "alpn": ["h2"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "http", "path": "PATH_TP_PH4"}
    }
INBOUND_VMESS_H2T
        sed -i "s|PORT_VMESS_H2T_PH|$PORT_VMESS_H2T|g; s|UUID_VMESS_PH6|$UUID_VMESS|g; s|PATH_TP_PH4|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VMess-HTTPUpgrade-TLS ---
    if $ENABLE_VMESS_HUT; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VMESS_HUT'
    {
      "type": "vmess", "tag": "vmess-hut-in",
      "listen": "::", "listen_port": PORT_VMESS_HUT_PH,
      "users": [{"uuid": "UUID_VMESS_PH7", "alterId": 0}],
      "tls": {"enabled": true, "alpn": ["http/1.1"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "httpupgrade", "path": "PATH_TP_PH5"}
    }
INBOUND_VMESS_HUT
        sed -i "s|PORT_VMESS_HUT_PH|$PORT_VMESS_HUT|g; s|UUID_VMESS_PH7|$UUID_VMESS|g; s|PATH_TP_PH5|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VLESS-WS-TLS ---
    if $ENABLE_VLESS_WST; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VLESS_WST'
    {
      "type": "vless", "tag": "vless-wst-in",
      "listen": "::", "listen_port": PORT_VLESS_WST_PH,
      "users": [{"uuid": "UUID_VLESS_TLS_PH"}],
      "tls": {"enabled": true,
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "ws", "path": "PATH_TP_PH6", "early_data_header_name": "Sec-WebSocket-Protocol"}
    }
INBOUND_VLESS_WST
        sed -i "s|PORT_VLESS_WST_PH|$PORT_VLESS_WST|g; s|UUID_VLESS_TLS_PH|$UUID_VLESS_TLS|g; s|PATH_TP_PH6|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VLESS-H2-TLS ---
    if $ENABLE_VLESS_H2T; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VLESS_H2T'
    {
      "type": "vless", "tag": "vless-h2t-in",
      "listen": "::", "listen_port": PORT_VLESS_H2T_PH,
      "users": [{"uuid": "UUID_VLESS_TLS_PH2"}],
      "tls": {"enabled": true, "alpn": ["h2"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "http", "path": "PATH_TP_PH7"}
    }
INBOUND_VLESS_H2T
        sed -i "s|PORT_VLESS_H2T_PH|$PORT_VLESS_H2T|g; s|UUID_VLESS_TLS_PH2|$UUID_VLESS_TLS|g; s|PATH_TP_PH7|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- VLESS-HTTPUpgrade-TLS ---
    if $ENABLE_VLESS_HUT; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_VLESS_HUT'
    {
      "type": "vless", "tag": "vless-hut-in",
      "listen": "::", "listen_port": PORT_VLESS_HUT_PH,
      "users": [{"uuid": "UUID_VLESS_TLS_PH3"}],
      "tls": {"enabled": true, "alpn": ["http/1.1"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "httpupgrade", "path": "PATH_TP_PH8"}
    }
INBOUND_VLESS_HUT
        sed -i "s|PORT_VLESS_HUT_PH|$PORT_VLESS_HUT|g; s|UUID_VLESS_TLS_PH3|$UUID_VLESS_TLS|g; s|PATH_TP_PH8|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- Trojan-WS-TLS ---
    if $ENABLE_TROJAN_WST; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_TROJAN_WST'
    {
      "type": "trojan", "tag": "trojan-wst-in",
      "listen": "::", "listen_port": PORT_TROJAN_WST_PH,
      "users": [{"password": "PSK_TROJAN_TLS_PH"}],
      "tls": {"enabled": true,
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "ws", "path": "PATH_TP_PH9", "early_data_header_name": "Sec-WebSocket-Protocol"}
    }
INBOUND_TROJAN_WST
        sed -i "s|PORT_TROJAN_WST_PH|$PORT_TROJAN_WST|g; s|PSK_TROJAN_TLS_PH|$PSK_TROJAN_TLS|g; s|PATH_TP_PH9|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- Trojan-H2-TLS ---
    if $ENABLE_TROJAN_H2T; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_TROJAN_H2T'
    {
      "type": "trojan", "tag": "trojan-h2t-in",
      "listen": "::", "listen_port": PORT_TROJAN_H2T_PH,
      "users": [{"password": "PSK_TROJAN_TLS_PH2"}],
      "tls": {"enabled": true, "alpn": ["h2"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "http", "path": "PATH_TP_PH10"}
    }
INBOUND_TROJAN_H2T
        sed -i "s|PORT_TROJAN_H2T_PH|$PORT_TROJAN_H2T|g; s|PSK_TROJAN_TLS_PH2|$PSK_TROJAN_TLS|g; s|PATH_TP_PH10|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi

    # --- Trojan-HTTPUpgrade-TLS ---
    if $ENABLE_TROJAN_HUT; then
        $need_comma && echo "," >> "$TEMP_INBOUNDS"
        cat >> "$TEMP_INBOUNDS" <<'INBOUND_TROJAN_HUT'
    {
      "type": "trojan", "tag": "trojan-hut-in",
      "listen": "::", "listen_port": PORT_TROJAN_HUT_PH,
      "users": [{"password": "PSK_TROJAN_TLS_PH3"}],
      "tls": {"enabled": true, "alpn": ["http/1.1"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"},
      "transport": {"type": "httpupgrade", "path": "PATH_TP_PH11"}
    }
INBOUND_TROJAN_HUT
        sed -i "s|PORT_TROJAN_HUT_PH|$PORT_TROJAN_HUT|g; s|PSK_TROJAN_TLS_PH3|$PSK_TROJAN_TLS|g; s|PATH_TP_PH11|$PATH_TRANSPORT|g" "$TEMP_INBOUNDS"
        need_comma=true
    fi
    cat > "$CONFIG_PATH" <<'CONFIG_HEAD'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
CONFIG_HEAD
    
    cat "$TEMP_INBOUNDS" >> "$CONFIG_PATH"
    
    cat >> "$CONFIG_PATH" <<'CONFIG_TAIL'
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ]
}
CONFIG_TAIL

    rm -f "$TEMP_INBOUNDS"

    sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1 \
       && info "配置文件验证通过" \
       || warn "配置文件验证失败,但继续执行"

    # 保存配置缓存（追加/覆盖）
    cat > /etc/sing-box/.config_cache <<CACHEEOF
ENABLE_SS=$ENABLE_SS
ENABLE_HY2=$ENABLE_HY2
ENABLE_TUIC=$ENABLE_TUIC
ENABLE_REALITY=$ENABLE_REALITY
ENABLE_SOCKS5=$ENABLE_SOCKS5
ENABLE_TROJAN=$ENABLE_TROJAN
ENABLE_VLESS_H2=$ENABLE_VLESS_H2
ENABLE_VMESS_TCP=$ENABLE_VMESS_TCP
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
ENABLE_VMESS_HTTP=$ENABLE_VMESS_HTTP
ENABLE_VMESS_QUIC=$ENABLE_VMESS_QUIC
ENABLE_VMESS_WST=$ENABLE_VMESS_WST
ENABLE_VMESS_H2T=$ENABLE_VMESS_H2T
ENABLE_VMESS_HUT=$ENABLE_VMESS_HUT
ENABLE_VLESS_WST=$ENABLE_VLESS_WST
ENABLE_VLESS_H2T=$ENABLE_VLESS_H2T
ENABLE_VLESS_HUT=$ENABLE_VLESS_HUT
ENABLE_TROJAN_WST=$ENABLE_TROJAN_WST
ENABLE_TROJAN_H2T=$ENABLE_TROJAN_H2T
ENABLE_TROJAN_HUT=$ENABLE_TROJAN_HUT
VMESS_TLS_SNI=$FIXED_VMESS_TLS_SNI
VLESS_TLS_SNI=$FIXED_VLESS_TLS_SNI
TROJAN_TLS_SNI=$FIXED_TROJAN_TLS_SNI
CACHEEOF

    $ENABLE_SS && cat >> /etc/sing-box/.config_cache <<CACHEEOF
SS_PORT=$PORT_SS
SS_PSK=$PSK_SS
SS_METHOD=$SS_METHOD
CACHEEOF

    $ENABLE_HY2 && cat >> /etc/sing-box/.config_cache <<CACHEEOF
HY2_PORT=$PORT_HY2
HY2_PSK=$PSK_HY2
HY2_SNI=$FIXED_HY2_SNI
CACHEEOF

    $ENABLE_TUIC && cat >> /etc/sing-box/.config_cache <<CACHEEOF
TUIC_PORT=$PORT_TUIC
TUIC_UUID=$UUID_TUIC
TUIC_PSK=$PSK_TUIC
TUIC_SNI=$FIXED_TUIC_SNI
CACHEEOF

    $ENABLE_REALITY && cat >> /etc/sing-box/.config_cache <<CACHEEOF
REALITY_PORT=$PORT_REALITY
REALITY_UUID=$UUID
REALITY_PK=$REALITY_PK
REALITY_SID=$REALITY_SID
REALITY_PUB=$REALITY_PUB
REALITY_SNI=$REALITY_SNI
CACHEEOF

    $ENABLE_SOCKS5 && cat >> /etc/sing-box/.config_cache <<CACHEEOF
SOCKS5_PORT=$PORT_SOCKS5
SOCKS5_USER=$USER_SOCKS5
SOCKS5_PASS=$PASS_SOCKS5
CACHEEOF

    $ENABLE_TROJAN && cat >> /etc/sing-box/.config_cache <<CACHEEOF
TROJAN_PORT=$PORT_TROJAN
TROJAN_PSK=$PSK_TROJAN
TROJAN_SNI=$FIXED_TROJAN_SNI
CACHEEOF

    $ENABLE_VLESS_H2 && cat >> /etc/sing-box/.config_cache <<CACHEEOF
VLESS_H2_PORT=$PORT_VLESS_H2
VLESS_H2_UUID=$UUID_VLESS_H2
VLESS_H2_PK=$REALITY_PK
VLESS_H2_SID=$REALITY_SID
VLESS_H2_PUB=$REALITY_PUB
CACHEEOF

    # VMess 族
    if $ENABLE_VMESS_TCP || $ENABLE_VMESS_WS || $ENABLE_VMESS_HTTP || $ENABLE_VMESS_QUIC || \
       $ENABLE_VMESS_WST || $ENABLE_VMESS_H2T || $ENABLE_VMESS_HUT; then
        cat >> /etc/sing-box/.config_cache <<CACHEEOF
VMESS_UUID=$UUID_VMESS
PATH_TRANSPORT=$PATH_TRANSPORT
CACHEEOF
    fi
    $ENABLE_VMESS_TCP  && echo "VMESS_TCP_PORT=$PORT_VMESS_TCP"   >> /etc/sing-box/.config_cache
    $ENABLE_VMESS_WS   && echo "VMESS_WS_PORT=$PORT_VMESS_WS"     >> /etc/sing-box/.config_cache
    $ENABLE_VMESS_HTTP && echo "VMESS_HTTP_PORT=$PORT_VMESS_HTTP"  >> /etc/sing-box/.config_cache
    $ENABLE_VMESS_QUIC && echo "VMESS_QUIC_PORT=$PORT_VMESS_QUIC"  >> /etc/sing-box/.config_cache
    $ENABLE_VMESS_WST  && echo "VMESS_WST_PORT=$PORT_VMESS_WST"   >> /etc/sing-box/.config_cache
    $ENABLE_VMESS_H2T  && echo "VMESS_H2T_PORT=$PORT_VMESS_H2T"   >> /etc/sing-box/.config_cache
    $ENABLE_VMESS_HUT  && echo "VMESS_HUT_PORT=$PORT_VMESS_HUT"   >> /etc/sing-box/.config_cache

    # VLESS-TLS 族
    if $ENABLE_VLESS_WST || $ENABLE_VLESS_H2T || $ENABLE_VLESS_HUT; then
        cat >> /etc/sing-box/.config_cache <<CACHEEOF
VLESS_TLS_UUID=$UUID_VLESS_TLS
PATH_TRANSPORT=$PATH_TRANSPORT
CACHEEOF
    fi
    $ENABLE_VLESS_WST  && echo "VLESS_WST_PORT=$PORT_VLESS_WST"   >> /etc/sing-box/.config_cache
    $ENABLE_VLESS_H2T  && echo "VLESS_H2T_PORT=$PORT_VLESS_H2T"   >> /etc/sing-box/.config_cache
    $ENABLE_VLESS_HUT  && echo "VLESS_HUT_PORT=$PORT_VLESS_HUT"   >> /etc/sing-box/.config_cache

    # Trojan-TLS 族
    if $ENABLE_TROJAN_WST || $ENABLE_TROJAN_H2T || $ENABLE_TROJAN_HUT; then
        cat >> /etc/sing-box/.config_cache <<CACHEEOF
TROJAN_TLS_PSK=$PSK_TROJAN_TLS
PATH_TRANSPORT=$PATH_TRANSPORT
CACHEEOF
    fi
    $ENABLE_TROJAN_WST && echo "TROJAN_WST_PORT=$PORT_TROJAN_WST" >> /etc/sing-box/.config_cache
    $ENABLE_TROJAN_H2T && echo "TROJAN_H2T_PORT=$PORT_TROJAN_H2T" >> /etc/sing-box/.config_cache
    $ENABLE_TROJAN_HUT && echo "TROJAN_HUT_PORT=$PORT_TROJAN_HUT" >> /etc/sing-box/.config_cache

    # 全局写入 CUSTOM_IP（哪怕为空也写）
    echo "CUSTOM_IP=$CUSTOM_IP" >> /etc/sing-box/.config_cache

    info "配置缓存已保存到 /etc/sing-box/.config_cache"
}

# 调用配置生成
create_config

info "配置生成完成，准备设置服务..."

# -----------------------
# 设置服务
setup_service() {
    info "配置系统服务..."
    
    if [ "$OS" = "alpine" ]; then
        SERVICE_PATH="/etc/init.d/sing-box"
        
        cat > "$SERVICE_PATH" <<'OPENRC'
#!/sbin/openrc-run

name="sing-box"
description="Sing-box Proxy Server"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.err"
# 自动拉起（程序崩溃、OOM、被 kill 后自动恢复）
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --mode 0755 /var/log
    checkpath --directory --mode 0755 /run
}
OPENRC
        
        chmod +x "$SERVICE_PATH"
        rc-update add sing-box default >/dev/null 2>&1 || warn "添加开机自启失败"
        rc-service sing-box restart || {
            err "服务启动失败"
            tail -20 /var/log/sing-box.err 2>/dev/null || tail -20 /var/log/sing-box.log 2>/dev/null || true
            exit 1
        }
        
        sleep 2
        if rc-service sing-box status >/dev/null 2>&1; then
            info "✅ OpenRC 服务已启动"
        else
            err "服务状态异常"
            exit 1
        fi
        
    else
        SERVICE_PATH="/etc/systemd/system/sing-box.service"
        
        cat > "$SERVICE_PATH" <<'SYSTEMD'
[Unit]
Description=Sing-box Proxy Server
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SYSTEMD
        
        systemctl daemon-reload
        systemctl enable sing-box >/dev/null 2>&1
        systemctl restart sing-box || {
            err "服务启动失败"
            journalctl -u sing-box -n 30 --no-pager
            exit 1
        }
        
        sleep 2
        if systemctl is-active sing-box >/dev/null 2>&1; then
            info "✅ Systemd 服务已启动"
        else
            err "服务状态异常"
            exit 1
        fi
    fi
    
    info "服务配置完成: $SERVICE_PATH"
}

setup_service

# -----------------------
# BBR 内核加速（借鉴开源项目 sing-box-main bbr.sh）
apply_bbr() {
    if [ "$FIXED_ENABLE_BBR" != "true" ]; then
        info "跳过 BBR 优化（模板参数未启用）"
        return 0
    fi

    info "尝试启用 BBR 内核加速..."
    local kernel_major kernel_minor
    kernel_major=$(uname -r | cut -d. -f1)
    kernel_minor=$(uname -r | cut -d. -f2)

    if [[ $kernel_major -ge 5 ]] || [[ $kernel_major -eq 4 && $kernel_minor -ge 9 ]]; then
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
        {
            echo "net.ipv4.tcp_congestion_control = bbr"
            echo "net.core.default_qdisc = fq"
        } >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
        info "✅ BBR 内核加速已启用"
    else
        warn "内核版本 $(uname -r) 过低（需 4.9+），已跳过 BBR 优化"
    fi
}

apply_bbr

# 检测 IPv4 函数
get_ipv4() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://myip.ipip.net/s"; do
        ip=$(curl -s -4 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# 检测 IPv6 函数
get_ipv6() {
    local ip=""
    for url in "https://api64.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://icanhazip.com"; do
        ip=$(curl -s -6 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ "$ip" =~ ^[a-fA-F0-9:]+$ ]] && [[ "$ip" == *":"* ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

get_public_ip() {
    local v4=$(get_ipv4)
    if [ -n "$v4" ]; then
        echo "$v4"
        return 0
    fi
    local v6=$(get_ipv6)
    if [ -n "$v6" ]; then
        echo "$v6"
        return 0
    fi
    return 1
}

# -----------------------
# 生成链接(仅生成已选择的协议)
generate_uris() {
    local host="$PUB_IP"
    if [[ "$host" == *":"* ]]; then
        host="[$host]"
    fi
    
    if $ENABLE_SS; then
        local ss_userinfo="${SS_METHOD}:${PSK_SS}"
        ss_encoded=$(printf "%s" "$ss_userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')

        echo "=== Shadowsocks (SS) ==="
        echo "ss://${ss_encoded}@${host}:${PORT_SS}#ss${suffix}"
        echo "ss://${ss_b64}@${host}:${PORT_SS}#ss${suffix}"
        echo ""
    fi
    
    if $ENABLE_HY2; then
        hy2_encoded=$(printf "%s" "$PSK_HY2" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Hysteria2 (HY2) ==="
        echo "hy2://${hy2_encoded}@${host}:${PORT_HY2}/?sni=${FIXED_HY2_SNI}&alpn=h3&insecure=1#hy2${suffix}"
        echo ""
    fi

    if $ENABLE_TUIC; then
        tuic_encoded=$(printf "%s" "$PSK_TUIC" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== TUIC ==="
        echo "tuic://${UUID_TUIC}:${tuic_encoded}@${host}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=${FIXED_TUIC_SNI}&insecure=1#tuic${suffix}"
        echo ""
    fi
    
    if $ENABLE_REALITY; then
        echo "=== VLESS Reality ==="
        echo "vless://${UUID}@${host}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality${suffix}"
        echo ""
    fi

    if $ENABLE_SOCKS5; then
        echo "=== SOCKS5 ==="
        echo "socks5://${USER_SOCKS5}:${PASS_SOCKS5}@${host}:${PORT_SOCKS5}#socks5${suffix}"
        echo ""
    fi

    if $ENABLE_TROJAN; then
        trojan_encoded=$(printf "%s" "$PSK_TROJAN" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan ==="
        echo "trojan://${trojan_encoded}@${host}:${PORT_TROJAN}?sni=${FIXED_TROJAN_SNI}&allowInsecure=1#trojan${suffix}"
        echo ""
    fi

    if $ENABLE_VLESS_H2; then
        echo "=== VLESS-H2-Reality ==="
        echo "vless://${UUID_VLESS_H2}@${host}:${PORT_VLESS_H2}?encryption=none&flow=&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=h2&path=/&alpn=h2#vless-h2${suffix}"
        echo ""
    fi

    # VMess base64 URI 生成器
    vmess_b64() {
        local ps="$1" addr="$2" port="$3" uuid="$4" net="$5" tls="${6:-}" path="${7:-}" host="${8:-$2}" alpn="${9:-}"
        local allow_insecure="false"
        [ "$tls" = "tls" ] && allow_insecure="true"
        local json="{\"v\":\"2\",\"ps\":\"$ps\",\"add\":\"$addr\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"$net\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$tls\",\"sni\":\"$host\",\"alpn\":\"$alpn\",\"allowInsecure\":$allow_insecure}"
        printf 'vmess://%s' "$(printf '%s' "$json" | base64 | tr -d '\n')"
    }

    local raw_host="$PUB_IP"  # 不含中括号，用于 vmess JSON host 字段
    local vmess_tls_sni="$FIXED_VMESS_TLS_SNI"
    local vless_tls_sni="$FIXED_VLESS_TLS_SNI"
    local trojan_tls_sni="$FIXED_TROJAN_TLS_SNI"
    if [ -z "$vmess_tls_sni" ]; then
        vmess_tls_sni="$raw_host"
    fi
    if [ -z "$vless_tls_sni" ]; then
        vless_tls_sni="$raw_host"
    fi
    if [ -z "$trojan_tls_sni" ]; then
        trojan_tls_sni="$raw_host"
    fi

    if $ENABLE_VMESS_TCP; then
        echo "=== VMess-TCP ==="
        vmess_b64 "vmess-tcp${suffix}" "$raw_host" "$PORT_VMESS_TCP" "$UUID_VMESS" "tcp" "" ""
        echo ""
    fi

    if $ENABLE_VMESS_WS; then
        echo "=== VMess-WS ==="
        vmess_b64 "vmess-ws${suffix}" "$raw_host" "$PORT_VMESS_WS" "$UUID_VMESS" "ws" "" "$PATH_TRANSPORT"
        echo ""
    fi

    if $ENABLE_VMESS_HTTP; then
        echo "=== VMess-HTTP ==="
        vmess_b64 "vmess-http${suffix}" "$raw_host" "$PORT_VMESS_HTTP" "$UUID_VMESS" "http" "" "$PATH_TRANSPORT"
        echo ""
    fi

    if $ENABLE_VMESS_QUIC; then
        echo "=== VMess-QUIC ==="
        vmess_b64 "vmess-quic${suffix}" "$raw_host" "$PORT_VMESS_QUIC" "$UUID_VMESS" "quic" "tls" "" "$vmess_tls_sni"
        echo ""
    fi

    if $ENABLE_VMESS_WST; then
        echo "=== VMess-WS-TLS (allowInsecure) ==="
        vmess_b64 "vmess-wst${suffix}" "$raw_host" "$PORT_VMESS_WST" "$UUID_VMESS" "ws" "tls" "$PATH_TRANSPORT" "$vmess_tls_sni"
        echo ""
    fi

    if $ENABLE_VMESS_H2T; then
        echo "=== VMess-H2-TLS (allowInsecure) ==="
        vmess_b64 "vmess-h2t${suffix}" "$raw_host" "$PORT_VMESS_H2T" "$UUID_VMESS" "h2" "tls" "$PATH_TRANSPORT" "$vmess_tls_sni" "h2"
        echo ""
    fi

    if $ENABLE_VMESS_HUT; then
        echo "=== VMess-HTTPUpgrade-TLS (allowInsecure) ==="
        vmess_b64 "vmess-hut${suffix}" "$raw_host" "$PORT_VMESS_HUT" "$UUID_VMESS" "httpupgrade" "tls" "$PATH_TRANSPORT" "$vmess_tls_sni"
        echo ""
    fi

    if $ENABLE_VLESS_WST; then
        echo "=== VLESS-WS-TLS (allowInsecure) ==="
        echo "vless://${UUID_VLESS_TLS}@${host}:${PORT_VLESS_WST}?security=tls&sni=${vless_tls_sni}&type=ws&path=${PATH_TRANSPORT}&allowInsecure=1&host=${vless_tls_sni}#vless-wst${suffix}"
        echo ""
    fi

    if $ENABLE_VLESS_H2T; then
        echo "=== VLESS-H2-TLS (allowInsecure) ==="
        echo "vless://${UUID_VLESS_TLS}@${host}:${PORT_VLESS_H2T}?security=tls&sni=${vless_tls_sni}&type=h2&path=${PATH_TRANSPORT}&host=${vless_tls_sni}&allowInsecure=1&alpn=h2#vless-h2t${suffix}"
        echo ""
    fi

    if $ENABLE_VLESS_HUT; then
        echo "=== VLESS-HTTPUpgrade-TLS (allowInsecure) ==="
        echo "vless://${UUID_VLESS_TLS}@${host}:${PORT_VLESS_HUT}?security=tls&sni=${vless_tls_sni}&type=httpupgrade&path=${PATH_TRANSPORT}&host=${vless_tls_sni}&allowInsecure=1#vless-hut${suffix}"
        echo ""
    fi

    if $ENABLE_TROJAN_WST; then
        local twst_enc=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan-WS-TLS (allowInsecure) ==="
        echo "trojan://${twst_enc}@${host}:${PORT_TROJAN_WST}?sni=${trojan_tls_sni}&type=ws&path=${PATH_TRANSPORT}&allowInsecure=1&host=${trojan_tls_sni}#trojan-wst${suffix}"
        echo ""
    fi

    if $ENABLE_TROJAN_H2T; then
        local th2t_enc=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan-H2-TLS (allowInsecure) ==="
        echo "trojan://${th2t_enc}@${host}:${PORT_TROJAN_H2T}?sni=${trojan_tls_sni}&type=h2&path=${PATH_TRANSPORT}&host=${trojan_tls_sni}&allowInsecure=1&alpn=h2#trojan-h2t${suffix}"
        echo ""
    fi

    if $ENABLE_TROJAN_HUT; then
        local thut_enc=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan-HTTPUpgrade-TLS (allowInsecure) ==="
        echo "trojan://${thut_enc}@${host}:${PORT_TROJAN_HUT}?sni=${trojan_tls_sni}&type=httpupgrade&path=${PATH_TRANSPORT}&host=${trojan_tls_sni}&allowInsecure=1#trojan-hut${suffix}"
        echo ""
    fi
}

info "正在检测网络环境..."

# 1. 执行检测并存储到全局变量
SERVER_IPV4=$(get_ipv4 || echo "")
SERVER_IPV6=$(get_ipv6 || echo "")

if [ -n "$SERVER_IPV4" ]; then
    info "检测到 IPv4: $SERVER_IPV4"
fi
if [ -n "$SERVER_IPV6" ]; then
    info "检测到 IPv6: $SERVER_IPV6"
fi

# 2. 确定用于生成链接的 PUB_IP (优先级: 自定义 > IPv4 > IPv6)
if [ -n "${CUSTOM_IP:-}" ]; then
    PUB_IP="$CUSTOM_IP"
    info "使用用户提供的连接IP或ddns域名: $PUB_IP"
elif [ -n "$SERVER_IPV4" ]; then
    PUB_IP="$SERVER_IPV4"
    info "优先使用 IPv4 作为节点连接地址: $PUB_IP"
elif [ -n "$SERVER_IPV6" ]; then
    PUB_IP="$SERVER_IPV6"
    info "仅检测到 IPv6，使用 IPv6 作为节点连接地址: $PUB_IP"
else
    PUB_IP="YOUR_SERVER_IP"
    warn "无法获取任何公网 IP，链接生成可能不正确"
fi

# -----------------------
# [修改] 上报节点信息到后端
# -----------------------
# 发送函数
curl_post_submit() {
    local url="$1"
    local json="$2"
    local msg="$3"
    
    # 优先尝试 IPv4 通道上报
    if curl -s -4 -X POST -H "Content-Type: application/json" -d "$json" "$url" >/dev/null 2>&1; then
        return 0
    fi
    # 失败则尝试 IPv6 通道
    if curl -s -6 -X POST -H "Content-Type: application/json" -d "$json" "$url" >/dev/null 2>&1; then
        return 0
    fi
    warn "$msg 上报请求失败 (网络不可达)"
    return 1
}

# -----------------------
# [新增] 确保 Cron 环境存在并启动 (兼容跨平台及 Docker 环境)
# -----------------------
ensure_cron() {
    info "正在检查并确保 cron 服务已安装且在运行..."
    
    # 智能识别包管理器并进行安装
    if command -v apt-get >/dev/null 2>&1; then
        # Debian / Ubuntu 系列
        apt-get update -q >/dev/null 2>&1 || true
        apt-get install -y cron >/dev/null 2>&1 || true
        # 尝试启动 (兼容 Systemd 和 传统 init，如果在纯 Docker 无 init 环境则直接后台运行守护进程)
        systemctl enable cron --now >/dev/null 2>&1 || service cron start >/dev/null 2>&1 || cron &
    
    elif command -v yum >/dev/null 2>&1; then
        # CentOS / RHEL 系列 (包名通常叫 cronie)
        yum install -y cronie >/dev/null 2>&1 || true
        systemctl enable crond --now >/dev/null 2>&1 || service crond start >/dev/null 2>&1 || crond &
    
    elif command -v apk >/dev/null 2>&1; then
        # Alpine Linux 系列 (常用于极简 Docker)
        # Alpine 默认的 busybox 提供 crontab，但不一定有完整的 crond 服务起着，这里强装 dcron
        
        # 强制杀掉所有正在运行的 crond 进程 (包括 busybox 提供的自带 crond)
        killall crond >/dev/null 2>&1 || true
        
        # 卸载可能存在的旧版 dcron 或其他 cron 组件
        apk del dcron >/dev/null 2>&1 || true
        
        # 重新安装全新的 dcron
        apk add --no-cache dcron >/dev/null 2>&1 || true
        
        # Alpine 容器通常没有 systemd，直接运行守护进程
        crond &
    
    else
        warn "未知的系统环境，无法自动安装 cron，流量上报可能失效！"
        return 1
    fi
    
    info "cron 服务安装并启动完成。"
}

# -----------------------
# [修改] 配置流量监控与定时上报机制 (Bash + Cron 伪 Agent)
# -----------------------
setup_traffic_monitor() {
    # 如果没有提供参数，则不配置流量监控
    if [ -z "$REPORT_URL" ] || [ -z "$INSTALL_ID" ]; then
        info "未提供上报参数，跳过流量监控配置"
        return 0
    fi

    # 1. 确保系统有 cron 环境
    ensure_cron || true # 即使安装失败也继续尝试，利用兜底逻辑

    TRAFFIC_SCRIPT="/usr/local/bin/singbox_traffic.sh"
    
    # [优化 1] 精准替换 URL 末尾的 report 为 traffic，防止误伤域名
    TRAFFIC_URL=$(echo "$REPORT_URL" | sed 's|/report$|/traffic|')
    RESET_VAL="${RESET_DAY:-0}"
    
    info "配置流量监控机制 (重置日: ${RESET_VAL:-不重置})..."
    
    # 动态生成我们的 "伪 Agent" 脚本
    cat > "$TRAFFIC_SCRIPT" <<EOF
#!/bin/bash
REPORT_URL="$TRAFFIC_URL"
INSTALL_ID="$INSTALL_ID"
RESET_DAY="$RESET_VAL"

# 智能获取主网卡接口名称
IFACE=\$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -n1)
if [ -z "\$IFACE" ]; then exit 0; fi

# 读取系统当前网卡统计 (单位: Bytes)
RAW_RX=\$(cat /sys/class/net/\$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
RAW_TX=\$(cat /sys/class/net/\$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)

CACHE_FILE="/etc/sing-box/.traffic_cache"

# [优化 2] 确保缓存目录存在，防止误删导致写入失败
mkdir -p "\$(dirname "\$CACHE_FILE")"

# 加载本地历史缓存
if [ -f "\$CACHE_FILE" ]; then
    source "\$CACHE_FILE"
else
    PREV_RAW_RX=\$RAW_RX
    PREV_RAW_TX=\$RAW_TX
    ACCUMULATED_RX=0
    ACCUMULATED_TX=0
    LAST_RESET_MONTH=\$(date +%Y%m)
fi

# ================= 流量重置逻辑 =================
CURRENT_DAY=\$(date +%d)
CURRENT_MONTH=\$(date +%Y%m)
CURRENT_DAY_NUM=\$((10#\$CURRENT_DAY)) # 强制按10进制解析，防止08/09报错

if [ "\$RESET_DAY" -gt 0 ] && [ "\$CURRENT_MONTH" != "\$LAST_RESET_MONTH" ] && [ "\$CURRENT_DAY_NUM" -ge "\$RESET_DAY" ]; then
    ACCUMULATED_RX=0
    ACCUMULATED_TX=0
    LAST_RESET_MONTH=\$CURRENT_MONTH
fi

# ================= 计算增量逻辑 =================
# 检测服务器是否发生过重启 (当前网卡值小于记录的网卡值)
if [ "\$RAW_RX" -lt "\${PREV_RAW_RX:-0}" ]; then
    DELTA_RX=\$RAW_RX
    DELTA_TX=\$RAW_TX
else
    DELTA_RX=\$((\$RAW_RX - \$PREV_RAW_RX))
    DELTA_TX=\$((\$RAW_TX - \$PREV_RAW_TX))
fi

[ "\$DELTA_RX" -lt 0 ] && DELTA_RX=0
[ "\$DELTA_TX" -lt 0 ] && DELTA_TX=0

ACCUMULATED_RX=\$((ACCUMULATED_RX + DELTA_RX))
ACCUMULATED_TX=\$((ACCUMULATED_TX + DELTA_TX))

# ================= 保存缓存并上报 =================
cat > "\$CACHE_FILE" <<CACHE_EOF
PREV_RAW_RX=\$RAW_RX
PREV_RAW_TX=\$RAW_TX
ACCUMULATED_RX=\$ACCUMULATED_RX
ACCUMULATED_TX=\$ACCUMULATED_TX
LAST_RESET_MONTH=\$LAST_RESET_MONTH
CACHE_EOF

JSON_DATA="{\\"install_id\\": \\"\$INSTALL_ID\\", \\"rx_bytes\\": \$ACCUMULATED_RX, \\"tx_bytes\\": \$ACCUMULATED_TX}"

curl -s -4 -X POST -H "Content-Type: application/json" -d "\$JSON_DATA" "\$REPORT_URL" >/dev/null 2>&1 || \\
curl -s -6 -X POST -H "Content-Type: application/json" -d "\$JSON_DATA" "\$REPORT_URL" >/dev/null 2>&1

EOF

    chmod +x "$TRAFFIC_SCRIPT"

    # 清洗并挂载到 crontab 中
    crontab -l 2>/dev/null | grep -v "singbox_traffic.sh" > /tmp/crontab.tmp || true
    echo "*/5 * * * * bash $TRAFFIC_SCRIPT" >> /tmp/crontab.tmp
    crontab /tmp/crontab.tmp
    rm -f /tmp/crontab.tmp
    
    # [优化 3] 挂载完成后，立即在后台静默触发一次首报 (让面板瞬间变绿)
    bash "$TRAFFIC_SCRIPT" >/dev/null 2>&1 &
    
    info "✅ 流量监控配置完成 (上报间隔: 5 分钟，已触发首次心跳)"
}

# -----------------------
# [新增] 上报节点信息到后端
# -----------------------
report_nodes() {
    if [ -z "$REPORT_URL" ]; then return 0; fi
    if [ -z "$INSTALL_ID" ]; then warn "未提供安装 INSTALL_ID，跳过上报"; return 0; fi

    info "正在上报节点信息..."

    NODE_NAME=$(hostname)
    [ -z "$NODE_NAME" ] && NODE_NAME="SingBox-Node"
    
    # 处理 IPv6 格式 (加中括号)，用于生成链接
    local link_host="$PUB_IP"
    if [[ "$link_host" == *":"* ]]; then
        link_host="[$link_host]"
    fi

    # 1. SS
    if $ENABLE_SS; then
        local ss_userinfo="${SS_METHOD}:${PSK_SS}"
        local ss_encoded=$(printf "%s" "$ss_userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="ss://${ss_encoded}@${link_host}:${PORT_SS}#ss-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"ss\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "SS"
    fi

    # 2. HY2
    if $ENABLE_HY2; then
        local hy2_encoded=$(printf "%s" "$PSK_HY2" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="hy2://${hy2_encoded}@${link_host}:${PORT_HY2}/?sni=${FIXED_HY2_SNI}&alpn=h3&insecure=1#hy2-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"hy2\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "HY2"
    fi

    # 3. TUIC
    if $ENABLE_TUIC; then
        local tuic_encoded=$(printf "%s" "$PSK_TUIC" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="tuic://${UUID_TUIC}:${tuic_encoded}@${link_host}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=${FIXED_TUIC_SNI}&insecure=1#tuic-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"tuic\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "TUIC"
    fi

    # 4. Reality
    if $ENABLE_REALITY; then
        local link="vless://${UUID}@${link_host}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vless\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "Reality"
    fi
    
    # 5. SOCKS5
    if $ENABLE_SOCKS5; then
        local link="socks5://${USER_SOCKS5}:${PASS_SOCKS5}@${link_host}:${PORT_SOCKS5}#socks5-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"socks5\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "SOCKS5"
    fi

    # 6. Trojan
    if $ENABLE_TROJAN; then
        local trojan_encoded=$(printf "%s" "$PSK_TROJAN" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="trojan://${trojan_encoded}@${link_host}:${PORT_TROJAN}?sni=${FIXED_TROJAN_SNI}&allowInsecure=1#trojan-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"trojan\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "Trojan"
    fi

    # 7. VLESS-H2-Reality
    if $ENABLE_VLESS_H2; then
        local link="vless://${UUID_VLESS_H2}@${link_host}:${PORT_VLESS_H2}?encryption=none&flow=&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=h2&path=/&alpn=h2#vless-h2-${NODE_NAME}"
        local json_data="{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vless_h2\", \"link\": \"$link\"}"
        curl_post_submit "$REPORT_URL" "$json_data" "VLESS-H2"
    fi

    # 内部 vmess b64 辅助
    _vmess_b64_report() {
        local ps="$1" addr="$2" port="$3" uuid="$4" net="$5" tls="${6:-}" path="${7:-}" host="${8:-$2}" alpn="${9:-}"
        local allow_insecure="false"
        [ "$tls" = "tls" ] && allow_insecure="true"
        local json="{\"v\":\"2\",\"ps\":\"$ps\",\"add\":\"$addr\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"$net\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$tls\",\"sni\":\"$host\",\"alpn\":\"$alpn\",\"allowInsecure\":$allow_insecure}"
        printf 'vmess://%s' "$(printf '%s' "$json" | base64 | tr -d '\n')"
    }

    local rh="$PUB_IP"  # raw host (无中括号)
    local vmess_tls_sni="$FIXED_VMESS_TLS_SNI"
    local vless_tls_sni="$FIXED_VLESS_TLS_SNI"
    local trojan_tls_sni="$FIXED_TROJAN_TLS_SNI"
    if [ -z "$vmess_tls_sni" ]; then
        vmess_tls_sni="$rh"
    fi
    if [ -z "$vless_tls_sni" ]; then
        vless_tls_sni="$rh"
    fi
    if [ -z "$trojan_tls_sni" ]; then
        trojan_tls_sni="$rh"
    fi

    # 8. VMess-TCP
    if $ENABLE_VMESS_TCP; then
        local link=$(_vmess_b64_report "vmess-tcp-${NODE_NAME}" "$rh" "$PORT_VMESS_TCP" "$UUID_VMESS" "tcp")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_tcp\", \"link\": \"$link\"}" "VMess-TCP"
    fi
    # 9. VMess-WS
    if $ENABLE_VMESS_WS; then
        local link=$(_vmess_b64_report "vmess-ws-${NODE_NAME}" "$rh" "$PORT_VMESS_WS" "$UUID_VMESS" "ws" "" "$PATH_TRANSPORT")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_ws\", \"link\": \"$link\"}" "VMess-WS"
    fi
    # 10. VMess-HTTP
    if $ENABLE_VMESS_HTTP; then
        local link=$(_vmess_b64_report "vmess-http-${NODE_NAME}" "$rh" "$PORT_VMESS_HTTP" "$UUID_VMESS" "http" "" "$PATH_TRANSPORT")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_http\", \"link\": \"$link\"}" "VMess-HTTP"
    fi
    # 11. VMess-QUIC
    if $ENABLE_VMESS_QUIC; then
        local link=$(_vmess_b64_report "vmess-quic-${NODE_NAME}" "$rh" "$PORT_VMESS_QUIC" "$UUID_VMESS" "quic" "tls" "" "$vmess_tls_sni")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_quic\", \"link\": \"$link\"}" "VMess-QUIC"
    fi
    # 12. VMess-WS-TLS
    if $ENABLE_VMESS_WST; then
        local link=$(_vmess_b64_report "vmess-wst-${NODE_NAME}" "$rh" "$PORT_VMESS_WST" "$UUID_VMESS" "ws" "tls" "$PATH_TRANSPORT" "$vmess_tls_sni")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_wst\", \"link\": \"$link\"}" "VMess-WST"
    fi
    # 13. VMess-H2-TLS
    if $ENABLE_VMESS_H2T; then
        local link=$(_vmess_b64_report "vmess-h2t-${NODE_NAME}" "$rh" "$PORT_VMESS_H2T" "$UUID_VMESS" "h2" "tls" "$PATH_TRANSPORT" "$vmess_tls_sni" "h2")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_h2t\", \"link\": \"$link\"}" "VMess-H2T"
    fi
    # 14. VMess-HU-TLS
    if $ENABLE_VMESS_HUT; then
        local link=$(_vmess_b64_report "vmess-hut-${NODE_NAME}" "$rh" "$PORT_VMESS_HUT" "$UUID_VMESS" "httpupgrade" "tls" "$PATH_TRANSPORT" "$vmess_tls_sni")
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vmess_hut\", \"link\": \"$link\"}" "VMess-HUT"
    fi
    # 15. VLESS-WS-TLS
    if $ENABLE_VLESS_WST; then
        local link="vless://${UUID_VLESS_TLS}@${link_host}:${PORT_VLESS_WST}?security=tls&sni=${vless_tls_sni}&type=ws&path=${PATH_TRANSPORT}&allowInsecure=1&host=${vless_tls_sni}#vless-wst-${NODE_NAME}"
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vless_wst\", \"link\": \"$link\"}" "VLESS-WST"
    fi
    # 16. VLESS-H2-TLS
    if $ENABLE_VLESS_H2T; then
        local link="vless://${UUID_VLESS_TLS}@${link_host}:${PORT_VLESS_H2T}?security=tls&sni=${vless_tls_sni}&type=h2&path=${PATH_TRANSPORT}&host=${vless_tls_sni}&allowInsecure=1&alpn=h2#vless-h2t-${NODE_NAME}"
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vless_h2t\", \"link\": \"$link\"}" "VLESS-H2T"
    fi
    # 17. VLESS-HU-TLS
    if $ENABLE_VLESS_HUT; then
        local link="vless://${UUID_VLESS_TLS}@${link_host}:${PORT_VLESS_HUT}?security=tls&sni=${vless_tls_sni}&type=httpupgrade&path=${PATH_TRANSPORT}&host=${vless_tls_sni}&allowInsecure=1#vless-hut-${NODE_NAME}"
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"vless_hut\", \"link\": \"$link\"}" "VLESS-HUT"
    fi
    # 18. Trojan-WS-TLS
    if $ENABLE_TROJAN_WST; then
        local te=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="trojan://${te}@${link_host}:${PORT_TROJAN_WST}?sni=${trojan_tls_sni}&type=ws&path=${PATH_TRANSPORT}&allowInsecure=1&host=${trojan_tls_sni}#trojan-wst-${NODE_NAME}"
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"trojan_wst\", \"link\": \"$link\"}" "Trojan-WST"
    fi
    # 19. Trojan-H2-TLS
    if $ENABLE_TROJAN_H2T; then
        local te=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="trojan://${te}@${link_host}:${PORT_TROJAN_H2T}?sni=${trojan_tls_sni}&type=h2&path=${PATH_TRANSPORT}&host=${trojan_tls_sni}&allowInsecure=1&alpn=h2#trojan-h2t-${NODE_NAME}"
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"trojan_h2t\", \"link\": \"$link\"}" "Trojan-H2T"
    fi
    # 20. Trojan-HU-TLS
    if $ENABLE_TROJAN_HUT; then
        local te=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        local link="trojan://${te}@${link_host}:${PORT_TROJAN_HUT}?sni=${trojan_tls_sni}&type=httpupgrade&path=${PATH_TRANSPORT}&host=${trojan_tls_sni}&allowInsecure=1#trojan-hut-${NODE_NAME}"
        curl_post_submit "$REPORT_URL" "{\"install_id\": \"$INSTALL_ID\", \"protocol\": \"trojan_hut\", \"link\": \"$link\"}" "Trojan-HUT"
    fi

    # 8. 上报双栈 IP 信息
    local ip_json_data="{\"install_id\": \"$INSTALL_ID\", \"ipv4\": \"$SERVER_IPV4\", \"ipv6\": \"$SERVER_IPV6\"}"
    
    info "-> 上报双栈 IP 信息 (V4: ${SERVER_IPV4:-无}, V6: ${SERVER_IPV6:-无})..."
    curl_post_submit "$REPORT_URL" "$ip_json_data" "IP更新"


    info "✅ 上报完成"
}

# -----------------------
# 最终输出
echo ""
echo "=========================================="
info "🎉 Sing-box 部署完成!"
echo "=========================================="
echo ""
info "📋 配置信息:"
$ENABLE_SS && echo "   SS 端口: $PORT_SS | 密码: $PSK_SS | 加密: $SS_METHOD"
$ENABLE_HY2 && echo "   HY2 端口: $PORT_HY2 | 密码: $PSK_HY2 | SNI: $FIXED_HY2_SNI"
$ENABLE_TUIC && echo "   TUIC 端口: $PORT_TUIC | UUID: $UUID_TUIC | 密码: $PSK_TUIC | SNI: $FIXED_TUIC_SNI"
$ENABLE_REALITY && echo "   Reality 端口: $PORT_REALITY | UUID: $UUID"
$ENABLE_SOCKS5 && echo "   SOCKS5 端口: $PORT_SOCKS5 | 用户: $USER_SOCKS5 | 密码: $PASS_SOCKS5"
$ENABLE_TROJAN && echo "   Trojan 端口: $PORT_TROJAN | 密码: $PSK_TROJAN | SNI: $FIXED_TROJAN_SNI"
$ENABLE_VLESS_H2 && echo "   VLESS-H2-Reality 端口: $PORT_VLESS_H2 | UUID: $UUID_VLESS_H2"
$ENABLE_VMESS_TCP  && echo "   VMess-TCP 端口: $PORT_VMESS_TCP | UUID: $UUID_VMESS"
$ENABLE_VMESS_WS   && echo "   VMess-WS 端口: $PORT_VMESS_WS | UUID: $UUID_VMESS | Path: $PATH_TRANSPORT"
$ENABLE_VMESS_HTTP && echo "   VMess-HTTP 端口: $PORT_VMESS_HTTP | UUID: $UUID_VMESS | Path: $PATH_TRANSPORT"
$ENABLE_VMESS_QUIC && echo "   VMess-QUIC 端口: $PORT_VMESS_QUIC | UUID: $UUID_VMESS (TLS)"
$ENABLE_VMESS_WST  && echo "   VMess-WS-TLS 端口: $PORT_VMESS_WST | UUID: $UUID_VMESS | Path: $PATH_TRANSPORT"
$ENABLE_VMESS_H2T  && echo "   VMess-H2-TLS 端口: $PORT_VMESS_H2T | UUID: $UUID_VMESS | Path: $PATH_TRANSPORT"
$ENABLE_VMESS_HUT  && echo "   VMess-HU-TLS 端口: $PORT_VMESS_HUT | UUID: $UUID_VMESS | Path: $PATH_TRANSPORT"
$ENABLE_VLESS_WST  && echo "   VLESS-WS-TLS 端口: $PORT_VLESS_WST | UUID: $UUID_VLESS_TLS | Path: $PATH_TRANSPORT"
$ENABLE_VLESS_H2T  && echo "   VLESS-H2-TLS 端口: $PORT_VLESS_H2T | UUID: $UUID_VLESS_TLS | Path: $PATH_TRANSPORT"
$ENABLE_VLESS_HUT  && echo "   VLESS-HU-TLS 端口: $PORT_VLESS_HUT | UUID: $UUID_VLESS_TLS | Path: $PATH_TRANSPORT"
$ENABLE_TROJAN_WST && echo "   Trojan-WS-TLS 端口: $PORT_TROJAN_WST | 密码: $PSK_TROJAN_TLS | Path: $PATH_TRANSPORT"
$ENABLE_TROJAN_H2T && echo "   Trojan-H2-TLS 端口: $PORT_TROJAN_H2T | 密码: $PSK_TROJAN_TLS | Path: $PATH_TRANSPORT"
$ENABLE_TROJAN_HUT && echo "   Trojan-HU-TLS 端口: $PORT_TROJAN_HUT | 密码: $PSK_TROJAN_TLS | Path: $PATH_TRANSPORT"
echo "   服务器: $PUB_IP"
($ENABLE_REALITY || $ENABLE_VLESS_H2) && echo "   Reality server_name(SNI): ${REALITY_SNI:-addons.mozilla.org}"
echo ""
info "📂 文件位置:"
echo "   配置: $CONFIG_PATH"
($ENABLE_HY2 || $ENABLE_TUIC || $ENABLE_TROJAN || $ENABLE_VMESS_QUIC || $ENABLE_VMESS_WST || $ENABLE_VMESS_H2T || $ENABLE_VMESS_HUT || $ENABLE_VLESS_WST || $ENABLE_VLESS_H2T || $ENABLE_VLESS_HUT || $ENABLE_TROJAN_WST || $ENABLE_TROJAN_H2T || $ENABLE_TROJAN_HUT) && echo "   证书: /etc/sing-box/certs/"
echo "   服务: $SERVICE_PATH"
echo ""
info "📜 客户端链接:"
generate_uris | while IFS= read -r line; do
    echo "   $line"
done
echo ""
info "🔧 管理命令:"
if [ "$OS" = "alpine" ]; then
    echo "   启动: rc-service sing-box start"
    echo "   停止: rc-service sing-box stop"
    echo "   重启: rc-service sing-box restart"
    echo "   状态: rc-service sing-box status"
    echo "   日志: tail -f /var/log/sing-box.log"
else
    echo "   启动: systemctl start sing-box"
    echo "   停止: systemctl stop sing-box"
    echo "   重启: systemctl restart sing-box"
    echo "   状态: systemctl status sing-box"
    echo "   日志: journalctl -u sing-box -f"
fi
echo ""
echo "=========================================="

# 执行上报
report_nodes

# 配置并启动流量监控
setup_traffic_monitor

# -----------------------
# 创建 sb 管理脚本
SB_PATH="/usr/local/bin/sb"
info "正在创建 sb 管理面板: $SB_PATH"

cat > "$SB_PATH" <<'SB_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

CONFIG_PATH="/etc/sing-box/config.json"
CACHE_FILE="/etc/sing-box/.config_cache"
SERVICE_NAME="sing-box"

# 检测系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        ID=""
        ID_LIKE=""
    fi

    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi
}

detect_os

# 服务控制
service_start() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" start || systemctl start "$SERVICE_NAME"
}
service_stop() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" stop || systemctl stop "$SERVICE_NAME"
}
service_restart() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" restart || systemctl restart "$SERVICE_NAME"
}
service_status() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" status || systemctl status "$SERVICE_NAME" --no-pager
}

# 生成随机值
rand_port() { shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)); }
rand_pass() { openssl rand -base64 16 | tr -d '\n\r' || head -c 16 /dev/urandom | base64 | tr -d '\n\r'; }
rand_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | awk '{print substr($0,1,8)"-"substr($0,9,4)"-"substr($0,13,4)"-"substr($0,17,4)"-"substr($0,21,12)}'; }

# URL 编码
url_encode() {
    printf "%s" "$1" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/+/%2B/g' -e 's/\//%2F/g' -e 's/=/%3D/g'
}

# 读取配置
read_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "未找到配置文件: $CONFIG_PATH"
        return 1
    fi
    
    # 优先加载 .protocols 文件（确认协议标记）
    PROTOCOL_FILE="/etc/sing-box/.protocols"
    if [ -f "$PROTOCOL_FILE" ]; then
        . "$PROTOCOL_FILE"
    fi
    
    # 加载缓存文件（包含端口密码等详细配置）
    if [ -f "$CACHE_FILE" ]; then
        . "$CACHE_FILE"
    fi
    
    # 确保有默认值
    REALITY_SNI="${REALITY_SNI:-addons.mozilla.org}"
    CUSTOM_IP="${CUSTOM_IP:-}"

    # 读取各协议配置
    if [ "${ENABLE_SS:-false}" = "true" ]; then
        SS_PORT=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        SS_PSK=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .password // empty' "$CONFIG_PATH" | head -n1)
        SS_METHOD=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .method // empty' "$CONFIG_PATH" | head -n1)
    fi
    
    if [ "${ENABLE_HY2:-false}" = "true" ]; then
        HY2_PORT=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        HY2_PSK=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password // empty' "$CONFIG_PATH" | head -n1)
    fi
    
    if [ "${ENABLE_TUIC:-false}" = "true" ]; then
        TUIC_PORT=$(jq -r '.inbounds[] | select(.type=="tuic") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        TUIC_UUID=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].uuid // empty' "$CONFIG_PATH" | head -n1)
        TUIC_PSK=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].password // empty' "$CONFIG_PATH" | head -n1)
    fi
    
    if [ "${ENABLE_REALITY:-false}" = "true" ]; then
        REALITY_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        REALITY_UUID=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .users[0].uuid // empty' "$CONFIG_PATH" | head -n1)
        REALITY_PK=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.private_key // empty' "$CONFIG_PATH" | head -n1)
        REALITY_SID=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.short_id[0] // empty' "$CONFIG_PATH" | head -n1)
        [ -f /etc/sing-box/.reality_pub ] && REALITY_PUB=$(cat /etc/sing-box/.reality_pub)
    fi

    if [ "${ENABLE_SOCKS5:-false}" = "true" ]; then
        SOCKS5_PORT=$(jq -r '.inbounds[] | select(.type=="socks") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        SOCKS5_USER=$(jq -r '.inbounds[] | select(.type=="socks") | .users[0].username // empty' "$CONFIG_PATH" | head -n1)
        SOCKS5_PASS=$(jq -r '.inbounds[] | select(.type=="socks") | .users[0].password // empty' "$CONFIG_PATH" | head -n1)
    fi

    if [ "${ENABLE_TROJAN:-false}" = "true" ]; then
        TROJAN_PORT=$(jq -r '.inbounds[] | select(.tag=="trojan-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        TROJAN_PSK=$(jq -r '.inbounds[] | select(.tag=="trojan-in") | .users[0].password // empty' "$CONFIG_PATH" | head -n1)
        TROJAN_SNI="${TROJAN_SNI:-www.bing.com}"
    fi

    if [ "${ENABLE_VLESS_H2:-false}" = "true" ]; then
        VLESS_H2_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-h2-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
        VLESS_H2_UUID=$(jq -r '.inbounds[] | select(.tag=="vless-h2-in") | .users[0].uuid // empty' "$CONFIG_PATH" | head -n1)
        # 共用 Reality 公鑰
        [ -f /etc/sing-box/.reality_pub ] && VLESS_H2_PUB=$(cat /etc/sing-box/.reality_pub)
        [ -z "${REALITY_SID:-}" ] && REALITY_SID=$(jq -r '.inbounds[] | select(.tag=="vless-h2-in") | .tls.reality.short_id[0] // empty' "$CONFIG_PATH" | head -n1)
    fi

    # VMess 组（共用 UUID_VMESS 与 PATH_TRANSPORT，从缓存读取）
    UUID_VMESS="${UUID_VMESS:-}"
    PATH_TRANSPORT="${PATH_TRANSPORT:-/ray}"
    if [ "${ENABLE_VMESS_TCP:-false}" = "true" ]; then
        VMESS_TCP_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-tcp-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VMESS_WS:-false}" = "true" ]; then
        VMESS_WS_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-ws-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VMESS_HTTP:-false}" = "true" ]; then
        VMESS_HTTP_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-http-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VMESS_QUIC:-false}" = "true" ]; then
        VMESS_QUIC_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-quic-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VMESS_WST:-false}" = "true" ]; then
        VMESS_WST_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-wst-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VMESS_H2T:-false}" = "true" ]; then
        VMESS_H2T_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-h2t-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VMESS_HUT:-false}" = "true" ]; then
        VMESS_HUT_PORT=$(jq -r '.inbounds[] | select(.tag=="vmess-hut-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi

    # VLESS-TLS 组（共用 UUID_VLESS_TLS，从缓存读取）
    UUID_VLESS_TLS="${UUID_VLESS_TLS:-}"
    if [ "${ENABLE_VLESS_WST:-false}" = "true" ]; then
        VLESS_WST_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-wst-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VLESS_H2T:-false}" = "true" ]; then
        VLESS_H2T_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-h2t-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_VLESS_HUT:-false}" = "true" ]; then
        VLESS_HUT_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-hut-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi

    # Trojan-TLS 组（共用 PSK_TROJAN_TLS，从缓存读取）
    PSK_TROJAN_TLS="${PSK_TROJAN_TLS:-}"
    if [ "${ENABLE_TROJAN_WST:-false}" = "true" ]; then
        TROJAN_WST_PORT=$(jq -r '.inbounds[] | select(.tag=="trojan-wst-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_TROJAN_H2T:-false}" = "true" ]; then
        TROJAN_H2T_PORT=$(jq -r '.inbounds[] | select(.tag=="trojan-h2t-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
    if [ "${ENABLE_TROJAN_HUT:-false}" = "true" ]; then
        TROJAN_HUT_PORT=$(jq -r '.inbounds[] | select(.tag=="trojan-hut-in") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    fi
}

# 获取公网IP（原始方法）
get_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        [ -n "$ip" ] && echo "$ip" && return 0
    done
    echo "YOUR_SERVER_IP"
}

# 生成并保存URI
generate_uris() {
    read_config || return 1

    # 优先使用用户自定义入口 IP
    if [ -n "${CUSTOM_IP:-}" ]; then
        PUBLIC_IP="$CUSTOM_IP"
    else
        PUBLIC_IP=$(get_public_ip)
    fi

    node_suffix=$(cat /root/node_names.txt 2>/dev/null || echo "")
    
    URI_FILE="/etc/sing-box/uris.txt"
    > "$URI_FILE"
    
    if [ "${ENABLE_SS:-false}" = "true" ]; then
        ss_userinfo="${SS_METHOD}:${SS_PSK}"
        ss_encoded=$(url_encode "$ss_userinfo")
        ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')
        
        echo "=== Shadowsocks (SS) ===" >> "$URI_FILE"
        echo "ss://${ss_encoded}@${link_host}:${SS_PORT}#ss${node_suffix}" >> "$URI_FILE"
        echo "ss://${ss_b64}@${link_host}:${SS_PORT}#ss${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    
    if [ "${ENABLE_HY2:-false}" = "true" ]; then
        hy2_encoded=$(url_encode "$HY2_PSK")
        local _hy2_sni="${HY2_SNI:-www.bing.com}"
        echo "=== Hysteria2 (HY2) ===" >> "$URI_FILE"
        echo "hy2://${hy2_encoded}@${link_host}:${HY2_PORT}/?sni=${_hy2_sni}&alpn=h3&insecure=1#hy2${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    
    if [ "${ENABLE_TUIC:-false}" = "true" ]; then
        tuic_encoded=$(url_encode "$TUIC_PSK")
        local _tuic_sni="${TUIC_SNI:-www.bing.com}"
        echo "=== TUIC ===" >> "$URI_FILE"
        echo "tuic://${TUIC_UUID}:${tuic_encoded}@${link_host}:${TUIC_PORT}/?congestion_control=bbr&alpn=h3&sni=${_tuic_sni}&insecure=1#tuic${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    
    if [ "${ENABLE_REALITY:-false}" = "true" ]; then
        REALITY_SNI="${REALITY_SNI:-addons.mozilla.org}"
        echo "=== VLESS Reality ===" >> "$URI_FILE"
        echo "vless://${REALITY_UUID}@${link_host}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if [ "${ENABLE_SOCKS5:-false}" = "true" ]; then
        echo "=== SOCKS5 ===" >> "$URI_FILE"
        echo "socks5://${SOCKS5_USER}:${SOCKS5_PASS}@${link_host}:${SOCKS5_PORT}#socks5${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if [ "${ENABLE_TROJAN:-false}" = "true" ]; then
        trojan_encoded=$(url_encode "$TROJAN_PSK")
        local _trojan_sni="${TROJAN_SNI:-www.bing.com}"
        echo "=== Trojan ===" >> "$URI_FILE"
        echo "trojan://${trojan_encoded}@${link_host}:${TROJAN_PORT}?sni=${_trojan_sni}&allowInsecure=1#trojan${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if [ "${ENABLE_VLESS_H2:-false}" = "true" ]; then
        local _vless_h2_sni="${REALITY_SNI:-addons.mozilla.org}"
        local _vless_h2_pub="${VLESS_H2_PUB:-${REALITY_PUB:-}}"
        local _vless_h2_sid="${VLESS_H2_SID:-${REALITY_SID:-}}"
        echo "=== VLESS-H2-Reality ===" >> "$URI_FILE"
        echo "vless://${VLESS_H2_UUID}@${link_host}:${VLESS_H2_PORT}?encryption=none&flow=&security=reality&sni=${_vless_h2_sni}&fp=chrome&pbk=${_vless_h2_pub}&sid=${_vless_h2_sid}&type=h2&path=/&alpn=h2#vless-h2${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    # VMess base64 URI 辅助函数
    _vmess_b64() {
        local ps="$1" addr="$2" port="$3" uuid="$4" net="$5" tls="${6:-}" path="${7:-}" host="${8:-$2}" alpn="${9:-}"
        local allow_insecure="false"
        [ "$tls" = "tls" ] && allow_insecure="true"
        local json="{\"v\":\"2\",\"ps\":\"$ps\",\"add\":\"$addr\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"$net\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$tls\",\"sni\":\"$host\",\"alpn\":\"$alpn\",\"allowInsecure\":$allow_insecure}"
        printf 'vmess://%s' "$(printf '%s' "$json" | base64 | tr -d '\n')"
    }

    local rh="$PUBLIC_IP"
    local link_host="$PUBLIC_IP"
    if [[ "$link_host" == *":"* ]]; then
        link_host="[$link_host]"
    fi
    local vmess_tls_sni="${VMESS_TLS_SNI:-${TLS_SNI:-www.bing.com}}"
    local vless_tls_sni="${VLESS_TLS_SNI:-${TLS_SNI:-www.bing.com}}"
    local trojan_tls_sni="${TROJAN_TLS_SNI:-${TLS_SNI:-www.bing.com}}"
    local tp="${PATH_TRANSPORT:-/ray}"

    if [ "${ENABLE_VMESS_TCP:-false}" = "true" ]; then
        echo "=== VMess-TCP ===" >> "$URI_FILE"
        _vmess_b64 "vmess-tcp${node_suffix}" "$rh" "$VMESS_TCP_PORT" "$UUID_VMESS" "tcp" >> "$URI_FILE"
        echo "" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VMESS_WS:-false}" = "true" ]; then
        echo "=== VMess-WS ===" >> "$URI_FILE"
        _vmess_b64 "vmess-ws${node_suffix}" "$rh" "$VMESS_WS_PORT" "$UUID_VMESS" "ws" "" "$tp" >> "$URI_FILE"
        echo "" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VMESS_HTTP:-false}" = "true" ]; then
        echo "=== VMess-HTTP ===" >> "$URI_FILE"
        _vmess_b64 "vmess-http${node_suffix}" "$rh" "$VMESS_HTTP_PORT" "$UUID_VMESS" "http" "" "$tp" >> "$URI_FILE"
        echo "" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VMESS_QUIC:-false}" = "true" ]; then
        echo "=== VMess-QUIC(TLS) ===" >> "$URI_FILE"
        _vmess_b64 "vmess-quic${node_suffix}" "$rh" "$VMESS_QUIC_PORT" "$UUID_VMESS" "quic" "tls" "" "$vmess_tls_sni" >> "$URI_FILE"
        echo " (allowInsecure)" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VMESS_WST:-false}" = "true" ]; then
        echo "=== VMess-WS-TLS ===" >> "$URI_FILE"
        _vmess_b64 "vmess-wst${node_suffix}" "$rh" "$VMESS_WST_PORT" "$UUID_VMESS" "ws" "tls" "$tp" "$vmess_tls_sni" >> "$URI_FILE"
        echo " (allowInsecure)" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VMESS_H2T:-false}" = "true" ]; then
        echo "=== VMess-H2-TLS ===" >> "$URI_FILE"
        _vmess_b64 "vmess-h2t${node_suffix}" "$rh" "$VMESS_H2T_PORT" "$UUID_VMESS" "h2" "tls" "$tp" "$vmess_tls_sni" "h2" >> "$URI_FILE"
        echo " (allowInsecure)" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VMESS_HUT:-false}" = "true" ]; then
        echo "=== VMess-HU-TLS ===" >> "$URI_FILE"
        _vmess_b64 "vmess-hut${node_suffix}" "$rh" "$VMESS_HUT_PORT" "$UUID_VMESS" "httpupgrade" "tls" "$tp" "$vmess_tls_sni" >> "$URI_FILE"
        echo " (allowInsecure)" >> "$URI_FILE" ; echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VLESS_WST:-false}" = "true" ]; then
        echo "=== VLESS-WS-TLS ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS}@${link_host}:${VLESS_WST_PORT}?security=tls&sni=${vless_tls_sni}&type=ws&path=${tp}&allowInsecure=1&host=${vless_tls_sni}#vless-wst${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VLESS_H2T:-false}" = "true" ]; then
        echo "=== VLESS-H2-TLS ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS}@${link_host}:${VLESS_H2T_PORT}?security=tls&sni=${vless_tls_sni}&type=h2&path=${tp}&host=${vless_tls_sni}&allowInsecure=1&alpn=h2#vless-h2t${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_VLESS_HUT:-false}" = "true" ]; then
        echo "=== VLESS-HU-TLS ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS}@${link_host}:${VLESS_HUT_PORT}?security=tls&sni=${vless_tls_sni}&type=httpupgrade&path=${tp}&host=${vless_tls_sni}&allowInsecure=1#vless-hut${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_TROJAN_WST:-false}" = "true" ]; then
        local _te=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan-WS-TLS ===" >> "$URI_FILE"
        echo "trojan://${_te}@${link_host}:${TROJAN_WST_PORT}?sni=${trojan_tls_sni}&type=ws&path=${tp}&allowInsecure=1&host=${trojan_tls_sni}#trojan-wst${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_TROJAN_H2T:-false}" = "true" ]; then
        local _te=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan-H2-TLS ===" >> "$URI_FILE"
        echo "trojan://${_te}@${link_host}:${TROJAN_H2T_PORT}?sni=${trojan_tls_sni}&type=h2&path=${tp}&host=${trojan_tls_sni}&allowInsecure=1&alpn=h2#trojan-h2t${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "${ENABLE_TROJAN_HUT:-false}" = "true" ]; then
        local _te=$(printf "%s" "$PSK_TROJAN_TLS" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
        echo "=== Trojan-HU-TLS ===" >> "$URI_FILE"
        echo "trojan://${_te}@${link_host}:${TROJAN_HUT_PORT}?sni=${trojan_tls_sni}&type=httpupgrade&path=${tp}&host=${trojan_tls_sni}&allowInsecure=1#trojan-hut${node_suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    info "URI 已保存到: $URI_FILE"
}

# 查看URI
action_view_uri() {
    info "正在生成并显示 URI..."
    generate_uris || { err "生成 URI 失败"; return 1; }
    echo ""
    cat /etc/sing-box/uris.txt
}

# 查看配置文件路径
action_view_config() {
    echo "$CONFIG_PATH"
}

# 编辑配置
action_edit_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "配置文件不存在: $CONFIG_PATH"
        return 1
    fi
    
    ${EDITOR:-nano} "$CONFIG_PATH" 2>/dev/null || ${EDITOR:-vi} "$CONFIG_PATH"
    
    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
            info "配置校验通过,已重启服务"
            service_restart || warn "重启失败"
            generate_uris || true
        else
            warn "配置校验失败,服务未重启"
        fi
    fi
}

# 重置SS端口
action_reset_ss() {
    read_config || return 1
    
    if [ "${ENABLE_SS:-false}" != "true" ]; then
        err "SS 协议未启用"
        return 1
    fi
    
    read -p "输入新的 SS 端口(回车保持 $SS_PORT): " new_port
    new_port="${new_port:-$SS_PORT}"
    
    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    
    jq --argjson port "$new_port" '
    .inbounds |= map(if .type=="shadowsocks" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
    
    info "已启动服务并更新 SS 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 重置HY2端口
action_reset_hy2() {
    read_config || return 1
    
    if [ "${ENABLE_HY2:-false}" != "true" ]; then
        err "HY2 协议未启用"
        return 1
    fi
    
    read -p "输入新的 HY2 端口(回车保持 $HY2_PORT): " new_port
    new_port="${new_port:-$HY2_PORT}"
    
    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    
    jq --argjson port "$new_port" '
    .inbounds |= map(if .type=="hysteria2" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
    
    info "已启动服务并更新 HY2 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 重置TUIC端口
action_reset_tuic() {
    read_config || return 1
    
    if [ "${ENABLE_TUIC:-false}" != "true" ]; then
        err "TUIC 协议未启用"
        return 1
    fi
    
    read -p "输入新的 TUIC 端口(回车保持 $TUIC_PORT): " new_port
    new_port="${new_port:-$TUIC_PORT}"
    
    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    
    jq --argjson port "$new_port" '
    .inbounds |= map(if .type=="tuic" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
    
    info "已启动服务并更新 TUIC 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 重置Reality端口
action_reset_reality() {
    read_config || return 1
    
    if [ "${ENABLE_REALITY:-false}" != "true" ]; then
        err "Reality 协议未启用"
        return 1
    fi
    
    read -p "输入新的 Reality 端口(回车保持 $REALITY_PORT): " new_port
    new_port="${new_port:-$REALITY_PORT}"
    
    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    
    jq --argjson port "$new_port" '
    .inbounds |= map(if .tag=="vless-in" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
    
    info "已启动服务并更新 Reality 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 重置 SOCKS5 端口
action_reset_socks5() {
    read_config || return 1
    if [ "${ENABLE_SOCKS5:-false}" != "true" ]; then
        err "SOCKS5 协议未启用"
        return 1
    fi
    read -p "输入新的 SOCKS5 端口(回车保持 $SOCKS5_PORT): " new_port
    new_port="${new_port:-$SOCKS5_PORT}"

    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_port" '
    .inbounds |= map(if .type=="socks" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

    info "已启动服务并更新 SOCKS5 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 重置Trojan端口
action_reset_trojan() {
    read_config || return 1
    if [ "${ENABLE_TROJAN:-false}" != "true" ]; then
        err "Trojan 协议未启用"
        return 1
    fi
    read -p "输入新的 Trojan 端口(回车保持 $TROJAN_PORT): " new_port
    new_port="${new_port:-$TROJAN_PORT}"

    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_port" '
    .inbounds |= map(if .tag=="trojan-in" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

    info "已启动服务并更新 Trojan 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 重置VLESS-H2-Reality端口
action_reset_vless_h2() {
    read_config || return 1
    if [ "${ENABLE_VLESS_H2:-false}" != "true" ]; then
        err "VLESS-H2-Reality 协议未启用"
        return 1
    fi
    read -p "输入新的 VLESS-H2 端口(回车保持 $VLESS_H2_PORT): " new_port
    new_port="${new_port:-$VLESS_H2_PORT}"

    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_port" '
    .inbounds |= map(if .tag=="vless-h2-in" then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

    info "已启动服务并更新 VLESS-H2 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

# 通用 tag-based 端口重置辅助
_reset_port_by_tag() {
    local protocol_label="$1" enable_var="$2" port_var="$3" tag="$4"
    read_config || return 1
    eval "_enabled=\${${enable_var}:-false}"
    if [ "$_enabled" != "true" ]; then
        err "${protocol_label} 协议未启用"; return 1
    fi
    eval "_cur_port=\${${port_var}:-unknown}"
    read -p "输入新的 ${protocol_label} 端口(回车保持 ${_cur_port}): " new_port
    new_port="${new_port:-$_cur_port}"
    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    jq --argjson port "$new_port" --arg t "$tag" '
    .inbounds |= map(if .tag==$t then .listen_port = $port else . end)
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
    info "已启动服务并更新 ${protocol_label} 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

action_reset_vmess_tcp()  { _reset_port_by_tag "VMess-TCP"      ENABLE_VMESS_TCP  VMESS_TCP_PORT  "vmess-tcp-in";  }
action_reset_vmess_ws()   { _reset_port_by_tag "VMess-WS"       ENABLE_VMESS_WS   VMESS_WS_PORT   "vmess-ws-in";   }
action_reset_vmess_http() { _reset_port_by_tag "VMess-HTTP"      ENABLE_VMESS_HTTP VMESS_HTTP_PORT "vmess-http-in"; }
action_reset_vmess_quic() { _reset_port_by_tag "VMess-QUIC"      ENABLE_VMESS_QUIC VMESS_QUIC_PORT "vmess-quic-in"; }
action_reset_vmess_wst()  { _reset_port_by_tag "VMess-WS-TLS"   ENABLE_VMESS_WST  VMESS_WST_PORT  "vmess-wst-in";  }
action_reset_vmess_h2t()  { _reset_port_by_tag "VMess-H2-TLS"   ENABLE_VMESS_H2T  VMESS_H2T_PORT  "vmess-h2t-in";  }
action_reset_vmess_hut()  { _reset_port_by_tag "VMess-HU-TLS"   ENABLE_VMESS_HUT  VMESS_HUT_PORT  "vmess-hut-in";  }
action_reset_vless_wst()  { _reset_port_by_tag "VLESS-WS-TLS"   ENABLE_VLESS_WST  VLESS_WST_PORT  "vless-wst-in";  }
action_reset_vless_h2t()  { _reset_port_by_tag "VLESS-H2-TLS"   ENABLE_VLESS_H2T  VLESS_H2T_PORT  "vless-h2t-in";  }
action_reset_vless_hut()  { _reset_port_by_tag "VLESS-HU-TLS"   ENABLE_VLESS_HUT  VLESS_HUT_PORT  "vless-hut-in";  }
action_reset_trojan_wst() { _reset_port_by_tag "Trojan-WS-TLS"  ENABLE_TROJAN_WST TROJAN_WST_PORT "trojan-wst-in"; }
action_reset_trojan_h2t() { _reset_port_by_tag "Trojan-H2-TLS"  ENABLE_TROJAN_H2T TROJAN_H2T_PORT "trojan-h2t-in"; }
action_reset_trojan_hut() { _reset_port_by_tag "Trojan-HU-TLS"  ENABLE_TROJAN_HUT TROJAN_HUT_PORT "trojan-hut-in"; }
action_update() {
    info "开始更新 sing-box..."
    if [ "$OS" = "alpine" ]; then
        apk update && apk upgrade sing-box || bash <(curl -fsSL https://sing-box.app/install.sh)
    else
        bash <(curl -fsSL https://sing-box.app/install.sh)
    fi
    
    info "更新完成,已重启服务..."
    if command -v sing-box >/dev/null 2>&1; then
        NEW_VER=$(sing-box version 2>/dev/null | head -n1)
        info "当前版本: $NEW_VER"
        service_restart || warn "重启失败"
    fi
}

# 卸载
action_uninstall() {
    read -p "确认卸载 sing-box?(y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && info "已取消" && return 0
    
    info "正在卸载..."
    service_stop || true
    if [ "$OS" = "alpine" ]; then
        rc-update del sing-box default 2>/dev/null || true
        rm -f /etc/init.d/sing-box
        apk del sing-box 2>/dev/null || true
    else
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload 2>/dev/null || true
        apt purge -y sing-box >/dev/null 2>&1 || true
    fi
    rm -rf /etc/sing-box /var/log/sing-box* /usr/local/bin/sb /usr/bin/sing-box /root/node_names.txt 2>/dev/null || true
    info "卸载完成"
}

# 动态生成菜单
show_menu() {
    read_config 2>/dev/null || true
    
    cat <<'MENU'

==========================
 Sing-box 管理面板 (快速指令sb)
==========================
1) 查看协议链接
2) 查看配置文件路径
3) 编辑配置文件
MENU

    # 构建协议重置选项映射
    declare -g -A MENU_MAP
    MENU_MAP=()
    local option=4
    
    if [ "${ENABLE_SS:-false}" = "true" ]; then
        echo "$option) 重置 SS 端口"
        MENU_MAP[$option]="reset_ss"
        option=$((option + 1))
    fi
    
    if [ "${ENABLE_HY2:-false}" = "true" ]; then
        echo "$option) 重置 HY2 端口"
        MENU_MAP[$option]="reset_hy2"
        option=$((option + 1))
    fi
    
    if [ "${ENABLE_TUIC:-false}" = "true" ]; then
        echo "$option) 重置 TUIC 端口"
        MENU_MAP[$option]="reset_tuic"
        option=$((option + 1))
    fi
    
    if [ "${ENABLE_REALITY:-false}" = "true" ]; then
        echo "$option) 重置 Reality 端口"
        MENU_MAP[$option]="reset_reality"
        option=$((option + 1))
    fi

    if [ "${ENABLE_SOCKS5:-false}" = "true" ]; then
        echo "$option) 重置 SOCKS5 端口"
        MENU_MAP[$option]="reset_socks5"
        option=$((option + 1))
    fi

    if [ "${ENABLE_TROJAN:-false}" = "true" ]; then
        echo "$option) 重置 Trojan 端口"
        MENU_MAP[$option]="reset_trojan"
        option=$((option + 1))
    fi

    if [ "${ENABLE_VLESS_H2:-false}" = "true" ]; then
        echo "$option) 重置 VLESS-H2 端口"
        MENU_MAP[$option]="reset_vless_h2"
        option=$((option + 1))
    fi

    if [ "${ENABLE_VMESS_TCP:-false}" = "true" ]; then
        echo "$option) 重置 VMess-TCP 端口"
        MENU_MAP[$option]="reset_vmess_tcp"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VMESS_WS:-false}" = "true" ]; then
        echo "$option) 重置 VMess-WS 端口"
        MENU_MAP[$option]="reset_vmess_ws"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VMESS_HTTP:-false}" = "true" ]; then
        echo "$option) 重置 VMess-HTTP 端口"
        MENU_MAP[$option]="reset_vmess_http"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VMESS_QUIC:-false}" = "true" ]; then
        echo "$option) 重置 VMess-QUIC 端口"
        MENU_MAP[$option]="reset_vmess_quic"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VMESS_WST:-false}" = "true" ]; then
        echo "$option) 重置 VMess-WS-TLS 端口"
        MENU_MAP[$option]="reset_vmess_wst"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VMESS_H2T:-false}" = "true" ]; then
        echo "$option) 重置 VMess-H2-TLS 端口"
        MENU_MAP[$option]="reset_vmess_h2t"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VMESS_HUT:-false}" = "true" ]; then
        echo "$option) 重置 VMess-HU-TLS 端口"
        MENU_MAP[$option]="reset_vmess_hut"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VLESS_WST:-false}" = "true" ]; then
        echo "$option) 重置 VLESS-WS-TLS 端口"
        MENU_MAP[$option]="reset_vless_wst"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VLESS_H2T:-false}" = "true" ]; then
        echo "$option) 重置 VLESS-H2-TLS 端口"
        MENU_MAP[$option]="reset_vless_h2t"
        option=$((option + 1))
    fi
    if [ "${ENABLE_VLESS_HUT:-false}" = "true" ]; then
        echo "$option) 重置 VLESS-HU-TLS 端口"
        MENU_MAP[$option]="reset_vless_hut"
        option=$((option + 1))
    fi
    if [ "${ENABLE_TROJAN_WST:-false}" = "true" ]; then
        echo "$option) 重置 Trojan-WS-TLS 端口"
        MENU_MAP[$option]="reset_trojan_wst"
        option=$((option + 1))
    fi
    if [ "${ENABLE_TROJAN_H2T:-false}" = "true" ]; then
        echo "$option) 重置 Trojan-H2-TLS 端口"
        MENU_MAP[$option]="reset_trojan_h2t"
        option=$((option + 1))
    fi
    if [ "${ENABLE_TROJAN_HUT:-false}" = "true" ]; then
        echo "$option) 重置 Trojan-HU-TLS 端口"
        MENU_MAP[$option]="reset_trojan_hut"
        option=$((option + 1))
    fi

    # 固定功能选项
    MENU_MAP[$option]="start"
    echo "$option) 启动服务"
    option=$((option + 1))
    
    MENU_MAP[$option]="stop"
    echo "$((option))) 停止服务"
    option=$((option + 1))
    
    MENU_MAP[$option]="restart"
    echo "$((option))) 重启服务"
    option=$((option + 1))
    
    MENU_MAP[$option]="status"
    echo "$((option))) 查看状态"
    option=$((option + 1))
    
    MENU_MAP[$option]="update"
    echo "$((option))) 更新 sing-box"
    option=$((option + 1))

    MENU_MAP[$option]="uninstall"
    echo "$((option))) 卸载 sing-box"
    
    cat <<MENU2
0) 退出
==========================
MENU2
}

# 主循环
while true; do
    show_menu
    read -p "请输入选项: " opt
    
    # 处理退出
    if [ "$opt" = "0" ]; then
        exit 0
    fi
    
    # 处理固定选项
    case "$opt" in
        1) action_view_uri ;;
        2) action_view_config ;;
        3) action_edit_config ;;
        *)
            # 处理动态选项
            action="${MENU_MAP[$opt]:-}"
            case "$action" in
                reset_ss) action_reset_ss ;;
                reset_hy2) action_reset_hy2 ;;
                reset_tuic) action_reset_tuic ;;
                reset_reality) action_reset_reality ;;
                reset_socks5) action_reset_socks5 ;;
                reset_trojan) action_reset_trojan ;;
                reset_vless_h2) action_reset_vless_h2 ;;
                reset_vmess_tcp)  action_reset_vmess_tcp ;;
                reset_vmess_ws)   action_reset_vmess_ws ;;
                reset_vmess_http) action_reset_vmess_http ;;
                reset_vmess_quic) action_reset_vmess_quic ;;
                reset_vmess_wst)  action_reset_vmess_wst ;;
                reset_vmess_h2t)  action_reset_vmess_h2t ;;
                reset_vmess_hut)  action_reset_vmess_hut ;;
                reset_vless_wst)  action_reset_vless_wst ;;
                reset_vless_h2t)  action_reset_vless_h2t ;;
                reset_vless_hut)  action_reset_vless_hut ;;
                reset_trojan_wst) action_reset_trojan_wst ;;
                reset_trojan_h2t) action_reset_trojan_h2t ;;
                reset_trojan_hut) action_reset_trojan_hut ;;
                start) service_start && info "已启动" ;;
                stop) service_stop && info "已停止" ;;
                restart) service_restart && info "已重启" ;;
                status) service_status ;;
                update) action_update ;;
                uninstall) action_uninstall; exit 0 ;;
                *) warn "无效选项: $opt" ;;
            esac
            ;;
    esac
    
    echo ""
done
SB_SCRIPT

chmod +x "$SB_PATH"
info "✅ 管理面板已创建,可输入 sb 打开管理面板"
