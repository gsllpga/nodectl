// 路径: internal/server/install_handler.go
// 安装脚本生成接口（新版极简安装脚本 + Agent 二进制下载 + na 快捷命令）
package server

import (
	"fmt"
	"strings"

	"nodectl/internal/version"
)

// generateMinimalInstallScript 🆕 生成新版极简安装脚本
// 负责：检测系统环境 → 安装依赖 → 下载 agent → 写配置 → 注册系统服务 → 注册 na 快捷命令
// 支持 Debian/Ubuntu、CentOS/RHEL/Fedora、Alpine Linux 三大系统族
// 所有复杂逻辑（sing-box 安装、配置生成、证书管理）内置于 Agent 二进制中
func generateMinimalInstallScript(installID, panelURL string) string {
	// 获取当前面板的发布渠道（仅用于下载阶段，确保下载与面板版本匹配的 Agent）
	channel := string(version.GetChannel())

	return fmt.Sprintf(`#!/usr/bin/env bash
# NodeCTL Agent 安装脚本 (新版极简模式)
# 由面板动态生成，用户无需手动修改
# 可选参数：--report-url <URL>  指定备用回调地址（如 Tunnel 隧道地址）

set -euo pipefail

# ========== 面板生成时自动填充 ==========
INSTALL_ID="%s"
PANEL_URL="%s"
CHANNEL="%s"
# =========================================

# 彩色输出
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

# -----------------------
# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限"
        err "请使用: sudo bash -c \"\$(curl -fsSL ...)\" 或切换到 root 用户"
        exit 1
    fi
}

# 解析命令行参数
REPORT_URL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --report-url)
            REPORT_URL="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# 检测架构
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) err "不支持的架构: $arch"; exit 1 ;;
    esac
}

# 注册 na 快捷命令
install_na_command() {
    info "注册 na 快捷命令..."

    cat > /usr/local/bin/na <<'NAEOF'
#!/usr/bin/env bash
# NodeCTL Agent 快捷管理命令 (na)
# 用法: na [命令]  或直接运行 na 进入交互式菜单

set -euo pipefail

# 彩色输出
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; }

# 检查 root
if [ "$(id -u)" != "0" ]; then
    err "na 命令需要 root 权限，请使用 sudo na"
    exit 1
fi

# 检测 init 系统
detect_init() {
    if [ -f /etc/alpine-release ] || command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    else
        echo "systemd"
    fi
}

INIT_SYS=$(detect_init)

# ========== 各功能实现 ==========

do_start() {
    info "启动 nodectl-agent..."
    if [ "$INIT_SYS" = "openrc" ]; then
        rc-service nodectl-agent start
    else
        systemctl start nodectl-agent
    fi
    ok "nodectl-agent 已启动"
}

do_stop() {
    info "停止 nodectl-agent..."
    if [ "$INIT_SYS" = "openrc" ]; then
        rc-service nodectl-agent stop
    else
        systemctl stop nodectl-agent
    fi
    ok "nodectl-agent 已停止"
}

do_restart() {
    info "重启 nodectl-agent..."
    if [ "$INIT_SYS" = "openrc" ]; then
        rc-service nodectl-agent restart
    else
        systemctl restart nodectl-agent
    fi
    ok "nodectl-agent 已重启"
}

do_status() {
    echo ""
    echo -e "${CYAN}========== NodeCTL Agent 状态 ==========${NC}"
    if [ "$INIT_SYS" = "openrc" ]; then
        rc-service nodectl-agent status 2>/dev/null || warn "服务未运行"
    else
        systemctl status nodectl-agent --no-pager 2>/dev/null || warn "服务未运行"
    fi
    echo ""
    # 检查 sing-box 进程
    if pidof sing-box >/dev/null 2>&1; then
        ok "sing-box 运行中 (PID: $(pidof sing-box | awk '{print $1}'))"
    else
        warn "sing-box 未运行"
    fi
    echo -e "${CYAN}========================================${NC}"
}

do_log() {
    info "显示最近 50 行日志 (Ctrl+C 退出实时跟踪)..."
    echo ""
    if [ -f /var/log/nodectl-agent.log ]; then
        tail -50f /var/log/nodectl-agent.log
    else
        warn "日志文件不存在: /var/log/nodectl-agent.log"
        if [ "$INIT_SYS" = "systemd" ]; then
            info "尝试使用 journalctl..."
            journalctl -u nodectl-agent -n 50 -f
        fi
    fi
}

do_singbox_log() {
    info "显示 sing-box 最近 50 行日志 (Ctrl+C 退出实时跟踪)..."
    echo ""
    if [ -f /var/log/nodectl-agent/singbox.log ]; then
        tail -50f /var/log/nodectl-agent/singbox.log
    else
        warn "sing-box 日志文件不存在: /var/log/nodectl-agent/singbox.log"
    fi
}

do_uninstall() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║    ⚠️  警告：即将完整卸载 NodeCTL Agent      ║${NC}"
    echo -e "${RED}║                                              ║${NC}"
    echo -e "${RED}║  将删除以下内容：                            ║${NC}"
    echo -e "${RED}║    • nodectl-agent 服务和二进制               ║${NC}"
    echo -e "${RED}║    • sing-box 二进制和配置                    ║${NC}"
    echo -e "${RED}║    • 所有配置文件                             ║${NC}"
    echo -e "${RED}║    • 所有日志文件                             ║${NC}"
    echo -e "${RED}║    • 证书文件                                 ║${NC}"
    echo -e "${RED}║    • na 快捷命令                              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    read -r -p "确认卸载？输入 yes 继续: " confirm
    if [ "$confirm" != "yes" ]; then
        info "已取消卸载"
        return
    fi

    info "开始完整卸载..."

    # 1. 停止 sing-box 进程（agent 管理的子进程）
    info "[1/7] 停止 sing-box..."
    killall sing-box 2>/dev/null || true
    # 等待进程退出
    sleep 1
    # 强制清除残余进程
    pkill -9 -f "sing-box" 2>/dev/null || true

    # 2. 停止并禁用 nodectl-agent 服务
    info "[2/7] 停止 nodectl-agent 服务..."
    if [ "$INIT_SYS" = "openrc" ]; then
        rc-service nodectl-agent stop 2>/dev/null || true
        rc-update del nodectl-agent default 2>/dev/null || true
        rm -f /etc/init.d/nodectl-agent
    else
        systemctl stop nodectl-agent 2>/dev/null || true
        systemctl disable nodectl-agent 2>/dev/null || true
        rm -f /etc/systemd/system/nodectl-agent.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    # 确保进程完全退出
    killall nodectl-agent 2>/dev/null || true
    pkill -9 -f "nodectl-agent" 2>/dev/null || true

    # 3. 删除二进制文件
    info "[3/7] 删除二进制文件..."
    rm -f /usr/local/bin/nodectl-agent
    rm -f /var/lib/nodectl-agent/sing-box

    # 4. 删除配置文件
    info "[4/7] 删除配置文件..."
    rm -rf /etc/nodectl-agent
    rm -f /var/lib/nodectl-agent/singbox-config.json
    rm -f /var/lib/nodectl-agent/protocols.json

    # 5. 删除证书文件
    info "[5/7] 删除证书文件..."
    rm -rf /var/lib/nodectl-agent/certs

    # 6. 删除日志文件和数据目录
    info "[6/7] 删除日志和数据目录..."
    rm -f /var/log/nodectl-agent.log
    rm -rf /var/log/nodectl-agent
    rm -f /var/lib/nodectl-agent/singbox.pid
    # 清理数据目录（若已为空则删除）
    rmdir /var/lib/nodectl-agent 2>/dev/null || rm -rf /var/lib/nodectl-agent

    # 7. 删除 na 快捷命令自身
    info "[7/7] 删除 na 快捷命令..."
    rm -f /usr/local/bin/na

    echo ""
    ok "✅ NodeCTL Agent 已完整卸载！"
    ok "  已清除: 二进制、sing-box、配置、证书、日志、服务、na 命令"
    echo ""
}

do_update() {
    info "重新下载并更新 nodectl-agent..."
    # 读取当前配置中的 panel_url
    if [ -f /etc/nodectl-agent/config.json ]; then
        PANEL_URL=$(grep -o '"panel_url"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/nodectl-agent/config.json | head -1 | sed 's/.*"panel_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    else
        err "配置文件不存在，无法获取面板地址"
        return 1
    fi

    if [ -z "$PANEL_URL" ]; then
        err "无法从配置中读取 panel_url"
        return 1
    fi

    # 检测架构
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) err "不支持的架构: $arch"; return 1 ;;
    esac

    local DOWNLOAD_URL="${PANEL_URL}/api/public/download/agent?arch=${arch}"
    local AGENT_BIN="/usr/local/bin/nodectl-agent"

    # 停止服务
    do_stop 2>/dev/null || true

    info "下载新版本..."
    curl -fsSL "$DOWNLOAD_URL" -o "$AGENT_BIN"
    chmod +x "$AGENT_BIN"

    # 启动服务
    do_start
    ok "nodectl-agent 更新完成"
}

# ========== 交互式菜单 ==========

show_menu() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        NodeCTL Agent 管理面板 (na)           ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║                                              ║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}1)${NC} 启动 Agent                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}2)${NC} 停止 Agent                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}3)${NC} 重启 Agent                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}4)${NC} 查看状态                                 ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}5)${NC} 查看 Agent 日志                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}6)${NC} 查看 sing-box 日志                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}7)${NC} 更新 Agent                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}8)${NC} 完整卸载 (清除所有数据)                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}0)${NC} 退出                                     ${CYAN}║${NC}"
    echo -e "${CYAN}║                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    read -r -p "请选择 [0-8]: " choice
    case "$choice" in
        1) do_start ;;
        2) do_stop ;;
        3) do_restart ;;
        4) do_status ;;
        5) do_log ;;
        6) do_singbox_log ;;
        7) do_update ;;
        8) do_uninstall ;;
        0) echo "退出"; exit 0 ;;
        *) warn "无效选择，请重试" ;;
    esac
}

# ========== 命令行直接调用 ==========

show_help() {
    echo ""
    echo -e "${CYAN}NodeCTL Agent 快捷命令 (na)${NC}"
    echo ""
    echo "用法: na [命令]"
    echo ""
    echo "可用命令:"
    echo "  start       启动 Agent"
    echo "  stop        停止 Agent"
    echo "  restart     重启 Agent"
    echo "  status      查看运行状态"
    echo "  log         查看 Agent 日志"
    echo "  sblog       查看 sing-box 日志"
    echo "  update      更新 Agent"
    echo "  uninstall   完整卸载 (清除所有数据)"
    echo "  help        显示此帮助"
    echo ""
    echo "不带参数运行 na 可进入交互式菜单"
    echo ""
}

# ========== 主入口 ==========

if [ $# -eq 0 ]; then
    # 无参数，进入交互式菜单
    while true; do
        show_menu
        echo ""
        read -r -p "按回车继续..." _
    done
else
    # 有参数，直接执行对应命令
    case "$1" in
        start)      do_start ;;
        stop)       do_stop ;;
        restart)    do_restart ;;
        status)     do_status ;;
        log|logs)   do_log ;;
        sblog)      do_singbox_log ;;
        update)     do_update ;;
        uninstall)  do_uninstall ;;
        help|--help|-h) show_help ;;
        *)
            err "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
fi
NAEOF

    chmod +x /usr/local/bin/na
    info "na 快捷命令已注册 ✓"
    info "  用法: na        (交互式菜单)"
    info "  用法: na help   (查看所有命令)"
}

# 主安装逻辑
main() {
    # 0. 环境检测与准备
    detect_os
    check_root

    info "NodeCTL Agent 安装脚本"
    info "检测到系统: $OS (${OS_ID:-unknown})"

    local ARCH=$(detect_arch)

    info "检测到架构: $ARCH"

    # 1. 清理旧 agent（如果存在）
    if [ "$OS" = "alpine" ]; then
        rc-service nodectl-agent stop 2>/dev/null || true
    else
        systemctl stop nodectl-agent 2>/dev/null || true
    fi
    killall nodectl-agent 2>/dev/null || true

    # 2. 下载 agent（channel 参数确保下载与面板版本匹配的 Agent）
    local DOWNLOAD_URL="${PANEL_URL}/api/public/download/agent?arch=${ARCH}&channel=${CHANNEL}"
    local AGENT_BIN="/usr/local/bin/nodectl-agent"
    local CONFIG_DIR="/etc/nodectl-agent"
    local DATA_DIR="/var/lib/nodectl-agent"
    local LOG_DIR="/var/log"

    info "正在下载 nodectl-agent..."
    curl -fsSL "$DOWNLOAD_URL" -o "$AGENT_BIN"
    chmod +x "$AGENT_BIN"

    # 3. 创建必要目录
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"

    # 4. 生成最小化配置
    # 如果指定了 --report-url，则使用该地址作为回调地址；否则使用面板地址
    local CALLBACK_URL="${REPORT_URL:-$PANEL_URL}"

    cat > "${CONFIG_DIR}/config.json" <<EOF
{
  "install_id": "$INSTALL_ID",
  "panel_url": "$CALLBACK_URL",
  "interface": "auto",
  "log_level": "info"
}
EOF

    info "配置文件已写入: ${CONFIG_DIR}/config.json"
    if [ -n "$REPORT_URL" ]; then
        info "使用自定义回调地址: $REPORT_URL"
    fi

    # 5. 注册系统服务（根据 init 系统自动选择）
    if [ "$OS" = "alpine" ]; then
        # OpenRC 服务 (Alpine Linux)
        cat > /etc/init.d/nodectl-agent <<'SVCEOF'
#!/sbin/openrc-run
name="nodectl-agent"
description="NodeCTL Agent - 一体化代理管理器"
command="/usr/local/bin/nodectl-agent"
command_background=true
pidfile="/run/nodectl-agent.pid"
output_log="/var/log/nodectl-agent.log"
error_log="/var/log/nodectl-agent.log"

depend() {
    need net
    after firewall
}
SVCEOF
        chmod +x /etc/init.d/nodectl-agent
        rc-update add nodectl-agent default 2>/dev/null || true
        rc-service nodectl-agent restart 2>/dev/null || \
            rc-service nodectl-agent start 2>/dev/null || true
        info "OpenRC 服务已注册并启动 ✓"
    else
        # systemd 服务 (Debian/Ubuntu/CentOS/RHEL/Fedora 等)
        cat > /etc/systemd/system/nodectl-agent.service <<'SVCEOF'
[Unit]
Description=NodeCTL Agent - 一体化代理管理器
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nodectl-agent
WorkingDirectory=/var/lib/nodectl-agent
Restart=always
RestartSec=5
LimitNOFILE=1048576

StandardOutput=append:/var/log/nodectl-agent.log
StandardError=append:/var/log/nodectl-agent.log

[Install]
WantedBy=multi-user.target
SVCEOF
        systemctl daemon-reload
        systemctl enable nodectl-agent
        systemctl restart nodectl-agent
        info "systemd 服务已注册并启动 ✓"
    fi

    # 6. 注册 na 快捷命令
    install_na_command

    # 7. 验证安装
    sleep 2
    if pidof nodectl-agent >/dev/null 2>&1; then
        info "✅ nodectl-agent 安装完成！(PID: $(pidof nodectl-agent | awk '{print $1}'))"
    else
        warn "⚠️ nodectl-agent 进程未检测到，请检查日志"
        warn "  查看日志: tail -20 /var/log/nodectl-agent.log"
    fi

    info ""
    info "快捷管理命令:"
    info "  na          进入交互式管理菜单"
    info "  na start    启动 Agent"
    info "  na stop     停止 Agent"
    info "  na restart  重启 Agent"
    info "  na status   查看状态"
    info "  na log      查看日志"
    info "  na help     查看所有命令"
}

main
`, installID, panelURL, channel)
}

// getPanelURLForScript 获取面板 URL 用于安装脚本生成
// 优先使用配置中的 panel_url，否则从请求中推导
func getPanelURLForScript(configPanelURL string, requestHost string, isSecure bool) string {
	if strings.TrimSpace(configPanelURL) != "" {
		return strings.TrimRight(configPanelURL, "/")
	}

	scheme := "http"
	if isSecure {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, requestHost)
}
