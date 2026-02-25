#!/usr/bin/env bash
set -euo pipefail

# nodectl-agent 手动升级脚本（用于给旧节点补一次升级，之后由 agent 自更新接管）
# 用法：
#   sudo bash agent_install.sh
# 可选环境变量：
#   AGENT_BIN=/usr/local/bin/nodectl-agent
#   AGENT_CONF=/etc/nodectl-agent/config.json
#   AGENT_DOWNLOAD_BASE=https://github.com/hobin66/nodectl/releases/latest/download
#   AGENT_SERVICE_NAME=nodectl-agent

AGENT_BIN="${AGENT_BIN:-/usr/local/bin/nodectl-agent}"
AGENT_CONF="${AGENT_CONF:-/etc/nodectl-agent/config.json}"
AGENT_STATE_DIR="${AGENT_STATE_DIR:-/var/lib/nodectl-agent}"
AGENT_SERVICE_NAME="${AGENT_SERVICE_NAME:-nodectl-agent}"
AGENT_DOWNLOAD_BASE="${AGENT_DOWNLOAD_BASE:-https://github.com/hobin66/nodectl/releases/latest/download}"

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err()  { echo "[ERR ] $*" >&2; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "请使用 root 执行：sudo bash agent_install.sh"
    exit 1
  fi
}

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      err "不支持的架构: $m（仅支持 amd64 / arm64）"
      exit 1
      ;;
  esac
}

stop_service_if_any() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${AGENT_SERVICE_NAME}\.service"; then
    log "检测到 systemd 服务，准备停止 ${AGENT_SERVICE_NAME}"
    systemctl stop "${AGENT_SERVICE_NAME}" || true
    return 0
  fi

  if command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${AGENT_SERVICE_NAME}" ]; then
    log "检测到 OpenRC 服务，准备停止 ${AGENT_SERVICE_NAME}"
    rc-service "${AGENT_SERVICE_NAME}" stop || true
    return 0
  fi

  if pidof nodectl-agent >/dev/null 2>&1; then
    warn "未检测到服务管理器，尝试直接停止进程"
    pkill -x nodectl-agent || true
    sleep 1
  fi
}

start_service_if_any() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${AGENT_SERVICE_NAME}\.service"; then
    log "启动并设置开机自启: ${AGENT_SERVICE_NAME} (systemd)"
    systemctl daemon-reload || true
    systemctl enable "${AGENT_SERVICE_NAME}" || true
    systemctl restart "${AGENT_SERVICE_NAME}"
    return 0
  fi

  if command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${AGENT_SERVICE_NAME}" ]; then
    log "启动并设置开机自启: ${AGENT_SERVICE_NAME} (OpenRC)"
    rc-update add "${AGENT_SERVICE_NAME}" default >/dev/null 2>&1 || true
    rc-service "${AGENT_SERVICE_NAME}" restart || rc-service "${AGENT_SERVICE_NAME}" start
    return 0
  fi

  warn "未检测到 ${AGENT_SERVICE_NAME} 服务定义，将以后台方式临时启动（建议后续补 service）"
  nohup "${AGENT_BIN}" --config "${AGENT_CONF}" >/var/log/nodectl-agent.log 2>&1 &
}

main() {
  require_root

  if ! command -v curl >/dev/null 2>&1; then
    err "缺少 curl，请先安装后再执行"
    exit 1
  fi

  if [ ! -f "${AGENT_CONF}" ]; then
    err "未找到配置文件: ${AGENT_CONF}"
    err "请先确认节点已通过 nodectl 正常安装过 agent，再执行本脚本"
    exit 1
  fi

  mkdir -p "$(dirname "${AGENT_BIN}")" "${AGENT_STATE_DIR}"

  local arch url tmp_file backup_file
  arch="$(detect_arch)"
  url="${AGENT_DOWNLOAD_BASE}/nodectl-agent-linux-${arch}"
  tmp_file="$(mktemp /tmp/nodectl-agent.XXXXXX)"
  backup_file="${AGENT_BIN}.manual.$(date +%Y%m%d%H%M%S).bak"

  log "下载新版 nodectl-agent (${arch})"
  log "URL: ${url}"
  curl -fL --connect-timeout 15 --max-time 120 -o "${tmp_file}" "${url}"
  chmod +x "${tmp_file}"

  # 轻量校验：确认是可执行文件
  if ! file "${tmp_file}" 2>/dev/null | grep -Eq 'ELF|executable'; then
    err "下载文件不是有效可执行文件，已中止"
    rm -f "${tmp_file}"
    exit 1
  fi

  stop_service_if_any

  if [ -f "${AGENT_BIN}" ]; then
    cp -f "${AGENT_BIN}" "${backup_file}"
    log "已备份旧二进制 -> ${backup_file}"
  fi

  install -m 0755 "${tmp_file}" "${AGENT_BIN}"
  rm -f "${tmp_file}"

  log "新版本已安装到 ${AGENT_BIN}"

  # 打印版本（兼容旧版无 --version 的情况）
  if "${AGENT_BIN}" --version >/dev/null 2>&1; then
    "${AGENT_BIN}" --version || true
  else
    warn "该二进制不支持 --version 输出，跳过版本打印"
  fi

  start_service_if_any

  sleep 2
  if pidof nodectl-agent >/dev/null 2>&1; then
    log "升级成功：nodectl-agent 正在运行，后续将按新版本逻辑自动更新"
  else
    err "升级后未检测到 nodectl-agent 进程，请检查日志"
    if command -v systemctl >/dev/null 2>&1; then
      err "排查命令: journalctl -u ${AGENT_SERVICE_NAME} -n 50 --no-pager"
    else
      err "排查命令: tail -n 50 /var/log/nodectl-agent.log"
    fi
    exit 1
  fi
}

main "$@"
