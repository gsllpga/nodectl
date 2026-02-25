#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# nodectl-agent 一次性手动升级脚本（旧节点补升级专用）
#
# 运行方式（在节点服务器直接执行）：
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/hobin66/nodectl/main/agent_install.sh)"
#
# 或先下载后执行：
#   curl -fsSL -o /root/agent_install.sh https://raw.githubusercontent.com/hobin66/nodectl/main/agent_install.sh
#   sudo bash /root/agent_install.sh
#
# 说明：
# - 本脚本按 .github/workflows/release.yml 的命名规则匹配最新 agent：
#   nodectl-agent-linux-<arch>-vX.Y.Z(可带后缀)
# - 仅用于本次手动替换；替换完成后由新 agent 自更新机制接管
# ==========================================================

# 写死仓库坐标（按你的要求）
REPO_OWNER="hobin66"
REPO_NAME="nodectl"
RELEASE_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

AGENT_BIN="/usr/local/bin/nodectl-agent"
AGENT_CONF="/etc/nodectl-agent/config.json"
AGENT_STATE_DIR="/var/lib/nodectl-agent"
AGENT_SERVICE_NAME="nodectl-agent"

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err()  { echo "[ERR ] $*" >&2; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "请使用 root 执行"
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

fetch_latest_asset_url() {
  local arch="$1"
  local pattern="nodectl-agent-linux-${arch}-v"
  local api_json

  api_json="$(curl -fsSL -H 'Accept: application/vnd.github+json' -H 'User-Agent: nodectl-agent-installer' "${RELEASE_API}")"

  # 从 releases/latest 的 assets 中提取 browser_download_url
  # 只要匹配 nodectl-agent-linux-<arch>-v... 且排除 .sha256
  local url
  url="$(echo "${api_json}" \
    | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/^"browser_download_url"[[:space:]]*:[[:space:]]*"(.*)"$/\1/' \
    | grep "${pattern}" \
    | grep -vE '\.sha256$' \
    | head -n 1 || true)"

  if [ -z "${url}" ]; then
    err "未在 latest release 中找到匹配资产: ${pattern}*"
    err "请检查 ${RELEASE_API} 的 assets 命名是否符合 release.yml"
    exit 1
  fi

  echo "${url}"
}

stop_service_if_any() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${AGENT_SERVICE_NAME}\.service"; then
    log "检测到 systemd 服务，停止 ${AGENT_SERVICE_NAME}"
    systemctl stop "${AGENT_SERVICE_NAME}" || true
    return 0
  fi

  if command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${AGENT_SERVICE_NAME}" ]; then
    log "检测到 OpenRC 服务，停止 ${AGENT_SERVICE_NAME}"
    rc-service "${AGENT_SERVICE_NAME}" stop || true
    return 0
  fi

  if pidof nodectl-agent >/dev/null 2>&1; then
    warn "未检测到服务定义，尝试直接停止进程"
    pkill -x nodectl-agent || true
    sleep 1
  fi
}

start_service_if_any() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${AGENT_SERVICE_NAME}\.service"; then
    log "启动 ${AGENT_SERVICE_NAME} (systemd)"
    systemctl daemon-reload || true
    systemctl enable "${AGENT_SERVICE_NAME}" || true
    systemctl restart "${AGENT_SERVICE_NAME}"
    return 0
  fi

  if command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${AGENT_SERVICE_NAME}" ]; then
    log "启动 ${AGENT_SERVICE_NAME} (OpenRC)"
    rc-update add "${AGENT_SERVICE_NAME}" default >/dev/null 2>&1 || true
    rc-service "${AGENT_SERVICE_NAME}" restart || rc-service "${AGENT_SERVICE_NAME}" start
    return 0
  fi

  warn "未检测到 ${AGENT_SERVICE_NAME} 服务定义，使用 nohup 临时启动"
  nohup "${AGENT_BIN}" --config "${AGENT_CONF}" >/var/log/nodectl-agent.log 2>&1 &
}

is_elf_binary() {
  local f="$1"
  # 直接检查 ELF 魔数 0x7f 45 4c 46，避免依赖 file 命令
  local magic
  magic="$(dd if="${f}" bs=1 count=4 2>/dev/null | od -An -t x1 | tr -d ' \n')"
  [ "${magic}" = "7f454c46" ]
}

main() {
  require_root

  if ! command -v curl >/dev/null 2>&1; then
    err "缺少 curl，请先安装"
    exit 1
  fi

  if [ ! -f "${AGENT_CONF}" ]; then
    err "未找到配置文件: ${AGENT_CONF}"
    err "请先确认节点已安装过 nodectl-agent"
    exit 1
  fi

  mkdir -p "$(dirname "${AGENT_BIN}")" "${AGENT_STATE_DIR}"

  local arch url tmp_file backup_file
  arch="$(detect_arch)"
  url="$(fetch_latest_asset_url "${arch}")"
  tmp_file="$(mktemp /tmp/nodectl-agent.XXXXXX)"
  backup_file="${AGENT_BIN}.manual.$(date +%Y%m%d%H%M%S).bak"

  log "下载最新 nodectl-agent (${arch})"
  log "URL: ${url}"
  curl -fL --connect-timeout 15 --max-time 180 -o "${tmp_file}" "${url}"
  chmod +x "${tmp_file}"

  if ! is_elf_binary "${tmp_file}"; then
    err "下载文件不是有效 ELF 可执行文件，已中止"
    if command -v file >/dev/null 2>&1; then
      warn "file 检测结果: $(file "${tmp_file}" 2>/dev/null || echo unknown)"
    fi
    rm -f "${tmp_file}"
    exit 1
  fi

  # 可选输出：便于现场确认
  if command -v file >/dev/null 2>&1; then
    log "文件类型: $(file "${tmp_file}" 2>/dev/null || echo unknown)"
  fi

  stop_service_if_any

  if [ -f "${AGENT_BIN}" ]; then
    cp -f "${AGENT_BIN}" "${backup_file}"
    log "已备份旧二进制 -> ${backup_file}"
  fi

  install -m 0755 "${tmp_file}" "${AGENT_BIN}"
  rm -f "${tmp_file}"
  log "已安装新二进制 -> ${AGENT_BIN}"

  if "${AGENT_BIN}" --version >/dev/null 2>&1; then
    "${AGENT_BIN}" --version || true
  else
    warn "该二进制不支持 --version 输出，跳过版本打印"
  fi

  start_service_if_any

  sleep 2
  if pidof nodectl-agent >/dev/null 2>&1; then
    log "升级成功：nodectl-agent 已运行，后续将由新版本自动更新机制接管"
  else
    err "升级后未检测到 nodectl-agent 进程，请检查日志"
    if command -v systemctl >/dev/null 2>&1; then
      err "排查: journalctl -u ${AGENT_SERVICE_NAME} -n 80 --no-pager"
    else
      err "排查: tail -n 80 /var/log/nodectl-agent.log"
    fi
    exit 1
  fi
}

main "$@"
