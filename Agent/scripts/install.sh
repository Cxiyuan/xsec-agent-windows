#!/bin/bash
#
# xsec-agent Linux 安装脚本
#

set -e

VERSION="1.0.0"
AGENT_NAME="xsec-agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/xsec"
BIN_DIR="/usr/bin"
CONFIG_DIR="/etc/xsec"
LOG_DIR="/var/log/xsec"
RUN_DIR="/var/run"
SYSTEMD_UNIT="/etc/systemd/system/${AGENT_NAME}.service"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "需要 root 权限，请使用 sudo"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$NAME
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    if ! command -v systemctl &> /dev/null; then
        log_error "此系统未安装 systemd"
        exit 1
    fi
    log_info "检测到系统: ${OS_NAME}"
}

check_dependencies() {
    log_info "检查依赖..."
    if command -v dpkg &> /dev/null; then PKG_MANAGER="dpkg"
    elif command -v rpm &> /dev/null; then PKG_MANAGER="rpm"
    else PKG_MANAGER="unknown"; fi
    log_info "包管理器: ${PKG_MANAGER}"
}

interactive_config() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  xsec-agent 配置${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    while true; do
        read -p "请输入 Manager 服务端 IP 地址: " MANAGER_HOST
        if [[ -z "$MANAGER_HOST" ]]; then
            log_warn "地址不能为空"
        elif [[ ! "$MANAGER_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_warn "请输入有效的 IP 地址"
        else
            break
        fi
    done
    
    read -p "请输入 Manager 服务端端口 [8443]: " MANAGER_PORT
    MANAGER_PORT=${MANAGER_PORT:-8443}
    
    while true; do
        read -s -p "请输入认证密钥: " SECRET_KEY
        echo ""
        if [[ -z "$SECRET_KEY" ]]; then
            log_warn "密钥不能为空"
        else
            break
        fi
    done
    
    read -p "请输入 Agent ID（留空自动生成）: " AGENT_ID
    echo ""
}

create_dirs() {
    log_info "创建目录..."
    mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${RUN_DIR}"
}

backup_config() {
    if [[ -f "${CONFIG_DIR}/config.toml" ]]; then
        local BACKUP="${CONFIG_DIR}/config.toml.bak.$(date +%Y%m%d%H%M%S)"
        log_info "备份配置到: ${BACKUP}"
        cp "${CONFIG_DIR}/config.toml" "${BACKUP}"
    fi
}

install_binary() {
    log_info "提取二进制文件..."
    
    local SCRIPT_PATH="$(readlink -f "$0")"
    local EXTRACTED_BIN="/tmp/xsec-agent-bin-$$"
    local MARKER_LINE=$(grep -n "^---BINARY END---$" "$SCRIPT_PATH" | cut -d: -f1 | tail -1)
    
    if [[ -z "$MARKER_LINE" ]]; then
        log_error "未找到二进制标记"
        exit 1
    fi
    
    tail -n +$((MARKER_LINE + 1)) "$SCRIPT_PATH" | base64 -d > "$EXTRACTED_BIN"
    
    if [[ ! -f "$EXTRACTED_BIN" ]] || [[ ! -s "$EXTRACTED_BIN" ]]; then
        log_error "二进制文件提取失败"
        rm -f "$EXTRACTED_BIN"
        exit 1
    fi
    
    log_info "安装二进制文件..."
    install -m 755 "${EXTRACTED_BIN}" "${BIN_DIR}/${AGENT_NAME}"
    rm -f "$EXTRACTED_BIN"
    log_info "二进制文件已安装"
}

create_config() {
    log_info "创建配置文件..."
    
    if [[ -z "$AGENT_ID" ]]; then
        AGENT_ID="agent-$(hostname)-$(date +%s)"
    fi
    
    cat > "${CONFIG_DIR}/config.toml" << EOF
[agent]
id = "${AGENT_ID}"
hostname = "$(hostname)"

[manager]
host = "${MANAGER_HOST}"
port = ${MANAGER_PORT}

[auth]
secret_key = "${SECRET_KEY}"

[log]
level = "info"
path = "${LOG_DIR}/xsec-agent.log"

[server]
host = "0.0.0.0"
port = 8443
EOF

    chmod 640 "${CONFIG_DIR}/config.toml"
    log_info "配置文件已创建"
}

install_systemd_service() {
    log_info "注册 systemd 服务..."

    cat > "${SYSTEMD_UNIT}" << EOF
[Unit]
Description=xsec Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/${AGENT_NAME} --config ${CONFIG_DIR}/config.toml
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
Restart=on-failure
RestartSec=10

Environment="RUST_LOG=info"

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR} ${RUN_DIR} ${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SYSTEMD_UNIT}"
    log_info "systemd 服务已创建"
}

start_service() {
    log_info "启动服务..."
    systemctl daemon-reload
    systemctl enable "${AGENT_NAME}"
    if systemctl start "${AGENT_NAME}"; then
        log_info "服务启动成功"
    else
        log_error "服务启动失败，请检查日志"
        exit 1
    fi
}

verify_installation() {
    log_info "验证安装..."
    sleep 2
    if systemctl is-active --quiet "${AGENT_NAME}"; then
        log_info "服务运行中 ✓"
    else
        log_warn "服务未运行"
    fi
}

uninstall() {
    log_warn "开始卸载..."
    systemctl stop "${AGENT_NAME}" 2>/dev/null || true
    systemctl disable "${AGENT_NAME}" 2>/dev/null || true
    rm -f "${SYSTEMD_UNIT}"
    rm -rf "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"
    rm -f "${BIN_DIR}/${AGENT_NAME}"
    systemctl daemon-reload
    log_info "卸载完成"
}

show_help() {
    echo "用法: $0 [选项]"
    echo "选项:"
    echo "  --uninstall  卸载"
    echo "  --help       帮助"
}

main() {
    case "${1:-}" in
        --uninstall)
            check_root
            uninstall
            ;;
        --help)
            show_help
            ;;
        "")
            check_root
            detect_os
            check_dependencies
            interactive_config
            create_dirs
            backup_config
            install_binary
            create_config
            install_systemd_service
            start_service
            verify_installation
            
            echo ""
            echo -e "${GREEN}==========================================${NC}"
            echo -e "${GREEN}  xsec-agent 安装完成!${NC}"
            echo -e "${GREEN}==========================================${NC}"
            echo ""
            echo "  服务管理命令:"
            echo "    systemctl start   ${AGENT_NAME}  # 启动"
            echo "    systemctl stop    ${AGENT_NAME}  # 停止"
            echo "    systemctl restart ${AGENT_NAME}  # 重启"
            echo "    systemctl status  ${AGENT_NAME}  # 状态"
            echo "    journalctl -u     ${AGENT_NAME} -f  # 日志"
            echo ""
            echo "  配置文件: ${CONFIG_DIR}/config.toml"
            echo "  Manager: ${MANAGER_HOST}:${MANAGER_PORT}"
            echo ""
            exit 0
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
