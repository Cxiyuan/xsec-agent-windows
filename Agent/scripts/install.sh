#!/bin/bash
#
# xsec-agent 安装脚本
# 支持: Ubuntu/Debian, CentOS/RHEL, Rocky/Alma
#

set -e

AGENT_NAME="xsec-agent"
INSTALL_DIR="/opt/xsec-agent"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/xsec-agent"
LOG_DIR="/var/log/xsec-agent"
RUN_DIR="/var/run/xsec-agent"
SYSTEMD_UNIT="/etc/systemd/system/${AGENT_NAME}.service"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "需要 root 权限运行此脚本，请使用 sudo"
        exit 1
    fi
}

# 检测系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID=$ID
        OS_NAME=$NAME
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    
    # 检测 systemd
    if ! command -v systemctl &> /dev/null; then
        log_error "此系统未安装 systemd，不支持服务管理"
        exit 1
    fi
    
    log_info "检测到系统: ${OS_NAME}"
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    if ! systemctl --version &> /dev/null; then
        log_error "systemd 未安装"
        exit 1
    fi
    
    if command -v dpkg &> /dev/null; then
        PKG_MANAGER="dpkg"
    elif command -v rpm &> /dev/null; then
        PKG_MANAGER="rpm"
    else
        PKG_MANAGER="unknown"
    fi
    
    log_info "包管理器: ${PKG_MANAGER}"
}

# 交互式获取配置参数
interactive_config() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  xsec-agent 配置${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Manager 地址
    while true; do
        read -p "请输入 Manager 服务端 IP 地址: " MANAGER_HOST
        if [[ -z "$MANAGER_HOST" ]]; then
            log_warn "地址不能为空"
        elif [[ ! "$MANAGER_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_warn "请输入有效的 IP 地址格式 (如: 192.168.1.100)"
        else
            break
        fi
    done
    
    # Manager 端口
    read -p "请输入 Manager 服务端端口 [8443]: " MANAGER_PORT
    MANAGER_PORT=${MANAGER_PORT:-8443}
    if [[ ! "$MANAGER_PORT" =~ ^[0-9]+$ ]] || [[ "$MANAGER_PORT" -lt 1 ]] || [[ "$MANAGER_PORT" -gt 65535 ]]; then
        log_error "端口无效，使用默认 8443"
        MANAGER_PORT=8443
    fi
    
    # Agent ID（可选）
    read -p "请输入 Agent ID [自动生成]: " AGENT_ID
    AGENT_ID=${AGENT_ID:-""}
    
    # 认证密钥
    while true; do
        read -s -p "请输入认证密钥: " SECRET_KEY
        echo ""
        if [[ -z "$SECRET_KEY" ]]; then
            log_warn "密钥不能为空"
        else
            read -s -p "请再次输入密钥: " SECRET_KEY_CONFIRM
            echo ""
            if [[ "$SECRET_KEY" != "$SECRET_KEY_CONFIRM" ]]; then
                log_warn "两次输入不一致，请重新输入"
            else
                break
            fi
        fi
    done
    
    # TLS 配置
    read -p "是否使用 TLS 加密? [Y/n]: " USE_TLS
    USE_TLS=${USE_TLS:-Y}
    if [[ "$USE_TLS" =~ ^[Yy]$ ]]; then
        USE_TLS="true"
        read -p "是否接受自签名证书? [Y/n]: " ACCEPT_INVALID
        ACCEPT_INVALID=${ACCEPT_INVALID:-Y}
        if [[ "$ACCEPT_INVALID" =~ ^[Yy]$ ]]; then
            ACCEPT_INVALID_CERTS="true"
        else
            ACCEPT_INVALID_CERTS="false"
        fi
    else
        USE_TLS="false"
        ACCEPT_INVALID_CERTS="false"
    fi
    
    # 显示配置确认
    echo ""
    echo -e "${BLUE}配置确认:${NC}"
    echo "  Manager 地址: ${MANAGER_HOST}:${MANAGER_PORT}"
    echo "  Agent ID: ${AGENT_ID:-自动生成}"
    echo "  TLS 加密: ${USE_TLS}"
    echo ""
    
    read -p "确认安装? [Y/n]: " CONFIRM
    CONFIRM=${CONFIRM:-Y}
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_info "安装已取消"
        exit 0
    fi
}

# 创建目录
create_dirs() {
    log_info "创建目录..."
    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${LOG_DIR}"
    mkdir -p "${RUN_DIR}"
    
    chown -R root:root "${INSTALL_DIR}"
    chown -R root:root "${CONFIG_DIR}"
    chown -R root:root "${LOG_DIR}"
    chown -R root:root "${RUN_DIR}"
}

# 备份原有配置
backup_config() {
    if [[ -f "${CONFIG_DIR}/config.toml" ]]; then
        log_warn "发现已有配置，备份到 ${CONFIG_DIR}/config.toml.bak"
        cp "${CONFIG_DIR}/config.toml" "${CONFIG_DIR}/config.toml.bak"
    fi
}

# 安装二进制文件
install_binary() {
    log_info "提取二进制文件..."
    
    local SCRIPT_PATH="$(readlink -f "$0")"
    local EXTRACTED_BIN="/tmp/xsec-agent-bin-$$"
    
    # 找到 ---BINARY END--- 标记
    local MARKER_LINE=$(grep -n "^---BINARY END---$" "$SCRIPT_PATH" | cut -d: -f1 | tail -1)
    if [[ -z "$MARKER_LINE" ]]; then
        log_error "未找到二进制标记，请确认使用的是正确的安装脚本"
        exit 1
    fi
    
    # 提取并解码
    tail -n +$((MARKER_LINE + 1)) "$SCRIPT_PATH" | base64 -d > "$EXTRACTED_BIN"
    
    if [[ ! -f "$EXTRACTED_BIN" ]] || [[ ! -s "$EXTRACTED_BIN" ]]; then
        log_error "二进制文件提取失败"
        rm -f "$EXTRACTED_BIN"
        exit 1
    fi
    
    log_info "安装二进制文件..."
    install -m 755 "${EXTRACTED_BIN}" "${BIN_DIR}/${AGENT_NAME}"
    rm -f "$EXTRACTED_BIN"
    log_info "二进制文件已安装到 ${BIN_DIR}/${AGENT_NAME}"
}

# 创建配置文件
create_config() {
    log_info "创建配置文件..."
    
    # 如果 Agent ID 为空，生成一个默认的
    if [[ -z "$AGENT_ID" ]]; then
        AGENT_ID="agent-$(hostname)-$(date +%s)"
    fi
    
    cat > "${CONFIG_DIR}/config.toml" << EOF
# xsec-agent 配置文件
# 安装时自动生成

[manager]
host = "${MANAGER_HOST}"
port = ${MANAGER_PORT}

[agent]
agent_id = "${AGENT_ID}"
secret_key = "${SECRET_KEY}"

[connection]
heartbeat_interval_secs = 30
reconnect_delay_secs = 5
connection_timeout_secs = 10
use_tls = ${USE_TLS}
tls_accept_invalid_certs = ${ACCEPT_INVALID_CERTS}
tls_server_name = ""

[monitor]
realtime_interval_secs = 10
process_anomaly_threshold = 5
network_anomaly_threshold = 3

[log]
level = "info"
file = "/var/log/xsec-agent/agent.log"
max_size = 100
max_days = 30

[security]
enable_malicious_check = true
enable_hidden_check = true
enable_injection_check = true
enable_network_check = true
enable_startup_check = true
enable_fim = true
enable_sca = true
EOF
    
    chmod 640 "${CONFIG_DIR}/config.toml"
    log_info "配置文件已创建: ${CONFIG_DIR}/config.toml"
}

# 注册 systemd 服务
install_systemd_service() {
    log_info "注册 systemd 服务..."
    
    cat > "${SYSTEMD_UNIT}" << EOF
[Unit]
Description=xsec Security Agent - Host Security Monitoring Client
Documentation=https://github.com/your-repo/xsec
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
RestartForceExitStatus=213

Environment="RUST_LOG=info"

LimitNOFILE=65536
LimitNPROC=4096

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR} ${RUN_DIR} ${CONFIG_DIR}
PrivateTmp=true

CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "${SYSTEMD_UNIT}"
    log_info "systemd 服务文件已创建: ${SYSTEMD_UNIT}"
}

# 启动服务
start_service() {
    log_info "重新加载 systemd 配置..."
    systemctl daemon-reload
    
    log_info "启用服务（开机自启）..."
    systemctl enable "${AGENT_NAME}"
    
    log_info "启动服务..."
    if systemctl start "${AGENT_NAME}"; then
        log_info "服务启动成功"
    else
        log_error "服务启动失败，请检查日志: journalctl -u ${AGENT_NAME} -n 50"
        exit 1
    fi
}

# 验证安装
verify_installation() {
    log_info "验证安装..."
    
    sleep 2
    if systemctl is-active --quiet "${AGENT_NAME}"; then
        log_info "服务运行中 ✓"
    else
        log_warn "服务未运行，请检查: journalctl -u ${AGENT_NAME} -n 30"
    fi
    
    if "${BIN_DIR}/${AGENT_NAME}" --version &> /dev/null; then
        log_info "二进制版本: $("${BIN_DIR}/${AGENT_NAME}" --version)"
    fi
}

# 卸载函数
uninstall() {
    log_warn "开始卸载 xsec-agent..."
    
    systemctl stop "${AGENT_NAME}" 2>/dev/null || true
    systemctl disable "${AGENT_NAME}" 2>/dev/null || true
    
    rm -f "${SYSTEMD_UNIT}"
    rm -rf "${INSTALL_DIR}"
    rm -f "${BIN_DIR}/${AGENT_NAME}"
    rm -rf "${CONFIG_DIR}"
    rm -rf "${LOG_DIR}"
    rm -rf "${RUN_DIR}"
    
    systemctl daemon-reload
    
    log_info "卸载完成"
}

# 显示帮助
show_help() {
    cat << EOF
xsec-agent 安装脚本

用法: $0 [选项]

选项:
    --uninstall     卸载 xsec-agent
    --help          显示此帮助信息

示例:
    $0              # 安装 xsec-agent（交互式配置）
    $0 --uninstall  # 卸载 xsec-agent
EOF
}

# 主函数
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
            log_info "=========================================="
            log_info "  xsec-agent 安装完成!"
            log_info "=========================================="
            echo ""
            echo "  服务管理命令:"
            echo "    systemctl start   ${AGENT_NAME}  # 启动"
            echo "    systemctl stop    ${AGENT_NAME}  # 停止"
            echo "    systemctl restart ${AGENT_NAME}  # 重启"
            echo "    systemctl status  ${AGENT_NAME}  # 状态"
            echo "    journalctl -u     ${AGENT_NAME} -f  # 日志"
            echo ""
            echo "  配置文件: ${CONFIG_DIR}/config.toml"
            echo "  日志目录: ${LOG_DIR}"
            echo "  Manager: ${MANAGER_HOST}:${MANAGER_PORT}"
            echo ""
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
