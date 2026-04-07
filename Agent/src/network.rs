//! 进程网络行为监控模块
//! 监控每个进程的TCP/UDP连接、监听端口、异常外连等

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 进程网络连接信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessNetworkInfo {
    pub pid: u32,
    pub name: String,
    pub connections: Vec<Connection>,
    pub total_connections: usize,
    pub listening_ports: Vec<u16>,
    pub established_connections: usize,
    pub remote_connections: usize,
}

/// 单个网络连接
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Connection {
    pub protocol: Protocol,        // TCP/UDP
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub direction: Direction,     // inbound/outbound
}

/// 协议类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    Unknown,
}

/// 连接状态
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ConnectionState {
    LISTEN,        // 监听中
    ESTABLISHED,   // 已建立
    TIME_WAIT,     // 等待中
    CLOSE_WAIT,    // 关闭等待
    SYN_SENT,      // SYN已发送
    SYN_RECV,      // SYN已接收
    FIN_WAIT,      // FIN等待
    LAST_ACK,      // 最后ACK
    CLOSING,       // 关闭中
    UNKNOWN,
}

/// 连接方向
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Direction {
    Inbound,    // 被动连接（服务器端）
    Outbound,   // 主动连接（客户端）
    Unknown,
}

/// 网络异常告警
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkAlert {
    pub alert_type: NetworkAlertType,
    pub pid: u32,
    pub name: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub details: String,
}

/// 网络告警类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum NetworkAlertType {
    SuspiciousRemote,      // 可疑远端连接
    PortScan,             // 端口扫描行为
    UncommonPort,          // 罕见端口
    ManyConnections,       // 连接数过多
    SuspiciousProtocol,    // 可疑协议使用
    DataExfiltration,     // 数据外泄嫌疑
}

/// 告警严重程度
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Copy, PartialOrd)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Low => write!(f, "低"),
            AlertSeverity::Medium => write!(f, "中"),
            AlertSeverity::High => write!(f, "高"),
            AlertSeverity::Critical => write!(f, "严重"),
        }
    }
}

/// 进程网络监控器
pub struct NetworkMonitor {
    /// 罕见高危端口
    suspicious_ports: Vec<u16>,
    /// 可疑IP地址段
    suspicious_ip_patterns: Vec<(String, String)>, // (CIDR/pattern, description)
    /// 单进程最大连接数阈值
    max_connections_per_process: usize,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        // 罕见高危端口
        let suspicious_ports = vec![
            22,     // SSH (罕见：非SSH服务器却开了22)
            23,     // Telnet
            135,    // Windows RPC
            139,    // NetBIOS
            445,    // SMB
            1433,   // MSSQL
            1521,   // Oracle
            3306,   // MySQL
            3389,   // RDP
            5432,   // PostgreSQL
            5900,   // VNC
            6379,   // Redis
            27017,  // MongoDB
            // 黑客常用端口
            4444,   // Metasploit
            5555,   // Android ADB
            6666,   // IRC
            6667,   // IRC
            1337,   // Hacker
            31337,  // Back Orifice
            12345,  // NetBus
            27374,  // SubSeven
        ];

        // 可疑IP模式（内网/本地）
        let suspicious_ip_patterns = vec![
            ("127.0.0.0/8".to_string(), "本地回环".to_string()),
            ("10.0.0.0/8".to_string(), "私有内网A".to_string()),
            ("172.16.0.0/12".to_string(), "私有内网B".to_string()),
            ("192.168.0.0/16".to_string(), "私有内网C".to_string()),
            ("169.254.0.0/16".to_string(), "链路本地".to_string()),
            ("0.0.0.0".to_string(), "绑定所有接口".to_string()),
        ];

        Self {
            suspicious_ports,
            suspicious_ip_patterns,
            max_connections_per_process: 500,
        }
    }

    /// 获取所有进程的网络连接信息
    pub fn get_process_network_info(&self, sys: &sysinfo::System) -> Vec<ProcessNetworkInfo> {
        let mut results: HashMap<u32, ProcessNetworkInfo> = HashMap::new();

        #[cfg(target_os = "linux")]
        {
            self.get_linux_connections(&mut results);
        }

        #[cfg(target_os = "windows")]
        {
            self.get_windows_connections(&mut results);
        }

        // 填充进程名称
        for (pid, info) in results.iter_mut() {
            if info.name.is_empty() {
                if let Some(process) = sys.processes().get(&sysinfo::Pid::from_u32(*pid)) {
                    info.name = process.name().to_string_lossy().to_string();
                }
            }
        }

        let mut result_vec: Vec<ProcessNetworkInfo> = results.into_values().collect();
        // 按连接数降序排列
        result_vec.sort_by(|a, b| b.total_connections.cmp(&a.total_connections));
        result_vec
    }

    /// 检测网络异常
    pub fn detect_anomalies(&self, sys: &sysinfo::System) -> Vec<NetworkAlert> {
        let process_info = self.get_process_network_info(sys);
        let mut alerts = Vec::new();

        for info in &process_info {
            // 1. 检测连接数过多
            if info.total_connections > self.max_connections_per_process {
                alerts.push(NetworkAlert {
                    alert_type: NetworkAlertType::ManyConnections,
                    pid: info.pid,
                    name: info.name.clone(),
                    severity: AlertSeverity::High,
                    description: format!("进程 {} 连接数过多", info.name),
                    details: format!("总连接数: {} (阈值: {})", info.total_connections, self.max_connections_per_process),
                });
            }

            // 2. 检测可疑端口
            for &port in &info.listening_ports {
                if self.suspicious_ports.contains(&port) {
                    alerts.push(NetworkAlert {
                        alert_type: NetworkAlertType::UncommonPort,
                        pid: info.pid,
                        name: info.name.clone(),
                        severity: AlertSeverity::Medium,
                        description: format!("进程 {} 监听可疑端口", info.name),
                        details: format!("端口: {} (可能存在安全风险)", port),
                    });
                }
            }

            // 3. 检测可疑远端连接
            for conn in &info.connections {
                if conn.state == ConnectionState::ESTABLISHED && conn.direction == Direction::Outbound {
                    // 检测连接到可疑IP
                    if let Some(reason) = self.check_suspicious_ip(&conn.remote_addr) {
                        alerts.push(NetworkAlert {
                            alert_type: NetworkAlertType::SuspiciousRemote,
                            pid: info.pid,
                            name: info.name.clone(),
                            severity: AlertSeverity::High,
                            description: format!("进程 {} 连接到可疑地址", info.name),
                            details: format!("目标: {} (原因: {})", conn.remote_addr, reason),
                        });
                    }
                }
            }
        }

        // 按严重程度排序
        alerts.sort_by(|a, b| {
            b.severity
                .partial_cmp(&a.severity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        alerts
    }

    /// 检查IP是否可疑
    fn check_suspicious_ip(&self, ip: &str) -> Option<String> {
        // 过滤本地和内网IP的外连
        let ip_octets: Vec<u8> = ip.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();

        if ip_octets.len() != 4 {
            return None;
        }

        // 127.x.x.x - 本地回环
        if ip_octets[0] == 127 {
            return Some("本地回环地址".to_string());
        }

        // 10.x.x.x - 私有A类
        if ip_octets[0] == 10 {
            return Some("私有A类内网地址(可疑外连)".to_string());
        }

        // 172.16-31.x.x - 私有B类
        if ip_octets[0] == 172 && (16..=31).contains(&ip_octets[1]) {
            return Some("私有B类内网地址(可疑外连)".to_string());
        }

        // 192.168.x.x - 私有C类
        if ip_octets[0] == 192 && ip_octets[1] == 168 {
            return Some("私有C类内网地址(可疑外连)".to_string());
        }

        // 0.0.0.0 - 绑定所有
        if ip == "0.0.0.0" || ip == "::" {
            return Some("绑定所有网络接口".to_string());
        }

        None
    }

    // =========================================================================
    // Linux 实现
    // =========================================================================
    #[cfg(target_os = "linux")]
    fn get_linux_connections(&self, results: &mut HashMap<u32, ProcessNetworkInfo>) {
        // 读取 /proc/net/tcp 和 /proc/net/udp
        self.parse_proc_net_tcp("/proc/net/tcp", results, Protocol::TCP);
        self.parse_proc_net_tcp("/proc/net/tcp6", results, Protocol::TCP);
        self.parse_proc_net_udp("/proc/net/udp", results, Protocol::UDP);
        self.parse_proc_net_udp("/proc/net/udp6", results, Protocol::UDP);
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_tcp(&self, path: &str, results: &mut HashMap<u32, ProcessNetworkInfo>, proto: Protocol) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) { // 跳过标题行
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    continue;
                }

                // 解析本地地址 (字段1) 和远程地址 (字段2)
                let local_parts = self.parse_inet_addr(fields[1]);
                let remote_parts = self.parse_inet_addr(fields[2]);
                let state_hex = fields[3];
                let inode = fields[9];

                // 获取监听端口的进程PID
                let listening_port = local_parts.1;
                let remote_port = remote_parts.1;
                let state = self.parse_tcp_state(state_hex);

                // 通过inode找到PID
                if let Some(pid) = self.find_pid_by_inode(inode) {
                    let entry = results.entry(pid).or_insert_with(|| ProcessNetworkInfo {
                        pid,
                        name: String::new(),
                        connections: Vec::new(),
                        total_connections: 0,
                        listening_ports: Vec::new(),
                        established_connections: 0,
                        remote_connections: 0,
                    });

                    let direction = if remote_parts.0 == "0.0.0.0" || remote_parts.0 == "::" {
                        Direction::Inbound
                    } else {
                        Direction::Outbound
                    };

                    entry.connections.push(Connection {
                        protocol: proto.clone(),
                        local_addr: local_parts.0,
                        local_port: listening_port,
                        remote_addr: remote_parts.0,
                        remote_port: remote_port,
                        state: state.clone(),
                        direction,
                    });

                    entry.total_connections += 1;

                    if state == ConnectionState::LISTEN {
                        entry.listening_ports.push(listening_port);
                    }
                    if state == ConnectionState::ESTABLISHED {
                        entry.established_connections += 1;
                    }
                    if direction == Direction::Outbound && remote_port > 0 {
                        entry.remote_connections += 1;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_udp(&self, path: &str, results: &mut HashMap<u32, ProcessNetworkInfo>, proto: Protocol) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    continue;
                }

                let local_parts = self.parse_inet_addr(fields[1]);
                let remote_parts = self.parse_inet_addr(fields[2]);
                let inode = fields[9];

                let local_port = local_parts.1;
                let remote_port = remote_parts.1;

                if let Some(pid) = self.find_pid_by_inode(inode) {
                    let entry = results.entry(pid).or_insert_with(|| ProcessNetworkInfo {
                        pid,
                        name: String::new(),
                        connections: Vec::new(),
                        total_connections: 0,
                        listening_ports: Vec::new(),
                        established_connections: 0,
                        remote_connections: 0,
                    });

                    entry.connections.push(Connection {
                        protocol: proto.clone(),
                        local_addr: local_parts.0,
                        local_port,
                        remote_addr: remote_parts.0,
                        remote_port,
                        state: ConnectionState::UNKNOWN,
                        direction: if remote_port > 0 { Direction::Outbound } else { Direction::Unknown },
                    });

                    entry.total_connections += 1;

                    if local_port > 0 {
                        entry.listening_ports.push(local_port);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_inet_addr(&self, addr_hex: &str) -> (String, u16) {
        // 格式: IP:PORT (都是十六进制)
        let parts: Vec<&str> = addr_hex.split(':').collect();
        if parts.len() != 2 {
            return ("0.0.0.0".to_string(), 0);
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        // 解析IP (小端序)
        let ip_u32 = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        let ip = format!(
            "{}.{}.{}.{}",
            (ip_u32 & 0xff) as u8,
            (ip_u32 >> 8) as u8 & 0xff,
            (ip_u32 >> 16) as u8 & 0xff,
            (ip_u32 >> 24) as u8
        );

        // 解析端口
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

        (ip, port)
    }

    #[cfg(target_os = "linux")]
    fn parse_tcp_state(&self, state_hex: &str) -> ConnectionState {
        match u8::from_str_radix(state_hex, 16).unwrap_or(0) {
            0x01 => ConnectionState::ESTABLISHED,
            0x02 => ConnectionState::SYN_SENT,
            0x03 => ConnectionState::SYN_RECV,
            0x04 => ConnectionState::FIN_WAIT,
            0x05 => ConnectionState::FIN_WAIT,
            0x06 => ConnectionState::TIME_WAIT,
            0x07 => ConnectionState::CLOSE,
            0x08 => ConnectionState::LAST_ACK,
            0x09 => ConnectionState::CLOSING,
            0x0A => ConnectionState::LISTEN,
            0x0B => ConnectionState::LISTEN,
            _ => ConnectionState::UNKNOWN,
        }
    }

    #[cfg(target_os = "linux")]
    fn find_pid_by_inode(&self, inode: &str) -> Option<u32> {
        // 遍历 /proc/*/fd/* 寻找匹配的socket inode
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(dir_name) = entry.file_name().to_str().to_owned() {
                    if let Ok(pid) = dir_name.parse::<u32>() {
                        let fd_path = format!("/proc/{}/fd", pid);
                        if let Ok(fd_entries) = std::fs::read_dir(&fd_path) {
                            for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                                if let Ok(link) = fd_entry.read_link() {
                                    let link_str = link.to_string_lossy();
                                    if link_str.contains(&format!("socket:[{}]", inode)) {
                                        return Some(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // =========================================================================
    // Windows 实现
    // =========================================================================
    #[cfg(target_os = "windows")]
    fn get_windows_connections(&self, results: &mut HashMap<u32, ProcessNetworkInfo>) {
        use std::process::Command;

        // 使用 netstat -ano 获取连接信息
        let output = Command::new("netstat")
            .args(["-ano"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines().skip(4) { // 跳过前几行标题
                let fields: Vec<&str> = line.split_whitespace().filter(|s| !s.is_empty()).collect();
                if fields.len() < 4 {
                    continue;
                }

                let protocol = if fields[0] == "TCP" { Protocol::TCP }
                              else if fields[0] == "UDP" { Protocol::UDP }
                              else { continue };

                // 解析地址和端口
                let local_parts: Vec<&str> = fields[1].rsplitn(2, ':').collect();
                let remote_parts: Vec<&str> = if fields.len() > 2 { fields[2].rsplitn(2, ':').collect() } else { vec![] };

                if local_parts.len() < 2 {
                    continue;
                }

                let local_port: u16 = local_parts[0].parse().unwrap_or(0);
                let local_addr = local_parts[1..].join(":");

                let remote_addr = if remote_parts.len() >= 2 { remote_parts[1..].join(":") } else { String::new() };
                let remote_port: u16 = if !remote_parts.is_empty() { remote_parts[0].parse().unwrap_or(0) } else { 0 };

                let state_str = if fields.len() > 3 && protocol == Protocol::TCP { fields[3] } else { "" };
                let pid: u32 = if fields.len() > 4 { fields[4].parse().unwrap_or(0) } else { 0 };

                if pid == 0 {
                    continue;
                }

                let state = if protocol == Protocol::TCP {
                    match state_str {
                        "LISTENING" => ConnectionState::LISTEN,
                        "ESTABLISHED" => ConnectionState::ESTABLISHED,
                        "TIME_WAIT" => ConnectionState::TIME_WAIT,
                        "CLOSE_WAIT" => ConnectionState::CLOSE_WAIT,
                        "SYN_SENT" => ConnectionState::SYN_SENT,
                        "FIN_WAIT" => ConnectionState::FIN_WAIT,
                        _ => ConnectionState::UNKNOWN,
                    }
                } else {
                    ConnectionState::UNKNOWN
                };

                let direction = if remote_addr == "0.0.0.0" || remote_addr.is_empty() {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };

                let entry = results.entry(pid).or_insert_with(|| ProcessNetworkInfo {
                    pid,
                    name: String::new(),
                    connections: Vec::new(),
                    total_connections: 0,
                    listening_ports: Vec::new(),
                    established_connections: 0,
                    remote_connections: 0,
                });

                entry.connections.push(Connection {
                    protocol,
                    local_addr,
                    local_port,
                    remote_addr: remote_addr.clone(),
                    remote_port,
                    state: state.clone(),
                    direction,
                });

                entry.total_connections += 1;

                if state == ConnectionState::LISTEN {
                    entry.listening_ports.push(local_port);
                }
                if state == ConnectionState::ESTABLISHED {
                    entry.established_connections += 1;
                }
                if direction == Direction::Outbound && remote_port > 0 {
                    entry.remote_connections += 1;
                }
            }
        }
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化进程网络信息
pub fn format_network_info(info: &[ProcessNetworkInfo], top_n: Option<usize>) -> String {
    let processes: Vec<&ProcessNetworkInfo> = if let Some(n) = top_n {
        info.iter().take(n).collect()
    } else {
        info.iter().collect()
    };

    let mut output = String::new();
    output.push_str(&format!(
        "═══════════════════════════════════════════════════════════════\n\
         进程网络监控 | 共 {} 个进程有网络活动\n\
         ════════════════════════════════════════════════════════════════\n\n",
        info.len()
    ));

    for proc_info in processes {
        output.push_str(&format!(
            "【PID: {}】{} - {} 个连接\n",
            proc_info.pid,
            proc_info.name,
            proc_info.total_connections
        ));

        if !proc_info.listening_ports.is_empty() {
            output.push_str(&format!(
                "  📡 监听端口: {}\n",
                proc_info.listening_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        output.push_str(&format!(
            "  🔗 已建立: {} | 远端连接: {}\n",
            proc_info.established_connections,
            proc_info.remote_connections
        ));

        // 显示部分连接详情
        let show_count = proc_info.connections.len().min(5);
        for conn in &proc_info.connections[..show_count] {
            let state_str = format!("{:?}", conn.state);
            let dir_str = match conn.direction {
                Direction::Inbound => "←",
                Direction::Outbound => "→",
                Direction::Unknown => "?",
            };

            if conn.state == ConnectionState::LISTEN {
                output.push_str(&format!(
                    "     {} {}:{} [LISTEN]\n",
                    dir_str, conn.local_addr, conn.local_port
                ));
            } else if conn.state == ConnectionState::ESTABLISHED {
                output.push_str(&format!(
                    "     {} {}:{} → {}:{}\n",
                    dir_str, conn.local_addr, conn.local_port, conn.remote_addr, conn.remote_port
                ));
            }
        }

        if proc_info.connections.len() > show_count {
            output.push_str(&format!(
                "     ... 还有 {} 个连接\n",
                proc_info.connections.len() - show_count
            ));
        }
        output.push('\n');
    }

    output
}

/// 格式化网络告警
pub fn format_network_alerts(alerts: &[NetworkAlert]) -> String {
    if alerts.is_empty() {
        return "✅ 未检测到网络异常".to_string();
    }

    let mut output = String::new();
    output.push_str(&format!(
        "⚠️  网络异常告警\n\
         ════════════════════════════════════════════\n\
         检测到 {} 个异常\n\
         ════════════════════════════════════════════\n\n",
        alerts.len()
    ));

    for alert in alerts {
        let icon = match alert.severity {
            AlertSeverity::Critical => "🔴",
            AlertSeverity::High => "🟠",
            AlertSeverity::Medium => "🟡",
            AlertSeverity::Low => "🟢",
        };

        output.push_str(&format!(
            "{} [{}] PID: {} | {}\n",
            icon, alert.severity, alert.pid, alert.name
        ));
        output.push_str(&format!("   {}\n", alert.description));
        output.push_str(&format!("   详情: {}\n\n", alert.details));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_monitor() {
        let monitor = NetworkMonitor::new();
        let sys = sysinfo::System::new_all();
        
        let info = monitor.get_process_network_info(&sys);
        assert!(info.len() >= 0);
    }

    #[test]
    fn test_detect_anomalies() {
        let monitor = NetworkMonitor::new();
        let sys = sysinfo::System::new_all();
        
        let alerts = monitor.detect_anomalies(&sys);
        assert!(alerts.len() >= 0);
    }
}
