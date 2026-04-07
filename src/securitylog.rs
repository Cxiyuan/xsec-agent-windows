//! 安全事件日志采集模块
//! 收集系统和应用安全日志，支持 Linux 和 Windows

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// 日志来源类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum LogSource {
    /// Linux 系统日志 (/var/log/)
    LinuxSystem,
    /// Linux 认证日志 (/var/log/auth.log, /var/log/secure)
    LinuxAuth,
    /// Linux 内核日志 (/var/log/kern.log)
    LinuxKernel,
    /// Linux 应用日志
    LinuxApp(String),
    /// Windows 安全日志 (Event Viewer)
    WindowsSecurity,
    /// Windows 系统日志
    WindowsSystem,
    /// Windows 应用日志
    WindowsApplication,
    /// 自定义路径
    Custom(String),
}

/// 日志条目
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub source: String,
    pub level: LogLevel,
    pub message: String,
    pub raw: String,
    pub hostname: Option<String>,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

/// 日志级别
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    Alert = 6,
    Emergency = 7,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Notice => write!(f, "NOTICE"),
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
            LogLevel::Alert => write!(f, "ALERT"),
            LogLevel::Emergency => write!(f, "EMERGENCY"),
        }
    }
}

/// 安全日志事件类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SecurityEventType {
    /// 登录成功
    LoginSuccess,
    /// 登录失败
    LoginFailed,
    /// 用户创建/删除
    UserChange,
    /// 权限变更
    PrivilegeChange,
    /// sudo 使用
    SudoUsage,
    /// SSH 连接
    SshConnection,
    /// 进程异常
    ProcessAnomaly,
    /// 文件访问异常
    FileAccessAnomaly,
    /// 网络连接异常
    NetworkAnomaly,
    /// 服务状态变更
    ServiceChange,
    /// 内核模块加载
    KernelModuleLoad,
    /// SELinux/AppArmor 事件
    SecurityModule,
    /// 定时任务事件
    CronJob,
    /// 未知
    Unknown,
}

/// 解析后的安全事件
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub timestamp: u64,
    pub source: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub source_ip: Option<String>,
    pub target: Option<String>,
    pub message: String,
    pub severity: LogLevel,
    pub raw_log: String,
}

/// 日志收集器
pub struct LogCollector {
    /// 收集的日志源
    sources: Vec<LogSource>,
    /// 缓存的日志
    entries: Vec<LogEntry>,
    /// 收集统计
    stats: CollectStats,
}

/// 收集统计
#[derive(Debug, Default)]
pub struct CollectStats {
    pub total_collected: u64,
    pub by_source: HashMap<String, u64>,
    pub errors: u64,
}

impl LogCollector {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            entries: Vec::new(),
            stats: CollectStats::default(),
        }
    }

    /// 添加日志源
    pub fn add_source(&mut self, source: LogSource) {
        self.sources.push(source);
    }

    /// 收集所有日志
    pub fn collect(&mut self) {
        self.entries.clear();
        
        #[cfg(target_os = "linux")]
        {
            self.collect_linux_logs();
        }
        
        #[cfg(target_os = "windows")]
        {
            self.collect_windows_logs();
        }
    }

    #[cfg(target_os = "linux")]
    fn collect_linux_logs(&mut self) {
        // 收集 /var/log/auth.log 或 /var/log/secure
        let auth_logs = vec![
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/messages",
            "/var/log/syslog",
        ];

        for log_path in auth_logs {
            if let Ok(entries) = self.read_linux_log(log_path) {
                self.entries.extend(entries);
                *self.stats.by_source.entry(log_path.to_string()).or_insert(0) += entries.len() as u64;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn read_linux_log(&self, path: &str) -> Result<Vec<LogEntry>, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let mut entries = Vec::new();

        for line in content.lines().rev().take(1000) {
            if let Some(entry) = self.parse_linux_log_line(line, path) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    #[cfg(target_os = "linux")]
    fn parse_linux_log_line(&self, line: &str, source: &str) -> Option<LogEntry> {
        // Syslog 格式: "Oct 15 10:30:45 hostname process[pid]: message"
        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        if parts.len() < 5 {
            return None;
        }

        let timestamp_str = format!("{} {}", parts[0], parts[1]);
        let hostname = parts[2].to_string();
        let rest = parts[3..].join(" ");
        
        let (process, pid, message) = if rest.contains('[') {
            if let Some(end) = rest.find("]:") {
                let proc_part = &rest[..end];
                let pid = proc_part.split('[').nth(1)
                    .and_then(|s| s.parse::<u32>().ok());
                let message = rest[end + 2..].trim().to_string();
                (proc_part.split('[').next().map(|s| s.to_string()), pid, message)
            } else {
                (None, None, rest.clone())
            }
        } else {
            (None, None, rest)
        };

        let level = self.detect_log_level(&message);

        Some(LogEntry {
            timestamp: self.parse_syslog_timestamp(&timestamp_str),
            source: source.to_string(),
            level,
            message,
            raw: line.to_string(),
            hostname: Some(hostname),
            process,
            pid,
        })
    }

    #[cfg(target_os = "linux")]
    fn parse_syslog_timestamp(&self, ts: &str) -> u64 {
        // 简化实现，返回当前时间的 Unix 时间戳
        // 实际应该解析月份和日期
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(target_os = "windows")]
    fn collect_windows_logs(&mut self) {
        // Windows 日志源列表
        let log_names = vec![
            ("Security", "安全"),
            ("System", "系统"),
            ("Application", "应用"),
        ];

        for (log_name, log_desc) in &log_names {
            let ps_script = format!(r#"
$events = @()
try {{
    $events = Get-WinEvent -LogName '{}' -MaxEvents 500 -ErrorAction Stop | 
        Select-Object TimeCreated, Id, Level, ProviderName, Message
}} catch {{
    # 静默处理日志不存在的情况
}}
$events | ConvertTo-Json -Compress
"#, log_name);

            if let Ok(output) = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_script])
                .output()
            {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    if let Ok(events) = serde_json::from_str::<serde_json::Value>(&stdout) {
                        if events.is_array() {
                            for event in events.as_array().unwrap() {
                                if let Some(mut entry) = self.parse_windows_event(event, log_name) {
                                    self.entries.push(entry);
                                }
                            }
                        } else if !stdout.is_empty() && stdout != "null" {
                            // 单条事件的情况
                            if let Some(mut entry) = self.parse_windows_event(&events, log_name) {
                                self.entries.push(entry);
                            }
                        }
                    }
                }
            }
        }

        // 额外收集 PowerShell 日志（检测 PowerShell 攻击）
        self.collect_windows_powershell_logs();
        
        // 收集远程桌面日志（检测 RDP 暴力破解）
        self.collect_windows_rdp_logs();
    }

    #[cfg(target_os = "windows")]
    fn collect_windows_powershell_logs(&mut self) {
        let ps_script = r#"
$events = @()
try {{
    $events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 200 -ErrorAction Stop |
        Select-Object TimeCreated, Id, Level, ProviderName, Message
}} catch {{}}
$events | ConvertTo-Json -Compress
"#;

        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_script])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                if let Ok(events) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if events.is_array() {
                        for event in events.as_array().unwrap() {
                            if let Some(mut entry) = self.parse_windows_event(event, "PowerShell") {
                                self.entries.push(entry);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_windows_rdp_logs(&mut self) {
        // 远程桌面安全日志
        let ps_script = r#"
$events = @()
try {{
    # RDP 连接日志 (Event ID 4624, 4625, 4778, 4779)
    $events = Get-WinEvent -FilterHashtable @{{
        LogName='Security'
        Id=4624,4625,4778,4779
    }} -MaxEvents 300 -ErrorAction Stop |
        Select-Object TimeCreated, Id, Level, ProviderName, Message
}} catch {{}}
$events | ConvertTo-Json -Compress
"#;

        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_script])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                if let Ok(events) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if events.is_array() {
                        for event in events.as_array().unwrap() {
                            if let Some(mut entry) = self.parse_windows_event(event, "RDP") {
                                self.entries.push(entry);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_event(&self, event: &serde_json::Value, source: &str) -> Option<LogEntry> {
        let timestamp = event.get("TimeCreated")?
            .as_str()?
            .parse::<f64>()
            .ok()? as u64;
        
        let level = match event.get("Level")?.as_i64()? {
            1 => LogLevel::Critical,
            2 => LogLevel::Error,
            3 => LogLevel::Warning,
            4 => LogLevel::Info,
            _ => LogLevel::Debug,
        };

        Some(LogEntry {
            timestamp,
            source: source.to_string(),
            level,
            message: event.get("Message")?.as_str()?.to_string(),
            raw: event.to_string(),
            hostname: None,
            process: event.get("ProviderName")?.as_str().map(|s| s.to_string()),
            pid: None,
        })
    }

    /// 检测日志级别
    fn detect_log_level(&self, message: &str) -> LogLevel {
        let msg_lower = message.to_lowercase();
        
        if msg_lower.contains("emergency") || msg_lower.contains("emerg") {
            LogLevel::Emergency
        } else if msg_lower.contains("alert") {
            LogLevel::Alert
        } else if msg_lower.contains("critical") || msg_lower.contains("crit") {
            LogLevel::Critical
        } else if msg_lower.contains("error") || msg_lower.contains("err") {
            LogLevel::Error
        } else if msg_lower.contains("warning") || msg_lower.contains("warn") {
            LogLevel::Warning
        } else if msg_lower.contains("notice") || msg_lower.contains("note") {
            LogLevel::Notice
        } else if msg_lower.contains("info") || msg_lower.contains("information") {
            LogLevel::Info
        } else {
            LogLevel::Debug
        }
    }

    /// 获取所有日志条目
    pub fn get_entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// 获取安全事件
    pub fn get_security_events(&self) -> Vec<SecurityEvent> {
        let mut events = Vec::new();
        
        for entry in &self.entries {
            if let Some(event) = self.detect_security_event(entry) {
                events.push(event);
            }
        }
        
        events
    }

    /// 从日志条目检测安全事件
    fn detect_security_event(&self, entry: &LogEntry) -> Option<SecurityEvent> {
        let msg_lower = entry.message.to_lowercase();
        let raw_lower = entry.raw.to_lowercase();

        let (event_type, severity) = if msg_lower.contains("failed password") || msg_lower.contains("authentication failure") {
            (SecurityEventType::LoginFailed, LogLevel::Warning)
        } else if msg_lower.contains("accepted password") || msg_lower.contains("accepted publickey") || msg_lower.contains("session opened") {
            (SecurityEventType::LoginSuccess, LogLevel::Info)
        } else if msg_lower.contains("useradd") || msg_lower.contains("userdel") || msg_lower.contains("usermod") {
            (SecurityEventType::UserChange, LogLevel::Warning)
        } else if msg_lower.contains("sudo") && (msg_lower.contains("session opened") || msg_lower.contains("command")) {
            (SecurityEventType::SudoUsage, LogLevel::Notice)
        } else if msg_lower.contains("sshd") && (msg_lower.contains("connection from") || msg_lower.contains("opened connection")) {
            (SecurityEventType::SshConnection, LogLevel::Info)
        } else if msg_lower.contains("permission denied") || msg_lower.contains("access denied") {
            (SecurityEventType::FileAccessAnomaly, LogLevel::Warning)
        } else if msg_lower.contains("crontab") || msg_lower.contains("cron") {
            (SecurityEventType::CronJob, LogLevel::Info)
        } else if msg_lower.contains("module") && msg_lower.contains("loaded") {
            (SecurityEventType::KernelModuleLoad, LogLevel::Warning)
        } else {
            return None;
        };

        Some(SecurityEvent {
            event_type,
            timestamp: entry.timestamp,
            source: entry.source.clone(),
            hostname: entry.hostname.clone(),
            username: self.extract_username(&entry.message),
            source_ip: self.extract_ip(&entry.message),
            target: None,
            message: entry.message.clone(),
            severity,
            raw_log: entry.raw.clone(),
        })
    }

    /// 提取用户名
    fn extract_username(&self, message: &str) -> Option<String> {
        let patterns = ["for ", "user ", "by ", "from "];
        for pattern in &patterns {
            if let Some(pos) = message.find(pattern) {
                let start = pos + pattern.len();
                let end = message[start..].find(|c: char| c.is_whitespace() || c == '(' || c == ':')
                    .map(|i| start + i)
                    .unwrap_or(message.len());
                if start < end {
                    let username = &message[start..end];
                    if !username.is_empty() && username.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        return Some(username.to_string());
                    }
                }
            }
        }
        None
    }

    /// 提取 IP 地址
    fn extract_ip(&self, message: &str) -> Option<String> {
        let parts: Vec<&str> = message.split(|c: char| !c.is_ascii_digit() && c != '.').collect();
        for part in parts {
            let nums: Vec<&str> = part.split('.').collect();
            if nums.len() == 4 && nums.iter().all(|s| s.parse::<u8>().is_ok()) {
                let ip = nums.join(".");
                // 排除本地地址
                if ip != "0.0.0.0" && ip != "127.0.0.1" && !ip.starts_with("::") {
                    return Some(ip);
                }
            }
        }
        None
    }

    /// 按级别过滤日志
    pub fn filter_by_level(&self, min_level: LogLevel) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| e.level >= min_level).collect()
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> &CollectStats {
        &self.stats
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化安全事件列表
pub fn format_security_events(events: &[SecurityEvent]) -> String {
    if events.is_empty() {
        return "✅ 未检测到安全事件".to_string();
    }

    let mut output = format!(
        "═══════════════════════════════════════════\n\
         安全事件日志 | 共 {} 个事件\n\
         ════════════════════════════════════════════\n\n",
        events.len()
    );

    for event in events {
        output.push_str(&format!(
            "[{:?}] {} - {}\n\
             来源: {} | 时间: {}\n",
            event.event_type,
            event.severity,
            event.message.chars().take(80).collect::<String>(),
            event.source,
            event.timestamp
        ));
        
        if let Some(ref ip) = event.source_ip {
            output.push_str(&format!("  来源IP: {}\n", ip));
        }
        if let Some(ref user) = event.username {
            output.push_str(&format!("  用户: {}\n", user));
        }
        output.push('\n');
    }

    output
}

/// 格式化日志条目列表
pub fn format_log_entries(entries: &[LogEntry], max_entries: usize) -> String {
    let entries: Vec<&LogEntry> = entries.iter().take(max_entries).collect();
    
    let mut output = format!(
        "═══════════════════════════════════════════\n\
         日志条目 | 显示 {} / {} 条\n\
         ════════════════════════════════════════════\n\n",
        entries.len(),
        entries.len()
    );

    for entry in entries {
        output.push_str(&format!(
            "[{}] {} - {}\n\
             {} {}\n\n",
            entry.level,
            entry.source,
            entry.timestamp,
            entry.message.chars().take(80).collect::<String>(),
            if entry.message.len() > 80 { "..." } else { "" }
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Critical > LogLevel::Error);
        assert!(LogLevel::Error > LogLevel::Warning);
        assert!(LogLevel::Warning > LogLevel::Info);
    }

    #[test]
    fn test_extract_ip() {
        let collector = LogCollector::new();
        assert_eq!(
            collector.extract_ip("Connection from 192.168.1.100 port 22"),
            Some("192.168.1.100".to_string())
        );
    }
}
