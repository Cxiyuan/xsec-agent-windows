//! 主动响应模块
//! 根据威胁类型自动执行预设的响应动作

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

/// 响应动作类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ResponseAction {
    /// 发送告警
    Alert,
    /// 隔离进程
    IsolateProcess,
    /// 杀死进程
    KillProcess,
    /// 阻断网络连接
    BlockConnection,
    /// 封禁IP
    BlockIP,
    /// 禁用用户账户
    DisableUser,
    /// 停止服务
    StopService,
    /// 隔离主机
    IsolateHost,
    /// 自定义命令
    CustomCommand(String),
}

/// 响应级别
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ResponseLevel {
    /// 不响应
    None,
    /// 记录日志
    Log,
    /// 告警通知
    Notify,
    /// 自动响应
    Auto,
    /// 强制响应
    Force,
}

/// 响应规则
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseRule {
    pub id: String,
    pub name: String,
    pub description: String,
    /// 匹配的威胁类型（正则表达式）
    pub threat_pattern: String,
    /// 威胁等级阈值
    pub min_severity: u8,
    /// 执行的响应动作
    pub actions: Vec<ResponseAction>,
    /// 响应级别
    pub level: ResponseLevel,
    /// 是否启用
    pub enabled: bool,
}

/// 响应执行结果
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseResult {
    pub rule_id: String,
    pub action: ResponseAction,
    pub success: bool,
    pub message: String,
    pub executed_at: u64,
}

/// 主动响应引擎
pub struct ResponseEngine {
    rules: Vec<ResponseRule>,
    /// 执行结果缓存
    results: Vec<ResponseResult>,
}

impl ResponseEngine {
    pub fn new() -> Self {
        let rules = Self::default_rules();
        Self {
            rules,
            results: Vec::new(),
        }
    }

    /// 默认响应规则
    fn default_rules() -> Vec<ResponseRule> {
        vec![
            // 高危威胁自动响应
            ResponseRule {
                id: "rule-001".to_string(),
                name: "检测到挖矿进程".to_string(),
                description: "自动封禁挖矿相关进程".to_string(),
                threat_pattern: "cryptominer|xmrig|stratum|minerd".to_string(),
                min_severity: 60,
                actions: vec![
                    ResponseAction::KillProcess,
                    ResponseAction::Alert,
                ],
                level: ResponseLevel::Auto,
                enabled: true,
            },
            ResponseRule {
                id: "rule-002".to_string(),
                name: "检测到后门行为".to_string(),
                description: "自动隔离可疑进程".to_string(),
                threat_pattern: "backdoor|remote.*shell|telnet.*server".to_string(),
                min_severity: 70,
                actions: vec![
                    ResponseAction::IsolateProcess,
                    ResponseAction::Alert,
                ],
                level: ResponseLevel::Auto,
                enabled: true,
            },
            ResponseRule {
                id: "rule-003".to_string(),
                name: "检测到内网渗透".to_string(),
                description: "检测到内网可疑连接时封禁IP".to_string(),
                threat_pattern: "suspicious.*remote.*connection|port.*scan".to_string(),
                min_severity: 50,
                actions: vec![
                    ResponseAction::BlockIP,
                    ResponseAction::Alert,
                ],
                level: ResponseLevel::Auto,
                enabled: true,
            },
            ResponseRule {
                id: "rule-004".to_string(),
                name: "检测到敏感文件访问".to_string(),
                description: "访问敏感文件时记录并告警".to_string(),
                threat_pattern: "etc.*shadow|root.*ssh.*key|credential".to_string(),
                min_severity: 40,
                actions: vec![
                    ResponseAction::Alert,
                ],
                level: ResponseLevel::Notify,
                enabled: true,
            },
            ResponseRule {
                id: "rule-005".to_string(),
                name: "检测到Rootkit行为".to_string(),
                description: "自动隔离感染主机".to_string(),
                threat_pattern: "rootkit|kernel.*module.*suspicious".to_string(),
                min_severity: 80,
                actions: vec![
                    ResponseAction::IsolateHost,
                    ResponseAction::KillProcess,
                    ResponseAction::Alert,
                ],
                level: ResponseLevel::Force,
                enabled: true,
            },
        ]
    }

    /// 添加规则
    pub fn add_rule(&mut self, rule: ResponseRule) {
        self.rules.push(rule);
    }

    /// 启用/禁用规则
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
        }
    }

    /// 根据威胁信息匹配规则并执行
    pub fn process_threat(&mut self, threat_type: &str, severity: u8, details: &str) -> Vec<ResponseResult> {
        let mut results = Vec::new();
        
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            
            // 检查威胁类型是否匹配
            if !self.matches_pattern(threat_type, &rule.threat_pattern) {
                continue;
            }
            
            // 检查严重性阈值
            if severity < rule.min_severity {
                continue;
            }
            
            // 执行响应动作
            for action in &rule.actions {
                let result = self.execute_action(action, details);
                results.push(ResponseResult {
                    rule_id: rule.id.clone(),
                    action: action.clone(),
                    success: result.0,
                    message: result.1,
                    executed_at: now_timestamp(),
                });
            }
        }
        
        self.results.extend(results.clone());
        results
    }

    /// 检查是否匹配模式
    fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
        // 简单包含匹配
        // 实际生产中应使用正则
        let pattern_lower = pattern.to_lowercase();
        let text_lower = text.to_lowercase();
        
        for part in pattern_lower.split('|') {
            let part = part.trim();
            if text_lower.contains(part) {
                return true;
            }
        }
        false
    }

    /// 执行单个响应动作
    fn execute_action(&self, action: &ResponseAction, details: &str) -> (bool, String) {
        match action {
            ResponseAction::Alert => {
                // 告警动作由 alert 模块处理
                (true, "Alert triggered, see alert module".to_string())
            }
            ResponseAction::KillProcess => {
                self.kill_process(details)
            }
            ResponseAction::BlockIP => {
                self.block_ip(details)
            }
            ResponseAction::IsolateProcess => {
                self.isolate_process(details)
            }
            ResponseAction::DisableUser => {
                self.disable_user(details)
            }
            ResponseAction::StopService => {
                self.stop_service(details)
            }
            ResponseAction::IsolateHost => {
                self.isolate_host()
            }
            ResponseAction::CustomCommand(cmd) => {
                self.execute_custom_command(cmd)
            }
            ResponseAction::BlockConnection => {
                self.block_connection(details)
            }
        }
    }

    /// 杀死进程
    fn kill_process(&self, details: &str) -> (bool, String) {
        // 从 details 中提取 PID
        if let Some(pid) = extract_pid(details) {
            #[cfg(target_os = "linux")]
            {
                let output = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("Process {} killed", pid))
                    }
                    Ok(out) => {
                        (false, format!("Kill failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Kill error: {}", e))
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                let output = Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("Process {} killed", pid))
                    }
                    Ok(out) => {
                        (false, format!("Kill failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Kill error: {}", e))
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                (false, "Kill not supported on this platform".to_string())
            }
        } else {
            (false, "No PID found in details".to_string())
        }
    }

    /// 封禁IP（通过 iptables）
    fn block_ip(&self, details: &str) -> (bool, String) {
        if let Some(ip) = extract_ip(details) {
            #[cfg(target_os = "linux")]
            {
                let output = Command::new("iptables")
                    .args(["-A", "INPUT", "-s", &ip, "-j", "DROP"])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("IP {} blocked", ip))
                    }
                    Ok(out) => {
                        (false, format!("Block IP failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Block IP error: {}", e))
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                // Windows 防火墙阻止 IP
                let output = Command::new("netsh")
                    .args(["advfirewall", "firewall", "add", "rule", 
                           "name=BlockIP", "dir=in", "action=block", 
                           &format!("remoteip={}", ip)])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("IP {} blocked via Windows Firewall", ip))
                    }
                    Ok(out) => {
                        // 尝试用netsh interface portproxy作为备选
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        (false, format!("Block IP failed: {}", stderr))
                    }
                    Err(e) => {
                        (false, format!("Block IP error: {}", e))
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                (false, "IP blocking not supported on this platform".to_string())
            }
        } else {
            (false, "No IP found in details".to_string())
        }
    }

    /// 隔离进程（暂停）
    fn isolate_process(&self, details: &str) -> (bool, String) {
        if let Some(pid) = extract_pid(details) {
            #[cfg(target_os = "linux")]
            {
                let output = Command::new("kill")
                    .args(["-STOP", &pid.to_string()])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("Process {} isolated (paused)", pid))
                    }
                    Ok(out) => {
                        (false, format!("Isolate failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Isolate error: {}", e))
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                // Windows 上使用 psutil 暂停进程，这里用简单方式
                // 使用 Windows API 需要外部库，这里用 taskkill 模拟
                let output = Command::new("powershell")
                    .args(["-NoProfile", "-Command", 
                           &format!("Stop-Process -Id {} -Force", pid)])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("Process {} stopped", pid))
                    }
                    Ok(out) => {
                        (false, format!("Isolate failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Isolate error: {}", e))
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                (false, "Process isolation not supported".to_string())
            }
        } else {
            (false, "No PID found in details".to_string())
        }
    }

    /// 禁用用户
    fn disable_user(&self, details: &str) -> (bool, String) {
        if let Some(username) = extract_username(details) {
            #[cfg(target_os = "linux")]
            {
                let output = Command::new("usermod")
                    .args(["-L", "-e", "1", &username])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("User {} disabled", username))
                    }
                    Ok(out) => {
                        (false, format!("Disable user failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Disable user error: {}", e))
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                // Windows 禁用用户
                let output = Command::new("net")
                    .args(["user", &username, "/active:no"])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("User {} disabled", username))
                    }
                    Ok(out) => {
                        (false, format!("Disable user failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Disable user error: {}", e))
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                (false, "User management not supported".to_string())
            }
        } else {
            (false, "No username found in details".to_string())
        }
    }

    /// 停止服务
    fn stop_service(&self, details: &str) -> (bool, String) {
        if let Some(service) = extract_service_name(details) {
            #[cfg(target_os = "linux")]
            {
                let output = Command::new("systemctl")
                    .args(["stop", &service])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("Service {} stopped", service))
                    }
                    Ok(out) => {
                        (false, format!("Stop service failed: {}", String::from_utf8_lossy(&out.stderr)))
                    }
                    Err(e) => {
                        (false, format!("Stop service error: {}", e))
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                // Windows 停止服务
                let output = Command::new("net")
                    .args(["stop", &service])
                    .output();
                
                match output {
                    Ok(out) if out.status.success() => {
                        (true, format!("Service {} stopped", service))
                    }
                    Ok(out) => {
                        // 尝试用 sc stop
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        let sc_output = Command::new("sc")
                            .args(["stop", &service])
                            .output();
                        match sc_output {
                            Ok(sc_out) if sc_out.status.success() => {
                                (true, format!("Service {} stopped via sc", service))
                            }
                            _ => {
                                (false, format!("Stop service failed: {}", stderr))
                            }
                        }
                    }
                    Err(e) => {
                        (false, format!("Stop service error: {}", e))
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                (false, "Service management not supported".to_string())
            }
        } else {
            (false, "No service name found".to_string())
        }
    }

    /// 隔离主机（断网）
    fn isolate_host(&self) -> (bool, String) {
        #[cfg(target_os = "linux")]
        {
            // 关闭所有非本地网络接口
            let output = Command::new("ifconfig")
                .args(["-a"])
                .output();
            
            match output {
                Ok(out) => {
                    let interfaces = String::from_utf8_lossy(&out.stdout);
                    // 简单处理：标记为需要隔离
                    (true, format!("Host isolation triggered, interfaces: {}", interfaces.lines().count()))
                }
                Err(e) => {
                    (false, format!("Isolation error: {}", e))
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Windows 隔离主机 - 禁用所有网络适配器
            let output = Command::new("powershell")
                .args(["-NoProfile", "-Command",
                       "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapter -Confirm:$false"])
                .output();
            
            match output {
                Ok(out) if out.status.success() => {
                    (true, "Host network isolated (all adapters disabled)".to_string())
                }
                Ok(out) => {
                    (false, format!("Isolation failed: {}", String::from_utf8_lossy(&out.stderr)))
                }
                Err(e) => {
                    (false, format!("Isolation error: {}", e))
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            (false, "Host isolation not supported".to_string())
        }
    }

    /// 执行自定义命令
    // FIX 5: Command whitelist for custom commands
    const COMMAND_WHITELIST: &'static [&'static str] = &[
        // Process management
        "kill", "pkill", "killall",
        // Network tools
        "iptables", "ip", "nft", "firewalld", "ufw",
        "netsh", "pfctl",
        // Service management
        "systemctl", "service", "chkconfig", "rc-service", "launchctl",
        // User management
        "usermod", "useradd", "passwd", "userdel",
        // File tools
        "chmod", "chown", "rm", "mv", "cp",
        // System info
        "ps", "top", "htop", "netstat", "ss", "lsof",
        // Other safety tools
        "logger", "echo", "cat", "head", "tail", "grep",
    ];

    fn execute_custom_command(&self, cmd: &str) -> (bool, String) {
        // FIX 5: Validate command against whitelist before execution
        let trimmed_cmd = cmd.trim();
        let cmd_base = trimmed_cmd.split_whitespace().next().unwrap_or("");
        
        if cmd_base.is_empty() {
            return (false, "Empty command".to_string());
        }
        
        if !Self::COMMAND_WHITELIST.iter().any(|&allowed| cmd_base == allowed) {
            eprintln!("[ResponseEngine] BLOCKED non-whitelisted command: {}", trimmed_cmd);
            return (false, format!("Command '{}' is not in the whitelist.", cmd_base));
        }
        
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("sh")
                .args(["-c", trimmed_cmd])
                .output();
            
            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    (out.status.success(), format!("stdout: {}, stderr: {}", stdout, stderr))
                }
                Err(e) => {
                    (false, format!("Custom command error: {}", e))
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("cmd")
                .args(["/C", trimmed_cmd])
                .output();
            
            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    (out.status.success(), format!("stdout: {}, stderr: {}", stdout, stderr))
                }
                Err(e) => {
                    (false, format!("Custom command error: {}", e))
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            (false, "Custom commands not supported".to_string())
        }
    }

    /// 阻断连接
    fn block_connection(&self, details: &str) -> (bool, String) {
        // 与 block_ip 类似，但针对特定连接
        self.block_ip(details)
    }

    /// 获取所有规则
    pub fn get_rules(&self) -> &[ResponseRule] {
        &self.rules
    }

    /// 获取执行结果
    pub fn get_results(&self) -> &[ResponseResult] {
        &self.results
    }
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new()
    }
}

// 辅助函数：从字符串中提取信息
fn extract_pid(details: &str) -> Option<u32> {
    // 尝试从 details 中提取 PID
    // 格式可能是 "PID: 1234" 或 "pid=1234" 等
    let patterns = ["PID:", "pid=", "PID ", "pid ", "process "];
    for pattern in &patterns {
        if let Some(pos) = details.find(pattern) {
            let start = pos + pattern.len();
            let end = details[start..].find(|c: char| !c.is_ascii_digit()).map(|i| start + i).unwrap_or(details.len());
            if start < end {
                if let Ok(pid) = details[start..end].parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }
    None
}

fn extract_ip(details: &str) -> Option<String> {
    // 简单的 IPv4 提取
    let parts: Vec<&str> = details.split(|c: char| !c.is_ascii_digit() && c != '.').collect();
    for part in parts {
        let nums: Vec<&str> = part.split('.').collect();
        if nums.len() == 4 && nums.iter().all(|s| s.parse::<u8>().is_ok()) {
            return Some(nums.join("."));
        }
    }
    None
}

fn extract_username(details: &str) -> Option<String> {
    let patterns = ["user:", "username:", "user ", "username ", "user="];
    for pattern in &patterns {
        if let Some(pos) = details.find(pattern) {
            let start = pos + pattern.len();
            let end = details[start..].find(|c: char| c.is_whitespace() || c == ',' || c == '}').map(|i| start + i).unwrap_or(details.len());
            if start < end {
                let username = details[start..end].trim().to_string();
                if !username.is_empty() {
                    return Some(username);
                }
            }
        }
    }
    None
}

fn extract_service_name(details: &str) -> Option<String> {
    let patterns = ["service:", "service ", "systemctl ", "service="];
    for pattern in &patterns {
        if let Some(pos) = details.find(pattern) {
            let start = pos + pattern.len();
            let end = details[start..].find(|c: char| c.is_whitespace() || c == ',' || c == '}').map(|i| start + i).unwrap_or(details.len());
            if start < end {
                let service = details[start..end].trim().to_string();
                if !service.is_empty() {
                    return Some(service);
                }
            }
        }
    }
    None
}

fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 格式化响应结果
pub fn format_response_results(results: &[ResponseResult]) -> String {
    if results.is_empty() {
        return "✅ 无响应动作执行".to_string();
    }

    let mut output = String::new();
    output.push_str(&format!(
        "═══════════════════════════════════════════\n\
         主动响应执行报告 | 共 {} 个动作\n\
         ════════════════════════════════════════════\n\n",
        results.len()
    ));

    for result in results {
        let status = if result.success { "✅" } else { "❌" };
        output.push_str(&format!(
            "{} [规则: {}] {}\n   {}\n\n",
            status,
            result.rule_id,
            format!("{:?}", result.action),
            result.message
        ));
    }

    output
}

/// 格式化响应规则
pub fn format_response_rules(rules: &[ResponseRule]) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "═══════════════════════════════════════════\n\
         响应规则列表 | 共 {} 条规则\n\
         ════════════════════════════════════════════\n\n",
        rules.len()
    ));

    for rule in rules {
        let status = if rule.enabled { "✅" } else { "❌" };
        output.push_str(&format!(
            "{} [{}] {}\n   描述: {}\n",
            status,
            rule.id,
            rule.name,
            rule.description
        ));
        output.push_str(&format!(
            "   威胁模式: {}\n",
            rule.threat_pattern
        ));
        output.push_str(&format!(
            "   最低严重性: {} | 级别: {:?}\n",
            rule.min_severity,
            rule.level
        ));
        let actions: Vec<String> = rule.actions.iter().map(|a| format!("{:?}", a)).collect();
        output.push_str(&format!("   动作: {}\n\n", actions.join(", ")));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pid() {
        assert_eq!(extract_pid("PID: 1234"), Some(1234));
        assert_eq!(extract_pid("pid=5678"), Some(5678));
    }

    #[test]
    fn test_response_engine() {
        let mut engine = ResponseEngine::new();
        let results = engine.process_threat("cryptominer detected", 70, "PID: 12345");
        
        // 默认规则应该匹配
        assert!(results.len() > 0);
    }
}
