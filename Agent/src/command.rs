//! 远程命令执行模块
//! 接收并执行 Manager 下发的命令

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

/// 命令执行请求
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandRequest {
    pub id: String,              // 命令唯一ID
    pub command: String,           // 要执行的命令
    pub args: Vec<String>,        // 命令参数
    pub timeout_secs: u64,        // 超时时间
    pub user: String,             // 执行用户
    pub work_dir: Option<String>, // 工作目录
}

/// 命令执行结果
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandResult {
    pub id: String,              // 对应请求ID
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub executed_at: u64,
}

/// 命令白名单（安全限制）
pub struct CommandWhitelist {
    allowed_commands: HashMap<String, Vec<String>>, // command -> allowed args patterns
}

impl CommandWhitelist {
    pub fn new() -> Self {
        let mut allowed_commands = HashMap::new();
        
        // 系统监控命令
        allowed_commands.insert("ps".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("top".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("netstat".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("ss".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("df".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("du".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("free".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("uptime".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("who".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("w".to_string(), vec!["*".to_string()]);
        
        // 进程管理
        allowed_commands.insert("kill".to_string(), vec!["-*".to_string(), "[0-9]+".to_string()]);
        allowed_commands.insert("pkill".to_string(), vec!["-*".to_string(), ".*".to_string()]);
        allowed_commands.insert("killall".to_string(), vec!["-*".to_string(), ".*".to_string()]);
        
        // 网络命令
        allowed_commands.insert("iptables".to_string(), vec!["-*".to_string(), ".*".to_string()]);
        allowed_commands.insert("ip".to_string(), vec!["addr".to_string(), "link".to_string(), "rule".to_string()]);
        allowed_commands.insert("firewall-cmd".to_string(), vec!["*".to_string()]);
        
        // 文件查看
        allowed_commands.insert("ls".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("cat".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("head".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("tail".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("grep".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("awk".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("sed".to_string(), vec!["*".to_string()]);
        
        // 系统信息
        allowed_commands.insert("uname".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("hostname".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("ifconfig".to_string(), vec!["*".to_string()]);
        allowed_commands.insert("uptime".to_string(), vec!["*".to_string()]);
        
        // 服务管理
        allowed_commands.insert("systemctl".to_string(), vec!["status".to_string(), "stop".to_string(), "start".to_string(), "restart".to_string(), "enable".to_string(), "disable".to_string()]);
        allowed_commands.insert("service".to_string(), vec!["*".to_string()]);
        
        Self { allowed_commands }
    }

    /// 检查命令是否允许执行
    pub fn is_allowed(&self, command: &str, args: &[String]) -> (bool, String) {
        // 检查命令是否在白名单
        if let Some(allowed_args) = self.allowed_commands.get(command) {
            // 如果白名单包含 "*" 或 ".*"，表示允许任意参数（仅限安全的只读命令）
            if allowed_args.iter().any(|p| p == "*" || p == ".*") {
                return (true, "allowed".to_string());
            }

            // 否则，必须精确匹配参数模式
            // 所有传入的参数都必须被白名单接受
            for arg in args {
                let mut matched = false;
                for pattern in allowed_args {
                    let pattern_str = pattern.as_str();
                    // 检查是否匹配（支持 * 通配符）
                    if pattern_str == "*" {
                        matched = true;
                        break;
                    } else if pattern.ends_with("*") && pattern_str.len() > 1 {
                        // 前缀匹配，如 "status*" 匹配 "status", "statusall"
                        let prefix = &pattern_str[..pattern_str.len() - 1];
                        if arg.starts_with(prefix) {
                            matched = true;
                            break;
                        }
                    } else if arg == pattern_str {
                        // 精确匹配
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return (false, format!("argument '{}' not allowed for command '{}'", arg, command));
                }
            }

            // 所有参数都已验证通过
            return (true, "allowed".to_string());
        }

        (false, format!("command '{}' not in whitelist", command))
    }
}

impl Default for CommandWhitelist {
    fn default() -> Self {
        Self::new()
    }
}

/// 命令执行器
pub struct CommandExecutor {
    whitelist: CommandWhitelist,
}

impl CommandExecutor {
    pub fn new() -> Self {
        Self {
            whitelist: CommandWhitelist::new(),
        }
    }

    /// 执行命令
    pub fn execute(&self, request: &CommandRequest) -> CommandResult {
        let start = SystemTime::now();
        
        // 安全检查
        let (allowed, reason) = self.whitelist.is_allowed(&request.command, &request.args);
        if !allowed {
            return CommandResult {
                id: request.id.clone(),
                success: false,
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("Security check failed: {}", reason),
                duration_ms: 0,
                executed_at: now_timestamp(),
            };
        }

        // 构建命令
        let mut cmd = Command::new(&request.command);
        cmd.args(&request.args);
        
        // 设置工作目录
        if let Some(ref dir) = request.work_dir {
            cmd.current_dir(dir);
        }
        
        // 捕获输出
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // 执行
        let output = cmd.output();
        
        let duration = start.elapsed().unwrap_or_default();
        
        match output {
            Ok(out) => CommandResult {
                id: request.id.clone(),
                success: out.status.success(),
                exit_code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
                duration_ms: duration.as_millis() as u64,
                executed_at: now_timestamp(),
            },
            Err(e) => CommandResult {
                id: request.id.clone(),
                success: false,
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("Execution error: {}", e),
                duration_ms: duration.as_millis() as u64,
                executed_at: now_timestamp(),
            }
        }
    }

    /// 添加白名单命令
    pub fn add_to_whitelist(&mut self, command: &str, args_patterns: Vec<String>) {
        self.whitelist.allowed_commands.insert(command.to_string(), args_patterns);
    }
}

impl Default for CommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 格式化命令结果
pub fn format_command_result(result: &CommandResult) -> String {
    let status = if result.success { "✅ 成功" } else { "❌ 失败" };
    
    format!(
        "命令执行结果 [{}]\n\
         状态: {} | 退出码: {}\n\
         耗时: {}ms\n\
         ─────── STDOUT ───────\n{}\n\
         ─────── STDERR ───────\n{}",
        result.id,
        status,
        result.exit_code,
        result.duration_ms,
        truncate_output(&result.stdout),
        truncate_output(&result.stderr)
    )
}

fn truncate_output(s: &str) -> String {
    const MAX_LEN: usize = 2000;
    if s.len() > MAX_LEN {
        format!("{}...\n(输出截断，共 {} 字符)", &s[..MAX_LEN], s.len())
    } else if s.is_empty() {
        "(无输出)".to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist() {
        let whitelist = CommandWhitelist::new();
        assert!(whitelist.is_allowed("ps", &["aux".to_string()]).0);
        assert!(!whitelist.is_allowed("rm", &["-rf".to_string(), "/".to_string()]).0);
    }

    #[test]
    fn test_executor() {
        let executor = CommandExecutor::new();
        let result = executor.execute(&CommandRequest {
            id: "test-001".to_string(),
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            timeout_secs: 5,
            user: "root".to_string(),
            work_dir: None,
        });
        assert!(result.success);
    }
}
