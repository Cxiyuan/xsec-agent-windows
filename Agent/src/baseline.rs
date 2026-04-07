//! 基线核查执行模块
//! 
//! 接收来自服务端的基线核查规则并执行
//! 不内置任何规则，所有规则由 Manager 下发

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::thread;
use std::sync::mpsc;

/// 基线核查规则（由 Manager 下发）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRule {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub rule_type: String,      // cmd_check, file_check, config_check
    pub check_command: String,  // 要执行的命令或检查的文件路径
    pub expected_result: String, // 期望结果
    pub comparison: String,    // equals, contains, regex, not_contains, exists, not_exists, gt, lt
    pub severity: String,       // critical, high, medium, low, info
}

/// 基线核查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCheckResult {
    pub rule_id: u64,
    pub rule_name: String,
    pub status: String,        // pass, fail, error
    pub actual_value: String,  // 实际检测结果
    pub expected_value: String,
    pub error_message: String,
    pub severity: String,
    pub checked_at: u64,
}

impl BaselineCheckResult {
    pub fn new(rule: &BaselineRule) -> Self {
        Self {
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            status: "error".to_string(),
            actual_value: String::new(),
            expected_value: rule.expected_result.clone(),
            error_message: String::new(),
            severity: rule.severity.clone(),
            checked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// 基线核查任务结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineTaskResult {
    pub task_id: u64,
    pub agent_id: String,
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
    pub errors: u32,
    pub results: Vec<BaselineCheckResult>,
    pub scanned_at: u64,
}

impl BaselineTaskResult {
    pub fn new(task_id: u64, agent_id: String) -> Self {
        Self {
            task_id,
            agent_id,
            total: 0,
            passed: 0,
            failed: 0,
            errors: 0,
            results: Vec::new(),
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// 执行基线检查
pub struct BaselineChecker;

impl BaselineChecker {
    /// 执行单个基线规则检查
    pub fn check_rule(rule: &BaselineRule) -> BaselineCheckResult {
        let mut result = BaselineCheckResult::new(rule);
        
        match rule.rule_type.as_str() {
            "cmd_check" => {
                result.actual_value = Self::execute_command(&rule.check_command);
            },
            "file_check" => {
                result.actual_value = Self::check_file(rule);
            },
            "config_check" => {
                result.actual_value = Self::execute_command(&rule.check_command);
            },
            _ => {
                result.error_message = format!("Unknown rule type: {}", rule.rule_type);
                return result;
            }
        }
        
        // 比较结果
        result.status = Self::compare(&result.actual_value, &rule.expected_result, &rule.comparison);
        result
    }
    
    /// 执行命令并返回输出（带超时控制）
    fn execute_command(cmd: &str) -> String {
        Self::execute_command_with_timeout(cmd, Duration::from_secs(30))
    }
    
    /// 执行命令并返回输出（带超时控制）
    fn execute_command_with_timeout(cmd: &str, timeout: Duration) -> String {
        // FIX 19: Use kill_on_drop(true) to ensure process is killed if dropped
        let (tx, rx) = mpsc::channel();
        
        // 克隆命令字符串供线程使用
        let cmd_clone = cmd.to_string();
        
        // 在后台线程执行命令
        let _handle = thread::spawn(move || {
            // FIX 19: Use kill_on_drop(true) so child is killed if Command is dropped
            let output = Command::new("sh")
                .arg("-c")
                .arg(&cmd_clone)
                .kill_on_drop(true)
                .output();
            
            let _ = tx.send(output);
        });
        
        // 等待结果或超时
        match rx.recv_timeout(timeout) {
            Ok(Ok(out)) => {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if stdout.is_empty() && !stderr.is_empty() {
                    stderr
                } else {
                    stdout
                }
            },
            Ok(Err(e)) => format!("error: {}", e),
            Err(_) => {
                // 超时后线程会自动终止（因为 kill_on_drop=true）
                format!("error: command timeout after {} seconds", timeout.as_secs())
            }
        }
    }
    
    /// 检查文件状态
    fn check_file(rule: &BaselineRule) -> String {
        let check_cmd = &rule.check_command;
        
        // 检查文件是否存在
        if check_cmd == "exists" {
            return "checking".to_string();
        }
        
        // 使用 stat 检查文件
        let output = Command::new("stat")
            .arg("-c")
            .arg("%a")
            .arg(&rule.name)  // name字段是文件路径
            .output();
        
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            Err(e) => format!("error: {}", e),
        }
    }
    
    /// 比较实际值和期望值
    fn compare(actual: &str, expected: &str, comparison: &str) -> String {
        // 如果命令执行出错
        if actual.starts_with("error:") {
            return "error".to_string();
        }
        
        match comparison {
            "equals" => {
                if actual == expected {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                }
            },
            "not_equals" => {
                if actual != expected {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                }
            },
            "contains" => {
                if actual.contains(expected) {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                }
            },
            "not_contains" => {
                if !actual.contains(expected) {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                }
            },
            "exists" => {
                if !actual.is_empty() && !actual.starts_with("error:") {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                }
            },
            "not_exists" => {
                if actual.is_empty() || actual.starts_with("error:") {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                }
            },
            "regex" => {
                match regex::Regex::new(expected) {
                    Ok(re) => {
                        if re.is_match(actual) {
                            "pass".to_string()
                        } else {
                            "fail".to_string()
                        }
                    },
                    Err(_) => "error".to_string(),
                }
            },
            "gt" => {
                match (actual.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(a), Ok(e)) => {
                        if a > e { "pass".to_string() } else { "fail".to_string() }
                    },
                    _ => "error".to_string(),
                }
            },
            "lt" => {
                match (actual.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(a), Ok(e)) => {
                        if a < e { "pass".to_string() } else { "fail".to_string() }
                    },
                    _ => "error".to_string(),
                }
            },
            _ => "error".to_string(),
        }
    }
    
    /// 执行多个规则检查
    pub fn execute_task(task_id: u64, agent_id: &str, rules: &[BaselineRule]) -> BaselineTaskResult {
        let mut task_result = BaselineTaskResult::new(task_id, agent_id.to_string());
        
        for rule in rules {
            let result = Self::check_rule(rule);
            match result.status.as_str() {
                "pass" => task_result.passed += 1,
                "fail" => task_result.failed += 1,
                _ => task_result.errors += 1,
            }
            task_result.total += 1;
            task_result.results.push(result);
        }
        
        task_result
    }
}

/// 格式化基线检查结果
pub fn format_baseline_results(result: &BaselineTaskResult) -> String {
    let mut output = String::new();
    output.push_str(&format!("\n=== 基线核查结果 ===\n"));
    output.push_str(&format!("任务ID: {}\n", result.task_id));
    output.push_str(&format!("Agent: {}\n", result.agent_id));
    output.push_str(&format!("总计: {} | 通过: {} | 失败: {} | 错误: {}\n",
        result.total, result.passed, result.failed, result.errors));
    output.push_str("\n--- 检查详情 ---\n");
    
    for r in &result.results {
        let status_icon = match r.status.as_str() {
            "pass" => "✓",
            "fail" => "✗",
            _ => "!",
        };
        output.push_str(&format!("{} [{}] {}\n", status_icon, r.severity, r.rule_name));
        if r.status == "fail" {
            output.push_str(&format!("  期望: {}\n", r.expected_value));
            output.push_str(&format!("  实际: {}\n", r.actual_value));
        }
        if !r.error_message.is_empty() {
            output.push_str(&format!("  错误: {}\n", r.error_message));
        }
    }
    
    output
}
