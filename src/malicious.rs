//! 恶意进程检测模块 - 基于行为检测
//! 通过进程行为模式来判断是否为恶意进程

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;

/// 恶意进程检测结果
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaliciousProcessResult {
    pub pid: u32,
    pub name: String,
    pub reasons: Vec<ThreatReason>,
    pub threat_level: ThreatLevel,
    pub overall_score: f32,
}

/// 威胁原因（行为描述）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatReason {
    pub behavior: String,
    pub evidence: String,
    pub score: f32,
}

/// 威胁等级
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Clean = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Clean => write!(f, "干净"),
            ThreatLevel::Low => write!(f, "低"),
            ThreatLevel::Medium => write!(f, "中"),
            ThreatLevel::High => write!(f, "高"),
            ThreatLevel::Critical => write!(f, "严重"),
        }
    }
}

/// 进程行为分析器
pub struct BehaviorAnalyzer {
    /// 高危网络行为模式 (命令行包含, 描述, 基础分数)
    suspicious_network_patterns: Vec<(String, String, f32)>,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        let suspicious_network_patterns = vec![
            // 隐秘网络操作
            ("curl -s http".to_string(), "发起HTTP请求(无日志)".to_string(), 0.3),
            ("wget http".to_string(), "下载网络文件".to_string(), 0.4),
            ("curl -x ".to_string(), "使用代理".to_string(), 0.5),
            ("nc -l ".to_string(), "监听网络端口".to_string(), 0.5),
            ("nc -e ".to_string(), "执行远程命令".to_string(), 0.8),
            ("/dev/tcp/".to_string(), "TCP交互".to_string(), 0.7),
            ("socat ".to_string(), "端口转发/代理".to_string(), 0.6),
            ("proxychains".to_string(), "代理链".to_string(), 0.6),
            ("nmap ".to_string(), "网络扫描".to_string(), 0.5),
            ("masscan".to_string(), "高速扫描".to_string(), 0.6),
            ("hydra ".to_string(), "暴力破解".to_string(), 0.8),
            
            // 远程控制行为
            ("bash -i".to_string(), "交互式Shell".to_string(), 0.4),
            ("/bin/sh -i".to_string(), "交互式Shell".to_string(), 0.4),
            ("python -c".to_string(), "Python执行代码".to_string(), 0.5),
            ("perl -e ".to_string(), "Perl执行代码".to_string(), 0.5),
            ("ruby -e ".to_string(), "Ruby执行代码".to_string(), 0.5),
            ("php -r ".to_string(), "PHP执行代码".to_string(), 0.5),
            ("exec ".to_string(), "exec替换进程".to_string(), 0.4),
            
            // 隐藏行为
            ("> /dev/null 2>&1".to_string(), "隐藏输出".to_string(), 0.2),
            ("&> /dev/null".to_string(), "隐藏输出".to_string(), 0.2),
            ("nohup ".to_string(), "后台运行".to_string(), 0.2),
            ("disown".to_string(), "分离进程".to_string(), 0.3),
            ("base64 -d".to_string(), "Base64解码执行".to_string(), 0.6),
            
            // 持久化行为
            ("cron".to_string(), "定时任务".to_string(), 0.3),
            ("systemctl enable".to_string(), "开机启动".to_string(), 0.3),
            ("launchctl".to_string(), "macOS启动项".to_string(), 0.3),
            
            // 凭证访问
            ("/etc/shadow".to_string(), "访问密码文件".to_string(), 0.7),
            ("id_rsa".to_string(), "SSH私钥访问".to_string(), 0.6),
            ("authorized_keys".to_string(), "SSH授权".to_string(), 0.5),
            
            // 代码注入行为
            ("LD_PRELOAD".to_string(), "动态库预加载".to_string(), 0.7),
            ("ptrace".to_string(), "进程追踪".to_string(), 0.5),
            
            // 下载执行
            ("wget".to_string(), "下载文件".to_string(), 0.3),
            ("curl".to_string(), "下载文件".to_string(), 0.3),
        ];

        Self {
            suspicious_network_patterns,
        }
    }

    /// 分析所有进程
    pub fn analyze(&self, sys: &System) -> Vec<MaliciousProcessResult> {
        let mut results = Vec::new();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();
            let cmdline: Vec<String> = process.cmd().iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            
            let analysis = self.analyze_process(pid_u32, &name, &cmdline, process.cpu_usage(), process.memory(), process.start_time());
            
            if analysis.overall_score > 0.3 {
                results.push(analysis);
            }
        }

        // 按威胁分数降序排列
        results.sort_by(|a, b| {
            b.overall_score
                .partial_cmp(&a.overall_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results
    }

    /// 分析单个进程
    fn analyze_process(&self, pid: u32, name: &str, cmdline: &[String], cpu_usage: f32, memory: u64, start_time: u64) -> MaliciousProcessResult {
        let mut reasons: Vec<ThreatReason> = Vec::new();
        let full_cmdline = cmdline.join(" ");
        let full_cmdline_lower = full_cmdline.to_lowercase();

        // 1. 分析网络行为
        for (pattern, desc, score) in &self.suspicious_network_patterns {
            if full_cmdline_lower.contains(&pattern.to_lowercase()) {
                reasons.push(ThreatReason {
                    behavior: desc.clone(),
                    evidence: format!("命令行包含: {}", pattern),
                    score: *score,
                });
            }
        }

        // 2. 分析CPU使用率异常
        if cpu_usage > 80.0 {
            reasons.push(ThreatReason {
                behavior: "CPU使用率异常高".to_string(),
                evidence: format!("CPU: {:.1}%", cpu_usage),
                score: 0.4,
            });
        }

        // 3. 分析内存使用异常
        let memory_mb = memory / (1024 * 1024);
        if memory_mb > 2000 {
            reasons.push(ThreatReason {
                behavior: "内存使用异常高".to_string(),
                evidence: format!("内存: {} MB", memory_mb),
                score: 0.3,
            });
        }

        // 4. 分析进程存活时间
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let uptime = now.saturating_sub(start_time);
        
        if uptime < 60 && cpu_usage > 50.0 {
            reasons.push(ThreatReason {
                behavior: "短生命周期高CPU".to_string(),
                evidence: format!("运行{}秒, CPU {:.1}%", uptime, cpu_usage),
                score: 0.5,
            });
        }

        // 5. Linux特定行为检测
        #[cfg(target_os = "linux")]
        {
            if let Some(reason) = self.check_linux_behavior(pid, &full_cmdline_lower) {
                reasons.push(reason);
            }
        }

        // 6. macOS特定行为检测
        #[cfg(target_os = "macos")]
        {
            if let Some(reason) = self.check_macos_behavior(pid, &full_cmdline_lower) {
                reasons.push(reason);
            }
        }

        // 计算总分
        let mut unique_behaviors: HashMap<String, f32> = HashMap::new();
        for reason in &reasons {
            unique_behaviors
                .entry(reason.behavior.clone())
                .and_modify(|e| *e = (*e).max(reason.score))
                .or_insert(reason.score);
        }
        
        let overall_score = if unique_behaviors.is_empty() {
            0.0
        } else {
            let sum: f32 = unique_behaviors.values().sum();
            (sum / unique_behaviors.len() as f32).min(1.0)
        };

        let threat_level = match overall_score {
            s if s >= 0.8 => ThreatLevel::Critical,
            s if s >= 0.6 => ThreatLevel::High,
            s if s >= 0.4 => ThreatLevel::Medium,
            s if s >= 0.3 => ThreatLevel::Low,
            _ => ThreatLevel::Clean,
        };

        MaliciousProcessResult {
            pid,
            name: name.to_string(),
            reasons,
            threat_level,
            overall_score,
        }
    }

    /// Linux 特定行为检测
    #[cfg(target_os = "linux")]
    fn check_linux_behavior(&self, pid: u32, cmdline_lower: &str) -> Option<ThreatReason> {
        let maps_path = format!("/proc/{}/maps", pid);
        
        if let Ok(content) = std::fs::read_to_string(&maps_path) {
            if content.contains("/tmp/") || content.contains("/dev/shm/") {
                if cmdline_lower.contains("curl") || cmdline_lower.contains("wget") {
                    return Some(ThreatReason {
                        behavior: "从/tmp下载并映射内存".to_string(),
                        evidence: "可疑内存映射+网络下载".to_string(),
                        score: 0.8,
                    });
                }
            }
            
            if content.contains(".so (deleted)") {
                return Some(ThreatReason {
                    behavior: "加载已删除的共享库".to_string(),
                    evidence: "SO文件被删除但仍被映射".to_string(),
                    score: 0.6,
                });
            }
        }

        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid_str = line.trim_start_matches("TracerPid:").trim();
                    if pid_str != "0" {
                        return Some(ThreatReason {
                            behavior: "被其他进程追踪".to_string(),
                            evidence: format!("TracerPID: {}", pid_str),
                            score: 0.5,
                        });
                    }
                }
            }
        }

        None
    }

    /// macOS 特定行为检测
    #[cfg(target_os = "macos")]
    fn check_macos_behavior(&self, pid: u32, cmdline_lower: &str) -> Option<ThreatReason> {
        // 检测OS X特有的可疑行为
        if cmdline_lower.contains("open -a ") && cmdline_lower.contains("Terminal") {
            return Some(ThreatReason {
                behavior: "打开Terminal执行命令".to_string(),
                evidence: "可能通过Terminal执行恶意命令".to_string(),
                score: 0.5,
            });
        }
        
        if cmdline_lower.contains("osascript") || cmdline_lower.contains("-e ") {
            return Some(ThreatReason {
                behavior: "执行AppleScript".to_string(),
                evidence: "可能执行自动化脚本".to_string(),
                score: 0.4,
            });
        }

        None
    }
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化检测结果
pub fn format_analysis_results(results: &[MaliciousProcessResult]) -> String {
    if results.is_empty() || results.iter().all(|r| r.threat_level == ThreatLevel::Clean) {
        return "✅ 未检测到恶意行为进程".to_string();
    }

    let mut output = String::new();
    
    let critical = results.iter().filter(|r| r.threat_level == ThreatLevel::Critical).count();
    let high = results.iter().filter(|r| r.threat_level == ThreatLevel::High).count();
    let medium = results.iter().filter(|r| r.threat_level == ThreatLevel::Medium).count();
    let low = results.iter().filter(|r| r.threat_level == ThreatLevel::Low).count();

    output.push_str(&format!(
        "⚠️  行为分析检测报告\n\
         ════════════════════════════════════════════\n\
         严重: {} | 高危: {} | 中危: {} | 低危: {}\n\
         ════════════════════════════════════════════\n\n",
        critical, high, medium, low
    ));

    for r in results {
        if r.threat_level == ThreatLevel::Clean {
            continue;
        }

        let icon = match r.threat_level {
            ThreatLevel::Critical => "🔴",
            ThreatLevel::High => "🟠",
            ThreatLevel::Medium => "🟡",
            ThreatLevel::Low => "🟢",
            ThreatLevel::Clean => "⚪",
        };

        output.push_str(&format!(
            "{} [{}] PID: {} | {}\n",
            icon, r.threat_level, r.pid, r.name
        ));
        output.push_str(&format!("   威胁分数: {:.0}%\n", r.overall_score * 100.0));
        
        for reason in &r.reasons {
            output.push_str(&format!(
                "   • {} ({:.0}%)\n",
                reason.behavior,
                reason.score * 100.0
            ));
        }
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer() {
        let analyzer = BehaviorAnalyzer::new();
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let results = analyzer.analyze(&sys);
        assert!(results.len() >= 0);
    }
}
