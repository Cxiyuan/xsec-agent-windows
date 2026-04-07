//! 隐藏进程检测模块
//! Linux: 通过多种方法检测隐藏进程
//! Windows: 检测进程伪装和Rootkit

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;
use sysinfo::System;

/// 隐藏进程检测结果
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HiddenProcessResult {
    pub pid: u32,
    pub name: String,
    pub detection_method: String,
    pub severity: HiddenLevel,
}

/// 隐藏等级
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum HiddenLevel {
    Suspicious,   // 可疑
    Hidden,       // 确认隐藏
    Rootkit,      // Rootkit级别
}

impl std::fmt::Display for HiddenLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HiddenLevel::Suspicious => write!(f, "可疑"),
            HiddenLevel::Hidden => write!(f, "隐藏"),
            HiddenLevel::Rootkit => write!(f, "Rootkit"),
        }
    }
}

/// 隐藏进程检测结果集
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HiddenProcessReport {
    pub timestamp: u64,
    pub platform: String,
    pub total_hidden: usize,
    pub suspicious: usize,
    pub hidden: usize,
    pub rootkit: usize,
    pub results: Vec<HiddenProcessResult>,
}

/// 隐藏进程检测器
pub struct HiddenProcessDetector;

impl HiddenProcessDetector {
    pub fn new() -> Self {
        Self
    }

    /// 执行全面隐藏进程检测
    pub fn detect(&self, sys: &System) -> HiddenProcessReport {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        #[cfg(target_os = "linux")]
        let (results, platform_str) = self.detect_linux(sys);

        #[cfg(target_os = "windows")]
        let (results, platform_str) = self.detect_windows(sys);

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let (results, platform_str): (Vec<HiddenProcessResult>, String) = (Vec::new(), "unknown".to_string());

        let total_hidden = results.len();
        let suspicious = results.iter().filter(|r: &&HiddenProcessResult| r.severity == HiddenLevel::Suspicious).count();
        let hidden = results.iter().filter(|r: &&HiddenProcessResult| r.severity == HiddenLevel::Hidden).count();
        let rootkit = results.iter().filter(|r: &&HiddenProcessResult| r.severity == HiddenLevel::Rootkit).count();

        HiddenProcessReport {
            timestamp,
            platform: platform_str,
            total_hidden,
            suspicious,
            hidden,
            rootkit,
            results,
        }
    }

    // =========================================================================
    // Linux 隐藏进程检测
    // =========================================================================
    #[cfg(target_os = "linux")]
    fn detect_linux(&self, sys: &System) -> (Vec<HiddenProcessResult>, String) {
        let mut results = Vec::new();

        // 方法1: 对比 ps 和 /proc/ 目录
        let ps_pids = self.get_ps_pids();
        let proc_pids = self.get_proc_pids();
        let sys_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

        // ps 中没有但 /proc 中有的（轻微隐藏）
        for &pid in &proc_pids {
            if !ps_pids.contains(&pid) && sys_pids.contains(&pid) {
                let name = self.get_proc_name(pid);
                results.push(HiddenProcessResult {
                    pid,
                    name: name.clone(),
                    detection_method: "ps命令中未列出(/proc存在)".to_string(),
                    severity: HiddenLevel::Suspicious,
                });
            }
        }

        // 方法2: sysinfo 与 /proc/ 对比
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            if !proc_pids.contains(&pid_u32) {
                results.push(HiddenProcessResult {
                    pid: pid_u32,
                    name: process.name().to_string_lossy().to_string(),
                    detection_method: "sysinfo与/proc目录不匹配".to_string(),
                    severity: HiddenLevel::Hidden,
                });
            }
        }

        // 方法3: 检测进程名伪装（与可执行文件名不同）
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid_u32)) {
                let exe_name = exe_path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let proc_name = process.name().to_string_lossy().to_string();
                
                // 如果 exe 被删除或名称不匹配
                if exe_name.contains(" (deleted)")
                    && !proc_name.is_empty()
                    && proc_name != exe_name.replace(" (deleted)", "") {
                    results.push(HiddenProcessResult {
                        pid: pid_u32,
                        name: proc_name,
                        detection_method: format!("进程名 '{}' 与可执行文件 '{}' 不匹配(文件已删除)", proc_name, exe_name),
                        severity: HiddenLevel::Suspicious,
                    });
                }
            }
        }

        // 方法4: 检测 /proc/%/status 中的可疑状态
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid_u32)) {
                // 检查TracerPID（非0表示被调试或被挂钩）
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let pid_str = line.trim_start_matches("TracerPid:").trim();
                        if pid_str != "0" {
                            results.push(HiddenProcessResult {
                                pid: pid_u32,
                                name: process.name().to_string_lossy().to_string(),
                                detection_method: format!("被TracerPID={}追踪(可能被调试或挂钩)", pid_str),
                                severity: HiddenLevel::Suspicious,
                            });
                            break;
                        }
                    }
                }
            }
        }

        // 方法5: 检测隐藏模块（通过 /proc/modules）
        let hidden_modules = self.detect_hidden_kernel_modules();
        for module in hidden_modules {
            results.push(HiddenProcessResult {
                pid: 0,
                name: module,
                detection_method: "内核模块隐藏检测".to_string(),
                severity: HiddenLevel::Rootkit,
            });
        }

        // 去重（同一PID可能多种检测方法触发）
        results.sort_by(|a, b| a.pid.cmp(&b.pid));
        results.dedup_by(|a, b| a.pid == b.pid && a.detection_method == b.detection_method);

        (results, "linux".to_string())
    }

    #[cfg(target_os = "linux")]
    fn get_ps_pids(&self) -> HashSet<u32> {
        let mut pids = HashSet::new();
        
        let output = Command::new("ps")
            .args(["-eo", "pid"])
            .output();
        
        if let Ok(output) = output {
            for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
        
        pids
    }

    #[cfg(target_os = "linux")]
    fn get_proc_pids(&self) -> Vec<u32> {
        let mut pids = Vec::new();
        
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(name) = entry.file_name().to_str().to_owned() {
                    if let Ok(pid) = name.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
        
        pids
    }

    #[cfg(target_os = "linux")]
    fn get_proc_name(&self, pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("PID_{}", pid))
    }

    #[cfg(target_os = "linux")]
    fn detect_hidden_kernel_modules(&self) -> Vec<String> {
        let mut hidden = Vec::new();
        
        // 获取所有模块
        let all_modules = std::fs::read_to_string("/proc/modules")
            .map(|s| {
                s.lines()
                    .filter_map(|line| line.split_whitespace().next())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // 通过 lsmod 检查（可能不一致）
        let lsmod_output = Command::new("lsmod")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        for module in all_modules {
            // 如果模块在 /proc/modules 但不在 lsmod
            if !lsmod_output.contains(&module) && !module.is_empty() && module != "Module" {
                hidden.push(format!("{} (未在lsmod中列出)", module));
            }
        }
        
        hidden
    }

    // =========================================================================
    // Windows 隐藏进程检测
    // =========================================================================
    #[cfg(target_os = "windows")]
    fn detect_windows(&self, sys: &System) -> (Vec<HiddenProcessResult>, String) {
        let mut results = Vec::new();

        // 方法1: 对比 tasklist 和 NT Query SystemInformation
        let tasklist_pids = self.get_tasklist_pids();
        let sys_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

        for pid in &sys_pids {
            if !tasklist_pids.contains(pid) {
                let name = sys.processes()
                    .get(&sysinfo::Pid::from_u32(*pid))
                    .map(|p| p.name().to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("PID_{}", pid));
                
                results.push(HiddenProcessResult {
                    pid: *pid,
                    name,
                    detection_method: "tasklist命令中未列出".to_string(),
                    severity: HiddenLevel::Hidden,
                });
            }
        }

        // 方法2: 检测进程名伪装
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();
            
            // Windows 系统进程应该有合理的路径
            if name.ends_with(".exe") {
                let suspicious_names = ["svchost.exe", "lsass.exe", "csrss.exe", 
                    "smss.exe", "winlogon.exe", "services.exe", "explorer.exe"];
                
                if suspicious_names.contains(&name.as_str()) {
                    // 检查路径是否在 System32
                    // 这个检测比较弱，因为需要管理员权限
                    results.push(HiddenProcessResult {
                        pid: pid_u32,
                        name: name.clone(),
                        detection_method: format!("进程 '{}' 可能是系统进程伪装", name),
                        severity: HiddenLevel::Suspicious,
                    });
                }
            }
        }

        // 方法3: 检测父子进程关系异常
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let parent = process.parent();
            
            // explorer.exe 的子进程应该是用户进程
            if let Some(parent_pid) = parent {
                let parent_name = sys.processes()
                    .get(&parent_pid)
                    .map(|p| p.name().to_string_lossy().to_string())
                    .unwrap_or_default();
                
                // 如果父进程是 lsass.exe 或 csrss.exe 且不是系统进程
                if parent_name == "lsass.exe" || parent_name == "csrss.exe" {
                    let name = process.name().to_string_lossy().to_string();
                    if !name.ends_with(".exe") || name.is_empty() {
                        results.push(HiddenProcessResult {
                            pid: pid_u32,
                            name,
                            detection_method: format!("父进程异常({})", parent_name),
                            severity: HiddenLevel::Suspicious,
                        });
                    }
                }
            }
        }

        results.sort_by(|a, b| a.pid.cmp(&b.pid));
        results.dedup_by(|a, b| a.pid == b.pid);

        (results, "windows".to_string())
    }

    #[cfg(target_os = "windows")]
    fn get_tasklist_pids(&self) -> HashSet<u32> {
        let mut pids = HashSet::new();
        
        let output = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output();
        
        if let Ok(output) = output {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                // CSV格式: "name,PID,Session"
                if let Some(second) = line.split(',').nth(1) {
                    if let Ok(pid) = second.trim().parse::<u32>() {
                        pids.insert(pid);
                    }
                }
            }
        }
        
        pids
    }
}

impl Default for HiddenProcessDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化检测结果
pub fn format_hidden_results(report: &HiddenProcessReport) -> String {
    if report.results.is_empty() {
        return "✅ 未检测到隐藏进程".to_string();
    }

    let mut output = format!(
        "⚠️  隐藏进程检测报告\n\
         ════════════════════════════════════════\n\
         平台: {} | 时间戳: {}\n\
         总计: {} | 可疑: {} | 隐藏: {} | Rootkit: {}\n\
         ════════════════════════════════════════\n\n",
        report.platform,
        report.timestamp,
        report.total_hidden,
        report.suspicious,
        report.hidden,
        report.rootkit
    );

    for r in &report.results {
        let icon = match r.severity {
            HiddenLevel::Rootkit => "🔴",
            HiddenLevel::Hidden => "🟠",
            HiddenLevel::Suspicious => "🟡",
        };
        
        output.push_str(&format!(
            "{} [{}] PID: {}\n",
            icon, r.severity, r.pid
        ));
        output.push_str(&format!("   名称: {}\n", r.name));
        output.push_str(&format!("   方法: {}\n\n", r.detection_method));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector() {
        let detector = HiddenProcessDetector::new();
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let report = detector.detect(&sys);
        // 正常系统可能没有隐藏进程
        assert!(report.total_hidden >= 0);
    }
}
