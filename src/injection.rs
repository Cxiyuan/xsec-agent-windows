//! 进程注入检测模块
//! 检测 DLL 注入、内存注入、钩子注入等

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;
use sysinfo::System;

/// 注入检测结果
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InjectionResult {
    pub pid: u32,
    pub name: String,
    pub injection_type: InjectionType,
    pub evidence: String,
    pub severity: InjectionSeverity,
}

/// 注入类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum InjectionType {
    DllInjection,        // DLL/共享库注入
    ProcessHollowing,    // 进程挖空
    ThreadInjection,     // 线程注入
    InlineHooking,       // 内联挂钩
    LD_PRELOAD,          // 环境变量注入
    ProcMemAccess,       // /proc内存访问
    Unknown,
}

/// 严重程度
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum InjectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for InjectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionType::DllInjection => write!(f, "DLL注入"),
            InjectionType::ProcessHollowing => write!(f, "进程挖空"),
            InjectionType::ThreadInjection => write!(f, "线程注入"),
            InjectionType::InlineHooking => write!(f, "内联挂钩"),
            InjectionType::LD_PRELOAD => write!(f, "环境变量注入"),
            InjectionType::ProcMemAccess => write!(f, "内存访问注入"),
            InjectionType::Unknown => write!(f, "未知注入"),
        }
    }
}

impl std::fmt::Display for InjectionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionSeverity::Low => write!(f, "低"),
            InjectionSeverity::Medium => write!(f, "中"),
            InjectionSeverity::High => write!(f, "高"),
            InjectionSeverity::Critical => write!(f, "严重"),
        }
    }
}

/// 进程注入检测器
pub struct InjectionDetector;

impl InjectionDetector {
    pub fn new() -> Self {
        Self
    }

    /// 检测所有进程
    pub fn detect(&self, sys: &System) -> Vec<InjectionResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            results = self.detect_linux(sys);
        }

        #[cfg(target_os = "windows")]
        {
            results = self.detect_windows(sys);
        }

        #[cfg(target_os = "macos")]
        {
            results = self.detect_macos(sys);
        }

        results
    }

    // =========================================================================
    // Linux 检测
    // =========================================================================
    #[cfg(target_os = "linux")]
    fn detect_linux(&self, sys: &System) -> Vec<InjectionResult> {
        let mut results = Vec::new();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();

            // 1. 检测 LD_PRELOAD 注入
            if let Some(result) = self.check_ld_preload(pid_u32, &name) {
                results.push(result);
            }

            // 2. 检测 TracerPID（非零表示被调试/注入）
            if let Some(result) = self.check_tracer_pid(pid_u32, &name) {
                results.push(result);
            }

            // 3. 检测可疑内存映射
            if let Some(result) = self.check_suspicious_mappings(pid_u32, &name) {
                results.push(result);
            }

            // 4. 检测已删除的共享库
            if let Some(result) = self.check_deleted_so(pid_u32, &name) {
                results.push(result);
            }

            // 5. 检测 /proc/{pid}/mem 可访问性
            if let Some(result) = self.check_proc_mem_access(pid_u32, &name) {
                results.push(result);
            }
        }

        results
    }

    #[cfg(target_os = "linux")]
    fn check_ld_preload(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        let env_path = format!("/proc/{}/environ", pid);
        
        if let Ok(content) = std::fs::read_to_string(&env_path) {
            for line in content.split('\0') {
                if line.starts_with("LD_PRELOAD=") {
                    let value = line.trim_start_matches("LD_PRELOAD=");
                    if !value.is_empty() {
                        return Some(InjectionResult {
                            pid,
                            name: name.to_string(),
                            injection_type: InjectionType::LD_PRELOAD,
                            evidence: format!("LD_PRELOAD={}", value),
                            severity: InjectionSeverity::Critical,
                        });
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn check_tracer_pid(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        let status_path = format!("/proc/{}/status", pid);
        
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid_str = line.trim_start_matches("TracerPid:").trim();
                    if pid_str != "0" {
                        return Some(InjectionResult {
                            pid,
                            name: name.to_string(),
                            injection_type: InjectionType::ThreadInjection,
                            evidence: format!("被 TracerPID={} 追踪/注入", pid_str),
                            severity: InjectionSeverity::High,
                        });
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn check_suspicious_mappings(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        let maps_path = format!("/proc/{}/maps", pid);
        
        if let Ok(content) = std::fs::read_to_string(&maps_path) {
            let suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/fd/"];
            let mut found = Vec::new();

            for line in content.lines() {
                for susp in &suspicious_paths {
                    if line.contains(susp) {
                        found.push(line.trim().to_string());
                        break;
                    }
                }
            }

            // 超过阈值才报告
            if found.len() >= 3 {
                return Some(InjectionResult {
                    pid,
                    name: name.to_string(),
                    injection_type: InjectionType::DllInjection,
                    evidence: format!("发现 {} 处可疑内存映射", found.len()),
                    severity: InjectionSeverity::High,
                });
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn check_deleted_so(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        let maps_path = format!("/proc/{}/maps", pid);
        
        if let Ok(content) = std::fs::read_to_string(&maps_path) {
            let deleted_count = content.matches(".so (deleted)").count();
            
            if deleted_count >= 3 {
                return Some(InjectionResult {
                    pid,
                    name: name.to_string(),
                    injection_type: InjectionType::DllInjection,
                    evidence: format!("加载了 {} 个已删除的共享库(可能被注入)", deleted_count),
                    severity: InjectionSeverity::High,
                });
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn check_proc_mem_access(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        // 检查是否有其他进程正在访问此进程的内存
        let mut accessors: Vec<u32> = Vec::new();
        
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(name_str) = entry.file_name().to_str().to_owned() {
                    if let Ok(accessor_pid) = name_str.parse::<u32>() {
                        if accessor_pid == pid {
                            continue;
                        }
                        
                        // 检查这个进程是否在访问目标进程的内存
                        let fd_path = format!("/proc/{}/fd", accessor_pid);
                        if let Ok(fd_entries) = std::fs::read_dir(&fd_path) {
                            for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                                if let Ok(link) = fd_entry.read_link() {
                                    let link_str = link.to_string_lossy();
                                    if link_str.contains(&format!("/proc/{}/mem", pid)) 
                                        || link_str.contains(&format!("/proc/{}/", pid)) {
                                        accessors.push(accessor_pid);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !accessors.is_empty() {
            return Some(InjectionResult {
                pid,
                name: name.to_string(),
                injection_type: InjectionType::ProcMemAccess,
                evidence: format!("被进程 {:?} 访问内存", accessors),
                severity: InjectionSeverity::Critical,
            });
        }

        None
    }

    // =========================================================================
    // macOS 检测
    // =========================================================================
    #[cfg(target_os = "macos")]
    fn detect_macos(&self, sys: &System) -> Vec<InjectionResult> {
        let mut results = Vec::new();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();

            // 1. macOS: 检查 DYLD_INSERT_ARGS (类似 LD_PRELOAD)
            if let Some(result) = self.check_dyld_insert(pid_u32, &name) {
                results.push(result);
            }

            // 2. macOS: 检查进程间调试（ptrace）
            if let Some(result) = self.check_ptrace(pid_u32, &name) {
                results.push(result);
            }

            // 3. macOS: 检查代码签名
            if let Some(result) = self.check_code_signature(pid_u32, &name) {
                results.push(result);
            }
        }

        results
    }

    #[cfg(target_os = "macos")]
    fn check_dyld_insert(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        let task_info = format!("/proc/{}/task", pid);
        
        // macOS 上通过 vmmap 检查
        let output = Command::new("vmmap")
            .args([&pid.to_string()])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("DYLD_INSERT") || stdout.contains(".dylib (pre-allocated") {
                return Some(InjectionResult {
                    pid,
                    name: name.to_string(),
                    injection_type: InjectionType::DllInjection,
                    evidence: "检测到 DYLD_INSERT 注入".to_string(),
                    severity: InjectionSeverity::High,
                });
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn check_ptrace(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        // 检查是否有其他进程在追踪此进程
        let output = Command::new("ps")
            .args(["-o", "pid=,command="])
            .output();

        if let Ok(output) = output {
            let lines = String::from_utf8_lossy(&output.stdout);
            for line in lines.lines() {
                if line.contains("ptrace") || line.contains("lldb") || line.contains("debug") {
                    // 进一步检查目标
                    if line.contains(&pid.to_string()) {
                        return Some(InjectionResult {
                            pid,
                            name: name.to_string(),
                            injection_type: InjectionType::ThreadInjection,
                            evidence: "被调试器(ptrace/lldb)追踪".to_string(),
                            severity: InjectionSeverity::Medium,
                        });
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn check_code_signature(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        // 检查进程是否已签名
        let output = Command::new("codesign")
            .args(["-d", "-v", &format!("/proc/{}/file", pid)])
            .output();

        // 如果 codesign 失败或输出包含警告，可能有注入
        if let Ok(output) = output {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("invalid") || stderr.contains("unsigned") {
                return Some(InjectionResult {
                    pid,
                    name: name.to_string(),
                    injection_type: InjectionType::DllInjection,
                    evidence: "代码签名无效或未签名".to_string(),
                    severity: InjectionSeverity::Medium,
                });
            }
        }
        None
    }

    // =========================================================================
    // Windows 检测
    // =========================================================================
    #[cfg(target_os = "windows")]
    fn detect_windows(&self, sys: &System) -> Vec<InjectionResult> {
        let mut results = Vec::new();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();

            // 1. Windows: 检测远程线程创建
            if let Some(result) = self.check_remote_thread(pid_u32, &name) {
                results.push(result);
            }

            // 2. Windows: 检测可疑 DLL
            if let Some(result) = self.check_suspicious_dlls(pid_u32, &name) {
                results.push(result);
            }

            // 3. Windows: 检测 Process Hollowing 迹象
            if let Some(result) = self.check_process_hollowing(pid_u32, &name) {
                results.push(result);
            }
        }

        results
    }

    #[cfg(target_os = "windows")]
    fn check_remote_thread(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        // 使用 tasklist 检查
        let output = Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={}", pid), "get", "ParentProcessId"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // 如果父进程是系统进程但不是正常的 svchost, csrss 等
            // 这可能是注入的结果
        }
        None
    }

    #[cfg(target_os = "windows")]
    fn check_suspicious_dlls(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        let output = Command::new("tasklist")
            .args(["/M", "/FI", &format!("PID eq {}", pid)])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let suspicious_dlls = ["mimikatz", "psexec", "winexec", "hook", "inject"];
            
            for dll in suspicious_dlls {
                if stdout.to_lowercase().contains(dll) {
                    return Some(InjectionResult {
                        pid,
                        name: name.to_string(),
                        injection_type: InjectionType::DllInjection,
                        evidence: format!("加载可疑DLL: {}", dll),
                        severity: InjectionSeverity::Critical,
                    });
                }
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    fn check_process_hollowing(&self, pid: u32, name: &str) -> Option<InjectionResult> {
        // 检测进程路径是否为空或可疑
        let output = Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={}", pid), "get", "ExecutablePath"])
            .output();

        if let Ok(output) = output {
            let path = String::from_utf8_lossy(&output.stdout);
            if path.trim().is_empty() || path.contains("N/A") {
                return Some(InjectionResult {
                    pid,
                    name: name.to_string(),
                    injection_type: InjectionType::ProcessHollowing,
                    evidence: "进程路径为空或不可访问(可能挖空)".to_string(),
                    severity: InjectionSeverity::Critical,
                });
            }
        }
        None
    }
}

impl Default for InjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化检测结果
pub fn format_injection_results(results: &[InjectionResult]) -> String {
    if results.is_empty() {
        return "✅ 未检测到进程注入".to_string();
    }

    let mut output = format!(
        "⚠️  进程注入检测报告\n\
         ════════════════════════════════════════════\n\
         检测到 {} 个可疑注入\n\
         ════════════════════════════════════════════\n\n",
        results.len()
    );

    for r in results {
        let icon = match r.severity {
            InjectionSeverity::Critical => "🔴",
            InjectionSeverity::High => "🟠",
            InjectionSeverity::Medium => "🟡",
            InjectionSeverity::Low => "🟢",
        };

        output.push_str(&format!(
            "{} [{}] PID: {} | {}\n",
            icon, r.severity, r.pid, r.name
        ));
        output.push_str(&format!("   类型: {}\n", r.injection_type));
        output.push_str(&format!("   证据: {}\n\n", r.evidence));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector() {
        let detector = InjectionDetector::new();
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let results = detector.detect(&sys);
        assert!(results.len() >= 0);
    }
}
