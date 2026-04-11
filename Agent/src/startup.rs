//! 启动项监控模块
//! 监控 Linux 和 Windows 服务器的开机自启、计划任务等持久化机制

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 启动项信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartupItem {
    pub name: String,
    pub path: String,
    pub item_type: StartupType,
    pub enabled: bool,
    pub user: String,
    pub source: String,
    pub risk_level: RiskLevel,
}

/// 启动项类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum StartupType {
    SystemdService,      // systemd 服务
    InitScript,          // init.d 脚本
    Cron,                // 计划任务 (cron)
    SystemV,             // System V
    RcLocal,             // rc.local
    Profile,             // shell profile
    StartupDirectory,    // 启动目录 (~/.config/autostart 等)
    Registry,            // Windows 注册表
    ScheduledTask,       // Windows 计划任务
    WMI,                 // Windows WMI
    Unknown,
}

/// 风险等级
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "低"),
            RiskLevel::Medium => write!(f, "中"),
            RiskLevel::High => write!(f, "高"),
        }
    }
}

/// 启动项监控器
pub struct StartupMonitor {
    /// 可疑路径关键词
    suspicious_paths: HashSet<String>,
    /// 可疑名称关键词
    suspicious_names: HashSet<String>,
}

impl StartupMonitor {
    pub fn new() -> Self {
        let mut suspicious_paths = HashSet::new();
        suspicious_paths.insert("/tmp/".to_string());
        suspicious_paths.insert("/var/tmp/".to_string());
        suspicious_paths.insert("/dev/shm/".to_string());
        suspicious_paths.insert("/Downloads/".to_string());
        suspicious_paths.insert(".ssh/".to_string());
        suspicious_paths.insert(".bashrc".to_string());
        suspicious_paths.insert(".bash_profile".to_string());
        suspicious_paths.insert("AppData/Local/Temp".to_string());
        suspicious_paths.insert("AppData/Roaming".to_string());

        let mut suspicious_names = HashSet::new();
        suspicious_names.insert("update".to_string());
        suspicious_names.insert("sync".to_string());
        suspicious_names.insert("backup".to_string());
        suspicious_names.insert("cron".to_string());
        suspicious_names.insert("shell".to_string());
        suspicious_names.insert("watch".to_string());
        suspicious_names.insert("daemon".to_string());
        suspicious_names.insert("timer".to_string());
        suspicious_names.insert("miner".to_string());
        suspicious_names.insert("scan".to_string());
        suspicious_names.insert("sync".to_string());

        Self {
            suspicious_paths,
            suspicious_names,
        }
    }

    /// 获取所有启动项
    pub fn get_startup_items(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();

        #[cfg(target_os = "linux")]
        {
            items.extend(self.get_linux_startup_items());
        }

        #[cfg(target_os = "windows")]
        {
            items.extend(self.get_windows_startup_items());
        }

        items
    }

    /// 检测可疑启动项
    pub fn detect_suspicious(&self, items: &[StartupItem]) -> Vec<StartupItem> {
        items
            .iter()
            .filter(|item| {
                // 检查可疑路径
                let path_lower = item.path.to_lowercase();
                let has_suspicious_path = self
                    .suspicious_paths
                    .iter()
                    .any(|s| path_lower.contains(&s.to_lowercase()));

                // 检查可疑名称
                let name_lower = item.name.to_lowercase();
                let has_suspicious_name = self
                    .suspicious_names
                    .iter()
                    .any(|s| name_lower.contains(&s.to_lowercase()));

                has_suspicious_path || has_suspicious_name || item.risk_level == RiskLevel::High
            })
            .cloned()
            .collect()
    }

    // =========================================================================
    // Linux 实现
    // =========================================================================
    #[cfg(target_os = "linux")]
    fn get_linux_startup_items(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();

        // 1. systemd 服务
        items.extend(self.get_systemd_services());

        // 2. init.d 脚本
        items.extend(self.get_init_scripts());

        // 3. cron 计划任务
        items.extend(self.get_cron_jobs());

        // 4. rc.local
        if let Some(item) = self.get_rc_local() {
            items.push(item);
        }

        // 5. profile.d
        items.extend(self.get_profile_scripts());

        items
    }

    #[cfg(target_os = "linux")]
    fn get_systemd_services(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();
        let mut enabled_services: HashSet<String> = HashSet::new();

        // 获取已启用的服务
        let output = std::process::Command::new("systemctl")
            .args(["list-unit-files", "--type=service", "--state=enabled", "--no-pager"])
            .output();

        if let Ok(output) = output {
            for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if let Some(name) = fields.first() {
                    if name.ends_with(".service") {
                        enabled_services.insert(name.replace(".service", "").to_string());
                    }
                }
            }
        }

        // 获取服务详情
        for service in enabled_services {
            let exec_start = self.get_systemd_service_exec(&service);
            let risk = self.assess_risk(&service, &exec_start, StartupType::SystemdService);

            items.push(StartupItem {
                name: service.clone(),
                path: exec_start,
                item_type: StartupType::SystemdService,
                enabled: true,
                user: "system".to_string(),
                source: "systemctl".to_string(),
                risk_level: risk,
            });
        }

        items
    }

    #[cfg(target_os = "linux")]
    fn get_systemd_service_exec(&self, service: &str) -> String {
        let output = std::process::Command::new("systemctl")
            .args(["show", service, "--property=ExecStart", "--value"])
            .output();

        if let Ok(output) = output {
            let exec = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !exec.is_empty() && exec != "{}" {
                return exec;
            }
        }
        String::new()
    }

    #[cfg(target_os = "linux")]
    fn get_init_scripts(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();
        let init_paths = ["/etc/init.d/", "/etc/rc.d/"];

        for init_path in &init_paths {
            if let Ok(entries) = std::fs::read_dir(init_path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() && entry.file_name().to_string_lossy().starts_with(char::is_alphabetic) {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let risk = self.assess_risk(&name, &path.to_string_lossy(), StartupType::InitScript);

                        items.push(StartupItem {
                            name,
                            path: path.to_string_lossy().to_string(),
                            item_type: StartupType::InitScript,
                            enabled: self.is_init_enabled(&path),
                            user: "root".to_string(),
                            source: init_path.to_string(),
                            risk_level: risk,
                        });
                    }
                }
            }
        }

        items
    }

    #[cfg(target_os = "linux")]
    fn is_init_enabled(&self, path: &std::path::Path) -> bool {
        // 检查 /etc/rc*.d/ 目录中是否有对应的符号链接
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // 简化的检查
        let rc_dirs = ["/etc/rc2.d", "/etc/rc3.d", "/etc/rc5.d"];
        for rc_dir in &rc_dirs {
            if let Ok(entries) = std::fs::read_dir(rc_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.file_name().to_string_lossy().contains(filename) {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    fn get_cron_jobs(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();
        let cron_paths = [
            ("/etc/crontab", "root"),
            ("/var/spool/cron/crontabs/", ""), // 需要遍历用户
        ];

        // 系统 cron
        if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
            for line in content.lines() {
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }
                // 解析 crontab 格式
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let name = parts[5..].join(" ");
                    let risk = self.assess_risk(&name, &line, StartupType::Cron);
                    
                    items.push(StartupItem {
                        name,
                        path: line.clone(),
                        item_type: StartupType::Cron,
                        enabled: true,
                        user: parts[4].to_string(),
                        source: "/etc/crontab".to_string(),
                        risk_level: risk,
                    });
                }
            }
        }

        // cron.d 目录
        if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        for line in content.lines() {
                            if line.trim().is_empty() || line.starts_with('#') {
                                continue;
                            }
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 6 {
                                let name = path.file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("cron.d")
                                    .to_string();
                                let risk = self.assess_risk(&name, &line, StartupType::Cron);

                                items.push(StartupItem {
                                    name,
                                    path: line.clone(),
                                    item_type: StartupType::Cron,
                                    enabled: true,
                                    user: parts[4].to_string(),
                                    source: path.to_string_lossy().to_string(),
                                    risk_level: risk,
                                });
                            }
                        }
                    }
                }
            }
        }

        items
    }

    #[cfg(target_os = "linux")]
    fn get_rc_local(&self) -> Option<StartupItem> {
        // 检查 /etc/rc.local
        if std::path::Path::new("/etc/rc.local").exists() {
            if let Ok(content) = std::fs::read_to_string("/etc/rc.local") {
                let lines: Vec<&str> = content.lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                    .collect();
                
                if !lines.is_empty() {
                    let risk = self.assess_risk("rc.local", &content, StartupType::RcLocal);
                    return Some(StartupItem {
                        name: "rc.local".to_string(),
                        path: "/etc/rc.local".to_string(),
                        item_type: StartupType::RcLocal,
                        enabled: true,
                        user: "root".to_string(),
                        source: "/etc/rc.local".to_string(),
                        risk_level: risk,
                    });
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn get_profile_scripts(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();
        let profile_paths = [
            "/etc/profile.d/",
            "/etc/profile",
            "/etc/bash.bashrc",
        ];

        for profile_path in &profile_paths {
            let path = std::path::Path::new(profile_path);
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let entry_path = entry.path();
                        if entry_path.is_file() && entry_path.extension().map(|e| e == "sh").unwrap_or(false) {
                            let name = entry_path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("profile")
                                .to_string();
                            let risk = self.assess_risk(&name, &entry_path.to_string_lossy(), StartupType::Profile);

                            items.push(StartupItem {
                                name,
                                path: entry_path.to_string_lossy().to_string(),
                                item_type: StartupType::Profile,
                                enabled: true,
                                user: "root".to_string(),
                                source: profile_path.to_string(),
                                risk_level: risk,
                            });
                        }
                    }
                }
            } else if path.is_file() {
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("profile")
                    .to_string();
                let risk = self.assess_risk(&name, &path.to_string_lossy(), StartupType::Profile);

                items.push(StartupItem {
                    name,
                    path: path.to_string_lossy().to_string(),
                    item_type: StartupType::Profile,
                    enabled: true,
                    user: "root".to_string(),
                    source: path.to_string_lossy().to_string(),
                    risk_level: risk,
                });
            }
        }

        items
    }

    /// 评估风险等级
    fn assess_risk(&self, name: &str, path: &str, _item_type: StartupType) -> RiskLevel {
        let name_lower = name.to_lowercase();
        let path_lower = path.to_lowercase();

        // 高风险检测
        let high_risk_keywords = ["miner", "cryptojack", "backdoor", "rootkit", "keylogger", 
                                  "password", "credential", "sensitive"];
        for keyword in &high_risk_keywords {
            if name_lower.contains(keyword) || path_lower.contains(keyword) {
                return RiskLevel::High;
            }
        }

        // 中风险检测
        let medium_risk_keywords = ["curl", "wget", "python", "bash", "sh ", "/bin/", 
                                    "download", "update", "sync"];
        for keyword in &medium_risk_keywords {
            if path_lower.contains(keyword) {
                return RiskLevel::Medium;
            }
        }

        // 检查可疑路径
        let suspicious_path_keywords = ["/tmp/", "/var/tmp/", "/dev/shm/", "/Downloads/", ".ssh/"];
        for keyword in suspicious_path_keywords {
            if path_lower.contains(keyword) {
                return RiskLevel::Medium;
            }
        }

        RiskLevel::Low
    }

    // =========================================================================
    // Windows 实现
    // =========================================================================
    #[cfg(target_os = "windows")]
    fn get_windows_startup_items(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();

        // 1. 注册表 Run/RunOnce
        items.extend(self.get_registry_run_items());

        // 2. 计划任务
        items.extend(self.get_scheduled_tasks());

        items
    }

    #[cfg(target_os = "windows")]
    fn get_registry_run_items(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();
        
        // Registry paths for startup
        // Note: reg query requires full HKEY names, not abbreviations
        let registry_paths = [
            (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
        ];

        for (reg_path, hive) in &registry_paths {
            let output = std::process::Command::new("reg")
                .args(["query", reg_path])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.trim().is_empty() || line.contains("REG_") || line.starts_with("HKEY") {
                        continue;
                    }
                    
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let name = parts[0].trim().to_string();
                        let path = parts[1].trim().to_string();
                        let risk = self.assess_risk(&name, &path, StartupType::Registry);

                        items.push(StartupItem {
                            name,
                            path,
                            item_type: StartupType::Registry,
                            enabled: true,
                            user: hive.to_string(),
                            source: reg_path.to_string(),
                            risk_level: risk,
                        });
                    }
                }
            }
        }

        items
    }

    #[cfg(target_os = "windows")]
    fn get_scheduled_tasks(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();

        let output = std::process::Command::new("schtasks")
            .args(["/query", "/fo", "CSV", "/v"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                // CSV parsing - with bounds checking to prevent panics
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() < 6 {
                    continue; // Skip malformed lines
                }
                let task_name = fields.get(1).map(|s| s.trim_matches('"')).unwrap_or("");
                let status = fields.get(3).map(|s| s.trim_matches('"')).unwrap_or("");
                let run_type = fields.get(5).map(|s| s.trim_matches('"')).unwrap_or("");
                    
                    if status != "Disabled" {
                        let risk = self.assess_risk(task_name, run_type, StartupType::ScheduledTask);
                        let user = fields.get(2).map(|s| s.trim_matches('"')).unwrap_or("");

                        items.push(StartupItem {
                            name: task_name.to_string(),
                            path: run_type.to_string(),
                            item_type: StartupType::ScheduledTask,
                            enabled: status == "Ready",
                            user: user.to_string(),
                            source: "schtasks".to_string(),
                            risk_level: risk,
                        });
                    }
                }
            }
        }

        items
    }
}

impl Default for StartupMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化启动项列表
pub fn format_startup_items(items: &[StartupItem], suspicious_only: bool) -> String {
    let filtered: Vec<&StartupItem> = if suspicious_only {
        items.iter()
            .filter(|i| i.risk_level != RiskLevel::Low)
            .collect()
    } else {
        items.iter().collect()
    };

    if filtered.is_empty() {
        return if suspicious_only {
            "✅ 未检测到可疑启动项".to_string()
        } else {
            "✅ 未检测到启动项".to_string()
        };
    }

    let mut output = String::new();
    output.push_str(&format!(
        "═══════════════════════════════════════════════════════════════\n\
         启动项监控 | 共 {} 个启动项{} | 目标平台: Linux/Windows Server\n\
         ════════════════════════════════════════════════════════════════\n\n",
        items.len(),
        if suspicious_only { " (仅显示可疑)" } else { "" }
    ));

    // 按类型分组显示
    let mut systemd: Vec<&StartupItem> = Vec::new();
    let mut cron: Vec<&StartupItem> = Vec::new();
    let mut init: Vec<&StartupItem> = Vec::new();
    let mut other: Vec<&StartupItem> = Vec::new();

    for item in &filtered {
        match item.item_type {
            StartupType::SystemdService => systemd.push(item),
            StartupType::Cron => cron.push(item),
            StartupType::InitScript | StartupType::RcLocal | StartupType::Profile => init.push(item),
            StartupType::Registry | StartupType::ScheduledTask => other.push(item),
            _ => other.push(item),
        }
    }

    if !systemd.is_empty() {
        output.push_str(&format!("📋 Systemd 服务 ({})\n", systemd.len()));
        output.push_str("───────────────────────────────────────────────────────\n");
        for item in systemd {
            output.push_str(&format_startup_item(item));
        }
        output.push('\n');
    }

    if !cron.is_empty() {
        output.push_str(&format!("⏰ Cron 计划任务 ({})\n", cron.len()));
        output.push_str("───────────────────────────────────────────────────────\n");
        for item in cron {
            output.push_str(&format_startup_item(item));
        }
        output.push('\n');
    }

    if !init.is_empty() {
        output.push_str(&format!("🔧 初始化脚本 ({})\n", init.len()));
        output.push_str("───────────────────────────────────────────────────────\n");
        for item in init {
            output.push_str(&format_startup_item(item));
        }
        output.push('\n');
    }

    if !other.is_empty() {
        output.push_str(&format!("📦 其他启动项 ({})\n", other.len()));
        output.push_str("───────────────────────────────────────────────────────\n");
        for item in other {
            output.push_str(&format_startup_item(item));
        }
        output.push('\n');
    }

    output
}

fn format_startup_item(item: &StartupItem) -> String {
    let risk_icon = match item.risk_level {
        RiskLevel::High => "🔴",
        RiskLevel::Medium => "🟡",
        RiskLevel::Low => "🟢",
    };

    format!(
        "{} {} | 用户: {}\n   路径: {}\n   命令: {}\n\n",
        risk_icon,
        item.name,
        item.user,
        item.source,
        truncate_string(&item.path, 60)
    )
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}..", &s[..max_len - 2])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_startup_items() {
        let monitor = StartupMonitor::new();
        let items = monitor.get_startup_items();
        assert!(items.len() >= 0);
    }

    #[test]
    fn test_detect_suspicious() {
        let monitor = StartupMonitor::new();
        let items = monitor.get_startup_items();
        let suspicious = monitor.detect_suspicious(&items);
        assert!(suspicious.len() >= 0);
    }
}
