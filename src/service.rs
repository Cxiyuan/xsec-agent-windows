//! 服务管理模块
//! Linux: systemd 服务
//! Windows: Windows Services

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "windows")]
use std::process::Command;

/// 服务信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub status: String,
    pub active_state: String,
    pub sub_state: String,
    pub pid: Option<u32>,
}

/// 服务列表
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceList {
    pub timestamp: u64,
    pub platform: String,
    pub total_count: usize,
    pub running_count: usize,
    pub stopped_count: usize,
    pub services: Vec<ServiceInfo>,
}

/// 获取服务列表（跨平台）
pub fn get_service_list() -> ServiceList {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    #[cfg(target_os = "linux")]
    {
        get_linux_services(timestamp)
    }

    #[cfg(target_os = "windows")]
    {
        get_windows_services(timestamp)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        ServiceList {
            timestamp,
            platform: "unknown".to_string(),
            total_count: 0,
            running_count: 0,
            stopped_count: 0,
            services: vec![],
        }
    }
}

// ============================================================================
// Linux: systemd 服务
// ============================================================================
#[cfg(target_os = "linux")]
fn get_linux_services(timestamp: u64) -> ServiceList {
    let mut services = Vec::new();
    let mut running_count = 0;
    let mut stopped_count = 0;

    // 获取所有服务单元
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
            "--output=json",
        ])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // 逐行解析 JSON 输出
        for line in stdout.lines() {
            if line.trim().is_empty() || !line.starts_with('{') {
                continue;
            }

            // 解析 JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let name = json.get("unit").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let active_state = json.get("activeState").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let sub_state = json.get("subState").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let description = json.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let load_state = json.get("loadState").and_then(|v| v.as_str()).unwrap_or("");
                
                // 跳过 not-found 服务
                if load_state == "not-found" {
                    continue;
                }

                let status = if active_state == "active" && sub_state == "running" {
                    running_count += 1;
                    "running"
                } else {
                    stopped_count += 1;
                    "stopped"
                };

                // 获取 PID（如果运行中）
                let pid = if status == "running" {
                    get_service_pid_linux(&name)
                } else {
                    None
                };

                services.push(ServiceInfo {
                    name,
                    description: description.to_string(),
                    status: status.to_string(),
                    active_state,
                    sub_state,
                    pid,
                });
            }
        }
    }

    // 如果 systemctl 失败，尝试其他方式
    if services.is_empty() {
        services = get_linux_services_fallback(timestamp);
    }

    let total_count = services.len();

    ServiceList {
        timestamp,
        platform: "linux".to_string(),
        total_count,
        running_count,
        stopped_count,
        services,
    }
}

#[cfg(target_os = "linux")]
fn get_service_pid_linux(name: &str) -> Option<u32> {
    let output = Command::new("systemctl")
        .args(["show", name, "--property=MainPID", "--value"])
        .output()
        .ok()?;
    
    let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    pid_str.parse::<u32>().ok().filter(|&p| p > 0)
}

#[cfg(target_os = "linux")]
fn get_linux_services_fallback(timestamp: u64) -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    
    // 尝试从 /etc/init.d/ 读取
    if let Ok(entries) = std::fs::read_dir("/etc/init.d/") {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() && entry.file_name().to_string_lossy().starts_with(char::is_alphabetic) {
                let name = entry.file_name().to_string_lossy().to_string();
                services.push(ServiceInfo {
                    name,
                    description: String::new(),
                    status: "unknown".to_string(),
                    active_state: "unknown".to_string(),
                    sub_state: "unknown".to_string(),
                    pid: None,
                });
            }
        }
    }
    
    services
}

// ============================================================================
// Windows: Windows Services
// ============================================================================
#[cfg(target_os = "windows")]
fn get_windows_services(timestamp: u64) -> ServiceList {
    let mut services = Vec::new();
    let mut running_count = 0;
    let mut stopped_count = 0;

    // 使用 sc query 获取所有服务
    let output = Command::new("sc")
        .args(["query", "state=", "all"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();

        let mut current_service: Option<ServiceInfo> = None;

        for line in lines {
            let line = line.trim();
            
            if line.starts_with("SERVICE_NAME:") {
                // 保存上一个服务
                if let Some(svc) = current_service.take() {
                    if svc.status == "running" {
                        running_count += 1;
                    } else {
                        stopped_count += 1;
                    }
                    services.push(svc);
                }

                let name = line.trim_start_matches("SERVICE_NAME:").trim();
                current_service = Some(ServiceInfo {
                    name: name.to_string(),
                    description: String::new(),
                    status: "unknown".to_string(),
                    active_state: String::new(),
                    sub_state: String::new(),
                    pid: None,
                });
            } else if let Some(ref mut svc) = current_service {
                if line.starts_with("STATE") && line.contains("RUNNING") {
                    svc.status = "running".to_string();
                    svc.active_state = "active".to_string();
                    svc.sub_state = "running".to_string();
                } else if line.starts_with("STATE") {
                    svc.status = "stopped".to_string();
                    svc.active_state = "inactive".to_string();
                    svc.sub_state = "stopped".to_string();
                } else if line.starts_with("DISPLAY_NAME:") {
                    svc.description = line.trim_start_matches("DISPLAY_NAME:").trim().to_string();
                } else if line.starts_with("        PID") {
                    if let Some(pid_str) = line.split(':').nth(1) {
                        if let Ok(pid) = pid_str.trim().parse::<u32>() {
                            svc.pid = Some(pid);
                        }
                    }
                }
            }
        }

        // 保存最后一个服务
        if let Some(svc) = current_service {
            if svc.status == "running" {
                running_count += 1;
            } else {
                stopped_count += 1;
            }
            services.push(svc);
        }
    }

    let total_count = services.len();

    ServiceList {
        timestamp,
        platform: "windows".to_string(),
        total_count,
        running_count,
        stopped_count,
        services,
    }
}

/// 格式化服务列表
pub fn format_service_list(service_list: &ServiceList, show_all: bool) -> String {
    let mut output = format!(
        "═══════════════════════════════════════════\n\
         时间戳: {} | 平台: {}\n\
         总服务数: {} | 运行中: {} | 已停止: {}\n\
         ═══════════════════════════════════════════\n",
        service_list.timestamp,
        service_list.platform,
        service_list.total_count,
        service_list.running_count,
        service_list.stopped_count
    );

    output.push_str(&format!(
        "{:<40} {:<12} {:<15} {}\n",
        "名称", "状态", "活跃状态", "PID"
    ));
    output.push_str("───────────────────────────────────────────────────\n");

    let services: Vec<&ServiceInfo> = if show_all {
        service_list.services.iter().collect()
    } else {
        // 默认只显示运行中的服务
        service_list.services.iter().filter(|s| s.status == "running").collect()
    };

    for svc in services {
        let pid_str = svc.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
        output.push_str(&format!(
            "{:<40} {:.<12} {:.<15} {}\n",
            truncate(&svc.name, 38),
            svc.status,
            svc.sub_state,
            pid_str
        ));
    }

    output
}

/// 截断字符串
fn truncate(s: &str, max_len: usize) -> String {
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
    fn test_get_service_list() {
        let list = get_service_list();
        assert!(!list.platform.is_empty());
        assert!(list.total_count > 0);
    }

    #[test]
    fn test_format_service_list() {
        let list = get_service_list();
        let output = format_service_list(&list, false);
        assert!(!output.is_empty());
    }
}
