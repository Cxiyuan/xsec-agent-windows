mod process;
mod service;
mod malicious;
mod hidden;
mod injection;
mod network;
mod startup;
mod lineage;
mod alert;
mod memfeature;
mod realtime;
mod command;
mod response;
mod protocol;
mod client;
mod securitylog;
mod fim;
mod webmalware;

use serde::{Deserialize, Serialize};
use std::time::Duration;
use sysinfo::{Disks, Networks, System};

pub use process::{format_process_list, get_process_list, ProcessInfo, ProcessList};
pub use service::{format_service_list, get_service_list, ServiceInfo, ServiceList};
pub use malicious::{format_analysis_results, BehaviorAnalyzer, MaliciousProcessResult, ThreatLevel};
pub use hidden::{format_hidden_results, HiddenProcessDetector, HiddenProcessReport, HiddenLevel};
pub use injection::{format_injection_results, InjectionDetector, InjectionResult, InjectionType, InjectionSeverity};
pub use network::{format_network_info, format_network_alerts, NetworkMonitor, ProcessNetworkInfo, NetworkAlert};
pub use startup::{format_startup_items, StartupMonitor, StartupItem, StartupType};
pub use lineage::{format_lineage_tree, format_lineage_path, LineageAnalyzer, ProcessNode};
pub use alert::{AlertManager, Alert, AlertLevel, AlertCategory, format_alert_stats};
pub use memfeature::{format_memory_features, MemoryFeatureDetector, ProcessMemoryFeatures};
pub use realtime::{RealtimeMonitor, MonitorConfig, MonitorStats, format_monitor_stats, format_monitor_config};
pub use command::{CommandExecutor, CommandRequest, CommandResult, CommandWhitelist, format_command_result};
pub use response::{ResponseEngine, ResponseRule, ResponseAction, ResponseResult, ResponseLevel, format_response_results, format_response_rules};
pub use protocol::{Message, MsgType, AgentInfo, HeartbeatData, ThreatReportPayload, CommandPayload, CommandResultPayload, ResponsePolicyPayload, create_register_message, create_heartbeat_message, create_threat_message, create_command_result_message, create_status_message};
pub use client::{Client, ManagerConfig, ConnectionState, ClientError};
pub use securitylog::{LogCollector, LogEntry, LogLevel, SecurityEvent, SecurityEventType, format_security_events, format_log_entries};
pub use fim::{FimMonitor, FimReport, MonitoredItem, FileSnapshot, FileChangeEvent, RiskLevel, format_fim_report, format_change_events};
pub use webmalware::{WebMalwareScanner, MaliciousFileResult, MaliciousFileType, MalwareThreatLevel, ScanConfig, format_scan_results, format_single_result};

// ============================================================================
// 系统监控数据类型
// ============================================================================

/// 实时系统监控数据
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemMetrics {
    pub timestamp: u64,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: Vec<DiskMetrics>,
    pub network: NetworkMetrics,
}

/// CPU 利用率
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CpuMetrics {
    pub usage_percent: f32,           // 总体 CPU 使用率 (0-100)
    pub per_core_usage: Vec<f32>,   // 每个核心的使用率 (0-100)
}

/// 内存利用率
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f32,
}

/// 磁盘利用率
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiskMetrics {
    pub name: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f32,
}

/// 网络利用率
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMetrics {
    pub interfaces: Vec<NetworkInterface>,
    pub total_rx_bytes_per_sec: u64,
    pub total_tx_bytes_per_sec: u64,
}

/// 单个网络接口
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

// ============================================================================
// 系统监控器
// ============================================================================

/// 系统监控器
pub struct SystemMonitor {
    sys: System,
    networks: Networks,
    prev_network_rx: u64,
    prev_network_tx: u64,
    prev_timestamp: u64,
}

impl SystemMonitor {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            prev_network_rx: 0,
            prev_network_tx: 0,
            prev_timestamp: now_timestamp(),
        }
    }

    /// 采集实时系统指标
    pub fn collect(&mut self) -> SystemMetrics {
        self.sys.refresh_all();
        self.networks.refresh(true);

        let timestamp = now_timestamp();

        // CPU
        let per_core_usage: Vec<f32> = self.sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();
        let usage_percent = if per_core_usage.is_empty() {
            0.0
        } else {
            per_core_usage.iter().sum::<f32>() / per_core_usage.len() as f32
        };

        // 内存
        let total_bytes = self.sys.total_memory();
        let used_bytes = self.sys.used_memory();
        let available_bytes = self.sys.available_memory();
        let memory_usage_percent = if total_bytes > 0 {
            (used_bytes as f32 / total_bytes as f32) * 100.0
        } else {
            0.0
        };

        // 磁盘
        let disks = Disks::new_with_refreshed_list();
        let disk_metrics: Vec<DiskMetrics> = disks
            .iter()
            .map(|disk| {
                let total = disk.total_space();
                let available = disk.available_space();
                let used = total.saturating_sub(available);
                let usage_percent = if total > 0 {
                    (used as f32 / total as f32) * 100.0
                } else {
                    0.0
                };
                DiskMetrics {
                    name: disk.name().to_string_lossy().to_string(),
                    mount_point: disk.mount_point().to_string_lossy().to_string(),
                    total_bytes: total,
                    used_bytes: used,
                    available_bytes: available,
                    usage_percent,
                }
            })
            .collect();

        // 网络（计算每秒速率）
        let mut total_rx: u64 = 0;
        let mut total_tx: u64 = 0;
        let mut interfaces_data: Vec<NetworkInterface> = Vec::new();

        for (interface_name, data) in self.networks.iter() {
            let rx = data.total_received();
            let tx = data.total_transmitted();
            total_rx += rx;
            total_tx += tx;

            let rx_per_sec = if timestamp > self.prev_timestamp {
                rx.saturating_sub(self.prev_network_rx) / (timestamp - self.prev_timestamp).max(1)
            } else {
                0
            };
            let tx_per_sec = if timestamp > self.prev_timestamp {
                tx.saturating_sub(self.prev_network_tx) / (timestamp - self.prev_timestamp).max(1)
            } else {
                0
            };

            interfaces_data.push(NetworkInterface {
                name: interface_name.to_string(),
                rx_bytes_per_sec: rx_per_sec,
                tx_bytes_per_sec: tx_per_sec,
            });
        }

        // 更新上一次的数据
        let prev_rx = self.prev_network_rx;
        let prev_tx = self.prev_network_tx;
        self.prev_network_rx = total_rx;
        self.prev_network_tx = total_tx;
        self.prev_timestamp = timestamp;

        let total_rx_per_sec = if timestamp > self.prev_timestamp {
            total_rx.saturating_sub(prev_rx) / (timestamp - self.prev_timestamp).max(1)
        } else {
            0
        };
        let total_tx_per_sec = if timestamp > self.prev_timestamp {
            total_tx.saturating_sub(prev_tx) / (timestamp - self.prev_timestamp).max(1)
        } else {
            0
        };

        SystemMetrics {
            timestamp,
            cpu: CpuMetrics {
                usage_percent,
                per_core_usage,
            },
            memory: MemoryMetrics {
                total_bytes,
                used_bytes,
                available_bytes,
                usage_percent: memory_usage_percent,
            },
            disk: disk_metrics,
            network: NetworkMetrics {
                interfaces: interfaces_data,
                total_rx_bytes_per_sec: total_rx_per_sec,
                total_tx_bytes_per_sec: total_tx_per_sec,
            },
        }
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 工具函数
// ============================================================================

/// 获取当前时间戳（秒）
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 格式化字节数为可读字符串
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// 格式化速率为可读字符串
pub fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

// ============================================================================
// 主程序
// ============================================================================


// ============================================================================
// Daemon 模式
// ============================================================================

fn run_daemon_mode() {
    println!("[xsec-agent] 启动 Daemon 模式...");
    
    // 读取配置
    let config_path = "/etc/xsec-agent/config.toml";
    let config_content = std::fs::read_to_string(config_path).unwrap_or_default();
    
    // 简单的配置解析
    let manager_host = extract_config_value(&config_content, "host").unwrap_or("127.0.0.1".to_string());
    let manager_port: u16 = extract_config_value(&config_content, "port")
        .unwrap_or("8443".to_string())
        .parse()
        .unwrap_or(8443);
    let secret_key = extract_config_value(&config_content, "secret_key").unwrap_or("qaz@7410".to_string());
    let agent_id = extract_config_value(&config_content, "id")
        .unwrap_or_else(|| hostname::get().map(|s| s.to_string_lossy().to_string()).unwrap_or_default());
    
    println!("[xsec-agent] Manager: {}:{}", manager_host, manager_port);
    
    let config = ManagerConfig {
        host: manager_host,
        port: manager_port,
        agent_id: agent_id.clone(),
        secret_key,
        heartbeat_interval_secs: 30,
        reconnect_delay_secs: 5,
        connection_timeout_secs: 10,
    };
    
    let client = Client::new(config);
    
    // 连接 Manager
    loop {
        println!("[xsec-agent] 尝试连接 Manager...");
        match client.connect() {
            Ok(_) => {
                println!("[xsec-agent] 已连接到 Manager");
                break;
            }
            Err(e) => {
                println!("[xsec-agent] 连接失败: {:?}, 5秒后重试...", e);
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }
    
    // 主循环 - 发送心跳
    loop {
        let mut monitor = SystemMonitor::new();
        monitor.collect();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let metrics = monitor.collect();
        
        let heartbeat_data = HeartbeatData {
            status: "online".to_string(),
            cpu_percent: metrics.cpu.usage_percent,
            memory_percent: metrics.memory.usage_percent,
            disk_percent: metrics.disk.first().map(|d| d.usage_percent).unwrap_or(0.0),
            network_in: metrics.network.total_rx_bytes_per_sec,
            network_out: metrics.network.total_tx_bytes_per_sec,
            active_threats: 0,
            pending_commands: 0,
        };
        
        let heartbeat = create_heartbeat_message(&agent_id, heartbeat_data);
        
        if let Err(e) = client.send_message(&heartbeat) {
            println!("[xsec-agent] 发送心跳失败: {:?}, 重新连接...", e);
            loop {
                match client.connect() {
                    Ok(_) => {
                        println!("[xsec-agent] 重新连接成功");
                        break;
                    }
                    Err(e) => {
                        println!("[xsec-agent] 重连失败: {:?}, 5秒后重试...", e);
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                }
            }
        }
        
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

fn extract_config_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with(&format!("{}=", key)) {
            let value = line.split('=').nth(1)?.trim();
            // 去掉引号
            let value = value.trim_matches('"').trim_matches('\'');
            return Some(value.to_string());
        }
    }
    None
}

// ============================================================================
// 主程序入口
// ============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // 检查 daemon 模式
    if args.contains(&"--daemon".to_string()) || args.contains(&"-d".to_string()) {
        run_daemon_mode();
        return;
    }
    
    println!("══════════════════════════════════════════");
    println!("  XSEC Agent - 系统监控工具");
    println!("  支持平台: Linux / Windows");
    println!("══════════════════════════════════════════");
    println!();
    println!("功能菜单:");
    println!("  1. 系统监控 (CPU/内存/磁盘/网络)");
    println!("  2. 进程列表 (Top 20 CPU)");
    println!("  3. 服务列表 (运行中的服务)");
    println!("  4. 恶意进程检测 (行为分析)");
    println!("  5. 隐藏进程检测");
    println!("  6. 进程注入检测");
    println!("  7. 进程网络监控");
    println!("  8. 启动项监控");
    println!("  9. 进程谱系追踪");
    println!("  a. 内存特征检测");
    println!("  b. 实时监控 (后台)");
    println!("  c. 告警统计");
    println!("  d. 全部显示");
    println!("  0. 退出");
    println!();
    println!("当前平台: {}", cfg!(target_os = "linux").then(|| "Linux").unwrap_or("Windows"));
    println!();
    println!("提示: 使用 --daemon 参数可后台运行连接 Manager");
    println!();

    loop {
        print!("请选择功能 (0-4): ");
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            break;
        }

        match input.trim() {
            "1" => show_system_metrics(),
            "2" => show_processes(),
            "3" => show_services(),
            "4" => show_malicious_processes(),
            "5" => show_hidden_processes(),
            "6" => show_injection(),
            "7" => show_network_monitoring(),
            "8" => show_startup_items(),
            "9" => show_process_lineage(),
            "a" => show_memory_features(),
            "b" => show_realtime_monitor(),
            "c" => show_alert_stats(),
            "d" => show_all(),
            "0" => {
                println!("退出...");
                break;
            }
            _ => {
                println!("无效选择，请输入 0-9 或 a/b/c/d");
            }
        }
        println!();
    }
}

fn show_system_metrics() {
    println!("\n========== 系统监控 ==========");
    
    let mut monitor = SystemMonitor::new();
    monitor.collect(); // 初始化
    std::thread::sleep(Duration::from_secs(1));
    
    let metrics = monitor.collect();

    println!("【CPU】总体: {:.2}%", metrics.cpu.usage_percent);
    for (i, usage) in metrics.cpu.per_core_usage.iter().enumerate() {
        println!("       核心{}: {:.2}%", i, usage);
    }

    println!(
        "【内存】已用: {} / {} ({:.2}%)",
        format_bytes(metrics.memory.used_bytes),
        format_bytes(metrics.memory.total_bytes),
        metrics.memory.usage_percent
    );

    println!("【磁盘】");
    for disk in &metrics.disk {
        println!(
            "       {} ({}): {} / {} ({:.2}%)",
            disk.name,
            disk.mount_point,
            format_bytes(disk.used_bytes),
            format_bytes(disk.total_bytes),
            disk.usage_percent
        );
    }

    println!("【网络】总接收: {}, 总发送: {}",
        format_rate(metrics.network.total_rx_bytes_per_sec),
        format_rate(metrics.network.total_tx_bytes_per_sec)
    );
    for iface in &metrics.network.interfaces {
        if iface.rx_bytes_per_sec > 0 || iface.tx_bytes_per_sec > 0 {
            println!(
                "       {}: ↓{} ↑{}",
                iface.name,
                format_rate(iface.rx_bytes_per_sec),
                format_rate(iface.tx_bytes_per_sec)
            );
        }
    }
}

fn show_processes() {
    println!("\n========== 进程列表 (Top 20 by CPU) ==========");
    let process_list = get_process_list();
    println!("{}", format_process_list(&process_list, Some(20)));
}

fn show_services() {
    println!("\n========== 服务列表 ==========");
    let service_list = get_service_list();
    println!("{}", format_service_list(&service_list, false));
}

fn show_malicious_processes() {
    println!("\n========== 恶意进程检测 (行为分析) ==========");
    let analyzer = BehaviorAnalyzer::new();
    let mut sys = System::new_all();
    sys.refresh_all();
    let results = analyzer.analyze(&sys);
    println!("{}", format_analysis_results(&results));
}

fn show_hidden_processes() {
    println!("\n========== 隐藏进程检测 ==========");
    let detector = HiddenProcessDetector::new();
    let mut sys = System::new_all();
    sys.refresh_all();
    let report = detector.detect(&sys);
    println!("{}", format_hidden_results(&report));
}

fn show_injection() {
    println!("\n========== 进程注入检测 ==========");
    let detector = InjectionDetector::new();
    let mut sys = System::new_all();
    sys.refresh_all();
    let results = detector.detect(&sys);
    println!("{}", format_injection_results(&results));
}

fn show_network_monitoring() {
    println!("\n========== 进程网络监控 ==========");
    let monitor = NetworkMonitor::new();
    let sys = sysinfo::System::new_all();
    
    // 显示网络信息
    let network_info = monitor.get_process_network_info(&sys);
    println!("{}", format_network_info(&network_info, Some(20)));
    
    // 显示网络异常
    let alerts = monitor.detect_anomalies(&sys);
    println!("{}", format_network_alerts(&alerts));
}

fn show_startup_items() {
    println!("\n========== 启动项监控 ==========");
    let monitor = StartupMonitor::new();
    let items = monitor.get_startup_items();
    let suspicious = monitor.detect_suspicious(&items);
    
    println!("{}", format_startup_items(&items, false));
    println!("\n--- 可疑启动项 ---\n");
    println!("{}", format_startup_items(&suspicious, true));
}

fn show_process_lineage() {
    println!("\n========== 进程谱系追踪 ==========");
    let analyzer = LineageAnalyzer::new();
    let sys = sysinfo::System::new_all();
    
    let nodes = analyzer.build_lineage_tree(&sys);
    let suspicious = analyzer.get_suspicious_lineages(&nodes);
    
    println!("{}", format_lineage_tree(&nodes, 5, false));
    println!("\n--- 可疑谱系 ---\n");
    println!("{}", format_lineage_tree(&nodes, 10, true));
}

fn show_alert_stats() {
    println!("\n========== 告警统计 ==========");
    let manager = AlertManager::new();
    let stats = manager.get_stats();
    println!("{}", format_alert_stats(&stats));
}

fn show_memory_features() {
    println!("\n========== 进程内存特征检测 ==========");
    let detector = MemoryFeatureDetector::new();
    let sys = sysinfo::System::new_all();
    let results = detector.detect(&sys);
    println!("{}", format_memory_features(&results, Some(20)));
}

fn show_realtime_monitor() {
    println!("\n========== 实时监控 ==========");
    
    let config = MonitorConfig {
        interval_secs: 60,
        enable_malicious: true,
        enable_hidden: true,
        enable_injection: true,
        enable_network: true,
        enable_startup: true,
        enable_lineage: true,
        enable_memfeature: true,
        cpu_alert_threshold: 90.0,
        memory_alert_threshold: 90.0,
    };
    
    let alert_manager = AlertManager::new();
    let monitor = RealtimeMonitor::new(config, alert_manager);
    
    println!("{}", format_monitor_config(&monitor.get_config()));
    
    // 执行一次扫描
    println!("执行一次完整扫描...\n");
    monitor.scan_once();
    
    let stats = monitor.get_stats();
    println!("{}", format_monitor_stats(&stats));
}

fn show_all() {
    println!("\n{}", "═".repeat(60));
    println!("  XSEC Agent - 全部安全检测");
    println!("{}", "═".repeat(60));
    
    show_system_metrics();
    println!();
    
    show_processes();
    println!();
    
    show_services();
    println!();
    
    show_malicious_processes();
    println!();
    
    show_hidden_processes();
    println!();
    
    show_injection();
    println!();
    
    show_network_monitoring();
    println!();
    
    show_startup_items();
    println!();
    
    show_process_lineage();
    println!();
    
    show_alert_stats();
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_system_monitor() {
        let mut monitor = SystemMonitor::new();
        let metrics = monitor.collect();
        assert!(metrics.cpu.usage_percent >= 0.0 && metrics.cpu.usage_percent <= 100.0);
        assert!(metrics.memory.total_bytes > 0);
        assert!(metrics.memory.usage_percent >= 0.0 && metrics.memory.usage_percent <= 100.0);
    }

    #[test]
    fn test_process_list() {
        let list = get_process_list();
        assert!(list.total_count > 0);
        assert!(!list.processes.is_empty());
    }

    #[test]
    fn test_service_list() {
        let list = get_service_list();
        assert!(!list.platform.is_empty());
        assert!(list.total_count > 0);
    }
}
