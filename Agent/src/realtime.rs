//! 实时监控模块
//! 后台持续监控，发现威胁立即告警

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;

use crate::alert::{AlertLevel, AlertManager};
use crate::hidden::HiddenProcessDetector;
use crate::injection::InjectionDetector;
use crate::lineage::LineageAnalyzer;
use crate::malicious::BehaviorAnalyzer;
use crate::network::NetworkMonitor;
use crate::startup::StartupMonitor;
use crate::memfeature::MemoryFeatureDetector;

/// 监控配置
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// 监控间隔（秒）
    pub interval_secs: u64,
    /// 是否启用恶意进程检测
    pub enable_malicious: bool,
    /// 是否启用隐藏进程检测
    pub enable_hidden: bool,
    /// 是否启用注入检测
    pub enable_injection: bool,
    /// 是否启用网络监控
    pub enable_network: bool,
    /// 是否启用启动项监控
    pub enable_startup: bool,
    /// 是否启用进程谱系监控
    pub enable_lineage: bool,
    /// 是否启用内存特征检测
    pub enable_memfeature: bool,
    /// CPU 使用率告警阈值 (%)
    pub cpu_alert_threshold: f32,
    /// 内存使用率告警阈值 (%)
    pub memory_alert_threshold: f32,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
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
        }
    }
}

/// 监控统计
#[derive(Debug, Default, Clone)]
pub struct MonitorStats {
    pub total_scans: u64,
    pub threats_detected: u64,
    pub alerts_sent: u64,
    pub last_scan_time: u64,
}

impl MonitorStats {
    pub fn new() -> Self {
        Self::default()
    }
}

/// 实时监控器
pub struct RealtimeMonitor {
    config: MonitorConfig,
    alert_manager: AlertManager,
    running: Arc<AtomicBool>,
    stats: Arc<std::sync::Mutex<MonitorStats>>,
}

impl RealtimeMonitor {
    pub fn new(config: MonitorConfig, alert_manager: AlertManager) -> Self {
        Self {
            config,
            alert_manager,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(std::sync::Mutex::new(MonitorStats::new())),
        }
    }

    /// 启动监控
    pub fn start(&self) {
        if self.running.load(Ordering::SeqCst) {
            println!("监控已在运行中");
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        println!("🚀 实时监控已启动 (间隔: {}秒)", self.config.interval_secs);
        println!("   - 恶意进程检测: {}", if self.config.enable_malicious { "✓" } else { "✗" });
        println!("   - 隐藏进程检测: {}", if self.config.enable_hidden { "✓" } else { "✗" });
        println!("   - 进程注入检测: {}", if self.config.enable_injection { "✓" } else { "✗" });
        println!("   - 网络监控: {}", if self.config.enable_network { "✓" } else { "✗" });
        println!("   - 启动项监控: {}", if self.config.enable_startup { "✓" } else { "✗" });
        println!("   - 进程谱系: {}", if self.config.enable_lineage { "✓" } else { "✗" });
        println!("   - 内存特征: {}", if self.config.enable_memfeature { "✓" } else { "✗" });
        println!();
    }

    /// 停止监控
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        println!("🛑 实时监控已停止");
        
        let mut stats = self.stats.lock().unwrap();
        println!("📊 监控统计:");
        println!("   总扫描次数: {}", stats.total_scans);
        println!("   威胁检测: {}", stats.threats_detected);
        println!("   告警发送: {}", stats.alerts_sent);
    }

    /// 是否在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 执行一次完整扫描
    pub fn scan_once(&self) {
        let mut sys = System::new_all();
        sys.refresh_all();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut threats_found: u64 = 0;

        // 1. 恶意进程检测
        if self.config.enable_malicious {
            let analyzer = BehaviorAnalyzer::new();
            let results = analyzer.analyze(&sys);
            let high_threats = results.iter()
                .filter(|r| r.overall_score > 0.6)
                .count();
            
            if high_threats > 0 {
                threats_found += high_threats as u64;
                self.alert_manager.alert_security(
                    AlertLevel::High,
                    "检测到恶意进程",
                    &format!("发现 {} 个高威胁进程，威胁分数 > 0.6", high_threats),
                );
            }
        }

        // 2. 隐藏进程检测
        if self.config.enable_hidden {
            let detector = HiddenProcessDetector::new();
            let report = detector.detect(&sys);
            
            if report.total_hidden > 0 {
                threats_found += report.total_hidden as u64;
                self.alert_manager.alert_security(
                    AlertLevel::High,
                    "检测到隐藏进程",
                    &format!("发现 {} 个隐藏进程，可能存在Rootkit", report.total_hidden),
                );
            }
        }

        // 3. 进程注入检测
        if self.config.enable_injection {
            let detector = InjectionDetector::new();
            let results = detector.detect(&sys);
            
            if !results.is_empty() {
                threats_found += results.len() as u64;
                self.alert_manager.alert_security(
                    AlertLevel::Critical,
                    "检测到进程注入",
                    &format!("发现 {} 个进程可能存在注入行为", results.len()),
                );
            }
        }

        // 4. 网络异常检测
        if self.config.enable_network {
            let monitor = NetworkMonitor::new();
            let alerts = monitor.detect_anomalies(&sys);
            
            let high_alerts = alerts.iter()
                .filter(|a| matches!(a.severity, crate::network::AlertSeverity::High | crate::network::AlertSeverity::Critical))
                .count();
            
            if high_alerts > 0 {
                threats_found += high_alerts as u64;
                self.alert_manager.alert_network(
                    AlertLevel::High,
                    "检测到网络异常",
                    &format!("发现 {} 个高危网络异常", high_alerts),
                );
            }
        }

        // 5. 启动项检测
        if self.config.enable_startup {
            let monitor = StartupMonitor::new();
            let items = monitor.get_startup_items();
            let suspicious = monitor.detect_suspicious(&items);
            
            let high_risk = suspicious.iter()
                .filter(|i| matches!(i.risk_level, crate::startup::RiskLevel::High))
                .count();
            
            if high_risk > 0 {
                threats_found += high_risk as u64;
                self.alert_manager.alert_security(
                    AlertLevel::Medium,
                    "检测到可疑启动项",
                    &format!("发现 {} 个高风险启动项", high_risk),
                );
            }
        }

        // 6. 进程谱系异常
        if self.config.enable_lineage {
            let analyzer = LineageAnalyzer::new();
            let nodes = analyzer.build_lineage_tree(&sys);
            let suspicious = analyzer.get_suspicious_lineages(&nodes);
            
            let high_anomalies = suspicious.iter()
                .filter(|n| n.anomalies.iter().any(|a| matches!(a.severity, crate::lineage::AnomalySeverity::High | crate::lineage::AnomalySeverity::Critical)))
                .count();
            
            if high_anomalies > 0 {
                threats_found += high_anomalies as u64;
                self.alert_manager.alert_security(
                    AlertLevel::Medium,
                    "检测到进程谱系异常",
                    &format!("发现 {} 个可疑父子进程关系", high_anomalies),
                );
            }
        }

        // 7. 内存特征检测
        if self.config.enable_memfeature {
            let detector = MemoryFeatureDetector::new();
            let results = detector.detect(&sys);
            
            let high_risk = results.iter()
                .filter(|r| r.risk_score > 0.6)
                .count();
            
            if high_risk > 0 {
                threats_found += high_risk as u64;
                self.alert_manager.alert_security(
                    AlertLevel::High,
                    "检测到可疑内存特征",
                    &format!("发现 {} 个进程有高风险内存特征", high_risk),
                );
            }
        }

        // 8. 系统资源告警
        let total_cpu = sys.cpus().iter()
            .map(|c| c.cpu_usage())
            .sum::<f32>() / sys.cpus().len() as f32;
        
        let total_memory = sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0;

        if total_cpu > self.config.cpu_alert_threshold {
            threats_found += 1;
            self.alert_manager.alert_system(
                AlertLevel::Low,
                "CPU使用率过高",
                &format!("CPU使用率: {:.1}% (阈值: {}%)", total_cpu, self.config.cpu_alert_threshold),
            );
        }

        if total_memory > self.config.memory_alert_threshold as f64 {
            threats_found += 1;
            self.alert_manager.alert_system(
                AlertLevel::Low,
                "内存使用率过高",
                &format!("内存使用率: {:.1}% (阈值: {}%)", total_memory, self.config.memory_alert_threshold),
            );
        }

        // 更新统计
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_scans += 1;
            stats.threats_detected += threats_found;
            stats.last_scan_time = now;
        }
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> MonitorStats {
        self.stats.lock().unwrap().clone()
    }

    /// 获取配置
    pub fn get_config(&self) -> MonitorConfig {
        self.config.clone()
    }
}

/// 格式化监控统计
pub fn format_monitor_stats(stats: &MonitorStats) -> String {
    format!(
        "═══════════════════════════════════════════\n\
         实时监控统计\n\
         ════════════════════════════════════════════\n\
         总扫描次数: {}\n\
         威胁检测: {}\n\
         告警发送: {}\n\
         最后扫描: {}\n\
         ════════════════════════════════════════════\n",
        stats.total_scans,
        stats.threats_detected,
        stats.alerts_sent,
        stats.last_scan_time
    )
}

/// 格式化监控配置
pub fn format_monitor_config(config: &MonitorConfig) -> String {
    format!(
        "═══════════════════════════════════════════\n\
         实时监控配置\n\
         ════════════════════════════════════════════\n\
         监控间隔: {} 秒\n\
         恶意进程检测: {}\n\
         隐藏进程检测: {}\n\
         进程注入检测: {}\n\
         网络监控: {}\n\
         启动项监控: {}\n\
         进程谱系: {}\n\
         内存特征检测: {}\n\
         CPU告警阈值: {}%\n\
         内存告警阈值: {}%\n\
         ════════════════════════════════════════════\n",
        config.interval_secs,
        config.enable_malicious,
        config.enable_hidden,
        config.enable_injection,
        config.enable_network,
        config.enable_startup,
        config.enable_lineage,
        config.enable_memfeature,
        config.cpu_alert_threshold,
        config.memory_alert_threshold
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_config() {
        let config = MonitorConfig::default();
        assert_eq!(config.interval_secs, 60);
    }

    #[test]
    fn test_monitor_stats() {
        let stats = MonitorStats::new();
        assert_eq!(stats.total_scans, 0);
    }
}
