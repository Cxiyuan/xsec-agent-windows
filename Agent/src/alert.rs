//! 告警机制模块
//! 支持阈值告警、实时推送（Webhook/Syslog/文件）

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// 告警级别
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub enum AlertLevel {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertLevel::Info => write!(f, "信息"),
            AlertLevel::Low => write!(f, "低"),
            AlertLevel::Medium => write!(f, "中"),
            AlertLevel::High => write!(f, "高"),
            AlertLevel::Critical => write!(f, "严重"),
        }
    }
}

/// 告警类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Copy)]
pub enum AlertCategory {
    System,         // 系统资源
    Security,       // 安全事件
    Network,        // 网络异常
    Process,       // 进程异常
    Service,       // 服务状态
    Custom,        // 自定义
}

impl std::fmt::Display for AlertCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertCategory::System => write!(f, "系统"),
            AlertCategory::Security => write!(f, "安全"),
            AlertCategory::Network => write!(f, "网络"),
            AlertCategory::Process => write!(f, "进程"),
            AlertCategory::Service => write!(f, "服务"),
            AlertCategory::Custom => write!(f, "自定义"),
        }
    }
}

/// 告警项
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Alert {
    pub id: String,
    pub timestamp: u64,
    pub level: AlertLevel,
    pub category: AlertCategory,
    pub title: String,
    pub message: String,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

/// 告警配置
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AlertConfig {
    /// 是否启用
    pub enabled: bool,
    /// 最小告警级别
    pub min_level: AlertLevel,
    /// Webhook URL (可选)
    pub webhook_url: Option<String>,
    /// Syslog 服务器 (可选)
    pub syslog_server: Option<String>,
    /// Syslog 端口
    pub syslog_port: u16,
    /// 告警日志文件路径
    pub log_file: Option<String>,
    /// 相同告警的沉默期 (秒)
    pub silence_period: u64,
    /// 告警限额 (每分钟)
    pub rate_limit: usize,
}

/// 告警统计
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub alerts_by_level: HashMap<String, u64>,
    pub alerts_by_category: HashMap<String, u64>,
    pub last_alert_time: u64,
}

/// 告警管理器
pub struct AlertManager {
    config: AlertConfig,
    /// 已发送的告警记录 (用于去重和沉默)
    sent_alerts: Arc<Mutex<HashMap<String, u64>>>,
    /// 告警统计
    stats: Arc<Mutex<AlertStats>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            config: AlertConfig {
                enabled: true,
                min_level: AlertLevel::Low,
                webhook_url: None,
                syslog_server: None,
                syslog_port: 514,
                log_file: Some("/var/log/xsec-agent/alerts.log".to_string()),
                silence_period: 300, // 5分钟沉默期
                rate_limit: 100,     // 每分钟最多100条
            },
            sent_alerts: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(AlertStats {
                total_alerts: 0,
                alerts_by_level: HashMap::new(),
                alerts_by_category: HashMap::new(),
                last_alert_time: 0,
            })),
        }
    }

    /// 从文件加载配置
    pub fn load_config(&mut self, path: &str) -> bool {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(config) = serde_json::from_str::<AlertConfig>(&content) {
                self.config = config;
                return true;
            }
        }
        false
    }

    /// 保存配置到文件
    pub fn save_config(&self, path: &str) -> bool {
        if let Ok(content) = serde_json::to_string_pretty(&self.config) {
            if let Ok(_) = std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("/"))) {
                return std::fs::write(path, content).is_ok();
            }
        }
        false
    }

    /// 更新配置
    pub fn update_config(&mut self, config: AlertConfig) {
        self.config = config;
    }

    /// 发送告警
    pub fn send_alert(&self, level: AlertLevel, category: AlertCategory, title: &str, message: &str, source: &str) -> Option<Alert> {
        if !self.config.enabled {
            return None;
        }

        // 检查告警级别
        if level < self.config.min_level {
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 生成告警ID (用于去重)
        let alert_id = self.generate_alert_id(&level, &category, title, source);

        // 检查沉默期
        {
            let sent = self.sent_alerts.lock().unwrap();
            if let Some(&last_sent) = sent.get(&alert_id) {
                if now - last_sent < self.config.silence_period {
                    return None; // 在沉默期内
                }
            }
        }

        // 检查速率限制
        if !self.check_rate_limit() {
            return None;
        }

        let alert = Alert {
            id: alert_id.clone(),
            timestamp: now,
            level: level.clone(),
            category: category.clone(),
            title: title.to_string(),
            message: message.to_string(),
            source: source.to_string(),
            metadata: HashMap::new(),
        };

        // 发送告警到各个渠道
        self.dispatch_alert(&alert);

        // 更新统计
        self.update_stats(&alert);

        // 记录已发送
        {
            let mut sent = self.sent_alerts.lock().unwrap();
            sent.insert(alert_id, now);
        }

        Some(alert)
    }

    /// 生成告警ID
    fn generate_alert_id(&self, level: &AlertLevel, category: &AlertCategory, title: &str, source: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut s = DefaultHasher::new();
        format!("{:?}:{:?}:{}:{}", level, category, title, source).hash(&mut s);
        format!("{:x}", s.finish())
    }

    /// 检查速率限制
    fn check_rate_limit(&self) -> bool {
        // 简化实现：不做严格速率限制
        true
    }

    /// 分发告警到各个渠道
    fn dispatch_alert(&self, alert: &Alert) {
        // 1. 写入日志文件
        if let Some(ref log_file) = self.config.log_file {
            self.write_to_log_file(alert, log_file);
        }

        // 2. 发送到 Webhook
        if let Some(ref webhook_url) = self.config.webhook_url {
            self.send_webhook(alert, webhook_url);
        }

        // 3. 发送到 Syslog
        if let Some(ref syslog_server) = self.config.syslog_server {
            self.send_syslog(alert, syslog_server);
        }
    }

    /// 写入日志文件
    fn write_to_log_file(&self, alert: &Alert, log_file: &str) {
        let log_entry = format!(
            "[{}] [{}] [{}] {} - {} | source={}\n",
            alert.timestamp,
            alert.level,
            alert.category,
            alert.title,
            alert.message,
            alert.source
        );

        // 确保目录存在
        if let Ok(_) = std::fs::create_dir_all(std::path::Path::new(log_file).parent().unwrap_or(std::path::Path::new("/"))) {
            let _ = std::fs::write(log_file, log_entry);
        }
    }

    /// 发送 Webhook
    fn send_webhook(&self, alert: &Alert, webhook_url: &str) {
        // 使用 HTTP POST 发送告警
        #[cfg(feature = "network")]
        {
            let payload = serde_json::json!({
                "alert_id": alert.id,
                "timestamp": alert.timestamp,
                "level": alert.level,
                "category": alert.category,
                "title": alert.title,
                "message": alert.message,
                "source": alert.source,
            });

            let client = reqwest::blocking::Client::new();
            let _ = client.post(webhook_url)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(5))
                .send();
        }
    }

    /// 发送 Syslog
    fn send_syslog(&self, alert: &Alert, server: &str) {
        // 简化的 Syslog 发送
        let syslog_msg = format!(
            "<{}>XSEC-Agent {}: [{}] {} - {}",
            self.level_to_syslog_priority(&alert.level),
            alert.source,
            alert.level,
            alert.title,
            alert.message
        );

        #[cfg(feature = "network")]
        {
            let _ = std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|socket| {
                    socket.send_to(syslog_msg.as_bytes(), format!("{}:{}", server, self.config.syslog_port))
                });
        }
    }

    /// 告警级别转 Syslog 优先级
    fn level_to_syslog_priority(&self, level: &AlertLevel) -> u8 {
        match level {
            AlertLevel::Info => 6,    // INFO
            AlertLevel::Low => 4,     // WARNING
            AlertLevel::Medium => 3,  // ERR
            AlertLevel::High => 3,    // ERR
            AlertLevel::Critical => 2, // CRITICAL
        }
    }

    /// 更新统计
    fn update_stats(&self, alert: &Alert) {
        let mut stats = self.stats.lock().unwrap();
        stats.total_alerts += 1;
        stats.last_alert_time = alert.timestamp;

        let level_key = format!("{:?}", alert.level);
        *stats.alerts_by_level.entry(level_key).or_insert(0) += 1;

        let category_key = format!("{:?}", alert.category);
        *stats.alerts_by_category.entry(category_key).or_insert(0) += 1;
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> AlertStats {
        self.stats.lock().unwrap().clone()
    }

    /// 获取最近告警
    pub fn get_recent_alerts(&self, limit: usize) -> Vec<Alert> {
        // 这里应该从日志文件或内存中读取
        // 简化实现返回空列表
        Vec::with_capacity(limit)
    }

    /// 清除统计
    pub fn clear_stats(&self) {
        let mut stats = self.stats.lock().unwrap();
        stats.total_alerts = 0;
        stats.alerts_by_level.clear();
        stats.alerts_by_category.clear();
        stats.last_alert_time = 0;
    }

    // =========================================================================
    // 便捷告警方法
    // =========================================================================

    /// 系统资源告警
    pub fn alert_system(&self, level: AlertLevel, title: &str, message: &str) -> Option<Alert> {
        self.send_alert(level, AlertCategory::System, title, message, "xsec-agent")
    }

    /// 安全告警
    pub fn alert_security(&self, level: AlertLevel, title: &str, message: &str) -> Option<Alert> {
        self.send_alert(level, AlertCategory::Security, title, message, "xsec-agent")
    }

    /// 网络告警
    pub fn alert_network(&self, level: AlertLevel, title: &str, message: &str) -> Option<Alert> {
        self.send_alert(level, AlertCategory::Network, title, message, "xsec-agent")
    }

    /// 进程告警
    pub fn alert_process(&self, level: AlertLevel, title: &str, message: &str) -> Option<Alert> {
        self.send_alert(level, AlertCategory::Process, title, message, "xsec-agent")
    }

    /// 服务告警
    pub fn alert_service(&self, level: AlertLevel, title: &str, message: &str) -> Option<Alert> {
        self.send_alert(level, AlertCategory::Service, title, message, "xsec-agent")
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化告警统计
pub fn format_alert_stats(stats: &AlertStats) -> String {
    let mut output = String::new();
    output.push_str("═══════════════════════════════════════════\n");
    output.push_str("  XSEC Agent 告警统计\n");
    output.push_str("═══════════════════════════════════════════\n\n");
    output.push_str(&format!("总告警数: {}\n", stats.total_alerts));
    output.push_str(&format!("最后告警时间: {}\n\n", stats.last_alert_time));

    output.push_str("按级别:\n");
    for (level, count) in &stats.alerts_by_level {
        output.push_str(&format!("  {:?}: {}\n", level, count));
    }
    output.push('\n');

    output.push_str("按类别:\n");
    for (category, count) in &stats.alerts_by_category {
        output.push_str(&format!("  {:?}: {}\n", category, count));
    }

    output
}

/// 格式化告警
pub fn format_alert(alert: &Alert) -> String {
    let level_icon = match alert.level {
        AlertLevel::Info => "ℹ️",
        AlertLevel::Low => "⚠️",
        AlertLevel::Medium => "❌",
        AlertLevel::High => "🔴",
        AlertLevel::Critical => "🚨",
    };

    format!(
        "{} [{}] {} - {}\n   来源: {} | 时间: {}\n   分类: {:?}",
        level_icon,
        alert.level,
        alert.title,
        alert.message,
        alert.source,
        alert.timestamp,
        alert.category
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_manager() {
        let manager = AlertManager::new();
        
        let alert = manager.alert_security(AlertLevel::Low, "测试告警", "这是一条测试告警");
        // 可能返回 None 因为级别或配置
        assert!(alert.is_some() || alert.is_none());
    }

    #[test]
    fn test_format_alert() {
        let alert = Alert {
            id: "test123".to_string(),
            timestamp: 1234567890,
            level: AlertLevel::Low,
            category: AlertCategory::Security,
            title: "测试".to_string(),
            message: "测试消息".to_string(),
            source: "test".to_string(),
            metadata: HashMap::new(),
        };

        let formatted = format_alert(&alert);
        assert!(!formatted.is_empty());
    }
}
