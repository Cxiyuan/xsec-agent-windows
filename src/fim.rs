//! 文件完整性监控模块 (FIM)
//! 监控关键文件/目录的变化

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// 文件监控项
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitoredItem {
    /// 路径
    pub path: String,
    /// 类型
    pub item_type: MonitoredItemType,
    /// 监控模式（目录时）
    pub recursive: bool,
    /// 关联的风险级别
    pub risk_level: RiskLevel,
}

/// 监控项类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum MonitoredItemType {
    /// 文件
    File,
    /// 目录
    Directory,
    /// 符号链接
    Symlink,
}

/// 风险级别
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// 文件状态快照
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileSnapshot {
    pub path: String,
    pub size: u64,
    pub permissions: String,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub modified_time: u64,
    pub created_time: u64,
    /// 文件内容哈希
    pub content_hash: String,
    /// 文件类型
    pub file_type: FileType,
}

/// 文件类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    Unknown,
}

/// 文件变更事件
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileChangeEvent {
    pub path: String,
    pub event_type: ChangeType,
    pub timestamp: u64,
    pub old_snapshot: Option<FileSnapshot>,
    pub new_snapshot: Option<FileSnapshot>,
    pub risk_level: RiskLevel,
}

/// 变更类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ChangeType {
    /// 文件创建
    Created,
    /// 文件删除
    Deleted,
    /// 文件修改
    Modified,
    /// 权限变更
    PermissionChanged,
    /// 所有者变更
    OwnerChanged,
    /// 重命名
    Renamed,
    /// 移动
    Moved,
}

/// FIM 监控器
pub struct FimMonitor {
    /// 监控项列表
    items: Vec<MonitoredItem>,
    /// 基线快照（路径 -> 快照）
    baseline: HashMap<String, FileSnapshot>,
    /// 当前快照
    current: HashMap<String, FileSnapshot>,
    /// 变更事件
    events: Vec<FileChangeEvent>,
}

/// FIM 报告
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FimReport {
    pub total_monitored: usize,
    pub changes_detected: usize,
    pub high_risk_changes: usize,
    pub events: Vec<FileChangeEvent>,
    pub timestamp: u64,
}

impl FimMonitor {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            baseline: HashMap::new(),
            current: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// 添加监控项
    pub fn add_item(&mut self, item: MonitoredItem) {
        self.items.push(item);
    }

    /// 添加默认的监控路径（Linux 系统关键文件）
    pub fn add_default_linux_items(&mut self) {
        let critical_files = vec![
            ("/etc/passwd", MonitoredItemType::File, RiskLevel::Critical),
            ("/etc/shadow", MonitoredItemType::File, RiskLevel::Critical),
            ("/etc/group", MonitoredItemType::File, RiskLevel::High),
            ("/etc/gshadow", MonitoredItemType::File, RiskLevel::Critical),
            ("/etc/sudoers", MonitoredItemType::File, RiskLevel::Critical),
            ("/etc/ssh/sshd_config", MonitoredItemType::File, RiskLevel::High),
            ("/etc/ssh/ssh_config", MonitoredItemType::File, RiskLevel::Medium),
            ("/etc/crontab", MonitoredItemType::File, RiskLevel::High),
            ("/etc/fstab", MonitoredItemType::File, RiskLevel::High),
            ("/etc/hosts", MonitoredItemType::File, RiskLevel::Medium),
            ("/etc/hostname", MonitoredItemType::File, RiskLevel::Low),
            ("/etc/resolv.conf", MonitoredItemType::File, RiskLevel::Low),
            ("/etc/systemd/system", MonitoredItemType::Directory, RiskLevel::High),
            ("/etc/cron.d", MonitoredItemType::Directory, RiskLevel::High),
            ("/etc/cron.daily", MonitoredItemType::Directory, RiskLevel::High),
            ("/etc/cron.hourly", MonitoredItemType::Directory, RiskLevel::High),
            ("/var/log", MonitoredItemType::Directory, RiskLevel::Medium),
            ("/root/.ssh", MonitoredItemType::Directory, RiskLevel::Critical),
        ];

        for (path, item_type, risk) in critical_files {
            self.add_item(MonitoredItem {
                path: path.to_string(),
                item_type,
                recursive: true,
                risk_level: risk,
            });
        }
    }

    /// 添加默认的监控路径（Windows 系统关键文件）
    #[cfg(target_os = "windows")]
    pub fn add_default_windows_items(&mut self) {
        let critical_files = vec![
            ("C:\\Windows\\System32\\config\\SAM", MonitoredItemType::File, RiskLevel::Critical),
            ("C:\\Windows\\System32\\config\\SYSTEM", MonitoredItemType::File, RiskLevel::Critical),
            ("C:\\Windows\\System32\\config\\SECURITY", MonitoredItemType::File, RiskLevel::Critical),
            ("C:\\Windows\\System32\\drivers\\etc\\hosts", MonitoredItemType::File, RiskLevel::High),
            ("C:\\Windows\\System32\\ssh\\sshd_config", MonitoredItemType::File, RiskLevel::High),
            ("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", MonitoredItemType::Directory, RiskLevel::High),
            ("C:\\Windows\\System32\\tasks", MonitoredItemType::Directory, RiskLevel::High),
            ("C:\\Windows\\System32\\winevt\\Logs", MonitoredItemType::Directory, RiskLevel::Medium),
        ];

        for (path, item_type, risk) in critical_files {
            self.add_item(MonitoredItem {
                path: path.to_string(),
                item_type,
                recursive: true,
                risk_level: risk,
            });
        }
    }

    /// 建立基线快照
    pub fn create_baseline(&mut self) {
        self.baseline.clear();
        
        for item in &self.items {
            if let Some(snapshot) = self.create_snapshot(&item.path, item.item_type == MonitoredItemType::Directory, item.recursive) {
                self.baseline.insert(item.path.clone(), snapshot);
            }
        }
    }

    /// 执行一次检查，对比基线
    pub fn check(&mut self) -> &Vec<FileChangeEvent> {
        self.events.clear();
        self.current.clear();

        // 克隆监控项列表避免borrow冲突
        let items_clone = self.items.clone();
        for item in items_clone {
            self.scan_single_item(&item);
        }

        // 检测变更
        self.detect_changes();

        &self.events
    }

    /// 扫描单个监控项
    fn scan_single_item(&mut self, item: &MonitoredItem) {
        let path = Path::new(&item.path);
        
        if !path.exists() {
            // 文件已删除
            self.current.insert(item.path.clone(), FileSnapshot {
                path: item.path.clone(),
                size: 0,
                permissions: String::new(),
                owner_uid: 0,
                owner_gid: 0,
                modified_time: 0,
                created_time: 0,
                content_hash: String::new(),
                file_type: FileType::Unknown,
            });
            return;
        }

        if let Some(snapshot) = self.create_snapshot(&item.path, item.item_type == MonitoredItemType::Directory, item.recursive) {
            self.current.insert(item.path.clone(), snapshot);
        }
    }

    /// 创建文件快照
    fn create_snapshot(&self, path: &str, is_dir: bool, recursive: bool) -> Option<FileSnapshot> {
        let p = Path::new(path);
        
        if !p.exists() {
            return None;
        }

        if is_dir && recursive {
            // 目录递归创建快照
            return self.create_directory_snapshot(p);
        }

        // 单文件快照
        self.create_file_snapshot(p)
    }

    fn create_file_snapshot(&self, path: &Path) -> Option<FileSnapshot> {
        let metadata = fs::metadata(path).ok()?;
        
        let file_type = if metadata.is_file() {
            FileType::Regular
        } else if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::Unknown
        };

        let modified_time = metadata
            .modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();

        let created_time = metadata
            .created()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();

        let content_hash = if metadata.is_file() && metadata.len() < 10 * 1024 * 1024 {
            // 小于 10MB 的文件计算哈希
            self.calculate_hash(path).unwrap_or_default()
        } else {
            String::new()
        };

        #[cfg(target_os = "linux")]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            format!("{:o}", metadata.permissions().mode() & 0o777)
        };

        #[cfg(not(target_os = "linux"))]
        let permissions = String::from("unknown");

        Some(FileSnapshot {
            path: path.to_string_lossy().to_string(),
            size: metadata.len(),
            permissions,
            owner_uid: 0, // 需要额外处理
            owner_gid: 0,
            modified_time,
            created_time,
            content_hash,
            file_type,
        })
    }

    fn create_directory_snapshot(&self, path: &Path) -> Option<FileSnapshot> {
        // 对于目录，创建汇总快照
        let metadata = fs::metadata(path).ok()?;
        
        Some(FileSnapshot {
            path: path.to_string_lossy().to_string(),
            size: 0,
            permissions: String::from("directory"),
            owner_uid: 0,
            owner_gid: 0,
            modified_time: metadata
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs(),
            created_time: metadata
                .created()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs(),
            content_hash: String::new(),
            file_type: FileType::Directory,
        })
    }

    /// 计算文件哈希
    fn calculate_hash(&self, path: &Path) -> Option<String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        
        let content = fs::read(path).ok()?;
        let mut hasher = DefaultHasher::new();
        hasher.write(&content);
        Some(format!("{:x}", hasher.finish()))
    }

    /// 检测变更
    fn detect_changes(&mut self) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 检测删除和修改
        for (path, old_snapshot) in &self.baseline {
            if let Some(new_snapshot) = self.current.get(path) {
                if new_snapshot.file_type == FileType::Unknown {
                    // 文件被删除
                    self.events.push(FileChangeEvent {
                        path: path.clone(),
                        event_type: ChangeType::Deleted,
                        timestamp,
                        old_snapshot: Some(old_snapshot.clone()),
                        new_snapshot: None,
                        risk_level: RiskLevel::Critical,
                    });
                } else if old_snapshot.content_hash != new_snapshot.content_hash 
                    && !old_snapshot.content_hash.is_empty() 
                    && !new_snapshot.content_hash.is_empty() {
                    // 文件内容被修改
                    let risk_level = self.get_risk_for_change(old_snapshot, new_snapshot);
                    self.events.push(FileChangeEvent {
                        path: path.clone(),
                        event_type: ChangeType::Modified,
                        timestamp,
                        old_snapshot: Some(old_snapshot.clone()),
                        new_snapshot: Some(new_snapshot.clone()),
                        risk_level,
                    });
                } else if old_snapshot.permissions != new_snapshot.permissions {
                    // 权限变更
                    self.events.push(FileChangeEvent {
                        path: path.clone(),
                        event_type: ChangeType::PermissionChanged,
                        timestamp,
                        old_snapshot: Some(old_snapshot.clone()),
                        new_snapshot: Some(new_snapshot.clone()),
                        risk_level: RiskLevel::High,
                    });
                }
            }
        }

        // 检测新建
        for (path, new_snapshot) in &self.current {
            if !self.baseline.contains_key(path) && new_snapshot.file_type != FileType::Unknown {
                let risk_level = self.get_risk_for_new(new_snapshot);
                self.events.push(FileChangeEvent {
                    path: path.clone(),
                    event_type: ChangeType::Created,
                    timestamp,
                    old_snapshot: None,
                    new_snapshot: Some(new_snapshot.clone()),
                    risk_level,
                });
            }
        }
    }

    fn get_risk_for_change(&self, old: &FileSnapshot, new: &FileSnapshot) -> RiskLevel {
        // 高风险变更：shadow, passwd, sudoers, sshd_config
        let high_risk_paths = ["shadow", "passwd", "sudoers", "sshd_config", "SAM", "SYSTEM"];
        
        for path in &high_risk_paths {
            if old.path.contains(path) {
                return RiskLevel::Critical;
            }
        }

        // 大小突然增加很多可能是可疑的
        if new.size > old.size && new.size > old.size * 10 {
            return RiskLevel::High;
        }

        RiskLevel::Medium
    }

    fn get_risk_for_new(&self, snapshot: &FileSnapshot) -> RiskLevel {
        let path_lower = snapshot.path.to_lowercase();
        
        // 检查是否在敏感目录
        if path_lower.contains("/etc/cron") || path_lower.contains("/etc/systemd") {
            return RiskLevel::High;
        }
        if path_lower.contains("/root/.ssh") || path_lower.contains("authorized_keys") {
            return RiskLevel::Critical;
        }
        
        RiskLevel::Medium
    }

    /// 生成报告
    pub fn generate_report(&self) -> FimReport {
        let high_risk_events: Vec<&FileChangeEvent> = self.events
            .iter()
            .filter(|e| e.risk_level >= RiskLevel::High)
            .collect();

        FimReport {
            total_monitored: self.items.len(),
            changes_detected: self.events.len(),
            high_risk_changes: high_risk_events.len(),
            events: self.events.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// 获取监控项数量
    pub fn get_item_count(&self) -> usize {
        self.items.len()
    }

    /// 获取基线快照
    pub fn get_baseline(&self) -> &HashMap<String, FileSnapshot> {
        &self.baseline
    }
}

impl Default for FimMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化 FIM 报告
pub fn format_fim_report(report: &FimReport) -> String {
    let mut output = String::new();
    
    output.push_str(&format!(
        "═══════════════════════════════════════════\n\
         文件完整性监控报告\n\
         ════════════════════════════════════════════\n\
         监控项: {} | 变更: {} | 高风险: {}\n\
         时间: {}\n\n",
        report.total_monitored,
        report.changes_detected,
        report.high_risk_changes,
        report.timestamp
    ));

    if report.events.is_empty() {
        output.push_str("✅ 未检测到文件变更\n");
        return output;
    }

    output.push_str("📋 变更详情:\n\n");

    for event in &report.events {
        let risk_icon = match event.risk_level {
            RiskLevel::Low => "ℹ️",
            RiskLevel::Medium => "⚠️",
            RiskLevel::High => "🔴",
            RiskLevel::Critical => "🚨",
        };

        let change_icon = match event.event_type {
            ChangeType::Created => "🆕",
            ChangeType::Deleted => "🗑️",
            ChangeType::Modified => "✏️",
            ChangeType::PermissionChanged => "🔐",
            ChangeType::OwnerChanged => "👤",
            ChangeType::Renamed => "📝",
            ChangeType::Moved => "➡️",
        };

        output.push_str(&format!(
            "{} {} [{}] {}\n  路径: {}\n",
            risk_icon,
            change_icon,
            format!("{:?}", event.risk_level),
            format!("{:?}", event.event_type),
            event.path
        ));

        if let Some(ref old) = event.old_snapshot {
            if !old.content_hash.is_empty() && old.content_hash != event.new_snapshot.as_ref()
                .map(|s| &s.content_hash).unwrap_or(&String::new()).as_str() {
                output.push_str(&format!("  旧哈希: {} ...\n", &old.content_hash[..8.min(old.content_hash.len())]));
            }
        }
        if let Some(ref new) = event.new_snapshot {
            if !new.content_hash.is_empty() {
                output.push_str(&format!("  新哈希: {} ...\n", &new.content_hash[..8.min(new.content_hash.len())]));
            }
        }
        output.push('\n');
    }

    output
}

/// 格式化变更事件
pub fn format_change_events(events: &[FileChangeEvent]) -> String {
    if events.is_empty() {
        return "✅ 未检测到文件变更".to_string();
    }

    let mut output = String::new();
    
    for event in events {
        let risk_icon = match event.risk_level {
            RiskLevel::Low => "ℹ️",
            RiskLevel::Medium => "⚠️",
            RiskLevel::High => "🔴",
            RiskLevel::Critical => "🚨",
        };

        output.push_str(&format!(
            "{} {} {:?} - {}\n",
            risk_icon,
            format!("{:?}", event.event_type),
            event.risk_level,
            event.path
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }

    #[test]
    fn test_fim_monitor() {
        let mut monitor = FimMonitor::new();
        monitor.add_item(MonitoredItem {
            path: "/etc/passwd".to_string(),
            item_type: MonitoredItemType::File,
            recursive: false,
            risk_level: RiskLevel::High,
        });
        
        assert_eq!(monitor.get_item_count(), 1);
    }
}
