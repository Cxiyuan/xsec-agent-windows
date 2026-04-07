//! 勒索软件检测模块
//! 蜜罐文件 + 行为检测 + 熵值分析 + 批量操作检测

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write as IoWrite};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use sysinfo::System;

use crate::alert::{Alert, AlertLevel, AlertCategory};

/// 蜜罐文件信息
#[derive(Debug, Clone)]
pub struct HoneypotFile {
    pub path: PathBuf,
    pub original_content: Vec<u8>,
    pub created_at: u64,
    pub accessed: bool,
    pub modified: bool,
    pub entropy_checked: bool,
}

/// 蜜罐配置
#[derive(Debug, Clone)]
pub struct HoneypotConfig {
    pub enabled: bool,
    pub directories: Vec<PathBuf>,
    pub file_count: usize,
    pub extensions: Vec<String>,
}

/// 勒索软件告警详情
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RansomwareAlert {
    pub honeypot_triggered: bool,
    pub entropy_alert: bool,
    pub batch_ops_alert: bool,
    pub extension_alert: bool,
    pub score: u32,
    pub triggered_files: Vec<String>,
    pub batch_count: usize,
    pub details: String,
}

/// 评分因子权重
const SCORE_HONEYPOT_ACCESSED: u32 = 30;
const SCORE_ENTROPY_HIGH: u32 = 25;
const SCORE_BATCH_OPS: u32 = 25;
const SCORE_EXTENSION_CHANGE: u32 = 20;

/// 熵值阈值（高于此值视为疑似加密）
const ENTROPY_THRESHOLD: f64 = 7.2;

/// 批量操作阈值（1秒内超过此数量则告警）
const BATCH_OPS_THRESHOLD: usize = 10;

/// 常见勒索软件扩展名
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
    ".ransom", ".pay", ".bit", ".wallet", ".AES",
    ".RSA", ".cry", ".crj", ".hasp", ".hlp",
    ".p3d", ".pzdc", ".sst", ".ttf", ".crypted",
    ".xxx", ".qqq", ".aaa", ".abc", ".zzz",
    ".micro", ".magic", ".SUPER", ".CRAB", ".WANNACRY",
];

/// 诱饵标记（用于识别被访问）
const HONEYPOT_SIGNATURE: &[u8] = b"XSECHONEYPOT2024_V1";

/// HoneypotManager
pub struct HoneypotManager {
    honeypots: Arc<Mutex<Vec<HoneypotFile>>>,
    config: HoneypotConfig,
    /// 文件访问时间追踪：path -> last_access_timestamp
    access_log: Arc<Mutex<HashMap<String, u64>>>,
    /// 批量操作计数：timestamp -> count
    batch_counter: Arc<Mutex<HashMap<u64, usize>>>,
    /// 扩展名变化追踪
    extension_changes: Arc<Mutex<Vec<(String, String)>>>,
    /// 已触发过的告警（防止重复）
    alerted: Arc<Mutex<bool>>,
}

impl HoneypotManager {
    pub fn new(config: HoneypotConfig) -> Self {
        Self {
            honeypots: Arc::new(Mutex::new(Vec::new())),
            config,
            access_log: Arc::new(Mutex::new(HashMap::new())),
            batch_counter: Arc::new(Mutex::new(HashMap::new())),
            extension_changes: Arc::new(Mutex::new(Vec::new())),
            alerted: Arc::new(Mutex::new(false)),
        }
    }

    /// 生成随机诱饵内容
    fn generate_honeypot_content() -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);
        let salt = hasher.finish();
        
        let mut content = Vec::with_capacity(4096);
        content.extend_from_slice(HONEYPOT_SIGNATURE);
        content.extend_from_slice(&salt.to_le_bytes());
        // 填充随机数据
        let mut rng_state = salt;
        for _ in 0..200 {
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            content.push((rng_state >> 16) as u8);
        }
        content
    }

    /// 生成随机文件名
    fn random_name(extensions: &[String], idx: usize) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
        idx.hash(&mut hasher);
        let h = hasher.finish();
        let name_idx = (h as usize) % extensions.len();
        format!("{}_{:016x}.exe", extensions[name_idx], h)
    }

    /// 部署蜜罐文件
    pub fn deploy(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut deployed = Vec::new();
        let extensions: Vec<String> = vec![
            "docx".into(), "pdf".into(), "xlsx".into(),
            "pptx".into(), "txt".into(), "jpg".into(),
            "png".into(), "zip".into(), "rar".into(),
        ];

        for dir in &self.config.directories {
            if !dir.exists() {
                let _ = fs::create_dir_all(dir);
            }
        }

        for idx in 0..self.config.file_count {
            let dir_idx = idx % self.config.directories.len();
            let dir = &self.config.directories[dir_idx];
            let file_name = Self::random_name(&extensions, idx);
            let path = dir.join(&file_name);
            
            let content = Self::generate_honeypot_content();
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = fs::Permissions::from_mode(0o666);
                file.set_permissions(perm).ok();
            }

            let hp = HoneypotFile {
                path: path.clone(),
                original_content: content,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                accessed: false,
                modified: false,
                entropy_checked: false,
            };
            self.honeypots.lock().unwrap().push(hp);
            deployed.push(path);
        }
        Ok(deployed)
    }

    /// 计算文件熵值（Shannon熵）
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let len = data.len() as f64;
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let mut entropy = 0.0;
        for &count in &freq {
            if count == 0 { continue; }
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
        entropy
    }

    /// 检查单个文件熵值
    fn check_file_entropy(path: &PathBuf) -> Option<f64> {
        let mut file = File::open(path).ok()?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).ok()?;
        Some(Self::calculate_entropy(&buf))
    }

    /// 检测勒索软件扩展名变化
    fn detect_ransomware_extension(path: &PathBuf) -> bool {
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            for &ransom_ext in RANSOMWARE_EXTENSIONS {
                if ext_lower.contains(ransom_ext.to_lowercase().trim_start_matches('.')) {
                    return true;
                }
            }
        }
        false
    }

    /// 检测文件是否被修改（内容变化检测）
    fn is_modified(&self, path: &PathBuf) -> bool {
        let hp = self.honeypots.lock().unwrap();
        for h in hp.iter() {
            if &h.path == path {
                if let Ok(current) = fs::read(path) {
                    return current != h.original_content;
                }
            }
        }
        false
    }

    /// 记录批量文件操作
    pub fn record_file_operation(&self, path: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut counter = self.batch_counter.lock().unwrap();
        *counter.entry(now).or_insert(0) += 1;
        // 清理1秒前的记录
        counter.retain(|&t, _| now.saturating_sub(t) < 2);
    }

    /// 执行勒索软件检测扫描
    pub fn scan(&self) -> RansomwareAlert {
        let mut score: u32 = 0;
        let mut triggered_files: Vec<String> = Vec::new();
        let mut batch_count: usize = 0;
        let mut details_vec: Vec<String> = Vec::new();

        // 1. 蜜罐文件检测
        {
            let honeypots = self.honeypots.lock().unwrap();
            for hp in honeypots.iter() {
                // 检查文件是否存在
                if !hp.path.exists() {
                    // 文件被删除或移动 - 严重告警
                    score += SCORE_HONEYPOT_ACCESSED;
                    triggered_files.push(hp.path.to_string_lossy().to_string());
                    details_vec.push(format!("蜜罐文件被删除/移动: {}", hp.path.display()));
                    continue;
                }

                // 检查文件是否被修改（熵值变化）
                if let Some(entropy) = Self::check_file_entropy(&hp.path) {
                    if entropy > ENTROPY_THRESHOLD {
                        // 文件熵值异常升高
                        score += SCORE_ENTROPY_HIGH;
                        triggered_files.push(hp.path.to_string_lossy().to_string());
                        details_vec.push(format!(
                            "熵值告警: {} (熵={:.2} > {:.2})",
                            hp.path.display(), entropy, ENTROPY_THRESHOLD
                        ));
                    }
                }

                // 检查文件大小是否异常（勒索软件可能修改大小）
                if let Ok(metadata) = fs::metadata(&hp.path) {
                    let orig_size = hp.original_content.len() as u64;
                    let curr_size = metadata.len();
                    if curr_size > 0 && (orig_size == 0 || (curr_size as f64 / orig_size as f64) < 0.5 || (curr_size as f64 / orig_size as f64) > 2.0) {
                        score += SCORE_ENTROPY_HIGH / 2;
                        details_vec.push(format!(
                            "大小异常: {} (原始={}, 当前={})",
                            hp.path.display(), orig_size, curr_size
                        ));
                    }
                }
            }
        }

        // 2. 批量操作检测
        {
            let counter = self.batch_counter.lock().unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            batch_count = counter.get(&now).copied().unwrap_or(0);
            if batch_count > BATCH_OPS_THRESHOLD {
                score += SCORE_BATCH_OPS;
                details_vec.push(format!(
                    "批量操作: 1秒内{}个文件被修改（阈值={})",
                    batch_count, BATCH_OPS_THRESHOLD
                ));
            }
        }

        // 3. 扩展名检测（扫描常见目录是否有勒索扩展名）
        {
            let extensions = self.extension_changes.lock().unwrap();
            for (orig, new) in extensions.iter() {
                triggered_files.push(new.clone());
                details_vec.push(format!("扩展名变化: {} -> {}", orig, new));
            }
        }

        // 扫描可疑扩展名
        let sys = System::new_all();
        let suspicious_paths = vec![
            std::env::var("HOME").map(|h| PathBuf::from(h).join("Desktop")).unwrap_or_default(),
            std::env::var("HOME").map(|h| PathBuf::from(h).join("Documents")).unwrap_or_default(),
            std::env::var("HOME").map(|h| PathBuf::from(h).join("Downloads")).unwrap_or_default(),
        ];

        for base_dir in &suspicious_paths {
            if base_dir.as_os_str().is_empty() { continue; }
            if let Ok(entries) = fs::read_dir(base_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && Self::detect_ransomware_extension(&path) {
                        score += SCORE_EXTENSION_CHANGE;
                        triggered_files.push(path.to_string_lossy().to_string());
                        details_vec.push(format!("可疑勒索扩展名: {}", path.display()));
                    }
                }
            }
        }

        // 生成告警
        let honeypot_triggered = triggered_files.iter().any(|f| {
            self.honeypots.lock().unwrap().iter().any(|h| h.path.to_string_lossy() == *f)
        });

        RansomwareAlert {
            honeypot_triggered,
            entropy_alert: details_vec.iter().any(|d| d.contains("熵值")),
            batch_ops_alert: batch_count > BATCH_OPS_THRESHOLD,
            extension_alert: details_vec.iter().any(|d| d.contains("扩展名")),
            score,
            triggered_files,
            batch_count,
            details: details_vec.join("; "),
        }
    }

    /// 获取告警级别
    pub fn get_alert_level(&self, alert: &RansomwareAlert) -> Option<Alert> {
        const ALERT_THRESHOLD: u32 = 30;
        
        if alert.score < ALERT_THRESHOLD {
            return None;
        }

        let level = if alert.score >= 60 {
            AlertLevel::Critical
        } else if alert.score >= 45 {
            AlertLevel::High
        } else {
            AlertLevel::Medium
        };

        let mut metadata = HashMap::new();
        metadata.insert("honeypot_triggered".into(), alert.honeypot_triggered.to_string());
        metadata.insert("entropy_alert".into(), alert.entropy_alert.to_string());
        metadata.insert("batch_ops_alert".into(), alert.batch_ops_alert.to_string());
        metadata.insert("extension_alert".into(), alert.extension_alert.to_string());
        metadata.insert("score".into(), alert.score.to_string());
        metadata.insert("batch_count".into(), alert.batch_count.to_string());
        metadata.insert("triggered_files".into(), alert.triggered_files.join(","));
        metadata.insert("details".into(), alert.details.clone());

        Some(Alert {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            level,
            category: AlertCategory::Security,
            title: "勒索软件疑似活动".to_string(),
            message: format!(
                "检测到疑似勒索软件行为 (评分={}, 触发文件={})",
                alert.score,
                alert.triggered_files.len()
            ),
            source: "ransomware_detector".to_string(),
            metadata,
        })
    }

    /// 获取已部署的蜜罐列表
    pub fn list_honeypots(&self) -> Vec<String> {
        self.honeypots.lock().unwrap()
            .iter()
            .map(|h| h.path.to_string_lossy().to_string())
            .collect()
    }

    /// 清理蜜罐文件
    pub fn cleanup(&self) {
        let paths: Vec<PathBuf> = self.honeypots.lock().unwrap()
            .iter()
            .map(|h| h.path.clone())
            .collect();
        for path in paths {
            let _ = fs::remove_file(&path);
        }
        self.honeypots.lock().unwrap().clear();
    }
}

/// 格式化检测结果
pub fn format_ransomware_result(alert: &RansomwareAlert) -> String {
    let mut lines = vec![
        format!("=== 勒索软件检测报告 ==="),
        format!("风险评分: {}/100", alert.score),
        format!("蜜罐触发: {}", if alert.honeypot_triggered { "是" } else { "否" }),
        format!("熵值告警: {}", if alert.entropy_alert { "是" } else { "否" }),
        format!("批量操作: {} (阈值={})", alert.batch_count, BATCH_OPS_THRESHOLD),
        format!("扩展名告警: {}", if alert.extension_alert { "是" } else { "否" }),
    ];
    if !alert.triggered_files.is_empty() {
        lines.push(format!("触发文件 ({}):", alert.triggered_files.len()));
        for f in alert.triggered_files.iter().take(10) {
            lines.push(format!("  - {}", f));
        }
    }
    if !alert.details.is_empty() {
        lines.push(format!("详情: {}", alert.details));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // 低熵：重复数据
        let low = vec![0u8; 1000];
        let entropy_low = HoneypotManager::calculate_entropy(&low);
        assert!(entropy_low < 1.0, "重复数据熵值应接近0");

        // 高熵：随机数据（接近加密）
        let high: Vec<u8> = (0..255).cycle().take(1000).collect();
        let entropy_high = HoneypotManager::calculate_entropy(&high);
        assert!(entropy_high > 7.0, "随机数据熵值应大于7");
    }

    #[test]
    fn test_ransomware_extension_detection() {
        let path = PathBuf::from("/tmp/test.encrypted");
        assert!(HoneypotManager::detect_ransomware_extension(&path));
        
        let path2 = PathBuf::from("/tmp/test.pdf");
        assert!(!HoneypotManager::detect_ransomware_extension(&path2));
    }
}
