//! YARA规则引擎模块
//! 支持从Manager获取规则、本地缓存、文件/进程/目录扫描

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::process;

/// YARA规则结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: String,
    pub name: String,
    pub content: String,
    pub category: String,
    pub severity: String,
    pub updated_at: u64,
}

/// YARA匹配结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub file_path: Option<String>,
    pub process_id: Option<u32>,
    pub matches: Vec<YaraMatchString>,
    pub severity: String,
    pub timestamp: u64,
}

/// 匹配的字符串
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchString {
    pub identifier: String,
    pub offset: u64,
    pub data: String,
}

/// 扫描配置
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub max_file_size: u64,
    pub timeout_seconds: u64,
    pub recursive: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            timeout_seconds: 30,
            recursive: true,
        }
    }
}

/// 扫描统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub files_matched: u64,
    pub bytes_scanned: u64,
    pub errors: u64,
    pub duration_ms: u64,
}

/// YaraScanner
pub struct YaraScanner {
    rules: Arc<Mutex<Vec<YaraRule>>>,
    cache_dir: PathBuf,
    last_update: Arc<Mutex<u64>>,
    stats: Arc<Mutex<ScanStats>>,
    config: ScanConfig,
}

impl YaraScanner {
    pub fn new(cache_dir: PathBuf) -> Self {
        // 确保缓存目录存在
        let rules_dir = cache_dir.join("rules");
        let _ = fs::create_dir_all(&rules_dir);

        Self {
            rules: Arc::new(Mutex::new(Vec::new())),
            cache_dir,
            last_update: Arc::new(Mutex::new(0)),
            stats: Arc::new(Mutex::new(ScanStats::default())),
            config: ScanConfig::default(),
        }
    }

    /// 从Manager获取规则列表
    pub async fn fetch_rules(&self, manager_url: &str, token: &str) -> Result<Vec<YaraRule>, String> {
        let url = format!("{}/api/rules", manager_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client.get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| format!("Failed to fetch rules: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Manager returned status: {}", resp.status()));
        }

        let body: serde_json::Value = resp.json()
            .await
            .map_err(|e| format!("Failed to parse rules response: {}", e))?;

        let rules_raw = body.get("data")
            .and_then(|d| d.as_array())
            .ok_or("Invalid rules response format")?;

        let rules: Vec<YaraRule> = rules_raw.iter().filter_map(|r| {
            Some(YaraRule {
                id: r.get("id")?.as_str()?.to_string(),
                name: r.get("name")?.as_str()?.to_string(),
                content: r.get("content")?.as_str()?.to_string(),
                category: r.get("category").and_then(|c| c.as_str()).unwrap_or("unknown").to_string(),
                severity: r.get("severity").and_then(|s| s.as_str()).unwrap_or("medium").to_string(),
                updated_at: r.get("updated_at").and_then(|u| u.as_u64()).unwrap_or(0),
            })
        }).collect();

        Ok(rules)
    }

    /// 保存规则到本地缓存
    pub fn cache_rules(&self, rules: &[YaraRule]) -> std::io::Result<()> {
        let rules_dir = self.cache_dir.join("rules");
        let _ = fs::create_dir_all(&rules_dir);

        for rule in rules {
            let safe_name = rule.name.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>();
            let path = rules_dir.join(format!("{}.yar", safe_name));
            let mut file = File::create(&path)?;
            file.write_all(rule.content.as_bytes())?;
        }

        // 保存规则索引
        let index_path = rules_dir.join("index.json");
        let index_data = serde_json::to_string_pretty(rules).unwrap();
        fs::write(&index_path, index_data)?;

        // 更新本地规则列表
        *self.rules.lock().unwrap() = rules.to_vec();
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        *self.last_update.lock().unwrap() = now;

        Ok(())
    }

    /// 加载本地缓存的规则
    pub fn load_cached_rules(&self) -> std::io::Result<()> {
        let index_path = self.cache_dir.join("rules").join("index.json");
        if !index_path.exists() {
            return Ok(());
        }

        let data = fs::read_to_string(&index_path)?;
        let rules: Vec<YaraRule> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        *self.rules.lock().unwrap() = rules;
        Ok(())
    }

    /// 检查是否有新规则更新
    pub fn needs_update(&self, min_interval_secs: u64) -> bool {
        let last = *self.last_update.lock().unwrap();
        if last == 0 { return true; }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(last) > min_interval_secs
    }

    /// 获取内置基础规则（无需网络）
    pub fn get_builtin_rules() -> Vec<YaraRule> {
        vec![
            YaraRule {
                id: "builtin_meterpreter".to_string(),
                name: "meterpreter_payload".to_string(),
                content: r#"
rule meterpreter_payload {
    strings:
        $s1 = "meterpreter" ascii
        $s2 = "METERPRETER" ascii
        $s3 = " metsrv" ascii
        $s4 = "pass_the_hash" ascii
    condition:
        2 of them
}
"#.to_string(),
                category: "trojan".to_string(),
                severity: "high".to_string(),
                updated_at: 0,
            },
            YaraRule {
                id: "builtin_cobalt_strike".to_string(),
                name: "cobalt_strike_beacon".to_string(),
                content: r#"
rule cobalt_strike_beacon {
    strings:
        $s1 = "cobaltstrike" ascii nocase
        $s2 = "beacon.dll" ascii nocase
        $s3 = "VirtualAlloc" ascii
    condition:
        2 of them
}
"#.to_string(),
                category: "trojan".to_string(),
                severity: "critical".to_string(),
                updated_at: 0,
            },
            YaraRule {
                id: "builtin_ransom_note".to_string(),
                name: "ransom_note_files".to_string(),
                content: r#"
rule ransom_note_files {
    strings:
        $note1 = "README_TO_RESTORE" ascii nocase
        $note2 = "HOW_TO_RESTORE" ascii nocase
        $note3 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase
        $note4 = "DECRYPT_INSTRUCTIONS" ascii nocase
        $note5 = "bitcoin" ascii nocase
        $note6 = "ransom" ascii nocase
    condition:
        3 of them
}
"#.to_string(),
                category: "ransomware".to_string(),
                severity: "high".to_string(),
                updated_at: 0,
            },
            YaraRule {
                id: "builtin_shell_reverse".to_string(),
                name: "reverse_shell_indicator".to_string(),
                content: r#"
rule reverse_shell_indicator {
    strings:
        $s1 = "/bin/sh -i" ascii
        $s2 = "bash -i" ascii
        $s3 = "python3 -c" ascii nocase
        $s4 = "nc -e" ascii
        $s5 = "/dev/tcp/" ascii
    condition:
        2 of them
}
"#.to_string(),
                category: "exploit".to_string(),
                severity: "high".to_string(),
                updated_at: 0,
            },
            YaraRule {
                id: "builtin_suspicious_pe".to_string(),
                name: "suspicious_pe_header".to_string(),
                content: r#"
rule suspicious_pe_header {
    strings:
        $mz = "MZ"
        $sus1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
    condition:
        $mz at 0
}
"#.to_string(),
                category: "general".to_string(),
                severity: "low".to_string(),
                updated_at: 0,
            },
        ]
    }

    /// 简单字符串匹配扫描文件
    fn simple_scan(data: &[u8], rules: &[YaraRule]) -> Vec<YaraMatch> {
        let mut matches = Vec::new();
        let data_str = String::from_utf8_lossy(data);

        for rule in rules {
            let mut rule_matches = Vec::new();
            let lines: Vec<&str> = rule.content.lines().collect();
            
            for line in lines {
                let line = line.trim();
                if !line.starts_with("$") || !line.contains("=") {
                    continue;
                }
                // 解析 $s1 = "string" ascii 格式
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start+1..].find('"') {
                        let search_str = &line[start+1..start+1+end];
                        if !search_str.is_empty() && data_str.contains(search_str) {
                            rule_matches.push(YaraMatchString {
                                identifier: line.split('=').next().unwrap_or("$?").trim().to_string(),
                                offset: data_str.find(search_str).unwrap_or(0) as u64,
                                data: search_str.chars().take(50).collect(),
                            });
                        }
                    }
                }
            }

            if !rule_matches.is_empty() {
                matches.push(YaraMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    file_path: None,
                    process_id: None,
                    matches: rule_matches,
                    severity: rule.severity.clone(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                });
            }
        }
        matches
    }

    /// 扫描文件
    pub fn scan_file(&self, path: &str, rules: Option<&[YaraRule]>) -> Vec<YaraMatch> {
        let start = std::time::Instant::now();
        let rules: Vec<YaraRule> = match rules { Some(r) => r.to_vec(), None => self.rules.lock().unwrap().clone() };

        let path_buf = PathBuf::from(path);
        if !path_buf.exists() || !path_buf.is_file() {
            return Vec::new();
        }

        // 检查文件大小
        if let Ok(meta) = fs::metadata(&path_buf) {
            if meta.len() > self.config.max_file_size {
                return Vec::new();
            }
        }

        let data = match fs::read(&path_buf) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut all_matches = Self::simple_scan(&data, &rules);
        
        for m in &mut all_matches {
            m.file_path = Some(path.to_string());
        }

        // 更新统计
        if let Ok(mut stats) = self.stats.lock() {
            stats.files_scanned += 1;
            stats.bytes_scanned += data.len() as u64;
            if !all_matches.is_empty() {
                stats.files_matched += 1;
            }
            stats.duration_ms += start.elapsed().as_millis() as u64;
        }

        all_matches
    }

    /// 扫描进程内存 (通过 /proc/<pid>/mem 或其他方式)
    pub fn scan_process(&self, pid: u32, rules: Option<&[YaraRule]>) -> Vec<YaraMatch> {
        let rules: Vec<YaraRule> = match rules { Some(r) => r.to_vec(), None => self.rules.lock().unwrap().clone() };
        let mut all_matches = Vec::new();

        #[cfg(target_os = "linux")]
        {
            // 尝试读取进程的 /proc/<pid>/mem
            let mem_path = format!("/proc/{}/mem", pid);
            let data = match fs::read(&mem_path) {
                Ok(d) => d,
                Err(_) => return Vec::new(),
            };

            let matches = Self::simple_scan(&data, &rules);
            for mut m in matches {
                m.process_id = Some(pid);
                all_matches.push(m);
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS 可以用 vmmap 或读取 /proc/<pid>/mem
            let mem_path = format!("/proc/{}/mem", pid);
            let data = match fs::read(&mem_path) {
                Ok(d) => d,
                Err(_) => return Vec::new(),
            };

            let matches = Self::simple_scan(&data, &rules);
            for mut m in matches {
                m.process_id = Some(pid);
                all_matches.push(m);
            }
        }

        all_matches
    }

    /// 扫描目录
    pub fn scan_directory(&self, path: &str, rules: Option<&[YaraRule]>, recursive: bool) -> Vec<YaraMatch> {
        let mut all_matches = Vec::new();
        let rules: Vec<YaraRule> = match rules { Some(r) => r.to_vec(), None => self.rules.lock().unwrap().clone() };

        fn scan_dir_recursive(
            scanner: &YaraScanner,
            dir: &str,
            rules: &[YaraRule],
            recursive: bool,
            matches: &mut Vec<YaraMatch>,
        ) {
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && recursive {
                    scan_dir_recursive(scanner, &path.to_string_lossy(), rules, recursive, matches);
                } else if path.is_file() {
                    let file_matches = scanner.scan_file(&path.to_string_lossy(), Some(rules));
                    matches.extend(file_matches);
                }
            }
        }

        scan_dir_recursive(self, path, &rules, recursive, &mut all_matches);
        all_matches
    }

    /// 获取当前规则列表
    pub fn get_rules(&self) -> Vec<YaraRule> {
        self.rules.lock().unwrap().clone()
    }

    /// 获取扫描统计
    pub fn get_stats(&self) -> ScanStats {
        self.stats.lock().unwrap().clone()
    }

    /// 重置统计
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = ScanStats::default();
    }
}

/// 格式化扫描结果
pub fn format_scan_results(matches: &[YaraMatch]) -> String {
    if matches.is_empty() {
        return "YARA扫描: 未发现匹配".to_string();
    }

    let mut lines = vec![format!("=== YARA扫描结果 ({}个匹配) ===", matches.len())];
    
    let mut by_severity: HashMap<&str, Vec<&YaraMatch>> = HashMap::new();
    for m in matches {
        by_severity.entry(m.severity.as_str()).or_default().push(m);
    }

    for sev in &["critical", "high", "medium", "low", "unknown"] {
        if let Some(sev_matches) = by_severity.get(sev) {
            for m in sev_matches {
                lines.push(format!(
                    "[{}] {} (rule: {})",
                    m.severity.to_uppercase(),
                    m.rule_name,
                    m.rule_id
                ));
                if let Some(ref fp) = m.file_path {
                    lines.push(format!("  文件: {}", fp));
                }
                if let Some(pid) = m.process_id {
                    lines.push(format!("  进程: PID {}", pid));
                }
                for ms in &m.matches {
                    lines.push(format!(
                        "  字符串: {} @ offset {}",
                        ms.identifier, ms.offset
                    ));
                }
            }
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_scan() {
        let rules = YaraScanner::get_builtin_rules();
        let data = b"This is a test file containing meterpreter payload detection";
        let matches = YaraScanner::simple_scan(data, &rules);
        assert!(!matches.is_empty(), "Should detect meterpreter in test data");
    }
}
