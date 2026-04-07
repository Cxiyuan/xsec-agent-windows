//! 进程内存特征检测模块

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum FeatureType {
    Url,
    IpAddress,
    FilePath,
    Base64Encoded,
    HexEncoded,
    BitcoinAddress,
    EthereumAddress,
    AwsKey,
    PrivateKey,
    ApiToken,
    SuspiciousString,
    CommandPattern,
    NetworkPattern,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemoryFeature {
    pub feature_type: FeatureType,
    pub value: String,
    pub offset: usize,
    pub context: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessMemoryFeatures {
    pub pid: u32,
    pub name: String,
    pub features: Vec<MemoryFeature>,
    pub risk_score: f32,
}

pub struct MemoryFeatureDetector {
    patterns: HashMap<FeatureType, Vec<(String, String)>>,
}

impl MemoryFeatureDetector {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        patterns.insert(FeatureType::Url, vec![
            ("https://".to_string(), "HTTPS URL".to_string()),
            ("http://".to_string(), "HTTP URL".to_string()),
            ("ftp://".to_string(), "FTP URL".to_string()),
        ]);

        patterns.insert(FeatureType::IpAddress, vec![
            ("10.0.0.".to_string(), "内网IP A类".to_string()),
            ("172.16.".to_string(), "内网IP B类".to_string()),
            ("192.168.".to_string(), "内网IP C类".to_string()),
            ("127.0.0.".to_string(), "本地回环".to_string()),
        ]);

        patterns.insert(FeatureType::FilePath, vec![
            ("/etc/passwd".to_string(), "系统密码文件".to_string()),
            ("/etc/shadow".to_string(), "系统影子密码".to_string()),
            ("/root/.ssh/".to_string(), "SSH密钥目录".to_string()),
            ("C:\\Windows\\System32".to_string(), "Windows系统目录".to_string()),
        ]);

        patterns.insert(FeatureType::AwsKey, vec![
            ("AKIA".to_string(), "AWS Access Key".to_string()),
        ]);

        patterns.insert(FeatureType::PrivateKey, vec![
            ("-----BEGIN RSA PRIVATE KEY-----".to_string(), "RSA私钥".to_string()),
            ("-----BEGIN PRIVATE KEY-----".to_string(), "私钥".to_string()),
            ("-----BEGIN CERTIFICATE-----".to_string(), "证书".to_string()),
        ]);

        patterns.insert(FeatureType::ApiToken, vec![
            ("ghp_".to_string(), "GitHub Token".to_string()),
            ("glpat-".to_string(), "GitLab Token".to_string()),
        ]);

        patterns.insert(FeatureType::SuspiciousString, vec![
            ("shellcode".to_string(), "Shellcode".to_string()),
            ("backdoor".to_string(), "后门".to_string()),
            ("keylogger".to_string(), "键盘记录".to_string()),
            ("cryptominer".to_string(), "挖矿".to_string()),
            ("mimikatz".to_string(), "凭证窃取".to_string()),
        ]);

        patterns.insert(FeatureType::CommandPattern, vec![
            ("curl ".to_string(), "Curl下载".to_string()),
            ("wget ".to_string(), "Wget下载".to_string()),
            ("bash -i".to_string(), "交互式Bash".to_string()),
            ("nc -".to_string(), "NetCat".to_string()),
            ("/dev/tcp/".to_string(), "TCP交互".to_string()),
        ]);

        Self { patterns }
    }

    pub fn detect(&self, sys: &sysinfo::System) -> Vec<ProcessMemoryFeatures> {
        let mut results = Vec::new();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();
            let features = self.scan_process_memory(pid_u32);
            let risk_score = self.calculate_risk_score(&features);

            if !features.is_empty() || risk_score > 0.3 {
                results.push(ProcessMemoryFeatures {
                    pid: pid_u32,
                    name,
                    features,
                    risk_score,
                });
            }
        }

        results.sort_by(|a, b| {
            b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal)
        });

        results
    }

    #[cfg(target_os = "linux")]
    fn scan_process_memory(&self, pid: u32) -> Vec<MemoryFeature> {
        let mut features = Vec::new();
        let maps_path = format!("/proc/{}/maps", pid);
        
        if let Ok(maps_content) = std::fs::read_to_string(&maps_path) {
            for line in maps_content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 { continue; }
                let path = if parts.len() > 5 { parts[5..].join(" ") } else { String::new() };
                if !path.is_empty() && (path.contains("/tmp/") || path.contains("/var/tmp/") || path.contains("(deleted)")) {
                    features.push(MemoryFeature {
                        feature_type: FeatureType::FilePath,
                        value: path,
                        offset: 0,
                        context: "可疑内存映射".to_string(),
                    });
                }
            }
        }

        let mem_path = format!("/proc/{}/mem", pid);
        if let Ok(output) = Command::new("strings").args(["-n", "6", &mem_path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.len() < 8 { continue; }
                for (feature_type, patterns) in &self.patterns {
                    for (pattern, description) in patterns {
                        if line.contains(pattern) {
                            features.push(MemoryFeature {
                                feature_type: feature_type.clone(),
                                value: line.chars().take(80).collect(),
                                offset: 0,
                                context: description.clone(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        features.sort_by(|a, b| a.value.cmp(&b.value));
        features.dedup_by(|a, b| a.value == b.value && a.feature_type == b.feature_type);
        features
    }

    #[cfg(target_os = "windows")]
    fn scan_process_memory(&self, pid: u32) -> Vec<MemoryFeature> {
        let mut features = Vec::new();
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("Get-Process -Id {} | Select-Object -ExpandProperty Path", pid)])
            .output() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() && (path.contains("Temp") || path.contains("AppData")) {
                features.push(MemoryFeature {
                    feature_type: FeatureType::FilePath,
                    value: path,
                    offset: 0,
                    context: "可疑路径".to_string(),
                });
            }
        }
        features
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn scan_process_memory(&self, _pid: u32) -> Vec<MemoryFeature> {
        Vec::new()
    }

    fn calculate_risk_score(&self, features: &[MemoryFeature]) -> f32 {
        if features.is_empty() { return 0.0; }
        let mut score = 0.0f32;
        for feature in features {
            let weight = match feature.feature_type {
                FeatureType::PrivateKey => 0.9,
                FeatureType::AwsKey => 0.8,
                FeatureType::BitcoinAddress => 0.8,
                FeatureType::CommandPattern => 0.7,
                FeatureType::SuspiciousString => 0.6,
                FeatureType::ApiToken => 0.7,
                FeatureType::NetworkPattern => 0.5,
                FeatureType::Url => 0.3,
                FeatureType::IpAddress => 0.3,
                FeatureType::FilePath => 0.4,
                FeatureType::Base64Encoded => 0.4,
                FeatureType::HexEncoded => 0.4,
                FeatureType::EthereumAddress => 0.7,
            };
            score += weight;
        }
        (score / features.len() as f32).min(1.0)
    }
}

impl Default for MemoryFeatureDetector {
    fn default() -> Self { Self::new() }
}

pub fn format_memory_features(results: &[ProcessMemoryFeatures], top_n: Option<usize>) -> String {
    let processes: Vec<&ProcessMemoryFeatures> = if let Some(n) = top_n {
        results.iter().take(n).collect()
    } else {
        results.iter().collect()
    };

    if processes.is_empty() {
        return "✅ 未检测到可疑内存特征".to_string();
    }

    let high_risk = processes.iter().filter(|p| p.risk_score > 0.6).count();
    let medium_risk = processes.iter().filter(|p| p.risk_score > 0.3 && p.risk_score <= 0.6).count();

    let mut output = format!(
        "═══════════════════════════════════════════════════════════════\n\
         进程内存特征检测 | 共 {} 个进程 | 高危: {} | 中危: {}\n\
         ════════════════════════════════════════════════════════════════\n\n",
        processes.len(), high_risk, medium_risk
    );

    for proc_info in processes {
        if proc_info.features.is_empty() { continue; }
        let risk_icon = if proc_info.risk_score > 0.6 { "🔴" } else if proc_info.risk_score > 0.3 { "🟡" } else { "🟢" };
        output.push_str(&format!("{} [风险: {:.0}%] PID: {} | {}\n", risk_icon, proc_info.risk_score * 100.0, proc_info.pid, proc_info.name));

        let mut by_type: HashMap<String, Vec<&MemoryFeature>> = HashMap::new();
        for f in &proc_info.features {
            by_type.entry(format!("{:?}", f.feature_type)).or_default().push(f);
        }
        for (t, feats) in &by_type {
            output.push_str(&format!("  📋 {} ({})\n", t, feats.len()));
            for f in feats.iter().take(3) {
                output.push_str(&format!("     • {} ({})\n", truncate(&f.value, 50), f.context));
            }
            if feats.len() > 3 { output.push_str(&format!("     ... 还有 {} 项\n", feats.len() - 3)); }
        }
        output.push('\n');
    }
    output
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len { format!("{}..", &s[..max_len-2]) } else { s.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_detector() {
        let d = MemoryFeatureDetector::new();
        let sys = sysinfo::System::new_all();
        let r = d.detect(&sys);
        assert!(r.len() >= 0);
    }
}
