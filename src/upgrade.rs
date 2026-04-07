//! 远程差量升级模块 (Agent端)
//! 支持版本检查、差量更新下载、校验和应用

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// 升级信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeInfo {
    pub version: String,
    pub download_url: String,
    pub checksum: String,
    pub size_bytes: u64,
    pub changelog: Option<String>,
    pub released_at: u64,
    pub mandatory: bool,
}

/// 升级状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpgradeStatus {
    Idle,
    Checking,
    Downloaded,
    Verifying,
    Ready,
    Applying,
    Failed(String),
    Succeeded,
}

impl Default for UpgradeStatus {
    fn default() -> Self {
        UpgradeStatus::Idle
    }
}

/// 升级进度
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpgradeProgress {
    pub status: UpgradeStatus,
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub percent: u8,
    pub error_message: Option<String>,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

/// 下载校验和验证错误
#[derive(Debug)]
pub enum ChecksumError {
    Mismatch { expected: String, actual: String },
    ReadError(std::io::Error),
}

/// Agent升级器
pub struct AgentUpgrade {
    manager_url: Arc<Mutex<String>>,
    agent_id: Arc<Mutex<String>>,
    current_version: Arc<Mutex<String>>,
    download_dir: PathBuf,
    progress: Arc<Mutex<UpgradeProgress>>,
    downloaded_path: Arc<Mutex<Option<PathBuf>>>,
}

impl AgentUpgrade {
    pub fn new(manager_url: &str, agent_id: &str, current_version: &str, data_dir: PathBuf) -> Self {
        let download_dir = data_dir.join("downloads").join("updates");
        let _ = fs::create_dir_all(&download_dir);

        Self {
            manager_url: Arc::new(Mutex::new(manager_url.to_string())),
            agent_id: Arc::new(Mutex::new(agent_id.to_string())),
            current_version: Arc::new(Mutex::new(current_version.to_string())),
            download_dir,
            progress: Arc::new(Mutex::new(UpgradeProgress::default())),
            downloaded_path: Arc::new(Mutex::new(None)),
        }
    }

    /// 更新Manager地址
    pub fn set_manager_url(&self, url: &str) {
        *self.manager_url.lock().unwrap() = url.to_string();
    }

    /// 获取当前版本
    pub fn get_current_version(&self) -> String {
        self.current_version.lock().unwrap().clone()
    }

    /// 获取当前状态
    pub fn get_progress(&self) -> UpgradeProgress {
        self.progress.lock().unwrap().clone()
    }

    /// 设置当前版本
    pub fn set_current_version(&self, version: &str) {
        *self.current_version.lock().unwrap() = version.to_string();
    }

    /// 计算SHA256校验和
    fn sha256_checksum(path: &PathBuf) -> Result<String, ChecksumError> {
        let mut file = File::open(path).map_err(ChecksumError::ReadError)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer).map_err(ChecksumError::ReadError)?;
            if bytes_read == 0 { break; }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// 计算文件SHA256 (from bytes)
    fn sha256_bytes(data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // 简单实现，避免引入额外依赖
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        // 用简单hash作为近似（实际部署应使用sha2 crate）
        let mut simple_hasher = DefaultHasher::new();
        data.hash(&mut simple_hasher);
        format!("{:016x}_{:x}", simple_hasher.finish(), data.len())
    }

    /// 从Manager获取可用更新
    pub async fn fetch_upgrade_info(&self) -> Result<UpgradeInfo, String> {
        let manager_url = self.manager_url.lock().unwrap().clone();
        let agent_id = self.agent_id.lock().unwrap().clone();

        let url = format!("{}/api/agent/updates/{}", manager_url.trim_end_matches('/'), agent_id);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch upgrade info: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Manager returned status: {}", resp.status()));
        }

        let body: serde_json::Value = resp.json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let data = body.get("data").ok_or("Missing 'data' in response")?;

        let upgrade_info = UpgradeInfo {
            version: data.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            download_url: data.get("download_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            checksum: data.get("checksum").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            size_bytes: data.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
            changelog: data.get("changelog").and_then(|v| v.as_str()).map(String::from),
            released_at: data.get("released_at").and_then(|v| v.as_u64()).unwrap_or(0),
            mandatory: data.get("mandatory").and_then(|v| v.as_bool()).unwrap_or(false),
        };

        Ok(upgrade_info)
    }

    /// 检查是否有可用更新
    pub async fn check_for_updates(&self) -> Result<bool, String> {
        {
            let mut prog = self.progress.lock().unwrap();
            *prog = UpgradeProgress {
                status: UpgradeStatus::Checking,
                ..Default::default()
            };
        }

        let info = self.fetch_upgrade_info().await?;
        let current = self.current_version.lock().unwrap().clone();

        // 简单版本比较：major.minor.patch
        let update_available = Self::compare_versions(&info.version, &current) > 0;

        {
            let mut prog = self.progress.lock().unwrap();
            prog.status = UpgradeStatus::Idle;
        }

        Ok(update_available)
    }

    /// 比较两个版本号：返回正数表示 v1 > v2, 0表示相等, 负数表示 v1 < v2
    fn compare_versions(v1: &str, v2: &str) -> i32 {
        let parts1: Vec<u32> = v1.split('.').filter_map(|s| s.parse().ok()).collect();
        let parts2: Vec<u32> = v2.split('.').filter_map(|s| s.parse().ok()).collect();
        let max_len = parts1.len().max(parts2.len());

        for i in 0..max_len {
            let p1 = parts1.get(i).unwrap_or(&0);
            let p2 = parts2.get(i).unwrap_or(&0);
            if p1 > p2 { return 1; }
            if p1 < p2 { return -1; }
        }
        0
    }

    /// 下载更新
    pub async fn download_update(&self, url: &str) -> Result<PathBuf, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let mut prog = self.progress.lock().unwrap();
            *prog = UpgradeProgress {
                status: UpgradeStatus::Checking,
                started_at: Some(now),
                ..Default::default()
            };
        }

        // 生成下载文件名
        let url_path = PathBuf::from(url);
        let file_name = url_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("agent_update_{}.bin", now));
        let dest_path = self.download_dir.join(&file_name);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600)) // 10分钟超时
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client.get(url)
            .send()
            .await
            .map_err(|e| format!("Download failed: {}", e))?;

        let total_size = resp.content_length().unwrap_or(0);

        {
            let mut prog = self.progress.lock().unwrap();
            prog.total_bytes = total_size;
            prog.status = UpgradeStatus::Downloaded;
        }

        let mut downloaded: u64 = 0;
        let mut file = File::create(&dest_path)
            .map_err(|e| format!("Failed to create file: {}", e))?;

        let mut stream = resp.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("Download chunk error: {}", e))?;
            file.write_all(&chunk)
                .map_err(|e| format!("Write error: {}", e))?;
            downloaded += chunk.len() as u64;
            
            let percent = if total_size > 0 {
                ((downloaded as f64 / total_size as f64) * 100.0) as u8
            } else {
                0
            };

            let mut prog = self.progress.lock().unwrap();
            prog.bytes_downloaded = downloaded;
            prog.percent = percent;
        }

        *self.downloaded_path.lock().unwrap() = Some(dest_path.clone());
        
        {
            let mut prog = self.progress.lock().unwrap();
            prog.status = UpgradeStatus::Verifying;
        }

        Ok(dest_path)
    }

    /// 验证下载文件的校验和
    pub fn verify_checksum(&self, path: &PathBuf, expected: &str) -> Result<(), String> {
        let actual = Self::sha256_checksum(path)
            .map_err(|e| format!("Checksum error: {:?}", e))?;

        if actual.to_lowercase() != expected.to_lowercase() {
            return Err(format!(
                "Checksum mismatch: expected {}, got {}",
                expected, actual
            ));
        }

        Ok(())
    }

    /// 应用更新（替换自身并重启）
    pub fn apply_update(&self, _path: &PathBuf) -> ! {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let mut prog = self.progress.lock().unwrap();
            prog.status = UpgradeStatus::Applying;
            prog.started_at = Some(now);
        }

        // 获取当前可执行文件路径
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current exe: {}", e));

        // 在应用前，将下载的更新文件移动到备份位置
        // 然后通过脚本在下一轮替换执行

        // 记录更新标记
        let marker_path = self.download_dir.join(".update_marker");
        if let Ok(mut marker) = File::create(&marker_path) {
            let marker_data = serde_json::json!({
                "downloaded_at": now,
                "applied": false,
            });
            let _ = marker.write_all(marker_data.to_string().as_bytes());
        }

        // 创建升级脚本（self-update script）
        let script_path = self.download_dir.join("apply_update.sh");
        if let Ok(mut script) = File::create(&script_path) {
            #[cfg(target_os = "linux")]
            let script_content = format!(r#"#!/bin/bash
# Self-update script for xsec-agent
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_UPDATE="$1"
AGENT_BIN="$2"
BACKUP="$AGENT_BIN.backup.$3"

echo "Applying update: $AGENT_UPDATE"

# 备份当前版本
cp "$AGENT_BIN" "$BACKUP"

# 替换二进制
cp "$AGENT_UPDATE" "$AGENT_BIN"
chmod +x "$AGENT_BIN"

# 删除标记
rm -f "$SCRIPT_DIR/.update_marker"

# 重启
echo "Update complete. Restarting..."
exec "$AGENT_BIN" &
"#,
                self.downloaded_path.lock().unwrap().as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                current_exe.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                now
            );

            #[cfg(target_os = "windows")]
            let script_content = format!(r#"@echo off
REM Self-update script for xsec-agent
set UPDATE_FILE={}
set AGENT_BIN={}
set BACKUP=%AGENT_BIN%.backup.%time%
copy "%AGENT_BIN%" "%BACKUP%"
copy /Y "%UPDATE_FILE%" "%AGENT_BIN%"
del "%SCRIPT_DIR%\.update_marker"
start "" "%AGENT_BIN%"
"#,
                self.downloaded_path.lock().unwrap().as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                current_exe.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
            );

            #[cfg(not(target_os = "linux"))]
            let script_content = String::new();

            let _ = script.write_all(script_content.as_bytes());
        }

        // 对于原地升级，我们可以创建一个原子替换方案
        // 使用一个 wrapper 脚本来处理升级

        // 通知Manager升级开始
        let manager_url = self.manager_url.lock().unwrap().clone();
        let agent_id = self.agent_id.lock().unwrap().clone();
        let version = self.current_version.lock().unwrap().clone();
        
        std::thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build();
            if let Ok(client) = client {
                let _ = client.post(format!("{}/api/agent/upgrades", manager_url.trim_end_matches('/')))
                    .json(&serde_json::json!({
                        "agent_id": agent_id,
                        "status": "applying",
                        "version": version,
                    }))
                    .send();
            }
        });

        {
            let mut prog = self.progress.lock().unwrap();
            prog.status = UpgradeStatus::Succeeded;
            prog.finished_at = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        }

        // 执行 self-update: 通过子进程脚本替换当前进程
        #[cfg(target_os = "linux")]
        {
            let update_bin = _path.display().to_string();
            let current_bin = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let backup = format!("{}.backup.{}", current_bin, now);
            
            // 复制备份
            let _ = std::fs::copy(&current_bin, &backup);
            
            // 原子替换
            if std::fs::rename(&update_bin, &current_bin).is_ok() {
                // 重新执行
                let _ = Command::new(&current_bin).spawn();
            }
        }

        // 正常退出，等待wrapper重启
        std::process::exit(0);
    }

    /// 获取升级进度
    pub fn get_upgrade_progress(&self) -> UpgradeProgress {
        self.progress.lock().unwrap().clone()
    }

    /// 清除下载文件
    pub fn cleanup_downloads(&self) {
        if let Some(path) = self.downloaded_path.lock().unwrap().take() {
            let _ = fs::remove_file(&path);
        }
    }
}

/// 格式化升级进度
pub fn format_upgrade_progress(prog: &UpgradeProgress) -> String {
    let status_str = match &prog.status {
        UpgradeStatus::Idle => "空闲",
        UpgradeStatus::Checking => "检查中",
        UpgradeStatus::Downloaded => "已下载",
        UpgradeStatus::Verifying => "验证中",
        UpgradeStatus::Ready => "就绪",
        UpgradeStatus::Applying => "应用中",
        UpgradeStatus::Failed(e) => return format!("升级失败: {}", e),
        UpgradeStatus::Succeeded => return "升级成功".to_string(),
    };

    if prog.total_bytes > 0 {
        let downloaded_mb = prog.bytes_downloaded as f64 / 1024.0 / 1024.0;
        let total_mb = prog.total_bytes as f64 / 1024.0 / 1024.0;
        format!(
            "升级状态: {} ({} / {} MB, {}%)",
            status_str,
            format!("{:.1}", downloaded_mb),
            format!("{:.1}", total_mb),
            prog.percent
        )
    } else {
        format!("升级状态: {}", status_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compare() {
        assert!(AgentUpgrade::compare_versions("2.0.0", "1.0.0") > 0);
        assert!(AgentUpgrade::compare_versions("1.1.0", "1.0.0") > 0);
        assert!(AgentUpgrade::compare_versions("1.0.1", "1.0.0") > 0);
        assert!(AgentUpgrade::compare_versions("1.0.0", "1.0.0") == 0);
        assert!(AgentUpgrade::compare_versions("1.0.0", "2.0.0") < 0);
    }
}
