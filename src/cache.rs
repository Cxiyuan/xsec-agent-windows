//! Agent 本地 SQLite 缓存模块
//!
//! 功能:
//!   1. 离线时缓存告警到本地 SQLite
//!   2. 网络恢复后自动上报缓存的告警
//!   3. 支持告警去重和清理策略

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::alert::{Alert, AlertLevel, AlertCategory};

// ============================================================================
// AlertCache - SQLite 本地告警缓存
// ============================================================================

pub struct AlertCache {
    db_path: String,
}

impl AlertCache {
    pub fn new(db_path: &str) -> std::io::Result<Self> {
        let cache = Self {
            db_path: db_path.to_string(),
        };
        cache.init_db()?;
        Ok(cache)
    }

    fn init_db(&self) -> std::io::Result<()> {
        let path = Path::new(&self.db_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS alert_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_key TEXT UNIQUE NOT NULL,
                agent_id TEXT NOT NULL,
                level INTEGER NOT NULL,
                category INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                created_at INTEGER NOT NULL,
                cached_at INTEGER NOT NULL,
                uploaded INTEGER DEFAULT 0,
                uploaded_at INTEGER
            )",
            [],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_uploaded ON alert_cache(uploaded)",
            [],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_key ON alert_cache(alert_key)",
            [],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        // 自动释放连接 (rusqlite Connection 有 Drop)
        drop(conn);
        Ok(())
    }

    /// 生成告警唯一键（用于去重）
    fn make_key(alert: &Alert) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut s = DefaultHasher::new();
        alert.source.hash(&mut s);
        alert.title.hash(&mut s);
        (alert.level as u8).hash(&mut s);
        alert.timestamp.hash(&mut s);
        format!("{:016x}", s.finish())
    }

    /// 缓存一条告警（仅在未上传时保存）
    pub fn save_alert(&self, alert: &Alert) -> std::io::Result<bool> {
        let key = Self::make_key(alert);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let metadata = serde_json::to_string(&alert.metadata)
            .unwrap_or_else(|_| "{}".to_string());

        let rows = conn.execute(
            "INSERT OR IGNORE INTO alert_cache \
             (alert_key, agent_id, level, category, title, message, source, metadata, created_at, cached_at, uploaded) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
            rusqlite::params![
                key,
                alert.source.clone(),
                alert.level as i32,
                alert.category as i32,
                alert.title,
                alert.message,
                alert.source,
                metadata,
                alert.timestamp as i64,
                now
            ],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        drop(conn);
        Ok(rows > 0)
    }

    /// 获取所有待上报的告警
    pub fn get_pending(&self, limit: usize) -> std::io::Result<Vec<CachedAlert>> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut stmt = conn
            .prepare("SELECT id, alert_key, agent_id, level, category, title, message, source, metadata, created_at, cached_at, uploaded, uploaded_at FROM alert_cache WHERE uploaded = 0 ORDER BY cached_at ASC LIMIT ?1")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut alerts = Vec::new();
        let rows = stmt
            .query_map([limit as i64], |row| {
                let metadata_str: String = row.get(8)?;
                Ok(CachedAlert {
                    id: row.get(0)?,
                    alert_key: row.get(1)?,
                    agent_id: row.get(2)?,
                    level: AlertLevel::from_i32(row.get(3)?),
                    category: AlertCategory::from_i32(row.get(4)?),
                    title: row.get(5)?,
                    message: row.get(6)?,
                    source: row.get(7)?,
                    metadata: metadata_str,
                    created_at: row.get::<_, i64>(9)? as u64,
                    cached_at: row.get::<_, i64>(10)?,
                    uploaded: false,
                    uploaded_at: row.get(12)?,
                })
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        for row in rows {
            if let Ok(a) = row {
                alerts.push(a);
            }
        }

        drop(stmt);
        drop(conn);
        Ok(alerts)
    }

    /// 标记已上报的告警
    pub fn mark_uploaded(&self, ids: &[i64]) -> std::io::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "UPDATE alert_cache SET uploaded = 1, uploaded_at = {} WHERE id IN ({})",
            now,
            placeholders.join(",")
        );

        let ids_owned: Vec<i64> = ids.to_vec();
        let params: Vec<&dyn rusqlite::ToSql> = ids_owned
            .iter()
            .map(|id| id as &dyn rusqlite::ToSql)
            .collect();

        conn.execute(&sql, params.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        drop(conn);
        Ok(())
    }

    /// 删除已上传的旧记录（保留7天）
    pub fn cleanup_uploaded(&self, retention_days: i64) -> std::io::Result<usize> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - (retention_days * 86400);

        let rows = conn
            .execute(
                "DELETE FROM alert_cache WHERE uploaded = 1 AND uploaded_at < ?1",
                [cutoff],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        drop(conn);
        Ok(rows)
    }

    /// 获取缓存统计
    pub fn stats(&self) -> std::io::Result<CacheStats> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_cache", [], |r| r.get(0))
            .unwrap_or(0);

        let pending: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_cache WHERE uploaded = 0", [], |r| r.get(0))
            .unwrap_or(0);

        let uploaded: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_cache WHERE uploaded = 1", [], |r| r.get(0))
            .unwrap_or(0);

        drop(conn);
        Ok(CacheStats {
            total,
            pending,
            uploaded,
        })
    }
}

// ============================================================================
// 缓存告警数据结构
// ============================================================================

#[derive(Debug, Clone)]
pub struct CachedAlert {
    pub id: i64,
    pub alert_key: String,
    pub agent_id: String,
    pub level: AlertLevel,
    pub category: AlertCategory,
    pub title: String,
    pub message: String,
    pub source: String,
    pub metadata: String,
    pub created_at: u64,
    pub cached_at: i64,
    pub uploaded: bool,
    pub uploaded_at: Option<i64>,
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub total: i64,
    pub pending: i64,
    pub uploaded: i64,
}

// ============================================================================
// AlertLevel/AlertCategory helpers
// ============================================================================

impl AlertLevel {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => AlertLevel::Info,
            1 => AlertLevel::Low,
            2 => AlertLevel::Medium,
            3 => AlertLevel::High,
            4 => AlertLevel::Critical,
            _ => AlertLevel::Info,
        }
    }
}

impl AlertCategory {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => AlertCategory::System,
            1 => AlertCategory::Security,
            2 => AlertCategory::Network,
            3 => AlertCategory::Process,
            4 => AlertCategory::Service,
            _ => AlertCategory::Custom,
        }
    }
}
