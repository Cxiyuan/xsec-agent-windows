//! 统一日志模块
//! 
//! 使用 tracing crate 实现结构化日志

use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter, prelude::*};

/// 日志配置
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// 日志目录
    pub log_dir: PathBuf,
    /// 日志级别: trace, debug, info, warn, error
    pub level: String,
    /// 是否输出到控制台
    pub console: bool,
    /// 是否输出到文件
    pub file: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("logs"),
            level: "info".to_string(),
            console: true,
            file: true,
        }
    }
}

/// 初始化日志系统
pub fn init_logging(config: &LogConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 创建日志目录
    std::fs::create_dir_all(&config.log_dir)?;

    // 构建 filter
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    // 根据配置选择输出
    if config.console && config.file {
        // 同时输出到控制台和文件
        let file_path = config.log_dir.join("xsec-agent.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        
        let file_layer = fmt::layer()
            .with_writer(move || file.try_clone().unwrap())
            .with_ansi(false);
        
        let stdout_layer = fmt::layer()
            .with_writer(std::io::stdout);
        
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else if config.console {
        fmt::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(std::io::stdout)
            .init();
    } else if config.file {
        let file_path = config.log_dir.join("xsec-agent.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        
        let file_layer = fmt::layer()
            .with_writer(move || file.try_clone().unwrap())
            .with_ansi(false);
        
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .init();
    }

    tracing::info!("xsec-agent logging initialized");
    tracing::info!("log_dir: {:?}", config.log_dir);
    tracing::info!("level: {}", config.level);

    Ok(())
}

/// 记录安全事件
pub fn log_security_event(event_type: &str, message: &str, details: Option<&str>) {
    match event_type {
        "threat" => {
            if let Some(d) = details {
                tracing::error!("[SECURITY THREAT] {} | Details: {}", message, d);
            } else {
                tracing::error!("[SECURITY THREAT] {}", message);
            }
        },
        "suspicious" => {
            if let Some(d) = details {
                tracing::warn!("[SUSPICIOUS] {} | Details: {}", message, d);
            } else {
                tracing::warn!("[SUSPICIOUS] {}", message);
            }
        },
        "info" => {
            if let Some(d) = details {
                tracing::info!("[SECURITY] {} | Details: {}", message, d);
            } else {
                tracing::info!("[SECURITY] {}", message);
            }
        },
        _ => {
            if let Some(d) = details {
                tracing::info!("[{}] {} | Details: {}", event_type, message, d);
            } else {
                tracing::info!("[{}] {}", event_type, message);
            }
        }
    }
}

/// 记录Agent模块启动/停止
pub fn log_module_event(module: &str, event: &str, details: Option<&str>) {
    match event {
        "start" => {
            tracing::info!("[MODULE:START] {} | {}", module, details.unwrap_or(""));
        },
        "stop" => {
            tracing::info!("[MODULE:STOP] {} | {}", module, details.unwrap_or(""));
        },
        "error" => {
            if let Some(d) = details {
                tracing::error!("[MODULE:ERROR] {} | {}", module, d);
            } else {
                tracing::error!("[MODULE:ERROR] {}", module);
            }
        },
        _ => {
            if let Some(d) = details {
                tracing::info!("[MODULE:{}] {} | {}", event, module, d);
            } else {
                tracing::info!("[MODULE:{}] {}", event, module);
            }
        }
    }
}

/// 记录命令执行
pub fn log_command_execution(command: &str, result: &str, duration_ms: u64) {
    tracing::info!(
        target: "command",
        "[COMMAND] executed: {} ({}ms) | result: {}",
        command,
        duration_ms,
        result
    );
}

/// 记录网络活动
pub fn log_network_activity(action: &str, details: &str) {
    tracing::info!(
        target: "network",
        "[NETWORK] {} | {}",
        action,
        details
    );
}
