use serde::{Deserialize, Serialize};
use sysinfo::System;

/// 进程信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,           // 可执行文件路径
    pub cmdline: Vec<String>,   // 命令行参数
    pub status: String,         // 运行状态
    pub cpu_usage: f32,        // CPU 使用率 (0-100)
    pub memory_bytes: u64,      // 内存使用量
    pub start_time: u64,       // 启动时间戳
    pub user: String,          // 所属用户
}

/// 进程列表
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessList {
    pub timestamp: u64,
    pub total_count: usize,
    pub processes: Vec<ProcessInfo>,
}

/// 获取进程列表
pub fn get_process_list() -> ProcessList {
    let mut sys = System::new_all();
    sys.refresh_all();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .map(|(pid, process)| {
            ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().to_string(),
                exe: process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                cmdline: process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect(),
                status: format!("{:?}", process.status()),
                cpu_usage: process.cpu_usage(),
                memory_bytes: process.memory(),
                start_time: process.start_time(),
                user: process
                    .user_id()
                    .map(|uid| uid.to_string())
                    .unwrap_or_default(),
            }
        })
        .collect();

    // 按 CPU 使用率降序排列
    processes.sort_by(|a, b| {
        b.cpu_usage
            .partial_cmp(&a.cpu_usage)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_count = processes.len();

    ProcessList {
        timestamp,
        total_count,
        processes,
    }
}

/// 格式化进程状态
pub fn format_process_list(process_list: &ProcessList, top_n: Option<usize>) -> String {
    let processes = if let Some(n) = top_n {
        process_list.processes.iter().take(n).collect::<Vec<_>>()
    } else {
        process_list.processes.iter().collect::<Vec<_>>()
    };

    let mut output = format!(
        "═══════════════════════════════════════════\n\
         时间戳: {} | 总进程数: {}\n\
         ═══════════════════════════════════════════\n",
        process_list.timestamp, process_list.total_count
    );

    output.push_str(&format!(
        "{:<8} {:<20} {:>7} {:>12} {:>10} {:<15}\n",
        "PID", "名称", "CPU%", "内存", "状态", "用户"
    ));
    output.push_str("───────────────────────────────────────────────────\n");

    for proc in processes {
        let mem_str = format_bytes(proc.memory_bytes);
        output.push_str(&format!(
            "{:<8} {:.<20} {:>6.1}% {:>11} {:>10} {:<15}\n",
            proc.pid,
            truncate(&proc.name, 18),
            proc.cpu_usage,
            mem_str,
            truncate(&proc.status, 10),
            truncate(&proc.user, 15)
        ));
    }

    output
}

/// 格式化字节数
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// 截断字符串
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}..", &s[..max_len - 2])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_process_list() {
        let list = get_process_list();
        assert!(list.total_count > 0);
        assert!(!list.processes.is_empty());
    }

    #[test]
    fn test_format_process_list() {
        let list = get_process_list();
        let output = format_process_list(&list, Some(10));
        assert!(!output.is_empty());
    }
}
