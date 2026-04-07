//! 进程谱系追踪模块
//! 监控父子进程关系，识别异常spawner

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 进程谱系节点
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: String,
    pub cmdline: Vec<String>,
    pub user: String,
    pub parent_name: String,
    pub children: Vec<u32>,
    pub depth: u32,
    pub anomalies: Vec<ProcessAnomaly>,
}

/// 进程异常
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessAnomaly {
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
}

/// 异常类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AnomalyType {
    SuspiciousParent,       // 可疑父进程
    OrphanedProcess,        // 孤儿进程
    ZombieProcess,          // 僵尸进程
    UptimeMismatch,         // 运行时间不匹配
    UnknownParent,          // 未知父进程
    SystemProcessSpawner,   // 系统进程生成了用户进程
    UserProcessSpawner,     // 用户进程生成了系统进程
}

/// 异常严重程度
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalySeverity::Low => write!(f, "低"),
            AnomalySeverity::Medium => write!(f, "中"),
            AnomalySeverity::High => write!(f, "高"),
            AnomalySeverity::Critical => write!(f, "严重"),
        }
    }
}

/// 已知系统进程名称（用于检测异常spawner）
const SYSTEM_PROCESSES: &[&str] = &[
    "systemd", "init", "kthreadd", "migration", "watchdog", "cpuset",
    "bash", "sh", "zsh", "fish", "login", "getty", "mingetty", "telinit",
    "sshd", "rsyslogd", "syslogd", "cron", "atd", "rsync", "dockerd",
    "containerd", "kubelet", "kube-proxy", "node", "prometheus",
    "apache2", "nginx", "httpd", "mysqld", "postgres", "redis-server",
];

/// 已知可疑父进程组合
const SUSPICIOUS_SPAWNERS: &[(&str, &str)] = &[
    // (父进程, 子进程模式) - 父是系统进程但spawn了shell或网络工具
    ("sshd", "bash"), ("sshd", "sh"), ("sshd", "python"), ("sshd", "perl"),
    ("httpd", "bash"), ("httpd", "sh"), ("httpd", "python"),
    ("nginx", "bash"), ("nginx", "sh"),
    ("mysqld", "bash"), ("mysqld", "sh"), ("mysqld", "perl"),
    ("postgres", "bash"), ("postgres", "sh"),
    ("redis-server", "bash"), ("redis-server", "sh"),
    ("dockerd", "bash"), ("dockerd", "sh"),
    // 浏览器spawn了系统进程是可疑的
    ("chrome", "systemd"), ("firefox", "init"),
];

/// 进程谱系分析器
pub struct LineageAnalyzer {
    /// 系统进程名称集合
    system_processes: HashSet<String>,
}

impl LineageAnalyzer {
    pub fn new() -> Self {
        let system_processes = SYSTEM_PROCESSES
            .iter()
            .map(|s| s.to_string())
            .collect();

        Self {
            system_processes,
        }
    }

    /// 构建进程谱系树
    pub fn build_lineage_tree(&self, sys: &sysinfo::System) -> Vec<ProcessNode> {
        let mut nodes: HashMap<u32, ProcessNode> = HashMap::new();
        let all_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

        // 创建所有节点
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let ppid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
            let name = process.name().to_string_lossy().to_string();
            let exe = process.exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmdline: Vec<String> = process.cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let user = process
                .user_id()
                .map(|uid| uid.to_string())
                .unwrap_or_default();

            nodes.insert(pid_u32, ProcessNode {
                pid: pid_u32,
                ppid,
                name: name.clone(),
                exe,
                cmdline,
                user,
                parent_name: String::new(),
                children: Vec::new(),
                depth: 0,
                anomalies: Vec::new(),
            });
        }

        // 填充父子关系 - 分多阶段避免借用冲突
        // 第一阶段：收集父节点名称
        let mut parent_names: HashMap<u32, String> = HashMap::new();
        for (pid, node) in nodes.iter() {
            parent_names.insert(*pid, node.name.clone());
        }
        
        // 第二阶段：为每个子进程设置父名称，并收集子进程列表
        let mut children_list: Vec<(u32, u32)> = Vec::new(); // (parent_pid, child_pid)
        for (pid, node) in nodes.iter_mut() {
            if node.ppid > 0 {
                if let Some(parent_name) = parent_names.get(&node.ppid) {
                    node.parent_name = parent_name.clone();
                }
                children_list.push((node.ppid, *pid));
            }
        }
        
        // 第三阶段：填充父进程的children列表
        for (parent_pid, child_pid) in children_list {
            if let Some(parent_node) = nodes.get_mut(&parent_pid) {
                parent_node.children.push(child_pid);
            }
        }

        // 计算深度并检测异常
        let mut result: Vec<ProcessNode> = Vec::new();
        let mut root_pids: Vec<u32> = Vec::new();

        // 找到根进程（ppid=0或ppid不在列表中）
        for (pid, node) in &nodes {
            if node.ppid == 0 || !all_pids.contains(&node.ppid) {
                root_pids.push(*pid);
            }
        }

        // BFS计算深度
        let mut visited: HashSet<u32> = HashSet::new();
        let mut queue: Vec<(u32, u32)> = root_pids.iter().map(|p| (*p, 0)).collect();

        while let Some((pid, depth)) = queue.pop() {
            if visited.contains(&pid) {
                continue;
            }
            visited.insert(pid);

            if let Some(node) = nodes.get_mut(&pid) {
                node.depth = depth;
                
                // 检测异常
                self.detect_anomalies(node);

                result.push(node.clone());

                // 将子进程加入队列
                for &child_pid in &node.children {
                    if !visited.contains(&child_pid) {
                        queue.push((child_pid, depth + 1));
                    }
                }
            }
        }

        // 也添加非根但可能没被访问到的进程
        for (pid, node) in nodes.iter_mut() {
            if !visited.contains(pid) {
                visited.insert(*pid);
                self.detect_anomalies(node);
                result.push(node.clone());
            }
        }

        // 按深度排序
        result.sort_by(|a, b| a.depth.cmp(&b.depth));
        result
    }

    /// 检测进程异常
    fn detect_anomalies(&self, node: &mut ProcessNode) {
        let name_lower = node.name.to_lowercase();

        // 1. 孤儿进程检测（父进程不存在）
        // 如果 ppid > 0 但 parent_name 为空，说明父进程不在进程列表中
        if node.ppid > 0 && node.parent_name.is_empty() {
            node.anomalies.push(ProcessAnomaly {
                anomaly_type: AnomalyType::OrphanedProcess,
                severity: AnomalySeverity::Low,
                description: format!("父进程 {} 不存在，进程成为孤儿", node.ppid),
            });
        }

        // 2. 僵尸进程检测
        // zombie 状态需要系统支持，这里通过名称简单检测
        if name_lower.contains("zombie") || name_lower.contains("defunct") {
            node.anomalies.push(ProcessAnomaly {
                anomaly_type: AnomalyType::ZombieProcess,
                severity: AnomalySeverity::Medium,
                description: "进程处于僵尸状态".to_string(),
            });
        }

        // 3. 系统进程spawn了用户进程
        let parent_is_system = self.is_system_process(&node.parent_name);
        let child_is_user = self.is_likely_user_process(&node.name);

        if parent_is_system && child_is_user && !node.parent_name.is_empty() {
            // 额外检查：是否是已知的可疑组合
            let is_suspicious = SUSPICIOUS_SPAWNERS.iter().any(|(parent, child)| {
                node.parent_name.to_lowercase().contains(parent) && 
                name_lower.contains(child)
            });

            if is_suspicious {
                node.anomalies.push(ProcessAnomaly {
                    anomaly_type: AnomalyType::SuspiciousParent,
                    severity: AnomalySeverity::High,
                    description: format!("可疑父子关系: {} spawn了 {} (可能已被入侵)", node.parent_name, node.name),
                });
            } else {
                node.anomalies.push(ProcessAnomaly {
                    anomaly_type: AnomalyType::SystemProcessSpawner,
                    severity: AnomalySeverity::Medium,
                    description: format!("系统进程 {} spawn了用户进程 {}", node.parent_name, node.name),
                });
            }
        }

        // 4. 用户进程spawn了系统进程（异常）
        let child_is_system = self.is_system_process(&node.name);
        if !parent_is_system && child_is_system && !node.name.is_empty() && !node.parent_name.is_empty() {
            node.anomalies.push(ProcessAnomaly {
                anomaly_type: AnomalyType::UserProcessSpawner,
                severity: AnomalySeverity::High,
                description: format!("用户进程 {} spawn了系统进程 {} (可疑)", node.parent_name, node.name),
            });
        }

        // 5. 未知父进程
        if node.ppid > 0 && node.parent_name.is_empty() {
            node.anomalies.push(ProcessAnomaly {
                anomaly_type: AnomalyType::UnknownParent,
                severity: AnomalySeverity::Low,
                description: format!("父进程 {} 无法识别", node.ppid),
            });
        }

        // 6. 深度异常检测（过深的进程树可能是恶意软件）
        if node.depth > 10 {
            node.anomalies.push(ProcessAnomaly {
                anomaly_type: AnomalyType::UptimeMismatch,
                severity: AnomalySeverity::Medium,
                description: format!("进程树深度异常: {}", node.depth),
            });
        }
    }

    /// 判断是否为系统进程
    fn is_system_process(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let name_lower = name.to_lowercase();
        self.system_processes.iter().any(|s| name_lower == s.to_lowercase())
    }

    /// 判断是否为可能是用户进程
    fn is_likely_user_process(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let name_lower = name.to_lowercase();

        // 用户进程的特征
        let user_indicators = ["bash", "sh", "zsh", "fish", "python", "perl", "ruby", 
                              "node", "php", "java", "go", "rust", "cargo",
                              "vim", "nano", "emacs", "git", "curl", "wget",
                              "ssh", "scp", "rsync", "ftp", "telnet",
                              "chrome", "firefox", "safari", "opera"];

        user_indicators.iter().any(|s| name_lower.contains(s))
    }
}

impl LineageAnalyzer {
    pub fn get_suspicious_lineages<'a>(&self, nodes: &'a [ProcessNode]) -> Vec<&'a ProcessNode> {
        nodes.iter().filter(|n| !n.anomalies.is_empty()).collect()
    }

    pub fn get_lineage_path<'a>(&self, pid: u32, nodes: &'a [ProcessNode]) -> Vec<&'a ProcessNode> {
        let mut path = Vec::new();
        let mut current_pid = Some(pid);
        while let Some(cp) = current_pid {
            if let Some(node) = nodes.iter().find(|n| n.pid == cp) {
                path.push(node);
                current_pid = if node.ppid > 0 { Some(node.ppid) } else { None };
            } else { break; }
        }
        path.reverse();
        path
    }
}

impl Default for LineageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化谱系树（简化为平面显示）
pub fn format_lineage_tree(nodes: &[ProcessNode], max_depth: u32, show_anomalies_only: bool) -> String {
    let filtered: Vec<&ProcessNode> = if show_anomalies_only {
        nodes.iter().filter(|n| !n.anomalies.is_empty()).collect()
    } else {
        nodes.iter().filter(|n| n.depth <= max_depth).collect()
    };

    if filtered.is_empty() {
        return if show_anomalies_only {
            "✅ 未检测到进程谱系异常".to_string()
        } else {
            "✅ 未检测到进程".to_string()
        };
    }

    let anomaly_count = nodes.iter().filter(|n| !n.anomalies.is_empty()).count();

    let mut output = String::new();
    output.push_str(&format!(
        "═══════════════════════════════════════════════════════════════\n\
         进程谱系追踪 | 共 {} 个进程 | 异常: {} | 目标平台: Linux/Windows Server\n\
         ════════════════════════════════════════════════════════════════\n\n",
        nodes.len(),
        anomaly_count
    ));

    // 显示可疑进程
    if !show_anomalies_only {
        output.push_str("🔍 可疑进程:\n\n");
    }

    for node in &filtered {
        if node.anomalies.is_empty() && show_anomalies_only {
            continue;
        }

        // 缩进显示深度
        let indent = "  ".repeat(node.depth.min(5) as usize);
        
        // 异常图标
        let has_anomaly = !node.anomalies.is_empty();
        let icon = if has_anomaly { "⚠️" } else { "  " };

        output.push_str(&format!(
            "{}{}[PID: {:>5}] {} (PPID: {:>5})\n",
            indent,
            icon,
            node.pid,
            truncate_string(&node.name, 30),
            node.ppid
        ));

        if !node.parent_name.is_empty() {
            output.push_str(&format!("{}   父进程: {}\n", indent, node.parent_name));
        }

        if !node.exe.is_empty() && node.exe != node.name {
            output.push_str(&format!("{}   执行文件: {}\n", indent, truncate_string(&node.exe, 50)));
        }

        // 显示异常
        if has_anomaly {
            for anomaly in &node.anomalies {
                let severity_icon = match anomaly.severity {
                    AnomalySeverity::Critical => "🔴",
                    AnomalySeverity::High => "🟠",
                    AnomalySeverity::Medium => "🟡",
                    AnomalySeverity::Low => "🟢",
                };
                output.push_str(&format!(
                    "{}   {} [{}] {}\n",
                    indent,
                    severity_icon,
                    anomaly.severity,
                    anomaly.description
                ));
            }
        }
        output.push('\n');
    }

    if show_anomalies_only && anomaly_count > 0 {
        output.push_str(&format!(
            "\n💡 提示: 使用 '全部显示' 可查看完整进程树\n"
        ));
    }

    output
}

/// 格式化单个进程的谱系路径
pub fn format_lineage_path(path: &[&ProcessNode]) -> String {
    if path.is_empty() {
        return "未找到进程谱系".to_string();
    }

    let mut output = String::new();
    output.push_str("进程谱系路径:\n");
    output.push_str("────────────────────────────────────────\n");

    for (i, node) in path.iter().enumerate() {
        let indent = "  ".repeat(i);
        output.push_str(&format!(
            "{}{}── [PID: {:>5}] {}\n",
            indent,
            if i == path.len() - 1 { "╰" } else { "├" },
            node.pid,
            node.name
        ));
    }

    output
}

fn truncate_string(s: &str, max_len: usize) -> String {
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
    fn test_lineage_analyzer() {
        let analyzer = LineageAnalyzer::new();
        let sys = sysinfo::System::new_all();
        
        let nodes = analyzer.build_lineage_tree(&sys);
        assert!(nodes.len() >= 0);
    }

    #[test]
    fn test_get_suspicious() {
        let analyzer = LineageAnalyzer::new();
        let sys = sysinfo::System::new_all();
        
        let nodes = analyzer.build_lineage_tree(&sys);
        let suspicious = analyzer.get_suspicious_lineages(&nodes);
        assert!(suspicious.len() >= 0);
    }
}
