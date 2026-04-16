//! Agent ↔ Manager 通讯协议
//! 定义消息格式和通信机制

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// 消息类型
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum MsgType {
    // Agent → Manager
    #[serde(rename = "agent_register")]
    AgentRegister,           // Agent 注册
    #[serde(rename = "agent_heartbeat")]
    AgentHeartbeat,           // 心跳
    #[serde(rename = "threat_report")]
    ThreatReport,            // 威胁报告
    #[serde(rename = "command_result")]
    CommandResult,           // 命令执行结果
    #[serde(rename = "response_result")]
    ResponseResult,          // 响应执行结果
    #[serde(rename = "status_report")]
    StatusReport,            // 状态报告
    
    // Manager → Agent
    #[serde(rename = "command_execute")]
    CommandExecute,          // 下发命令
    #[serde(rename = "response_policy")]
    ResponsePolicy,          // 下发响应策略
    #[serde(rename = "config_update")]
    ConfigUpdate,            // 配置更新
    #[serde(rename = "agent_control")]
    AgentControl,            // Agent 控制指令
}

/// 消息头
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MessageHeader {
    pub msg_id: String,          // 消息唯一ID
    pub msg_type: MsgType,        // 消息类型
    pub timestamp: u64,           // 时间戳
    pub agent_id: String,         // Agent ID
    pub session_id: Option<String>, // 会话ID（用于命令请求）
}

/// 消息体
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: MessagePayload,
}

/// Manager -> Agent 消息格式（扁平结构）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ManagerIncoming {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub agent_id: Option<String>,
    pub command_id: Option<String>,
    pub command_type: Option<String>,
    pub args: Option<serde_json::Value>,
    pub policy_id: Option<String>,
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ManagerIncoming {
    pub fn to_message(&self) -> Option<Message> {
        let msg_type = match self.msg_type.as_str() {
            "command_execute" => MsgType::CommandExecute,
            "response_policy" => MsgType::ResponsePolicy,
            "config_update" => MsgType::ConfigUpdate,
            "agent_control" => MsgType::AgentControl,
            _ => return None,
        };
        let agent_id = self.agent_id.clone().unwrap_or_default();
        let payload = match msg_type {
            MsgType::CommandExecute => {
                let cmd_payload = CommandPayload {
                    command_id: self.command_id.clone().unwrap_or_default(),
                    command: self.command_type.clone().unwrap_or_default(),
                    args: self.args.as_ref().and_then(|v| {
                        if let serde_json::Value::Array(arr) = v {
                            Some(arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        } else { None }
                    }).unwrap_or_default(),
                    timeout_secs: 60,
                    priority: 50,
                };
                MessagePayload::Command(cmd_payload)
            }
            MsgType::ResponsePolicy => MessagePayload::Policy(ResponsePolicyPayload {
                policy_id: self.policy_id.clone().unwrap_or_default(),
                rules: vec![],
                global_mode: "auto".to_string(),
            }),
            MsgType::ConfigUpdate => MessagePayload::Config(ConfigPayload {
                config_key: self.data.as_ref().and_then(|d| d.get("config_key")).and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                config_value: self.data.as_ref().and_then(|d| d.get("config_value")).and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                restart_required: self.data.as_ref().and_then(|d| d.get("restart_required")).and_then(|v| v.as_bool()).unwrap_or(false),
            }),
            MsgType::AgentControl => MessagePayload::Control(ControlPayload {
                action: self.data.as_ref().and_then(|d| d.get("action")).and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                args: None,
            }),
            _ => MessagePayload::Empty,
        };
        Some(Message::new(msg_type, &agent_id, payload))
    }
}

/// 将 Message 转换为 Manager 期望的扁平 JSON 格式
impl Message {
    pub fn to_manager_json(&self) -> Result<String, serde_json::Error> {
        let msg_type = match &self.header.msg_type {
            MsgType::AgentRegister => "agent_register",
            MsgType::AgentHeartbeat => "heartbeat",
            MsgType::ThreatReport => "threat_report",
            MsgType::CommandResult => "command_result",
            MsgType::ResponseResult => "response_result",
            MsgType::StatusReport => "status_report",
            MsgType::CommandExecute => "command_execute",
            MsgType::ResponsePolicy => "response_policy",
            MsgType::ConfigUpdate => "config_update",
            MsgType::AgentControl => "agent_control",
        };
        let mut map = serde_json::Map::new();
        map.insert("type".to_string(), serde_json::Value::String(msg_type.to_string()));
        map.insert("agent_id".to_string(), serde_json::Value::String(self.header.agent_id.clone()));
        match &self.payload {
            MessagePayload::Register(info) => {
                map.insert("hostname".to_string(), serde_json::Value::String(info.hostname.clone()));
                map.insert("ip".to_string(), serde_json::Value::String(info.ip.clone()));
                map.insert("mac".to_string(), serde_json::Value::String(info.mac.clone()));
                map.insert("os".to_string(), serde_json::Value::String(info.os.clone()));
                map.insert("arch".to_string(), serde_json::Value::String(info.arch.clone()));
                map.insert("version".to_string(), serde_json::Value::String(info.version.clone()));
            }
            MessagePayload::Heartbeat(data) => {
                map.insert("status".to_string(), serde_json::Value::String(data.status.clone()));
                map.insert("cpu_percent".to_string(), serde_json::json!(data.cpu_percent));
                map.insert("memory_percent".to_string(), serde_json::json!(data.memory_percent));
                map.insert("disk_percent".to_string(), serde_json::json!(data.disk_percent));
                map.insert("network_in".to_string(), serde_json::json!(data.network_in));
                map.insert("network_out".to_string(), serde_json::json!(data.network_out));
                map.insert("active_threats".to_string(), serde_json::json!(data.active_threats));
                map.insert("pending_commands".to_string(), serde_json::json!(data.pending_commands));
                if let Some(ref env) = data.environment_info {
                    map.insert("environment_info".to_string(), serde_json::json!(env));
                }
            }
            MessagePayload::Threat(threat) => {
                let mut data = serde_json::Map::new();
                data.insert("alert_type".to_string(), serde_json::Value::String(threat.threat_type.clone()));
                data.insert("severity".to_string(), serde_json::Value::String(threat.severity.to_string()));
                data.insert("title".to_string(), serde_json::Value::String(threat.title.clone()));
                data.insert("description".to_string(), serde_json::Value::String(threat.description.clone()));
                if let Some(pid) = threat.pid { data.insert("pid".to_string(), serde_json::json!(pid)); }
                if let Some(ref name) = threat.process_name { data.insert("process_name".to_string(), serde_json::Value::String(name.clone())); }
                if let Some(ref src_ip) = threat.source_ip { data.insert("source_ip".to_string(), serde_json::Value::String(src_ip.clone())); }
                if let Some(ref dst_ip) = threat.target_ip { data.insert("target_ip".to_string(), serde_json::Value::String(dst_ip.clone())); }
                map.insert("data".to_string(), serde_json::Value::Object(data));
            }
            MessagePayload::CommandResult(result) => {
                let mut data = serde_json::Map::new();
                data.insert("command_id".to_string(), serde_json::Value::String(result.command_id.clone()));
                data.insert("success".to_string(), serde_json::Value::Bool(result.success));
                data.insert("exit_code".to_string(), serde_json::json!(result.exit_code));
                data.insert("stdout".to_string(), serde_json::Value::String(result.stdout.clone()));
                data.insert("stderr".to_string(), serde_json::Value::String(result.stderr.clone()));
                data.insert("duration_ms".to_string(), serde_json::json!(result.duration_ms));
                map.insert("data".to_string(), serde_json::Value::Object(data));
            }
            MessagePayload::ResponseResult(result) => {
                let mut data = serde_json::Map::new();
                data.insert("policy_id".to_string(), serde_json::Value::String(result.rule_id.clone()));
                data.insert("action".to_string(), serde_json::Value::String(result.action.clone()));
                data.insert("success".to_string(), serde_json::Value::Bool(result.success));
                data.insert("message".to_string(), serde_json::Value::String(result.message.clone()));
                data.insert("target".to_string(), serde_json::Value::String(result.target.clone()));
                map.insert("data".to_string(), serde_json::Value::Object(data));
            }
            _ => {}
        }
        serde_json::to_string(&serde_json::Value::Object(map))
    }
}

/// 消息负载
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum MessagePayload {
    // Agent → Manager
    Register(AgentInfo),
    Heartbeat(HeartbeatData),
    Threat(ThreatReportPayload),
    CommandResult(CommandResultPayload),
    ResponseResult(ResponseResultPayload),
    Status(StatusPayload),
    
    // Manager → Agent
    Command(CommandPayload),
    Policy(ResponsePolicyPayload),
    Config(ConfigPayload),
    Control(ControlPayload),
    
    // 通用
    Empty,
}

/// Agent 注册信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentInfo {
    pub hostname: String,
    pub ip: String,
    pub mac: String,           // MAC 地址
    pub os: String,            // "linux" / "windows"
    pub arch: String,          // "x86_64" / "aarch64"
    pub version: String,       // Agent 版本
    pub capabilities: Vec<String>, // 支持的能力列表
}

/// 心跳数据
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatData {
    pub status: String,        // "online" / "busy" / "error"
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub disk_percent: f32,
    pub network_in: u64,        // bytes
    pub network_out: u64,      // bytes
    pub active_threats: u32,
    pub pending_commands: u32,
    pub environment_info: Option<EnvironmentInfo>,
}

/// 环境详细信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvironmentInfo {
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub cpu_frequency: String,
    pub memory_total: u64,
    pub memory_usable: u64,
    pub disk_info: Vec<DiskInfo>,
    pub ports: Vec<PortInfo>,
    pub os_version: String,
    pub kernel: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount: String,
    pub total: u64,
    pub available: u64,
    pub used: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortInfo {
    pub protocol: String,
    pub port: u16,
    pub program: String,
    pub pid: u32,
}

/// 威胁报告
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatReportPayload {
    pub threat_type: String,   // "cryptominer" / "backdoor" / etc.
    pub severity: u8,           // 0-100
    pub title: String,
    pub description: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
    pub raw_data: String,      // 原始数据 JSON
}

/// 命令执行请求（Manager → Agent）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandPayload {
    pub command_id: String,    // 命令唯一ID
    pub command: String,        // 命令类型
    pub args: Vec<String>,     // 参数
    pub timeout_secs: u64,     // 超时时间
    pub priority: u8,          // 优先级 0-100
}

/// 命令执行结果（Agent → Manager）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandResultPayload {
    pub command_id: String,    // 对应的命令ID
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// 响应策略（Manager → Agent）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponsePolicyPayload {
    pub policy_id: String,
    pub rules: Vec<PolicyRule>,
    pub global_mode: String,   // "disabled" / "log_only" / "auto" / "force"
}

/// 策略规则
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyRule {
    pub rule_id: String,
    pub name: String,
    pub threat_pattern: String,
    pub min_severity: u8,
    pub actions: Vec<String>,
    pub level: String,
    pub enabled: bool,
}

/// 响应结果（Agent → Manager）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseResultPayload {
    pub rule_id: String,
    pub action: String,
    pub success: bool,
    pub message: String,
    pub target: String,        // 影响的目标 (PID/IP/Username等)
}

/// 配置更新（Manager → Agent）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigPayload {
    pub config_key: String,
    pub config_value: String,
    pub restart_required: bool,
}

/// Agent 控制指令（Manager → Agent）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlPayload {
    pub action: String,        // "stop" / "restart" / "update" / "self_test"
    pub args: Option<Vec<String>>,
}

/// 状态报告
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatusPayload {
    pub module_status: Vec<ModuleStatus>,
    pub statistics: Statistics,
}

/// 模块状态
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ModuleStatus {
    pub name: String,
    pub enabled: bool,
    pub status: String,        // "running" / "stopped" / "error"
    pub last_run: u64,
}

/// 统计信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Statistics {
    pub threats_detected: u32,
    pub threats_blocked: u32,
    pub commands_executed: u32,
    pub responses_triggered: u32,
    pub uptime_secs: u64,
}

// =============================================================================
// 消息构建辅助函数
// =============================================================================

impl Message {
    /// 创建新消息
    pub fn new(msg_type: MsgType, agent_id: &str, payload: MessagePayload) -> Self {
        Self {
            header: MessageHeader {
                msg_id: generate_msg_id(),
                msg_type,
                timestamp: now_timestamp(),
                agent_id: agent_id.to_string(),
                session_id: None,
            },
            payload,
        }
    }

    /// 创建带会话ID的消息
    pub fn with_session(msg_type: MsgType, agent_id: &str, session_id: &str, payload: MessagePayload) -> Self {
        Self {
            header: MessageHeader {
                msg_id: generate_msg_id(),
                msg_type,
                timestamp: now_timestamp(),
                agent_id: agent_id.to_string(),
                session_id: Some(session_id.to_string()),
            },
            payload,
        }
    }

    /// 序列化消息为 JSON 字节
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// 从 JSON 字节反序列化消息
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// 生成唯一消息ID
pub fn generate_msg_id() -> String {
    let timestamp = now_timestamp();
    let random: u32 = rand_u32();
    format!("{:}-{:}", timestamp, random)
}

/// 生成随机数（使用加密安全的随机数生成器）
fn rand_u32() -> u32 {
    rand::random::<u32>()
}

/// 获取当前时间戳
pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 创建 Agent 注册消息
pub fn create_register_message(agent_id: &str, info: AgentInfo) -> Message {
    Message::new(MsgType::AgentRegister, agent_id, MessagePayload::Register(info))
}

/// 获取本机 MAC 地址
pub fn get_mac_address() -> String {
    // 尝试获取第一个非-loopback 网卡的 MAC 地址
    #[cfg(target_os = "linux")]
    {
        // 读取 /sys/class/net/*/address
        if let Ok(interfaces) = std::fs::read_dir("/sys/class/net") {
            for iface in interfaces.flatten() {
                if let Ok(name) = std::fs::read_to_string(iface.path().join("name")) {
                    let name = name.trim();
                    if name != "lo" {  // 跳过 loopback
                        if let Ok(addr) = std::fs::read_to_string(iface.path().join("address")) {
                            let mac = addr.trim().to_uppercase();
                            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                                return mac;
                            }
                        }
                    }
                }
            }
        }
        "00:00:00:00:00:00".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        // Windows 上使用 getmac 或读取注册表
        // 简化处理，返回空字符串
        "00:00:00:00:00:00".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        "00:00:00:00:00:00".to_string()
    }
}

/// 创建 Agent 注册消息（简便版本）
pub fn create_register_message_simple(agent_id: &str, hostname: &str) -> Message {
    let info = AgentInfo {
        hostname: hostname.to_string(),
        ip: local_ip_address::local_ip().map(|s| s.to_string()).unwrap_or_else(|_| "127.0.0.1".to_string()),
        mac: get_mac_address(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            "process".to_string(), "network".to_string(), "service".to_string(),
            "injection".to_string(), "hidden".to_string(), "startup".to_string(),
            "lineage".to_string(), "memfeature".to_string(), "realtime".to_string(),
            "response".to_string(), "command".to_string(),
        ],
    };
    Message::new(MsgType::AgentRegister, agent_id, MessagePayload::Register(info))
}

/// 创建心跳消息
pub fn create_heartbeat_message(agent_id: &str, data: HeartbeatData) -> Message {
    Message::new(MsgType::AgentHeartbeat, agent_id, MessagePayload::Heartbeat(data))
}

/// 创建威胁报告消息
pub fn create_threat_message(agent_id: &str, threat: ThreatReportPayload) -> Message {
    Message::new(MsgType::ThreatReport, agent_id, MessagePayload::Threat(threat))
}

/// 创建命令执行结果消息
pub fn create_command_result_message(agent_id: &str, session_id: &str, result: CommandResultPayload) -> Message {
    Message::with_session(MsgType::CommandResult, agent_id, session_id, MessagePayload::CommandResult(result))
}

/// 创建响应结果消息
pub fn create_response_result_message(agent_id: &str, result: ResponseResultPayload) -> Message {
    Message::new(MsgType::ResponseResult, agent_id, MessagePayload::ResponseResult(result))
}

/// 创建状态报告消息
pub fn create_status_message(agent_id: &str, status: StatusPayload) -> Message {
    Message::new(MsgType::StatusReport, agent_id, MessagePayload::Status(status))
}

/// 格式化消息为可读字符串
pub fn format_message(msg: &Message) -> String {
    format!(
        "📨 消息\n\
         类型: {:?}\n\
         Agent: {}\n\
         时间: {}\n\
         ID: {}",
        msg.header.msg_type,
        msg.header.agent_id,
        msg.header.timestamp,
        msg.header.msg_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = create_register_message("agent-001", AgentInfo {
            hostname: "test-host".to_string(),
            ip: "192.168.1.100".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            version: "0.1.0".to_string(),
            capabilities: vec!["process".to_string(), "network".to_string()],
        });

        let bytes = msg.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        
        assert_eq!(msg.header.agent_id, parsed.header.agent_id);
    }
}
