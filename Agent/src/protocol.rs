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

/// 生成随机数（简化版）
fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let rs = RandomState::new();
    let mut hasher = rs.build_hasher();
    hasher.write_u64(now_timestamp() as u64);
    hasher.finish() as u32
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
