//! Agent 通信模块
//! 负责与 Manager 服务端的网络通信

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::protocol::{
    self, AgentInfo, CommandPayload, CommandResultPayload, ConfigPayload,
    ControlPayload, HeartbeatData, Message, MessagePayload, ResponsePolicyPayload,
    StatusPayload, ThreatReportPayload,
};

/// Manager 连接配置
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    pub host: String,
    pub port: u16,
    pub agent_id: String,
    pub secret_key: String,
    pub heartbeat_interval_secs: u64,
    pub reconnect_delay_secs: u64,
    pub connection_timeout_secs: u64,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8443,
            agent_id: hostname::get()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            secret_key: String::new(),
            heartbeat_interval_secs: 30,
            reconnect_delay_secs: 5,
            connection_timeout_secs: 10,
        }
    }
}

/// 连接状态
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Error(String),
}

/// 通信客户端
pub struct Client {
    config: ManagerConfig,
    state: Arc<Mutex<ConnectionState>>,
    stream: Arc<Mutex<Option<TcpStream>>>,
    pending_commands: Arc<Mutex<Vec<CommandPayload>>>,
}

impl Client {
    /// 创建新客户端
    pub fn new(config: ManagerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            stream: Arc::new(Mutex::new(None)),
            pending_commands: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 连接到 Manager
    pub fn connect(&self) -> Result<(), ClientError> {
        self.set_state(ConnectionState::Connecting);

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let socket_addr: std::net::SocketAddr = addr.parse::<std::net::SocketAddr>()
            .map_err(|e| ClientError::InvalidAddress(e.to_string()))?;
        let stream = TcpStream::connect_timeout(
            &socket_addr,
            Duration::from_secs(self.config.connection_timeout_secs),
        )
        .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(self.config.connection_timeout_secs)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(self.config.connection_timeout_secs)))
            .ok();

        *self.stream.lock().unwrap() = Some(stream);

        // 发送注册消息
        self.send_register()?;

        self.set_state(ConnectionState::Connected);
        Ok(())
    }

    /// 断开连接
    pub fn disconnect(&self) {
        if let Some(ref mut stream) = *self.stream.lock().unwrap() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        *self.stream.lock().unwrap() = None;
        self.set_state(ConnectionState::Disconnected);
    }

    /// 发送注册消息
    fn send_register(&self) -> Result<(), ClientError> {
        let info = AgentInfo {
            hostname: hostname::get()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            ip: local_ip_address::local_ip()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: vec![
                "process".to_string(),
                "network".to_string(),
                "service".to_string(),
                "injection".to_string(),
                "hidden".to_string(),
                "startup".to_string(),
                "lineage".to_string(),
                "memfeature".to_string(),
                "realtime".to_string(),
                "response".to_string(),
                "command".to_string(),
            ],
        };

        let msg = protocol::create_register_message(&self.config.agent_id, info);
        self.send_message(&msg)
    }

    /// 发送消息
    pub fn send_message(&self, msg: &Message) -> Result<(), ClientError> {
        let bytes = msg
            .to_bytes()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // 添加消息长度前缀（4字节网络序）
        let len = (bytes.len() as u32).to_be_bytes();
        let mut packet = len.to_vec();
        packet.extend_from_slice(&bytes);

        let mut stream = self.stream.lock().unwrap();
        if let Some(ref mut s) = *stream {
            s.write_all(&packet)
                .map_err(|e| ClientError::SendFailed(e.to_string()))?;
            s.flush()
                .map_err(|e| ClientError::SendFailed(e.to_string()))?;
            Ok(())
        } else {
            Err(ClientError::NotConnected)
        }
    }

    /// 接收消息
    pub fn recv_message(&self) -> Result<Message, ClientError> {
        let mut stream = self.stream.lock().unwrap();
        if let Some(ref mut s) = *stream {
            // 读取消息长度（4字节）
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf)
                .map_err(|e| ClientError::ReceiveFailed(e.to_string()))?;
            let len = u32::from_be_bytes(len_buf) as usize;

            // 读取消息体
            let mut body_buf = vec![0u8; len];
            s.read_exact(&mut body_buf)
                .map_err(|e| ClientError::ReceiveFailed(e.to_string()))?;

            let msg = Message::from_bytes(&body_buf)
                .map_err(|e| ClientError::SerializationError(e.to_string()))?;
            Ok(msg)
        } else {
            Err(ClientError::NotConnected)
        }
    }

    /// 处理接收到的消息
    pub fn handle_message(&self, msg: &Message) -> Result<Option<Message>, ClientError> {
        match &msg.payload {
            MessagePayload::Command(cmd) => {
                // 添加到待执行命令队列
                self.pending_commands.lock().unwrap().push(cmd.clone());
                Ok(None)
            }
            MessagePayload::Policy(policy) => {
                // 更新响应策略
                Ok(Some(self.handle_policy_update(policy)))
            }
            MessagePayload::Config(config) => {
                // 处理配置更新
                Ok(Some(self.handle_config_update(config)))
            }
            MessagePayload::Control(ctrl) => {
                // 处理控制指令
                Ok(Some(self.handle_control(ctrl)))
            }
            _ => Ok(None),
        }
    }

    /// 处理策略更新
    fn handle_policy_update(&self, policy: &ResponsePolicyPayload) -> Message {
        // 通知配置已更新（实际由 response 模块处理）
        Message::new(
            protocol::MsgType::ResponsePolicy,
            &self.config.agent_id,
            MessagePayload::Empty,
        )
    }

    /// 处理配置更新
    fn handle_config_update(&self, config: &ConfigPayload) -> Message {
        // 通知配置已更新
        Message::new(
            protocol::MsgType::ConfigUpdate,
            &self.config.agent_id,
            MessagePayload::Empty,
        )
    }

    /// 处理控制指令
    fn handle_control(&self, ctrl: &ControlPayload) -> Message {
        match ctrl.action.as_str() {
            "stop" => {
                // 准备停止
                self.disconnect();
            }
            "restart" => {
                // 准备重启
            }
            "self_test" => {
                // 自检
            }
            _ => {}
        }
        Message::new(
            protocol::MsgType::AgentControl,
            &self.config.agent_id,
            MessagePayload::Empty,
        )
    }

    /// 获取待执行命令
    pub fn get_pending_commands(&self) -> Vec<CommandPayload> {
        self.pending_commands
            .lock()
            .unwrap()
            .drain(..)
            .collect()
    }

    /// 发送心跳
    pub fn send_heartbeat(&self, data: HeartbeatData) -> Result<(), ClientError> {
        let msg = protocol::create_heartbeat_message(&self.config.agent_id, data);
        self.send_message(&msg)
    }

    /// 发送威胁报告
    pub fn send_threat_report(&self, threat: ThreatReportPayload) -> Result<(), ClientError> {
        let msg = protocol::create_threat_message(&self.config.agent_id, threat);
        self.send_message(&msg)
    }

    /// 发送命令执行结果
    pub fn send_command_result(
        &self,
        session_id: &str,
        result: CommandResultPayload,
    ) -> Result<(), ClientError> {
        let msg =
            protocol::create_command_result_message(&self.config.agent_id, session_id, result);
        self.send_message(&msg)
    }

    /// 发送状态报告
    pub fn send_status_report(&self, status: StatusPayload) -> Result<(), ClientError> {
        let msg = protocol::create_status_message(&self.config.agent_id, status);
        self.send_message(&msg)
    }

    /// 获取连接状态
    pub fn get_state(&self) -> ConnectionState {
        self.state.lock().unwrap().clone()
    }

    fn set_state(&self, state: ConnectionState) {
        *self.state.lock().unwrap() = state;
    }
}

/// 客户端错误类型
#[derive(Debug, Clone, PartialEq)]
pub enum ClientError {
    NotConnected,
    ConnectionFailed(String),
    InvalidAddress(String),
    SendFailed(String),
    ReceiveFailed(String),
    SerializationError(String),
    Timeout,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::NotConnected => write!(f, "Not connected to manager"),
            ClientError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            ClientError::InvalidAddress(e) => write!(f, "Invalid address: {}", e),
            ClientError::SendFailed(e) => write!(f, "Send failed: {}", e),
            ClientError::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            ClientError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            ClientError::Timeout => write!(f, "Connection timeout"),
        }
    }
}

impl std::error::Error for ClientError {}

/// 创建本地回环测试用客户端（不实际连接）
#[cfg(test)]
pub fn create_test_client() -> Client {
    Client::new(ManagerConfig {
        host: "127.0.0.1".to_string(),
        port: 9999,
        agent_id: "test-agent".to_string(),
        secret_key: "test-secret".to_string(),
        heartbeat_interval_secs: 30,
        reconnect_delay_secs: 5,
        connection_timeout_secs: 5,
    })
}
