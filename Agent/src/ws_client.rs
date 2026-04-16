//! WebSocket 客户端模块
//! 通过 WSS (WebSocket over HTTPS) 与 Manager 通信
//! 支持：数据上报、心跳、命令下发、文件传输
//!
//! 注意: 本客户端配置为接受自签名证书，仅用于开发/测试环境
//! 生产环境应使用 Let's Encrypt 证书

use futures_util::{SinkExt, StreamExt};
use native_tls::TlsConnector as NativeTlsConnector;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sysinfo::System;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::{client_async, tungstenite::Message as WsRawMessage};
use url::Url;

use crate::protocol::{
    AgentInfo, CommandPayload, HeartbeatData, ManagerIncoming,
    MessagePayload, ThreatReportPayload,
};

/// WSS 客户端配置
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// 服务端地址 (硬编码)
    pub server_url: String,
    /// Agent ID
    pub agent_id: String,
    /// 连接令牌 (必填)
    pub token: String,
    /// 心跳间隔 (秒)
    pub heartbeat_interval_secs: u64,
    /// 重连延迟 (秒)
    pub reconnect_delay_secs: u64,
    /// 连接超时 (秒)
    pub connection_timeout_secs: u64,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            // 安全修复: 服务端地址硬编码，不允许配置修改
            server_url: "wss://center.xsec.dxp0rt.de5.net/ws".to_string(),
            agent_id: hostname::get()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            token: String::new(),
            heartbeat_interval_secs: 30,
            reconnect_delay_secs: 5,
            connection_timeout_secs: 10,
        }
    }
}

/// 连接状态
#[derive(Debug, Clone, PartialEq)]
pub enum WsConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Error(String),
}

/// WebSocket 消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsMessageType {
    // Agent -> Server
    #[serde(rename = "agent_register")]
    AgentRegister,
    #[serde(rename = "heartbeat")]
    Heartbeat,
    #[serde(rename = "threat_report")]
    ThreatReport,
    #[serde(rename = "command_result")]
    CommandResult,
    #[serde(rename = "file_chunk")]
    FileChunk,
    #[serde(rename = "pong")]
    Pong,

    // Server -> Agent
    #[serde(rename = "command_execute")]
    CommandExecute,
    #[serde(rename = "response_policy")]
    ResponsePolicy,
    #[serde(rename = "config_update")]
    ConfigUpdate,
    #[serde(rename = "agent_control")]
    AgentControl,
    #[serde(rename = "file_transfer")]
    FileTransfer,
    #[serde(rename = "ping")]
    Ping,
}

/// WebSocket 消息结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    #[serde(rename = "type")]
    pub msg_type: WsMessageType,
    pub agent_id: Option<String>,
    pub data: Option<serde_json::Value>,
}

/// 文件分片传输
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub chunk_id: u64,
    pub total_chunks: u64,
    pub filename: String,
    pub data: String,  // Base64 编码
    pub checksum: u32,
    pub action: String,  // "upload" or "download"
}

/// 文件传输元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferMeta {
    pub filename: String,
    pub total_size: u64,
    pub total_chunks: u64,
    pub checksum: u32,
    pub action: String,
}

/// WSS 客户端
pub struct WssClient {
    config: WsConfig,
    state: Arc<Mutex<WsConnectionState>>,
    command_tx: mpsc::Sender<CommandPayload>,
    // 用于发送消息的 channel
    write_tx: Arc<Mutex<Option<mpsc::Sender<String>>>>,
    // 系统监控器 (使用 Arc<Mutex> 以兼容 async)
    sys: Arc<Mutex<System>>,
}

/// 命令结果回调类型
pub type CommandCallback = Box<dyn Fn(CommandPayload) + Send + Sync>;

impl WssClient {
    /// 创建新的 WSS 客户端
    pub fn new(config: WsConfig, command_tx: mpsc::Sender<CommandPayload>) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(WsConnectionState::Disconnected)),
            command_tx,
            write_tx: Arc::new(Mutex::new(None)),
            sys: Arc::new(Mutex::new(System::new_all())),
        }
    }

    /// 启动客户端主循环
    pub async fn run(&self) {
        let mut reconnect_delay = self.config.reconnect_delay_secs;

        loop {
            self.set_state(WsConnectionState::Connecting);

            match self.connect_and_handle().await {
                Ok(_) => {
                    println!("[WSS] 连接正常关闭");
                    reconnect_delay = self.config.reconnect_delay_secs; // 重置延迟
                }
                Err(e) => {
                    eprintln!("[WSS] 连接错误: {}, {:.1}s 后重连...",
                        e, reconnect_delay as f64);
                }
            }

            // 指数退避重连，最大 5 分钟
            tokio::time::sleep(Duration::from_secs(reconnect_delay)).await;
            reconnect_delay = (reconnect_delay * 2).min(300);
        }
    }

    /// 创建接受自签名证书的 TLS 连接器 (tokio-native-tls)
    fn create_insecure_tls_connector(&self) -> Result<TlsConnector, String> {
        let inner = NativeTlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| format!("TLS 连接器创建失败: {}", e))?;
        Ok(TlsConnector::from(inner))
    }

    /// 连接并处理消息
    async fn connect_and_handle(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = Url::parse(&self.config.server_url)
            .map_err(|e| format!("无效的服务器 URL: {}", e))?;

        let domain = url.domain().unwrap_or("localhost");
        let port = url.port().unwrap_or(443);
        let addr = format!("{}:{}", domain, port);

        println!("[WSS] 连接到 {} (domain: {})", self.config.server_url, domain);

        // 创建接受自签名证书的 TLS 连接器
        let tls_connector = self.create_insecure_tls_connector()?;

        // TCP 连接
        let tcp_stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("TCP 连接失败 ({}): {}", addr, e))?;

        // TLS 升级
        let tls_stream = tls_connector.connect(domain, tcp_stream)
            .await
            .map_err(|e| format!("TLS 连接失败: {}", e))?;

        // WebSocket 握手 (client_async 自动处理握手，直接传 URL)
        let (ws_stream, _) = tokio::time::timeout(
            Duration::from_secs(self.config.connection_timeout_secs),
            client_async(url.as_str(), tls_stream),
        )
        .await
        .map_err(|_| "连接超时")?
        .map_err(|e| format!("WebSocket 连接失败: {}", e))?;

        println!("[WSS] 已连接，正在进行 WebSocket 握手...");

        let (mut write, mut read) = ws_stream.split();

        // 发送注册消息
        let register_msg = self.create_register_message();
        let json = serde_json::to_string(&register_msg)
            .map_err(|e| format!("JSON 序列化失败: {}", e))?;
        write.send(WsRawMessage::Text(json.into())).await
            .map_err(|e| format!("发送注册消息失败: {}", e))?;

        self.set_state(WsConnectionState::Authenticated);
        println!("[WSS] 已认证，开始处理消息...");

        // 创建消息发送 channel
        let (msg_tx, mut msg_rx) = mpsc::channel::<String>(100);
        {
            let mut write_lock = self.write_tx.lock().unwrap();
            *write_lock = Some(msg_tx);
        }

        // 消息处理循环
        loop {
            tokio::select! {
                // 接收消息
                msg = read.next() => {
                    match msg {
                        Some(Ok(WsRawMessage::Text(text))) => {
                            if let Err(e) = self.handle_message(&text.to_string()).await {
                                eprintln!("[WSS] 消息处理错误: {}", e);
                            }
                        }
                        Some(Ok(WsRawMessage::Ping(data))) => {
                            // 自动响应 Pong
                            write.send(WsRawMessage::Pong(data)).await.ok();
                        }
                        Some(Ok(WsRawMessage::Close(_))) => {
                            println!("[WSS] 服务端关闭连接");
                            break;
                        }
                        Some(Ok(WsRawMessage::Binary(data))) => {
                            // 处理二进制消息（如文件分片）
                            if let Err(e) = self.handle_binary(&data).await {
                                eprintln!("[WSS] 二进制消息处理错误: {}", e);
                            }
                        }
                        Some(Err(e)) => {
                            eprintln!("[WSS] 接收错误: {}", e);
                            break;
                        }
                        None => {
                            println!("[WSS] 连接已关闭");
                            break;
                        }
                        _ => {}
                    }
                }
                // 处理待发送的消息
                Some(json) = msg_rx.recv() => {
                    if write.send(WsRawMessage::Text(json.into())).await.is_err() {
                        println!("[WSS] 消息发送失败，连接可能已断开");
                        break;
                    }
                }
                // 心跳 (每 30 秒)
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    let heartbeat = self.create_heartbeat_message();
                    if let Ok(json) = serde_json::to_string(&heartbeat) {
                        if write.send(WsRawMessage::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }

        // 清除 write_tx
        {
            let mut write_lock = self.write_tx.lock().unwrap();
            *write_lock = None;
        }

        self.set_state(WsConnectionState::Disconnected);
        Ok(())
    }

    /// 处理接收到的消息
    async fn handle_message(&self, text: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg: WsMessage = serde_json::from_str(text)
            .map_err(|e| format!("JSON 解析失败: {}", e))?;

        match msg.msg_type {
            WsMessageType::Ping => {
                // 收到 Ping，回复 Pong
                println!("[WSS] 收到 Ping");
            }
            WsMessageType::CommandExecute => {
                // 收到命令，执行并返回结果
                if let Some(data) = msg.data {
                    if let Ok(cmd) = serde_json::from_value::<CommandPayload>(data) {
                        println!("[WSS] 收到命令: {} {:?}", cmd.command, cmd.args);
                        // 发送命令到处理队列
                        self.command_tx.send(cmd).await.ok();
                    }
                }
            }
            WsMessageType::ResponsePolicy => {
                println!("[WSS] 收到响应策略更新");
            }
            WsMessageType::ConfigUpdate => {
                println!("[WSS] 收到配置更新");
            }
            WsMessageType::AgentControl => {
                println!("[WSS] 收到控制指令");
            }
            WsMessageType::FileTransfer => {
                println!("[WSS] 收到文件传输请求");
            }
            _ => {
                println!("[WSS] 收到未知类型消息: {:?}", msg.msg_type);
            }
        }

        Ok(())
    }

    /// 处理二进制消息
    async fn handle_binary(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 二进制消息格式: [4字节类型][4字节长度][JSON元数据][二进制数据]
        if data.len() < 8 {
            return Ok(());
        }

        let msg_type = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let json_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

        if data.len() < 8 + json_len {
            return Ok(());
        }

        let json_data = &data[8..8 + json_len];
        let binary_data = &data[8 + json_len..];

        match msg_type {
            0x01 => {
                // 文件分片
                let chunk: FileChunk = serde_json::from_slice(json_data)?;
                println!("[WSS] 收到文件分片: {}/{}", chunk.chunk_id, chunk.total_chunks);
                // 处理文件写入
            }
            _ => {
                println!("[WSS] 收到未知二进制消息类型: {}", msg_type);
            }
        }

        Ok(())
    }

    /// 创建注册消息
    fn create_register_message(&self) -> WsMessage {
        let info = AgentInfo {
            hostname: hostname::get()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            ip: local_ip_address::local_ip()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            mac: crate::protocol::get_mac_address(),
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

        // 构建包含 token 的注册数据
        let register_data = serde_json::json!({
            "info": info,
            "token": self.config.token,
        });

        WsMessage {
            msg_type: WsMessageType::AgentRegister,
            agent_id: Some(self.config.agent_id.clone()),
            data: Some(register_data),
        }
    }

    /// 创建心跳消息 (使用真实系统指标)
    fn create_heartbeat_message(&self) -> WsMessage {
        let mut sys = self.sys.lock().unwrap();
        // 刷新系统信息
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let cpu_percent = sys.global_cpu_usage();
        let memory_percent = if sys.total_memory() > 0 {
            (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0
        } else {
            0.0
        };

        let heartbeat = HeartbeatData {
            status: "online".to_string(),
            cpu_percent,
            memory_percent,
            disk_percent: 0.0,  // 磁盘信息需要额外处理
            network_in: 0,
            network_out: 0,
            active_threats: 0,
            pending_commands: 0,
            environment_info: None,
        };

        WsMessage {
            msg_type: WsMessageType::Heartbeat,
            agent_id: Some(self.config.agent_id.clone()),
            data: Some(serde_json::to_value(heartbeat).unwrap_or_default()),
        }
    }

    /// 发送消息
    pub async fn send(&self, msg: &WsMessage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(msg)
            .map_err(|e| format!("JSON 序列化失败: {}", e))?;

        // 在锁外执行异步操作，避免 MutexGuard 跨越 await
        let tx = {
            let write_lock = self.write_tx.lock().unwrap();
            write_lock.clone()
        };

        if let Some(tx) = tx {
            tx.send(json).await
                .map_err(|e| format!("发送消息失败: {}", e))?;
            Ok(())
        } else {
            Err("WebSocket 未连接".into())
        }
    }

    fn set_state(&self, state: WsConnectionState) {
        *self.state.lock().unwrap() = state;
    }

    /// 获取当前状态
    pub fn get_state(&self) -> WsConnectionState {
        self.state.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_message_serialization() {
        let msg = WsMessage {
            msg_type: WsMessageType::Heartbeat,
            agent_id: Some("test-agent".to_string()),
            data: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"agent_id\":\"test-agent\""));
    }

    #[test]
    fn test_file_chunk_serialization() {
        let chunk = FileChunk {
            chunk_id: 1,
            total_chunks: 10,
            filename: "test.exe".to_string(),
            data: "base64data".to_string(),
            checksum: 12345,
            action: "download".to_string(),
        };

        let json = serde_json::to_string(&chunk).unwrap();
        assert!(json.contains("\"chunk_id\":1"));
        assert!(json.contains("\"filename\":\"test.exe\""));
    }
}
