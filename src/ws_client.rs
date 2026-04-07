//! Agent WebSocket 客户端模块
//! 用于从 Manager 接收实时告警推送
//! 协议: 继承 HTTP 基础认证, 通过 WebSocket 升级通道接收告警
//!
//! 使用方式:
//!   1. 与 Manager 建立 HTTP 连接获取认证 token
//!   2. 升级到 WebSocket 连接
//!   3. 接收 Manager 推送的告警事件

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::net::TcpStream;
use std::io::{Read, Write};
use rand::Rng;

use crate::alert::{AlertManager, AlertLevel, AlertCategory};

// ============================================================================
// WebSocket 帧处理 (RFC 6455)
// ============================================================================

/// WebSocket opcode
#[derive(Debug, Clone, Copy)]
pub enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

/// WebSocket 帧
#[derive(Debug)]
pub struct WsFrame {
    pub opcode: OpCode,
    pub payload: Vec<u8>,
}

impl WsFrame {
    /// 解析 WebSocket 帧
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Option<Self>> {
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).is_err() {
            return Ok(None); // 连接关闭
        }

        let opcode_byte = header[0] & 0x0F;
        let opcode = match opcode_byte {
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xA => OpCode::Pong,
            _ => return Ok(None),
        };

        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as usize;

        // 扩展长度 (126 = 16bit, 127 = 64bit)
        if payload_len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext)?;
            payload_len = usize::from(u16::from_be_bytes(ext));
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext)?;
            payload_len = usize::try_from(u64::from_be_bytes(ext))
                .unwrap_or(usize::MAX);
        }

        // 读取 masking key (如果客户端帧)
        let mut mask_key = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask_key)?;
        }

        // 读取 payload
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;

        // 解掩码
        if masked {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask_key[i % 4];
            }
        }

        Ok(Some(WsFrame { opcode, payload }))
    }

    /// 构建 WebSocket 文本帧
    pub fn text_frame(data: &str) -> Vec<u8> {
        Self::build_frame(OpCode::Text, data.as_bytes())
    }

    /// 构建 WebSocket 关闭帧
    pub fn close_frame() -> Vec<u8> {
        Self::build_frame(OpCode::Close, &[])
    }

    /// Ping 帧
    pub fn ping_frame() -> Vec<u8> {
        Self::build_frame(OpCode::Ping, &[])
    }

    fn build_frame(opcode: OpCode, payload: &[u8]) -> Vec<u8> {
        let payload_len = payload.len();
        let mut frame = Vec::with_capacity(2 + payload_len + if payload_len > 65535 { 10 } else if payload_len > 125 { 4 } else { 0 });

        // FIN + opcode
        frame.push(0x80 | (opcode as u8)); // FIN = 1
        // Payload length (服务端发送，不掩码)
        if payload_len > 65535 {
            frame.push(0x7F);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        } else if payload_len > 125 {
            frame.push(0x7E);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(payload_len as u8);
        }
        frame.extend_from_slice(payload);
        frame
    }
}

// ============================================================================
// WebSocket 握手 (HTTP Upgrade)
// ============================================================================

fn ws_handshake(host: &str, port: u16, path: &str) -> std::io::Result<TcpStream> {
    let mut socket = TcpStream::connect(format!("{}:{}", host, port))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;

    let key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        rand_key()
    );

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        path, host, port, key
    );

    socket.write_all(request.as_bytes())?;

    // 读取握手响应
    let mut response = vec![0u8; 1024];
    let n = socket.read(&mut response)?;
    let resp_str = String::from_utf8_lossy(&response[..n]);

    if !resp_str.contains("101 Switching Protocols") && !resp_str.contains("101") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("WebSocket handshake failed: {}", resp_str.lines().next().unwrap_or("unknown")))
        );
    }

    Ok(socket)
}

// FIX 9: Use rand::random for cryptographic randomness
fn rand_key() -> [u8; 16] {
    rand::random()
}

// ============================================================================
// 告警接收器
// ============================================================================

/// 从 Manager WebSocket 推送的告警消息
#[derive(Debug, serde::Deserialize)]
pub struct WsAlertMessage {
    pub alert_id: i64,
    pub agent_id: String,
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source_ip: String,
    pub created_at: String,
}

/// WebSocket 告警接收器
/// 管理与 Manager 的 WebSocket 连接，接收并处理实时告警推送
pub struct WsAlertReceiver {
    host: String,
    port: u16,
    path: String,
    agent_id: String,
    alert_manager: Arc<Mutex<AlertManager>>,
    running: Arc<Mutex<bool>>,
    last_ping: Arc<Mutex<u64>>,
}

impl WsAlertReceiver {
    pub fn new(host: String, port: u16, agent_id: String, alert_manager: Arc<Mutex<AlertManager>>) -> Self {
        Self {
            host,
            port,
            path: "/ws/alerts".to_string(),
            agent_id,
            alert_manager,
            running: Arc::new(Mutex::new(false)),
            last_ping: Arc::new(Mutex::new(0)),
        }
    }

    /// 启动接收循环 (blocking) with exponential backoff
    pub fn run(&self) {
        let mut retry_delay_secs: u64 = 1;
        let max_delay_secs: u64 = 60;
        
        loop {
            match self.connect_and_receive() {
                Ok(()) => {
                    retry_delay_secs = 1;  // Reset on successful connection
                }
                Err(e) => {
                    eprintln!("[WS] Connection error: {}, retrying in {}s (exponential backoff, max {}s)...",
                             e, retry_delay_secs, max_delay_secs);
                    std::thread::sleep(Duration::from_secs(retry_delay_secs));
                    // Exponential backoff: 1, 2, 4, 8, 16, 32, 60, 60, ...
                    retry_delay_secs = (retry_delay_secs * 2).min(max_delay_secs);
                }
            }
        }
    }

    fn connect_and_receive(&self) -> std::io::Result<()> {
        let mut stream = ws_handshake(&self.host, self.port, &self.path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;

        *self.running.lock().unwrap() = true;
        eprintln!("[WS] Connected to Manager at {}:{}", self.host, self.port);

        // 发送订阅消息
        let subscribe = serde_json::json!({
            "type": "subscribe",
            "channels": ["alerts"]
        });
        let msg = WsFrame::text_frame(&subscribe.to_string());
        stream.write_all(&msg)?;
        stream.flush()?;

        loop {
            match WsFrame::parse(&mut stream) {
                Ok(Some(frame)) => {
                    match frame.opcode {
                        OpCode::Text | OpCode::Binary => {
                            if let Ok(text) = String::from_utf8(frame.payload.clone()) {
                                self.handle_message(&text);
                            }
                        }
                        OpCode::Ping => {
                            // 响应 Pong
                            let pong = WsFrame::build_frame(OpCode::Pong, &[]);
                            stream.write_all(&pong)?;
                            stream.flush()?;
                        }
                        OpCode::Pong => {
                            *self.last_ping.lock().unwrap() = crate::protocol::now_timestamp();
                        }
                        OpCode::Close => {
                            eprintln!("[WS] Server closed connection");
                            break;
                        }
                        _ => { }
                    }
                }
                Ok(None) => {
                    eprintln!("[WS] Connection closed");
                    break;
                }
                Err(e) => {
                    eprintln!("[WS] Read error: {}", e);
                    break;
                }
            }
        }

        *self.running.lock().unwrap() = false;
        Ok(())
    }

    fn handle_message(&self, text: &str) {
        // 解析告警消息
        if let Ok(alert_msg) = serde_json::from_str::<WsAlertMessage>(text) {
            let level = match alert_msg.severity.to_lowercase().as_str() {
                "critical" => AlertLevel::Critical,
                "high" => AlertLevel::High,
                "medium" => AlertLevel::Medium,
                "low" => AlertLevel::Low,
                _ => AlertLevel::Info,
            };

            let category = match alert_msg.alert_type.as_str() {
                "security" => AlertCategory::Security,
                "network" => AlertCategory::Network,
                "process" => AlertCategory::Process,
                "service" => AlertCategory::Service,
                _ => AlertCategory::Custom,
            };

            // 通过 AlertManager 发送本地告警
            let am = self.alert_manager.lock().unwrap();
            am.send_alert(
                level,
                category,
                &alert_msg.title,
                &alert_msg.description,
                &format!("ws://{}", alert_msg.agent_id),
            );

            eprintln!(
                "[WS Alert] {} | {} - {} ({})",
                alert_msg.severity,
                alert_msg.title,
                alert_msg.description,
                alert_msg.source_ip
            );
        }
    }
}

// 实现 Debug 以满足 Arc
impl std::fmt::Debug for WsAlertReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WsAlertReceiver {{ host: {}:{}, path: {} }}", self.host, self.port, self.path)
    }
}
