//! USB设备控制模块
//! 监控USB设备插入/拔出，执行白名单/黑名单策略，自动隔离未授权设备

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::alert::{Alert, AlertLevel, AlertCategory};

/// USB设备类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UsbDeviceType {
    Storage,      // U盘/移动硬盘
    Keyboard,     // 键盘
    Mouse,        // 鼠标
    Network,      // 网卡
    Audio,        // 音频设备
    Printer,      // 打印机
    Camera,       // 摄像头
    Other,        // 其他
}

impl std::fmt::Display for UsbDeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbDeviceType::Storage => write!(f, "存储设备"),
            UsbDeviceType::Keyboard => write!(f, "键盘"),
            UsbDeviceType::Mouse => write!(f, "鼠标"),
            UsbDeviceType::Network => write!(f, "网卡"),
            UsbDeviceType::Audio => write!(f, "音频设备"),
            UsbDeviceType::Printer => write!(f, "打印机"),
            UsbDeviceType::Camera => write!(f, "摄像头"),
            UsbDeviceType::Other => write!(f, "其他"),
        }
    }
}

/// USB设备信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vid: String,
    pub pid: String,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub device_type: UsbDeviceType,
    pub bus: Option<String>,
    pub device_path: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub is_authorized: bool,
    pub is_connected: bool,
}

/// USB控制策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPolicy {
    pub enabled: bool,
    /// 存储设备控制: "allow", "block", "隔离"
    pub storage_action: String,
    /// 网络设备控制
    pub network_action: String,
    /// 其他设备控制
    pub other_action: String,
    /// 白名单（允许的VID:PID列表）
    pub whitelist: Vec<String>,
    /// 黑名单（禁止的VID:PID列表）
    pub blacklist: Vec<String>,
    /// 是否启用设备隔离（将未授权设备重定向到沙箱）
    pub isolation_enabled: bool,
    /// 敏感接口告警
    pub sensitive_interface_alert: bool,
}

impl Default for UsbPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_action: "allow".to_string(),
            network_action: "alert".to_string(),
            other_action: "allow".to_string(),
            whitelist: vec![],
            blacklist: vec![],
            isolation_enabled: false,
            sensitive_interface_alert: true,
        }
    }
}

/// USB事件类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsbEventType {
    Inserted,
    Removed,
    Authorized,
    Blocked,
    Isolated,
}

/// USB事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEvent {
    pub event_type: UsbEventType,
    pub device: UsbDevice,
    pub timestamp: u64,
    pub action_taken: Option<String>,
    pub policy_rule: Option<String>,
}

/// USB设备管理器
pub struct UsbController {
    devices: Arc<Mutex<HashMap<String, UsbDevice>>>,
    policy: Arc<Mutex<UsbPolicy>>,
    events: Arc<Mutex<Vec<UsbEvent>>>,
    alerted_devices: Arc<Mutex<HashMap<String, bool>>>,
}

impl UsbController {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            policy: Arc::new(Mutex::new(UsbPolicy::default())),
            events: Arc::new(Mutex::new(Vec::new())),
            alerted_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 生成设备唯一键
    fn device_key(vid: &str, pid: &str, serial: Option<&str>) -> String {
        match serial {
            Some(s) => format!("{}:{}:{}", vid, pid, s),
            None => format!("{}:{}", vid, pid),
        }
    }

    /// 解析设备类型（基于设备路径和ID）
    fn infer_device_type(vid: &str, pid: &str, product: Option<&str>, device_path: Option<&str>) -> UsbDeviceType {
        let vid_pid = format!("{}:{}", vid.to_lowercase(), pid.to_lowercase());
        let product_lower = product.unwrap_or("").to_lowercase();
        let path_lower = device_path.unwrap_or("").to_lowercase();

        // 常见存储设备VID/PID
        let storage_patterns = [
            "054c:0cba", // Sony
            "03f0:2504", // HP
            "0951:1643", // Kingston
            "0bc2:3300", // Seagate
            "1058:25a2", // WD
            "1f75:0911", // Innostor
            "1e68:1f3b", // Lexar
            "058f:6387", // Alcor
        ];

        for pattern in &storage_patterns {
            if vid_pid.contains(pattern) || pattern.contains(&vid_pid) {
                return UsbDeviceType::Storage;
            }
        }

        // 基于产品名称推断
        if product_lower.contains("flash") || product_lower.contains("disk") ||
           product_lower.contains("drive") || product_lower.contains("usb") ||
           product_lower.contains("memory") || product_lower.contains("stick") ||
           product_lower.contains("ssd") || product_lower.contains("hdd") {
            return UsbDeviceType::Storage;
        }

        if product_lower.contains("keyboard") || product_lower.contains("kbd") {
            return UsbDeviceType::Keyboard;
        }

        if product_lower.contains("mouse") || product_lower.contains("trackpad") {
            return UsbDeviceType::Mouse;
        }

        if product_lower.contains("ethernet") || product_lower.contains("network") ||
           product_lower.contains("wifi") || product_lower.contains("wlan") ||
           product_lower.contains("adapter") {
            return UsbDeviceType::Network;
        }

        if product_lower.contains("audio") || product_lower.contains("sound") ||
           product_lower.contains("headphone") || product_lower.contains("speaker") {
            return UsbDeviceType::Audio;
        }

        if product_lower.contains("camera") || product_lower.contains("webcam") ||
           product_lower.contains("camcorder") {
            return UsbDeviceType::Camera;
        }

        if product_lower.contains("printer") {
            return UsbDeviceType::Printer;
        }

        // 基于路径推断
        if path_lower.contains("storage") || path_lower.contains("disk") ||
           path_lower.contains("sdcard") || path_lower.contains("block") {
            return UsbDeviceType::Storage;
        }

        UsbDeviceType::Other
    }

    /// Linux下扫描USB设备
    #[cfg(target_os = "linux")]
    pub fn scan_devices(&self) -> Vec<UsbDevice> {
        let mut found: HashMap<String, UsbDevice> = HashMap::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 读取 /sys/bus/usb/devices
        if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                
                // 跳过USB接口（用冒号分隔）
                if name.contains(':') { continue; }

                let id_file = path.join("idVendor");
                let pid_file = path.join("idProduct");
                let serial_file = path.join("serial");
                let manufacturer_file = path.join("manufacturer");
                let product_file = path.join("product");

                let vid = fs::read_to_string(&id_file).map(|s| s.trim().to_string()).unwrap_or_default();
                let pid = fs::read_to_string(&pid_file).map(|s| s.trim().to_string()).unwrap_or_default();

                if vid.is_empty() || pid.is_empty() { continue; }

                let serial = fs::read_to_string(&serial_file).map(|s| s.trim().to_string()).ok();
                let manufacturer = fs::read_to_string(&manufacturer_file).map(|s| s.trim().to_string()).ok();
                let product = fs::read_to_string(&product_file).map(|s| s.trim().to_string()).ok();

                let device_path = Some(path.join("uevent").to_string_lossy().to_string());
                let device_type = Self::infer_device_type(&vid, &pid, product.as_deref(), device_path.as_deref());
                let key = Self::device_key(&vid, &pid, serial.as_deref());

                let is_auth = self.check_authorization(&vid, &pid, serial.as_deref());
                let bus = None;

                found.insert(key.clone(), UsbDevice {
                    vid,
                    pid,
                    serial,
                    manufacturer,
                    product,
                    device_type,
                    bus,
                    device_path,
                    first_seen: now,
                    last_seen: now,
                    is_authorized: is_auth,
                    is_connected: true,
                });
            }
        }

        // 更新内部设备列表
        let mut devices = self.devices.lock().unwrap();
        let mut events = Vec::new();

        // 检测新插入的设备
        for (key, new_dev) in &found {
            if !devices.contains_key(key) {
                // 新设备插入
                let event = UsbEvent {
                    event_type: UsbEventType::Inserted,
                    device: new_dev.clone(),
                    timestamp: now,
                    action_taken: None,
                    policy_rule: None,
                };
                events.push(event);
            }
            devices.insert(key.clone(), new_dev.clone());
        }

        // 检测拔出的设备
        let current_keys: std::collections::HashSet<_> = found.keys().cloned().collect();
        for key in devices.keys().cloned().collect::<Vec<_>>() {
            if !current_keys.contains(&key) {
                if let Some(old_dev) = devices.remove(&key) {
                    let mut dev = old_dev.clone();
                    dev.is_connected = false;
                    let event = UsbEvent {
                        event_type: UsbEventType::Removed,
                        device: dev,
                        timestamp: now,
                        action_taken: None,
                        policy_rule: None,
                    };
                    events.push(event);
                }
            }
        }

        // 保存事件
        if !events.is_empty() {
            let mut ev_buf = self.events.lock().unwrap();
            ev_buf.extend(events);
        }

        devices.values().cloned().collect()
    }

    /// macOS下扫描USB设备
    #[cfg(target_os = "macos")]
    pub fn scan_devices(&self) -> Vec<UsbDevice> {
        use std::process::Command;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let output = Command::new("system_profiler")
            .args(&["SPUSBDataType", "-json"])
            .output();

        let mut found: HashMap<String, UsbDevice> = HashMap::new();

        if let Ok(out) = output {
            if let Ok(json_str) = String::from_utf8(out.stdout) {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    if let Some(usb_data) = data.get("SPUSBDataType") {
                        fn parse_usb_tree(items: &[serde_json::Value], found: &mut HashMap<String, UsbDevice>, now: u64) {
                            for item in items {
                                let vid = item.get("vendor_id").and_then(|v| v.as_str()).unwrap_or("0000")
                                    .trim_start_matches("0x").to_uppercase();
                                let pid = item.get("product_id").and_then(|v| v.as_str()).unwrap_or("0000")
                                    .trim_start_matches("0x").to_uppercase();
                                
                                if vid == "0000" { continue; }

                                let serial = item.get("serial_number").and_then(|v| v.as_str()).map(String::from);
                                let manufacturer = item.get("manufacturer").and_then(|v| v.as_str()).map(String::from);
                                let product = item.get("_name").and_then(|v| v.as_str()).map(String::from);
                                let key = UsbController::device_key(&vid, &pid, serial.as_deref());

                                let is_auth = true; // macOS 默认授权
                                let device_type = UsbController::infer_device_type(&vid, &pid, product.as_deref(), None);
                                let device_path = item.get("bsd_name").and_then(|v| v.as_str()).map(String::from);

                                found.insert(key.clone(), UsbDevice {
                                    vid, pid, serial, manufacturer, product,
                                    device_type, bus: None,
                                    device_path,
                                    first_seen: now, last_seen: now,
                                    is_authorized: is_auth, is_connected: true,
                                });

                                if let Some(children) = item.get("built_in").and_then(|c| c.as_array())
                                    .or_else(|| item.get("devices").and_then(|c| c.as_array()))
                                {
                                    parse_usb_tree(children, found, now);
                                }
                            }
                        }
                        if let Some(items) = usb_data.as_array() {
                            parse_usb_tree(items, &mut found, now);
                        }
                    }
                }
            }
        }

        let mut devices = self.devices.lock().unwrap();
        for (key, new_dev) in &found {
            devices.insert(key.clone(), new_dev.clone());
        }

        devices.values().cloned().collect()
    }

    /// Windows下扫描USB设备
    #[cfg(target_os = "windows")]
    pub fn scan_devices(&self) -> Vec<UsbDevice> {
        use std::process::Command;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let output = Command::new("powershell")
            .args(&["-Command", 
                "Get-PnpDevice -Class USB -Status OK | Select-Object InstanceId,Manufacturer,Present,Status | ConvertTo-Json"])
            .output();

        let mut found: HashMap<String, UsbDevice> = HashMap::new();

        if let Ok(out) = output {
            if let Ok(json_str) = String::from_utf8(out.stdout).or_else(|_| String::from_utf8(out.stderr)) {
                if let Ok(items) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items_arr = if items.is_array() { items.as_array().unwrap().clone() } 
                                   else { vec![items] };

                    for item in items_arr {
                        let instance_id = item.get("InstanceId").and_then(|v| v.as_str()).unwrap_or("");
                        
                        // 解析 VID 和 PID (格式: USB\VID_xxxx&PID_xxxx\...)
                        let vid = instance_id.split("VID_")
                            .nth(1).map(|s| s.split('&').next().unwrap_or(s).to_uppercase())
                            .unwrap_or_else(|| "0000".to_string());
                        let pid = instance_id.split("PID_")
                            .nth(1).map(|s| s.split('\\').next().unwrap_or(s).to_uppercase())
                            .unwrap_or_else(|| "0000".to_string());

                        if vid == "0000" && pid == "0000" { continue; }

                        let manufacturer = item.get("Manufacturer").and_then(|v| v.as_str()).map(String::from);
                        let key = UsbController::device_key(&vid, &pid, None);
                        let device_type = UsbController::infer_device_type(&vid, &pid, manufacturer.as_deref(), None);
                        let is_auth = self.check_authorization(&vid, &pid, None);

                        found.insert(key.clone(), UsbDevice {
                            vid, pid, serial: None, manufacturer, product: None,
                            device_type, bus: None, device_path: None,
                            first_seen: now, last_seen: now,
                            is_authorized: is_auth, is_connected: true,
                        });
                    }
                }
            }
        }

        let mut devices = self.devices.lock().unwrap();
        for (key, new_dev) in &found {
            devices.insert(key.clone(), new_dev.clone());
        }
        devices.values().cloned().collect()
    }

    /// 更新策略
    pub fn update_policy(&self, policy: UsbPolicy) {
        *self.policy.lock().unwrap() = policy;
    }

    /// 获取当前策略
    pub fn get_policy(&self) -> UsbPolicy {
        self.policy.lock().unwrap().clone()
    }

    /// 检查设备授权状态
    fn check_authorization(&self, vid: &str, pid: &str, serial: Option<&str>) -> bool {
        let policy = self.policy.lock().unwrap();
        let key = format!("{}:{}", vid.to_uppercase(), pid.to_uppercase());

        // 黑名单优先
        if policy.blacklist.iter().any(|b| {
            let b_upper = b.to_uppercase();
            b_upper == key || b_upper == format!("{}:*", vid.to_uppercase()) || b_upper == "*"
        }) {
            return false;
        }

        // 白名单
        if !policy.whitelist.is_empty() {
            return policy.whitelist.iter().any(|w| {
                let w_upper = w.to_uppercase();
                w_upper == key || w_upper == format!("{}:*", vid.to_uppercase())
            });
        }

        true
    }

    /// 获取设备授权告警
    pub fn check_and_alert(&self) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let policy = self.policy.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !policy.enabled {
            return alerts;
        }

        let devices = self.devices.lock().unwrap();
        for dev in devices.values() {
            if !dev.is_connected { continue; }

            let key = format!("{}:{}", dev.vid, dev.pid);
            
            // 根据设备类型判断动作
            let action = match dev.device_type {
                UsbDeviceType::Storage => &policy.storage_action,
                UsbDeviceType::Network => &policy.network_action,
                _ => &policy.other_action,
            };

            // 告警：网络设备插入
            if dev.device_type == UsbDeviceType::Network && policy.sensitive_interface_alert {
                let alerted = self.alerted_devices.lock().unwrap();
                if !alerted.contains_key(&key) {
                    drop(alerted);
                    let mut ad = self.alerted_devices.lock().unwrap();
                    ad.insert(key.clone(), true);

                    let mut meta = std::collections::HashMap::new();
                    meta.insert("vid".into(), dev.vid.clone());
                    meta.insert("pid".into(), dev.pid.clone());
                    meta.insert("type".into(), "network".into());
                    if let Some(ref p) = dev.product {
                        meta.insert("product".into(), p.clone());
                    }
                    if let Some(ref m) = dev.manufacturer {
                        meta.insert("manufacturer".into(), m.clone());
                    }

                    alerts.push(Alert {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: now,
                        level: AlertLevel::Medium,
                        category: AlertCategory::Security,
                        title: "USB网卡设备插入".to_string(),
                        message: format!("检测到USB网卡设备: {} {}", 
                            dev.manufacturer.as_deref().unwrap_or("未知"),
                            dev.product.as_deref().unwrap_or("设备")),
                        source: "usb_controller".to_string(),
                        metadata: meta,
                    });
                }
            }

            // 告警：未授权存储设备
            if dev.device_type == UsbDeviceType::Storage && !dev.is_authorized && action != "allow" {
                let alerted = self.alerted_devices.lock().unwrap();
                let alert_key = format!("{}_unauth", key);
                if !alerted.contains_key(&alert_key) {
                    drop(alerted);
                    let mut ad = self.alerted_devices.lock().unwrap();
                    ad.insert(alert_key, true);

                    let mut meta = std::collections::HashMap::new();
                    meta.insert("vid".into(), dev.vid.clone());
                    meta.insert("pid".into(), dev.pid.clone());
                    meta.insert("action".into(), action.clone());
                    if let Some(ref p) = dev.product {
                        meta.insert("product".into(), p.clone());
                    }

                    alerts.push(Alert {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: now,
                        level: if action == "block" { AlertLevel::High } else { AlertLevel::Medium },
                        category: AlertCategory::Security,
                        title: "未授权USB存储设备".to_string(),
                        message: format!(
                            "未授权USB存储设备插入: {} (VID={}, PID={}, 操作={})",
                            dev.product.as_deref().unwrap_or("未知"),
                            dev.vid, dev.pid, action
                        ),
                        source: "usb_controller".to_string(),
                        metadata: meta,
                    });
                }
            }

            // 告警：摄像头/敏感设备
            if dev.device_type == UsbDeviceType::Camera && policy.sensitive_interface_alert {
                let mut meta = std::collections::HashMap::new();
                meta.insert("vid".into(), dev.vid.clone());
                meta.insert("pid".into(), dev.pid.clone());
                meta.insert("type".into(), "camera".into());
                alerts.push(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now,
                    level: AlertLevel::Medium,
                    category: AlertCategory::Security,
                    title: "USB摄像头设备插入".to_string(),
                    message: format!("检测到USB摄像头: {}", 
                        dev.product.as_deref().unwrap_or("未知")),
                    source: "usb_controller".to_string(),
                    metadata: meta,
                });
            }
        }

        alerts
    }

    /// 获取所有设备
    pub fn get_devices(&self) -> Vec<UsbDevice> {
        self.devices.lock().unwrap().values().cloned().collect()
    }

    /// 获取连接中的设备
    pub fn get_connected_devices(&self) -> Vec<UsbDevice> {
        self.devices.lock().unwrap()
            .values()
            .filter(|d| d.is_connected)
            .cloned()
            .collect()
    }

    /// 获取最近事件
    pub fn get_recent_events(&self, limit: usize) -> Vec<UsbEvent> {
        let events = self.events.lock().unwrap();
        events.iter().rev().take(limit).cloned().collect()
    }

    /// 清除已触发的告警标记
    pub fn clear_alert_flags(&self) {
        self.alerted_devices.lock().unwrap().clear();
    }
}

impl Default for UsbController {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化USB设备列表
pub fn format_usb_devices(devices: &[UsbDevice]) -> String {
    if devices.is_empty() {
        return "USB设备: 未检测到设备".to_string();
    }

    let mut lines = vec![format!("=== USB设备列表 ({}个) ===", devices.len())];
    let mut by_type: std::collections::HashMap<String, Vec<&UsbDevice>> = std::collections::HashMap::new();
    for d in devices {
        by_type.entry(d.device_type.to_string()).or_default().push(d);
    }

    for dtype in &["存储设备", "网卡", "键盘", "鼠标", "摄像头", "音频设备", "打印机", "其他"] {
        if let Some(devs) = by_type.get(*dtype) {
            lines.push(format!("\n[{}] ({}个)", dtype, devs.len()));
            for d in devs {
                lines.push(format!(
                    "  {} {} (VID={}, PID={}) {}",
                    d.manufacturer.as_deref().unwrap_or("?"),
                    d.product.as_deref().unwrap_or("?"),
                    d.vid, d.pid,
                    if d.is_authorized { "✓ 已授权" } else { "✗ 未授权" }
                ));
                if let Some(ref s) = d.serial {
                    lines.push(format!("    序列号: {}", s));
                }
            }
        }
    }
    lines.join("\n")
}
