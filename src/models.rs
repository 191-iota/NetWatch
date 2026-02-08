use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;

use pnet::util::MacAddr;

#[derive(Clone)]
pub struct AppState {
    pub devices: Arc<Mutex<HashMap<IpAddr, Device>>>,
    pub connection_pool: Arc<Mutex<Connection>>,
    pub vendor_map: Arc<HashMap<String, String>>,
    pub alert_tx: tokio::sync::broadcast::Sender<Alert>,
    pub src_dst: Arc<Mutex<HashMap<(IpAddr, IpAddr), Vec<(i64, usize)>>>>,
}

#[derive(Clone)]
pub struct Device {
    pub mac: MacAddr,
    pub vendor: String,
    pub hostname: String,
    pub ip: IpAddr,
    pub packet_count: u64,
    pub last_seen: i64,
    pub domains: HashSet<String>,
}

#[derive(Serialize, Clone)]
pub struct DeviceResponse {
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    pub ip: String,
    pub packet_count: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub domains: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct Alert {
    pub ip: String,
    pub reason: String,
    pub timestamp: i64,
}

#[derive(Clone, Serialize)]
pub enum AlertReason {
    NewDevice,
    BlockedDomain(String),
    SuspiciousCommunication(String),
    Beacon(String),
}

impl std::fmt::Display for AlertReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertReason::NewDevice => write!(f, "New device"),
            AlertReason::BlockedDomain(d) => write!(f, "Blocked domain: {}", d),
            AlertReason::SuspiciousCommunication(s) => write!(f, "Suspicious {}", s),
            AlertReason::Beacon(s) => write!(f, "Beaconing: {}", s),
        }
    }
}
