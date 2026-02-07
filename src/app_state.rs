use rusqlite::Connection;
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
}

#[derive(Clone)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: String,
    pub ip: IpAddr,
    pub packet_count: u64,
    pub last_seen: i64,
    pub domains: HashSet<String>,
}
