// TODO: Modularize code + better performance + less redundancy
// I wrote this in one session it is nowhere near production ready!

use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use actix_web::App;
use actix_web::HttpServer;
use actix_web::middleware::Logger;
use actix_web::web;
use dotenv::dotenv;
use env_logger::Env;
use pnet::datalink::Channel;
use pnet::datalink::Config;
use pnet::datalink::interfaces;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;
use rusqlite::Connection;
use rusqlite::params;

use self::handlers::get_alerts;
use self::handlers::get_device_by_ip;
use self::handlers::get_devices;
use self::models::Alert;
use self::models::AlertReason;
use self::models::AppState;
use self::models::Device;
use self::models::DeviceResponse;
use self::ws::ws_alert;

mod handlers;
mod models;
mod threat_detection_service;
mod ws;

/// Initializes environment variables, app state, database, and starts
/// the packet capture thread alongside the actix-web HTTP server.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let address = setup_address();
    log::info!("Running at http://{}:{}", address.0, address.1);

    // init the logger and define default log level
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let app_state = web::Data::new(init_app_state());
    let app_state = init_db(app_state);

    let state_clone = app_state.clone();
    std::thread::spawn(move || {
        spawn_continuous_scan(state_clone).unwrap();
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .configure(init_anon_scope)
    })
    .bind(format!("{}:{}", address.0, address.1))?
    .run()
    .await
}

// Registers anonymous (no-auth) route scopes.
fn init_anon_scope(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/api/devices", web::get().to(get_devices))
            .route("/api/devices/{ip}", web::get().to(get_device_by_ip))
            .route("/api/alerts", web::get().to(get_alerts))
            .route("/ws/alerts", web::get().to(ws_alert)),
    );
}

fn setup_address() -> (String, String) {
    let host = env::var("HOST").unwrap_or_else(|_| {
        log::warn!("Could not find HOST env, defaulting to 0.0.0.0");
        "0.0.0.0".to_string()
    });

    let port = env::var("PORT").unwrap_or_else(|_| {
        log::warn!("Could not find PORT env, defaulting to 8080");
        "8080".to_string()
    });

    (host, port)
}

fn init_app_state() -> AppState {
    let conn = Connection::open_in_memory().expect("Failed initializing sqlite in");
    let initial_state: Arc<Mutex<HashMap<IpAddr, models::Device>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let vendor_map: HashMap<String, String> = get_vendor_map();
    let (tx, _) = tokio::sync::broadcast::channel::<Alert>(100);

    AppState {
        devices: initial_state,
        vendor_map: Arc::new(vendor_map),
        connection_pool: Arc::new(Mutex::new(conn)),
        alert_tx: tx,
        src_dst: Arc::new(Mutex::new(HashMap::new())),
    }
}

fn init_db(app_state: web::Data<AppState>) -> web::Data<AppState> {
    let conn = app_state.connection_pool.lock().unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT NOT NULL,
            vendor TEXT NOT NULL,
            hostname TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            packet_count INTEGER NOT NULL
            )",
        (),
    )
    .expect("Failed creating table devices");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS dns_logs (
            ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )",
        (),
    )
    .expect("Failed creating table dns_logs");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts (
            ip TEXT NOT NULL,
            alert_reason TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )",
        (),
    )
    .expect("Failed creating table dns_logs");

    // Read the DNS lease file
    let contents = std::fs::read_to_string("/var/lib/misc/dnsmasq.leases").unwrap();

    for entry in contents.lines() {
        let mut parts = entry.split_whitespace();
        let _timestamp = parts.next().unwrap();
        let mac: MacAddr = parts.next().unwrap().parse().unwrap();
        let ip: IpAddr = parts.next().unwrap().parse().unwrap();
        let hostname = parts.next().unwrap().to_string();

        let mut devices = app_state.devices.lock().unwrap();
        let mac_str = mac.to_string().to_uppercase();
        let prefix = &mac_str[..8];
        let vendor = app_state
            .vendor_map
            .get(prefix)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        devices.insert(
            ip,
            models::Device {
                mac,
                hostname,
                vendor,
                ip,
                packet_count: 0,
                last_seen: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                domains: HashSet::new(),
            },
        );
    }

    app_state.clone()
}

/// Runs the blocking packet capture loop on a dedicated OS thread.
/// Processes Ethernet → IPv4 → UDP (DNS) / TCP (TLS SNI).
/// Flushes device state to SQLite every 50 packets.
fn spawn_continuous_scan(app_state: web::Data<AppState>) -> Result<(), io::Error> {
    let interfaces = interfaces();

    let default_interfaces = interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

    let found_interface = default_interfaces.unwrap();

    let ch = pnet::datalink::channel(found_interface, Config::default())?;

    let mut rx = match ch {
        Channel::Ethernet(_, rx) => rx,
        _ => panic!("Not an ethernet channel"),
    };

    let mut count = 0;
    let my_mac = found_interface.mac.unwrap();

    let blacklist_txt = include_str!("../assets/blacklist.txt");
    let mut blacklist: HashSet<String> = blacklist_txt.lines().map(String::from).collect();

    let mut known_ips: HashSet<IpAddr> = HashSet::new();
    // At startup, load from DB
    {
        let conn = app_state.connection_pool.lock().unwrap();
        let mut stmt = conn.prepare("SELECT ip FROM devices").unwrap();
        let rows = stmt
            .query_map([], |row| {
                let ip: String = row.get(0)?;
                Ok(ip.parse::<IpAddr>().unwrap())
            })
            .unwrap();
        for ip in rows {
            known_ips.insert(ip.unwrap());
        }
    }

    let mut device_port: HashMap<IpAddr, Vec<(u16, i64)>> = HashMap::new();
    loop {
        match rx.next() {
            Ok(packet) => {
                let wrapped_packet = EthernetPacket::new(packet);

                if let Some(p) = wrapped_packet {
                    let mut devices = app_state.devices.lock().unwrap();
                    if p.get_source() == my_mac {
                        continue;
                    }

                    let payload = p.payload();

                    if let Some(ipv4) = Ipv4Packet::new(payload)
                        && p.get_ethertype() == EtherTypes::Ipv4
                    {
                        let mut src_dst = app_state.src_dst.lock().unwrap();
                        let src_ip = IpAddr::V4(ipv4.get_source());
                        let dest_ip = IpAddr::V4(ipv4.get_destination());

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        src_dst
                            .entry((src_ip, dest_ip))
                            .and_modify(|e| {
                                e.push((now, p.payload().len()));
                            })
                            .or_insert(vec![(now, p.payload().len())]);

                        let dst_port = match ipv4.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                TcpPacket::new(ipv4.payload()).map(|t| t.get_destination())
                            }
                            IpNextHeaderProtocols::Udp => {
                                UdpPacket::new(ipv4.payload()).map(|u| u.get_destination())
                            }
                            _ => None,
                        };

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;

                        if let Some(port) = dst_port {
                            let ports = device_port.entry(src_ip).or_default();
                            ports.push((port, now));
                            ports.retain(|(_, ts)| now - ts < 60);

                            let unique_ports: HashSet<u16> =
                                ports.iter().map(|(p, _)| *p).collect();
                            if unique_ports.len() > 15 {
                                let mut conn = app_state.connection_pool.lock().unwrap();
                                save_device_alert(
                                    &mut conn,
                                    src_ip.to_string(),
                                    AlertReason::SuspiciousCommunication(
                                        "Port scan detected".into(),
                                    ),
                                    app_state.alert_tx.clone(),
                                )
                                .unwrap();
                                // Reset so it doesn't fire every packet
                                ports.clear();
                            }
                        }

                        let mac_str = p.get_source().to_string().to_uppercase();
                        let prefix = &mac_str[..8];
                        let vendor = app_state
                            .vendor_map
                            .get(prefix)
                            .cloned()
                            .unwrap_or_else(|| "Unknown".to_string());
                        devices
                            .entry(IpAddr::V4(ipv4.get_source()))
                            .and_modify(|d| {
                                d.packet_count += 1;
                                d.last_seen = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs() as i64;
                            })
                            .or_insert(Device {
                                mac: p.get_source(),
                                vendor,
                                hostname: String::from("Anonymous"),
                                ip: IpAddr::V4(ipv4.get_source()),
                                packet_count: 1,
                                last_seen: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs() as i64,
                                domains: HashSet::new(),
                            });

                        let source_ip = IpAddr::V4(ipv4.get_source());

                        let is_new = !known_ips.contains(&source_ip);

                        let udp_hit = check_udp(&ipv4, devices.get_mut(&source_ip), &blacklist);
                        let tcp_hit =
                            check_tcp_packets(&ipv4, devices.get_mut(&source_ip), &blacklist);

                        if is_new || udp_hit.is_some() || tcp_hit.is_some() {
                            let mut conn = app_state.connection_pool.lock().unwrap();
                            if is_new {
                                known_ips.insert(source_ip);
                                save_device_alert(
                                    &mut conn,
                                    source_ip.to_string(),
                                    AlertReason::NewDevice,
                                    app_state.alert_tx.clone(),
                                )
                                .unwrap();
                            }
                            if let Some(v) = udp_hit {
                                save_device_alert(
                                    &mut conn,
                                    source_ip.to_string(),
                                    AlertReason::BlockedDomain(v),
                                    app_state.alert_tx.clone(),
                                )
                                .unwrap();
                            }
                            if let Some(v) = tcp_hit {
                                save_device_alert(
                                    &mut conn,
                                    source_ip.to_string(),
                                    AlertReason::BlockedDomain(v),
                                    app_state.alert_tx.clone(),
                                )
                                .unwrap();
                            }
                        }
                    }

                    count += 1;
                    if count > 50 {
                        let mut conn = app_state.connection_pool.lock().unwrap();
                        batch_upsert_entries(&mut conn, &devices)
                            .expect("Failed storing to the db");
                        count = 0;
                    }
                }
            }

            Err(e) => eprintln!("error: {}", e),
        }
        let beacon_state = app_state.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                run_beaconing_analysis(&beacon_state);
            }
        });
    }
}

fn get_vendor_map() -> HashMap<String, String> {
    let oui_txt = include_str!("../assets/vendor.txt");
    let mut oui_map: HashMap<String, String> = HashMap::new();

    for line in oui_txt.lines() {
        if line.contains("(hex)") {
            let parts: Vec<&str> = line.split("(hex)").collect();
            let prefix = parts[0].trim().replace('-', ":").to_uppercase();
            let vendor = parts[1].trim().to_string();
            oui_map.insert(prefix, vendor);
        }
    }
    oui_map
}

/// Parses a TLS ClientHello to extract the SNI (Server Name Indication) hostname.
///
/// TLS ClientHello structure (all big-endian):
///
///   Record Header (5 bytes fixed):  content_type(1) + version(2) + length(2)
///   Handshake Header (4 bytes fixed): type(1) + length(3)
///   ClientHello Body:
///     client_version(2) + random(32)                    -- 43 bytes fixed total
///     session_id:      1-byte length prefix + N bytes   -- variable, skip
///     cipher_suites:   2-byte length prefix + N bytes   -- variable, skip
///     compression:     1-byte length prefix + N bytes   -- variable, skip
///     extensions:      2-byte length prefix, then repeating:
///       type(2) + length(2) + data(N)
///       SNI extension (type 0x0000) data:
///         list_length(2) + name_type(1) + name_length(2) + name(N bytes, UTF-8)
fn check_tcp_packets(
    ip_packet: &Ipv4Packet,
    device: Option<&mut Device>,
    blacklist: &HashSet<String>,
) -> Option<String> {
    // Return if the IP-Packet is not TCP
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let Some(tcp) = TcpPacket::new(ip_packet.payload()) else {
        return None;
    };

    if tcp.get_destination() != 443 {
        return None;
    }

    let payload = tcp.payload();

    // 0x16 => TLS Handshake
    if payload[0] == 0x16 {
        let mut pos: usize = 0;
        pos += 43;

        // Skip size byte and session_length
        let session_length = payload[pos];
        pos += 1 + session_length as usize;

        // Skip the 2 size bytes + cipher_suites_length
        let cipher_suites_length = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        pos += 2 + cipher_suites_length as usize;

        // Skip size byte + compression methods
        let compresssion_methods_length = payload[pos];
        pos += 1 + compresssion_methods_length as usize;

        let extensions_length = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        pos += 2;

        let extensions_end = pos + extensions_length as usize;

        let mut sni: Option<String> = None;

        while pos + 4 <= extensions_end {
            // Type is always a u16
            let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
            pos += 4;

            if ext_type == 0x0000 {
                // We are now at the host type

                // Skip: list_length(2) + name_type(1)
                pos += 3;

                let name_length = u16::from_be_bytes([payload[pos], payload[pos + 1]]);

                // Skip past the 2 bytes of name length
                pos += 2;

                // Create a &[u8]; This automatically creates a fat pointer with a length to it
                // and therefore satisfies the "Sized" traits requirements
                let host_name = &payload[pos..pos + name_length as usize];

                sni = Some(str::from_utf8(host_name).unwrap().to_string());

                break;
            } else {
                // Skip current extension
                pos += ext_len as usize;
            }
        }

        if let (Some(d), Some(sni)) = (device, sni) {
            d.domains.insert(sni.clone());
            if blacklist.contains(&sni) {
                return Some(sni);
            }
        }
    }

    None
}

/// Parses UDP packets for DNS queries (port 53) and records queried domains.
///
/// Layer path: IPv4 → UDP (port 53) → DNS query
///
/// Uses dns_parser to extract qname from each question record.
/// Inserts domain strings into device.domains (HashSet, deduped).
fn check_udp(
    ip_packet: &Ipv4Packet,
    device: Option<&mut Device>,
    blacklist: &HashSet<String>,
) -> Option<String> {
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let Some(udp) = UdpPacket::new(ip_packet.payload()) else {
        return None;
    };

    let Ok(packet) = dns_parser::Packet::parse(udp.payload()) else {
        return None;
    };

    if let Some(d) = device
        && udp.get_destination() == 53
    {
        for question in packet.questions {
            let domain_string = question.qname.to_string();
            if blacklist.contains(&domain_string) {
                return Some(domain_string);
            }
            d.domains.insert(domain_string);
        }
    }
    None
}

/// Batch upserts all devices and their DNS logs to SQLite
/// within a single transaction for SD card efficiency.
fn batch_upsert_entries(
    conn: &mut Connection,
    devices: &HashMap<IpAddr, Device>,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for device in devices.values() {
        tx.execute(
            "INSERT INTO devices (ip, mac, hostname, packet_count, first_seen, last_seen, vendor)
            VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
            ON CONFLICT(ip) DO UPDATE SET
            packet_count = ?4,
            last_seen = ?5",
            params![
                device.ip.to_string(),
                device.mac.to_string(),
                device.hostname,
                device.packet_count as i64,
                device.last_seen,
                device.vendor
            ],
        )?;

        for domain in device.domains.iter() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            tx.execute(
                "INSERT INTO dns_logs (ip, domain, timestamp)
                VALUES (?1, ?2, ?3)",
                params![device.ip.to_string(), domain, now],
            )?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Batch upserts all devices and their DNS logs to SQLite
/// within a single transaction for SD card efficiency.
pub fn get_db_devices(conn: &mut Connection) -> rusqlite::Result<Vec<DeviceResponse>> {
    let mut devices = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT ip, mac, hostname, packet_count, first_seen, last_seen, vendor FROM devices",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(DeviceResponse {
            ip: row.get(0)?,
            mac: row.get(1)?,
            hostname: row.get(2)?,
            packet_count: row.get(3)?,
            first_seen: row.get(4)?,
            last_seen: row.get(5)?,
            vendor: row.get(6)?,
            domains: vec![],
        })
    })?;

    for device in rows {
        let mut device = device?;
        let mut domain_stmt = conn.prepare("SELECT DISTINCT domain FROM dns_logs WHERE ip = ?1")?;
        let domains: Vec<String> = domain_stmt
            .query_map([&device.ip], |row| row.get(0))?
            .filter_map(|d| d.ok())
            .collect();
        device.domains = domains;
        devices.push(device);
    }

    Ok(devices)
}

pub fn get_db_device_by_ip(
    conn: &mut Connection,
    ip: String,
) -> rusqlite::Result<Option<DeviceResponse>> {
    // TODO: Implement
    let mut stmt = conn.prepare(
        "SELECT DISTINCT ip, mac, hostname, packet_count, first_seen, last_seen, vendor FROM devices WHERE ip = ?1",
    )?;

    let mut rows = stmt.query_map([&ip], |row| {
        Ok(DeviceResponse {
            ip: row.get(0)?,
            mac: row.get(1)?,
            hostname: row.get(2)?,
            packet_count: row.get(3)?,
            first_seen: row.get(4)?,
            last_seen: row.get(5)?,
            vendor: row.get(6)?,
            domains: vec![],
        })
    })?;

    let Some(device) = rows.next() else {
        return Ok(None);
    };

    let mut device = device?;

    let mut domain_stmt = conn.prepare("SELECT DISTINCT domain FROM dns_logs WHERE ip = ?1")?;
    let domains: Vec<String> = domain_stmt
        .query_map([&ip], |row| row.get(0))?
        .filter_map(|d| d.ok())
        .collect();
    device.domains = domains;

    Ok(Some(device))
}

pub fn save_device_alert(
    conn: &mut Connection,
    ip: String,
    reason: AlertReason,
    tx: tokio::sync::broadcast::Sender<Alert>,
) -> rusqlite::Result<()> {
    // TODO: Somehow integrate arp checking
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO alerts (ip, alert_reason, timestamp) VALUES (?1, ?2, ?3)",
        (&ip, reason.to_string(), now),
    )?;

    let _ = tx.send(Alert {
        ip,
        reason: reason.to_string(),
        timestamp: now,
    });

    Ok(())
}

pub fn get_db_alerts(conn: &mut Connection) -> rusqlite::Result<Vec<Alert>> {
    let mut stmt = conn.prepare("SELECT ip, alert_reason, timestamp FROM alerts")?;
    let rows = stmt.query_map([], |row| {
        Ok(Alert {
            ip: row.get(0)?,
            reason: row.get(1)?,
            timestamp: row.get(2)?,
        })
    })?;
    rows.collect()
}

fn run_beaconing_analysis(state: &web::Data<AppState>) {
    let port_data = state.src_dst.lock().unwrap();

    for ((src, dst), samples) in port_data.iter() {
        if samples.len() < 10 {
            continue;
        }
        if dst.to_string().ends_with(".255") {
            continue;
        }

        if src.to_string().ends_with(".255") {
            continue;
        }

        if src.to_string() == env::var("PI_HOST").unwrap()
            || dst.to_string() == env::var("PI_HOST").unwrap()
        {
            continue;
        }

        if !src.to_string().starts_with("192.168.1") {
            continue;
        }

        // Compute intervals between timestamps
        let intervals: Vec<f64> = samples
            .windows(2)
            .map(|w| (w[1].0 - w[0].0) as f64)
            .collect();

        let avg = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if avg == 0.0 {
            continue;
        }

        let variance =
            intervals.iter().map(|i| (i - avg).powi(2)).sum::<f64>() / intervals.len() as f64;

        let std_deviation = variance.sqrt();
        let cv = std_deviation / avg;

        if cv < 0.2 {
            let mut conn = state.connection_pool.lock().unwrap();
            // BEACON HIGHLY PROBABLE
            save_device_alert(
                &mut conn,
                src.to_string(),
                AlertReason::Beacon(format!("{} every ~{:.0}s", dst, avg)),
                state.alert_tx.clone(),
            )
            .unwrap();
        }
    }
}
