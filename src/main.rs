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

use self::app_state::AppState;
use self::app_state::Device;

mod app_state;
mod handlers;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let address = setup_address();
    log::info!("Running at http://{}:{}", address.0, address.1);

    // init the logger and define default log level
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let app_state = web::Data::new(init_app_state().await);
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
fn init_anon_scope(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope(""));
}

fn setup_address() -> (String, String) {
    let host = env::var("HOST").unwrap_or_else(|_| {
        log::warn!("Could not find HOST env, defaulting to 127.0.0.1");
        "127.0.0.1".to_string()
    });

    let port = env::var("PORT").unwrap_or_else(|_| {
        log::warn!("Could not find PORT env, defaulting to 8080");
        "8080".to_string()
    });

    (host, port)
}

async fn init_app_state() -> AppState {
    let conn = Connection::open("netwatch.db").expect("Failed initializing sqlite in");
    let initial_state: Arc<Mutex<HashMap<IpAddr, app_state::Device>>> =
        Arc::new(Mutex::new(HashMap::new()));

    AppState {
        devices: initial_state,
        connection_pool: Arc::new(Mutex::new(conn)),
    }
}

fn init_db(app_state: web::Data<AppState>) -> web::Data<AppState> {
    let conn = app_state.connection_pool.lock().unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT NOT NULL,
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

    // Read the DNS lease file
    let contents = std::fs::read_to_string("/var/lib/misc/dnsmasq.leases").unwrap();

    for entry in contents.lines() {
        let mut parts = entry.split_whitespace();
        let _timestamp = parts.next().unwrap();
        let mac: MacAddr = parts.next().unwrap().parse().unwrap();
        let ip: IpAddr = parts.next().unwrap().parse().unwrap();
        let hostname = parts.next().unwrap().to_string();

        let mut devices = app_state.devices.lock().unwrap();

        devices.insert(
            ip,
            app_state::Device {
                mac,
                hostname,
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
                                hostname: String::from("Anonymous"),
                                ip: IpAddr::V4(ipv4.get_source()),
                                packet_count: 1,
                                last_seen: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs() as i64,
                                domains: HashSet::new(),
                            });

                        check_udp(&ipv4, devices.get_mut(&IpAddr::V4(ipv4.get_source())));
                        check_tcp_packets(&ipv4, devices.get_mut(&IpAddr::V4(ipv4.get_source())));
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
    }
}

fn batch_upsert_entries(
    conn: &mut Connection,
    devices: &HashMap<IpAddr, Device>,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for device in devices.values() {
        tx.execute(
            "INSERT INTO devices (ip, mac, hostname, packet_count, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            ON CONFLICT(ip) DO UPDATE SET
            packet_count = ?4,
            last_seen = ?5",
            params![
                device.ip.to_string(),
                device.mac.to_string(),
                device.hostname,
                device.packet_count as i64,
                device.last_seen
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
fn check_tcp_packets(ip_packet: &Ipv4Packet, device: Option<&mut Device>) {
    // Return if the IP-Packet is not TCP
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return;
    }

    let Some(tcp) = TcpPacket::new(ip_packet.payload()) else {
        return;
    };

    if tcp.get_destination() != 443 {
        return;
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
                if let Some(name) = &sni {
                    println!("{}", name);
                }
                break;
            } else {
                // Skip current extension
                pos += ext_len as usize;
            }
        }
        if let (Some(d), Some(sni)) = (device, sni) {
            d.domains.insert(sni);
        }
    }
}

/// Parses UDP packets for DNS queries (port 53) and records queried domains.
///
/// Layer path: IPv4 → UDP (port 53) → DNS query
///
/// Uses dns_parser to extract qname from each question record.
/// Inserts domain strings into device.domains (HashSet, deduped).
fn check_udp(ip_packet: &Ipv4Packet, device: Option<&mut Device>) {
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return;
    }

    let Some(udp) = UdpPacket::new(ip_packet.payload()) else {
        return;
    };

    let Ok(packet) = dns_parser::Packet::parse(udp.payload()) else {
        return;
    };

    if let Some(d) = device
        && udp.get_destination() == 53
    {
        for question in packet.questions {
            let domain_string = question.qname.to_string();
            d.domains.insert(domain_string);
        }
    }
}
