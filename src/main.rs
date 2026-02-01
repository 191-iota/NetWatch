use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::Instant;

use pnet::datalink::Channel;
use pnet::datalink::Config;
use pnet::datalink::interfaces;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::Packet;
use pnet::util::MacAddr;

struct Device {
    mac: MacAddr,
    ip: IpAddr,
    packet_count: u64,
    last_seen: Instant,
}

fn main() -> Result<(), io::Error> {
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

    let mut devices: HashMap<MacAddr, Device> = HashMap::new();
    let mut count = 0;

    loop {
        match rx.next() {
            Ok(packet) => {
                let wrapped_packet = EthernetPacket::new(packet);

                if let Some(p) = wrapped_packet {
                    if p.get_ethertype() == EtherTypes::Ipv4 {
                        let payload = Ipv4Packet::new(p.payload());
                        if let Some(ipv4) = payload {
                            println!(
                                "ipv4 source: {} -- ipv4 dest: {}",
                                ipv4.get_source(),
                                ipv4.get_destination()
                            );
                        }
                    }

                    if devices.contains_key(&p.get_source()) {
                        let current_device = devices.get_mut(&p.get_source()).unwrap();
                        current_device.packet_count += 1;
                        current_device.last_seen = Instant::now();
                    } else if p.get_ethertype() == EtherTypes::Ipv4 {
                        let payload = Ipv4Packet::new(p.payload());
                        if let Some(ipv4) = payload {
                            devices.insert(
                                p.get_source(),
                                Device {
                                    mac: p.get_source(),
                                    ip: IpAddr::V4(ipv4.get_source()),
                                    packet_count: 1,
                                    last_seen: Instant::now(),
                                },
                            );
                            println!(
                                "ipv4 source: {} -- ipv4 dest: {}",
                                ipv4.get_source(),
                                ipv4.get_destination()
                            );
                        }
                    }
                    count += 1;
                    if count > 50 {
                        print_tracking_table(&devices);
                        count = 0;
                    }
                }
            }
            Err(e) => eprintln!("error: {}", e),
        }
    }
}

fn print_tracking_table(map: &HashMap<MacAddr, Device>) {
    print!("\x1B[2J\x1B[1;1H");
    println!("NetWatch - tracking wlan0");
    println!("------------------------------------------------");
    println!("MAC                   IP                  Packets         Last Seen");
    for (_, device) in map.iter() {
        println!(
            "{}     {}      {}  {:?}",
            device.mac,
            device.ip,
            device.packet_count,
            device.last_seen.elapsed().as_secs()
        );
    }
}
