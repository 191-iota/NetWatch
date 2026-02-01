use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::Instant;

use pnet::datalink::Channel;
use pnet::datalink::Config;
use pnet::datalink::interfaces;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
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
    let my_mac = found_interface.mac.unwrap();

    loop {
        match rx.next() {
            Ok(packet) => {
                let wrapped_packet = EthernetPacket::new(packet);

                if let Some(p) = wrapped_packet {
                    if p.get_source() == my_mac {
                        continue;
                    }
                    let payload = p.payload();

                    if let Some(ipv4) = Ipv4Packet::new(payload)
                        && p.get_ethertype() == EtherTypes::Ipv4
                    {
                        devices
                            .entry(p.get_source())
                            .and_modify(|d| {
                                d.packet_count += 1;
                                d.last_seen = Instant::now();
                            })
                            .or_insert(Device {
                                mac: p.get_source(),
                                ip: IpAddr::V4(ipv4.get_source()),
                                packet_count: 1,
                                last_seen: Instant::now(),
                            });

                        check_udp(ipv4);
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

fn check_udp(ip_packet: Ipv4Packet) {
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return;
    }

    let Some(udp) = UdpPacket::new(ip_packet.payload()) else {
        return;
    };

    let Ok(packet) = dns_parser::Packet::parse(udp.payload()) else {
        return;
    };

    if udp.get_destination() == 53 {
        for question in packet.questions {
            println!(
                "DNS: {} looked up {}",
                ip_packet.get_source(),
                question.qname
            );
        }
    }
}

fn print_tracking_table(map: &HashMap<MacAddr, Device>) {
    print!("\x1B[2J\x1B[1;1H");
    println!("NetWatch - tracking wlan0");
    println!("──────────────────────────────────────────────────────────────────");
    println!(
        "{:<20} {:<18} {:>10} {:>12}",
        "MAC", "IP", "Packets", "Last Seen"
    );
    println!("──────────────────────────────────────────────────────────────────");
    for (_, device) in map.iter() {
        let last_seen = device.last_seen.elapsed().as_secs();
        let last_seen_str = format!("{}s ago", last_seen);
        println!(
            "{:<20} {:<18} {:>10} {:>12}",
            device.mac, device.ip, device.packet_count, last_seen_str
        );
    }
}
