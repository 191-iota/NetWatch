use std::io;

use pnet::datalink::Channel;
use pnet::datalink::Config;
use pnet::datalink::interfaces;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::Packet;

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

    loop {
        match rx.next() {
            Ok(packet) => {
                let wrapped_packet = EthernetPacket::new(packet);

                println!("got packet: {} bytes", packet.len());
                if let Some(p) = wrapped_packet {
                    println!(
                        "packet source: {} -- packet dest: {}",
                        p.get_source(),
                        p.get_destination()
                    );

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
                }
            }
            Err(e) => eprintln!("error: {}", e),
        }
    }
}
