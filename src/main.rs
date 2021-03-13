use pcap::{Capture, Device};

use pnet::datalink::{self, Channel, Config};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};

use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let (dp_tx, mut dp_rx) = mpsc::channel(match option_env!("DP_BUFFER_SIZE") {
        Some(buffer_size) => buffer_size.parse().unwrap_or(1024 * 1024 * 10),
        None => 1024 * 1024 * 10,
    });

    // get interface for device
    let device = match option_env!("DP_INTERFACE_NAME") {
        Some(name) => Device {
            name: name.to_string(),
            desc: None,
        },
        None => Device::lookup().unwrap(),
    };

    // init lib_net
    let interface = datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == device.name)
        .unwrap();
    let mut data_link_tx = match datalink::channel(
        &interface,
        Config {
            write_buffer_size: 65535,
            read_buffer_size: 65535,
            ..Config::default()
        },
    ) {
        Ok(Channel::Ethernet(tx, _rx)) => tx,
        Ok(_) => panic!("unprocessed channel type"),
        Err(e) => panic!("create channel failure: {:#?}", e),
    };

    // init lib_pcap
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .timeout(0)
        .open()
        .unwrap();
    cap.filter(match option_env!("DP_FILTER") {
        Some(filter) => filter,
        None => "ip",
    })
    .unwrap();

    // build packet
    tokio::spawn(async move {
        while let Ok(packet) = cap.next() {
            let mut packet_data = vec![0; packet.data.len()];
            packet_data.clone_from_slice(&packet);

            let _ = dp_tx.send(packet_data).await;
        }
    });

    // consumer packet
    while let Some(packet) = dp_rx.recv().await {
        let packet: Ipv4Packet = Ipv4Packet::new(&packet[..]).unwrap();

        if packet.get_ttl() != 88 {
            data_link_tx.build_and_send(1, packet.packet().len(), &mut |new_packet| {
                let mut new_packet = MutableIpv4Packet::new(new_packet).unwrap();
                new_packet.clone_from(&packet);
                new_packet.set_ttl(88);
            });
        }
    }
}
