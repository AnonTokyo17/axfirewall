#![no_std]
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum FilterVerdict
{
    Accept,
    Drop,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInfo {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub proto: L4Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}
#[derive(Debug, Clone)]
pub struct Rule {
    pub proto: Option<L4Protocol>,
    pub src_ip: Option<Ipv4Address>,
    pub dst_ip: Option<Ipv4Address>,
    pub dst_port: Option<u16>,
    pub verdict: FilterVerdict,
}
impl Rule {
    pub fn matches(&self, pkt: &PacketInfo) -> bool {
        if let Some(proto) = self.proto {
            if proto != pkt.proto {
                return false;
            }
        }
        if let Some(src_ip) = self.src_ip {
            if src_ip != pkt.src_ip {
                return false;
            }
        }
        if let Some(dst_ip) = self.dst_ip {
            if dst_ip != pkt.dst_ip {
                return false;
            }
        }
        if let Some(dst_port) = self.dst_port {
            if pkt.dst_port != Some(dst_port) {
                return false;
            }
        }
        true
    }
}
pub fn parse_packet(raw_pkt: &[u8]) -> Option<PacketInfo> {
    let eth_frame = EthernetFrame::new_checked(raw_pkt).ok()?;

    if eth_frame.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }

    let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload()).ok()?;
    let src_ip = ipv4_packet.src_addr();
    let dst_ip = ipv4_packet.dst_addr();
    let payload = ipv4_packet.payload();

    let (proto, src_port, dst_port) = match ipv4_packet.next_header() {
        IpProtocol::Tcp => {
            if let Ok(tcp) = TcpPacket::new_checked(payload) {
                (L4Protocol::Tcp, Some(tcp.src_port()), Some(tcp.dst_port()))
            } else {
                (L4Protocol::Tcp, None, None)
            }
        }
        IpProtocol::Udp => {
            if let Ok(udp) = UdpPacket::new_checked(payload) {
                (L4Protocol::Udp, Some(udp.src_port()), Some(udp.dst_port()))
            } else {
                (L4Protocol::Udp, None, None)
            }
        }
        IpProtocol::Icmp => (L4Protocol::Icmp, None, None),
        IpProtocol::Unknown(val) => (L4Protocol::Other(val), None, None),
        _ => (L4Protocol::Other(0), None, None),
    };

    Some(PacketInfo {
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
    })
}
pub fn match_rules(pkt: &PacketInfo) -> FilterVerdict {
    let rules = [
        Rule {
            proto: Some(L4Protocol::Tcp),
            src_ip: None,
            dst_ip: None,
            dst_port: Some(5555),
            verdict: FilterVerdict::Drop,
        },
    ];

    for rule in &rules {
        if rule.matches(pkt) {
            return rule.verdict;
        }
    }

    FilterVerdict::Accept
}
pub fn filter_rx_packet(raw_pkt:&[u8])->FilterVerdict
{
    let pkt_info = match parse_packet(raw_pkt) {
        Some(info) => info,
        None => {
            return FilterVerdict::Accept;
        }
    };

    let verdict = match_rules(&pkt_info);

    log::info!(
        "[axfirewall] {:?} {}:{} -> {}:{} => {:?}",
        pkt_info.proto,
        pkt_info.src_ip,
        pkt_info.src_port.unwrap_or(0),
        pkt_info.dst_ip,
        pkt_info.dst_port.unwrap_or(0),
        verdict
    );

    verdict
}