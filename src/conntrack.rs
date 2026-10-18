use alloc::collections::BTreeMap;
use smoltcp::wire::Ipv4Address;
use crate::{L4Protocol, PacketInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub ip_min: Ipv4Address,
    pub ip_max: Ipv4Address,
    pub port_min: u16,
    pub port_max: u16,
    pub proto: u8,
}

impl FlowKey {
    pub fn from_packet(pkt: &PacketInfo) -> Option<Self> {
        let (sport, dport) = (pkt.src_port?, pkt.dst_port?);
        let proto = match pkt.proto {
            L4Protocol::Tcp => 6,
            L4Protocol::Udp => 17,
            L4Protocol::Icmp => 1,
            L4Protocol::Other(p) => p,
        };

        let (ip_min, ip_max) = if pkt.src_ip.octets() <= pkt.dst_ip.octets() {
            (pkt.src_ip, pkt.dst_ip)
        } else {
            (pkt.dst_ip, pkt.src_ip)
        };

        let (port_min, port_max) = if sport <= dport {
            (sport, dport)
        } else {
            (dport, sport)
        };

        Some(Self {
            ip_min,
            ip_max,
            port_min,
            port_max,
            proto,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnState {
    SynSent,
    Established,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    Tcp(TcpConnState),
    Generic,
}

#[derive(Debug, Clone)]
pub struct ConnEntry {
    pub state: FlowState,
    pub packets_seen: u64,
}

pub struct ConntrackTable {
    pub entries: BTreeMap<FlowKey, ConnEntry>,
}

impl ConntrackTable {
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    #[inline(always)]
    pub fn is_established(&self, key: &FlowKey) -> bool {
        if let Some(entry) = self.entries.get(key) {
            match entry.state {
                FlowState::Tcp(TcpConnState::Established) | FlowState::Tcp(TcpConnState::Closing) | FlowState::Generic => true,
                _ => false,
            }
        } else {
            false
        }
    }

    pub fn track_packet(&mut self, key: FlowKey, is_tcp: bool, is_syn: bool, is_fin_or_rst: bool) {
        let entry = self.entries.entry(key).or_insert_with(|| {
            if is_tcp {
                if is_syn {
                    ConnEntry { state: FlowState::Tcp(TcpConnState::SynSent), packets_seen: 0 }
                } else {
                    ConnEntry { state: FlowState::Tcp(TcpConnState::Established), packets_seen: 0 }
                }
            } else {
                ConnEntry { state: FlowState::Generic, packets_seen: 0 }
            }
        });

        entry.packets_seen += 1;

        if is_tcp {
            if let FlowState::Tcp(ref mut tcp_state) = entry.state {
                if is_fin_or_rst {
                    *tcp_state = TcpConnState::Closing;
                } else if *tcp_state == TcpConnState::SynSent && !is_syn {
                    *tcp_state = TcpConnState::Established;
                }
            }
        }
    }

    pub fn purge_closing(&mut self) {
        self.entries.retain(|_, v| match v.state {
            FlowState::Tcp(TcpConnState::Closing) => false,
            _ => true,
        });
    }
}