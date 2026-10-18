#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket,
};

pub mod linear;
pub mod conntrack;
use conntrack::{ConntrackTable, FlowKey};

pub const MAX_RULES: usize = 1024;
const BV_WORDS: usize = MAX_RULES / 64; 
const HASH_BUCKETS: usize = 256;       

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitVector1024 {
    pub bits: [u64; BV_WORDS],
}

impl BitVector1024 {
    pub const fn zero() -> Self {
        Self { bits: [0; BV_WORDS] }
    }

    pub const fn ones() -> Self {
        Self { bits: [!0; BV_WORDS] }
    }

    #[inline(always)]
    pub fn set_bit(&mut self, idx: usize) {
        if idx < MAX_RULES {
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    #[inline(always)]
    pub fn and(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..BV_WORDS {
            res.bits[i] = self.bits[i] & other.bits[i];
        }
        res
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    #[inline(always)]
    pub fn find_first_set(&self) -> Option<usize> {
        for (i, &word) in self.bits.iter().enumerate() {
            if word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
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
    pub is_syn: bool,
    pub is_fin_or_rst: bool,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub proto: Option<L4Protocol>,
    pub src_ip: Option<Ipv4Address>,
    pub dst_ip: Option<Ipv4Address>,
    pub dst_port: Option<u16>,
    pub verdict: FilterVerdict,
}

pub struct LbvsEngine {
    pub rules: Vec<Rule>,
    pub default_policy: FilterVerdict,

    proto_wildcard: BitVector1024,
    proto_tcp: BitVector1024,
    proto_udp: BitVector1024,
    proto_icmp: BitVector1024,

    dst_port_wildcard: BitVector1024,
    dst_port_buckets: [Vec<(u16, BitVector1024)>; HASH_BUCKETS],

    dst_ip_wildcard: BitVector1024,
    dst_ip_buckets: [Vec<(Ipv4Address, BitVector1024)>; HASH_BUCKETS],
}

impl LbvsEngine {
    pub fn new(default_policy: FilterVerdict) -> Self {
        const EMPTY_VEC_PORT: Vec<(u16, BitVector1024)> = Vec::new();
        const EMPTY_VEC_IP: Vec<(Ipv4Address, BitVector1024)> = Vec::new();
        Self {
            rules: Vec::new(),
            default_policy,
            proto_wildcard: BitVector1024::zero(),
            proto_tcp: BitVector1024::zero(),
            proto_udp: BitVector1024::zero(),
            proto_icmp: BitVector1024::zero(),
            dst_port_wildcard: BitVector1024::zero(),
            dst_port_buckets: [EMPTY_VEC_PORT; HASH_BUCKETS],
            dst_ip_wildcard: BitVector1024::zero(),
            dst_ip_buckets: [EMPTY_VEC_IP; HASH_BUCKETS],
        }
    }

    pub fn build(&mut self) {
        self.proto_wildcard = BitVector1024::zero();
        self.proto_tcp = BitVector1024::zero();
        self.proto_udp = BitVector1024::zero();
        self.proto_icmp = BitVector1024::zero();

        self.dst_port_wildcard = BitVector1024::zero();
        for b in self.dst_port_buckets.iter_mut() {
            b.clear();
        }

        self.dst_ip_wildcard = BitVector1024::zero();
        for b in self.dst_ip_buckets.iter_mut() {
            b.clear();
        }

        for (idx, rule) in self.rules.iter().enumerate().take(MAX_RULES) {
            match rule.proto {
                None => self.proto_wildcard.set_bit(idx),
                Some(L4Protocol::Tcp) => self.proto_tcp.set_bit(idx),
                Some(L4Protocol::Udp) => self.proto_udp.set_bit(idx),
                Some(L4Protocol::Icmp) => self.proto_icmp.set_bit(idx),
                Some(L4Protocol::Other(_)) => {}
            }

            match rule.dst_port {
                None => self.dst_port_wildcard.set_bit(idx),
                Some(port) => {
                    let bucket = ((port as usize) ^ (port as usize >> 8)) % HASH_BUCKETS;
                    if let Some(entry) = self.dst_port_buckets[bucket].iter_mut().find(|(p, _)| *p == port) {
                        entry.1.set_bit(idx);
                    } else {
                        let mut bv = BitVector1024::zero();
                        bv.set_bit(idx);
                        self.dst_port_buckets[bucket].push((port, bv));
                    }
                }
            }

            match rule.dst_ip {
                None => self.dst_ip_wildcard.set_bit(idx),
                Some(ip) => {
                    let ip_bytes = ip.octets();
                    let bucket = ((ip_bytes[2] as usize) << 8 | (ip_bytes[3] as usize)) % HASH_BUCKETS;
                    if let Some(entry) = self.dst_ip_buckets[bucket].iter_mut().find(|(i, _)| *i == ip) {
                        entry.1.set_bit(idx);
                    } else {
                        let mut bv = BitVector1024::zero();
                        bv.set_bit(idx);
                        self.dst_ip_buckets[bucket].push((ip, bv));
                    }
                }
            }
        }
    }

    #[inline(never)]
    pub fn classify(&self, pkt: &PacketInfo) -> FilterVerdict {
        let mut tmp_bv = BitVector1024::ones();

        let mut port_bv = self.dst_port_wildcard;
        if let Some(dport) = pkt.dst_port {
            let bucket = ((dport as usize) ^ (dport as usize >> 8)) % HASH_BUCKETS;
            if let Some((_, bv)) = self.dst_port_buckets[bucket].iter().find(|(p, _)| *p == dport) {
                for i in 0..BV_WORDS {
                    port_bv.bits[i] |= bv.bits[i];
                }
            }
        }
        tmp_bv = tmp_bv.and(&port_bv);
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        let mut proto_bv = self.proto_wildcard;
        let specific_proto_bv = match pkt.proto {
            L4Protocol::Tcp => &self.proto_tcp,
            L4Protocol::Udp => &self.proto_udp,
            L4Protocol::Icmp => &self.proto_icmp,
            L4Protocol::Other(_) => &BitVector1024::zero(),
        };
        for i in 0..BV_WORDS {
            proto_bv.bits[i] |= specific_proto_bv.bits[i];
        }
        tmp_bv = tmp_bv.and(&proto_bv);
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        let mut ip_bv = self.dst_ip_wildcard;
        let ip_bytes = pkt.dst_ip.octets();
        let bucket = ((ip_bytes[2] as usize) << 8 | (ip_bytes[3] as usize)) % HASH_BUCKETS;
        if let Some((_, bv)) = self.dst_ip_buckets[bucket].iter().find(|(ip, _)| *ip == pkt.dst_ip) {
            for i in 0..BV_WORDS {
                ip_bv.bits[i] |= bv.bits[i];
            }
        }
        tmp_bv = tmp_bv.and(&ip_bv);
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        if let Some(rule_idx) = tmp_bv.find_first_set() {
            self.rules[rule_idx].verdict
        } else {
            self.default_policy
        }
    }
}

pub static FIREWALL_ENGINE: Mutex<Option<LbvsEngine>> = Mutex::new(None);

pub fn init_firewall() {
    let mut engine = LbvsEngine::new(FilterVerdict::Accept);

    for p in 8000..8050 {
        engine.rules.push(Rule {
            proto: Some(L4Protocol::Tcp),
            src_ip: None,
            dst_ip: None,
            dst_port: Some(p),
            verdict: FilterVerdict::Accept,
        });
    }

    engine.rules.push(Rule {
        proto: Some(L4Protocol::Tcp),
        src_ip: None,
        dst_ip: None,
        dst_port: Some(5555),
        verdict: FilterVerdict::Accept,
    });

    engine.build();
    *FIREWALL_ENGINE.lock() = Some(engine);
    log::info!("[axfirewall] Global RuleManager initialized with Hash-LBVS!");

}

pub fn add_rule(rule: Rule) {
    let mut lock = FIREWALL_ENGINE.lock();
    if let Some(engine) = lock.as_mut() {
        if engine.rules.len() < MAX_RULES {
            engine.rules.push(rule);
            engine.build();
        }
    }
}

pub fn flush_rules() {
    let mut lock = FIREWALL_ENGINE.lock();
    if let Some(engine) = lock.as_mut() {
        engine.rules.clear();
        engine.build();
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

    let (proto, src_port, dst_port, is_syn, is_fin_or_rst) = match ipv4_packet.next_header() {
        IpProtocol::Tcp => {
            if let Ok(tcp) = TcpPacket::new_checked(payload) {
                let syn = tcp.syn();
                let fin_rst = tcp.fin() || tcp.rst();
                (L4Protocol::Tcp, Some(tcp.src_port()), Some(tcp.dst_port()), syn, fin_rst)
            } else {
                (L4Protocol::Tcp, None, None, false, false)
            }
        }
        IpProtocol::Udp => {
            if let Ok(udp) = UdpPacket::new_checked(payload) {
                (L4Protocol::Udp, Some(udp.src_port()), Some(udp.dst_port()), false, false)
            } else {
                (L4Protocol::Udp, None, None, false, false)
            }
        }
        IpProtocol::Icmp => (L4Protocol::Icmp, None, None, false, false),
        IpProtocol::Unknown(val) => (L4Protocol::Other(val), None, None, false, false),
        _ => (L4Protocol::Other(0), None, None, false, false),
    };

    Some(PacketInfo {
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
        is_syn,
        is_fin_or_rst,
    })
}

pub static CONNTRACK_TABLE: Mutex<ConntrackTable> = Mutex::new(ConntrackTable::new());

pub fn filter_rx_packet(raw_pkt: &[u8]) -> FilterVerdict {
    let pkt_info = match parse_packet(raw_pkt) {
        Some(info) => info,
        None => return FilterVerdict::Accept,
    };
    let flow_key = FlowKey::from_packet(&pkt_info);

    if let Some(ref key) = flow_key {
        let mut ct = CONNTRACK_TABLE.lock();
        if ct.is_established(key) {
            ct.track_packet(*key, pkt_info.proto == L4Protocol::Tcp, pkt_info.is_syn, pkt_info.is_fin_or_rst);
            log::info!("[axfirewall-fastpath] BYPASS: 已建连流直通放行 -> dst_port={:?}", pkt_info.dst_port);
            return FilterVerdict::Accept;
        }
    }

    let mut lock = FIREWALL_ENGINE.lock();
    if lock.is_none() {
        drop(lock);
        init_firewall();
        lock = FIREWALL_ENGINE.lock();
    }

    let verdict = if let Some(ref engine) = *lock {
        engine.classify(&pkt_info)
    } else {
        FilterVerdict::Accept
    };

    if verdict == FilterVerdict::Drop {
        log::warn!(
            "[axfirewall-lbvs] DROP: {:?} {}:{} -> {}:{}",
            pkt_info.proto,
            pkt_info.src_ip,
            pkt_info.src_port.unwrap_or(0),
            pkt_info.dst_ip,
            pkt_info.dst_port.unwrap_or(0),
        );
    } else if let Some(key) = flow_key {
        log::info!("[axfirewall-slowpath] ACCEPT: 首包/未建连包经 LBVS 查表放行并登记 Conntrack");
        let mut ct = CONNTRACK_TABLE.lock();
        ct.track_packet(key, pkt_info.proto == L4Protocol::Tcp, pkt_info.is_syn, pkt_info.is_fin_or_rst);
    }

    verdict
}