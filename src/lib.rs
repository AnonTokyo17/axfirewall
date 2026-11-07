#![no_std]

extern crate alloc;

pub mod conntrack;
pub mod parser;
pub mod config;
pub mod inspector;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket,
};
use spin::{Mutex, RwLock};
use core::sync::atomic::AtomicBool;
use conntrack::{ConntrackTable, FlowKey};

pub static BYPASS_FIREWALL: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    Accept,
    Drop,
    LogAccept,
    LogDrop,
}

impl FilterVerdict {
    #[inline(always)]
    pub fn is_drop(&self) -> bool {
        matches!(self, FilterVerdict::Drop | FilterVerdict::LogDrop)
    }

    #[inline(always)]
    pub fn should_log(&self) -> bool {
        matches!(self, FilterVerdict::LogAccept | FilterVerdict::LogDrop)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub addr: Ipv4Address,
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    pub const fn new(addr: Ipv4Address, prefix_len: u8) -> Self {
        let p = if prefix_len > 32 { 32 } else { prefix_len };
        let mask = Self::prefix_to_mask(p);
        let ip_u32 = u32::from_be_bytes(addr.octets()) & mask;
        let b = ip_u32.to_be_bytes();
        Self {
            addr: Ipv4Address::new(b[0], b[1], b[2], b[3]),
            prefix_len: p,
        }
    }

    pub const fn single(addr: Ipv4Address) -> Self {
        Self::new(addr, 32)
    }

    #[inline(always)]
    pub const fn prefix_to_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            !0u32
        } else {
            !0u32 << (32 - prefix_len)
        }
    }

    #[inline(always)]
    pub fn network_u32(&self) -> u32 {
        u32::from_be_bytes(self.addr.octets()) & Self::prefix_to_mask(self.prefix_len)
    }

    #[inline(always)]
    pub fn contains(&self, ip: Ipv4Address) -> bool {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        let mask = Self::prefix_to_mask(self.prefix_len);
        (ip_u32 & mask) == self.network_u32()
    }
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
    pub is_anomaly: bool,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub direction: Option<Direction>,
    pub proto: Option<L4Protocol>,
    pub src_cidr: Option<Ipv4Cidr>,
    pub dst_cidr: Option<Ipv4Cidr>,
    pub dst_port: Option<u16>,
    pub verdict: FilterVerdict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitVector1024 {
    pub bits: [u64; 16],
}

impl BitVector1024 {
    #[inline(always)]
    pub const fn zeros() -> Self {
        Self { bits: [0; 16] }
    }

    #[inline(always)]
    pub const fn ones() -> Self {
        Self { bits: [!0u64; 16] }
    }

    #[inline(always)]
    pub fn set_bit(&mut self, idx: usize) {
        if idx < 1024 {
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    #[inline(always)]
    pub fn and(&self, other: &Self) -> Self {
        let mut res = [0u64; 16];
        for i in 0..16 {
            res[i] = self.bits[i] & other.bits[i];
        }
        Self { bits: res }
    }

    #[inline(always)]
    pub fn or_assign(&mut self, other: &Self) {
        for i in 0..16 {
            self.bits[i] |= other.bits[i];
        }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        for i in 0..16 {
            if self.bits[i] != 0 {
                return false;
            }
        }
        true
    }

    #[inline(always)]
    pub fn find_first_set(&self) -> Option<usize> {
        for i in 0..16 {
            if self.bits[i] != 0 {
                return Some(i * 64 + (self.bits[i].trailing_zeros() as usize));
            }
        }
        None
    }
}

pub struct FirewallStats {
    pub rx_total: AtomicU64,
    pub rx_accepted: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub rx_fastpath: AtomicU64,
    pub tx_total: AtomicU64,
    pub tx_accepted: AtomicU64,
    pub tx_dropped: AtomicU64,
    pub tx_fastpath: AtomicU64,
}

impl FirewallStats {
    pub const fn new() -> Self {
        Self {
            rx_total: AtomicU64::new(0),
            rx_accepted: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            rx_fastpath: AtomicU64::new(0),
            tx_total: AtomicU64::new(0),
            tx_accepted: AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
            tx_fastpath: AtomicU64::new(0),
        }
    }
}

pub static FIREWALL_STATS: FirewallStats = FirewallStats::new();

const PORT_BUCKETS: usize = 256;
const IP_BUCKETS: usize = 256;

pub struct LbvsEngine {
    pub rules: Vec<Rule>,
    pub rule_hits: Vec<AtomicU64>,
    pub default_policy: FilterVerdict,
    pub in_bv: BitVector1024,
    pub out_bv: BitVector1024,
    pub tcp_bv: BitVector1024,
    pub udp_bv: BitVector1024,
    pub icmp_bv: BitVector1024,
    pub proto_wildcard: BitVector1024,
    pub dst_port_buckets: Vec<Vec<(u16, BitVector1024)>>,
    pub dst_port_wildcard: BitVector1024,
    pub dst_cidr_buckets: Vec<Vec<((u32, u8), BitVector1024)>>,
    pub active_dst_prefixes: Vec<u8>,
    pub dst_ip_wildcard: BitVector1024,
    pub src_cidr_buckets: Vec<Vec<((u32, u8), BitVector1024)>>,
    pub active_src_prefixes: Vec<u8>,
    pub src_ip_wildcard: BitVector1024,
}

impl LbvsEngine {
    pub fn new(default_policy: FilterVerdict) -> Self {
        Self {
            rules: Vec::new(),
            rule_hits: Vec::new(),
            default_policy,
            in_bv: BitVector1024::zeros(),
            out_bv: BitVector1024::zeros(),
            tcp_bv: BitVector1024::zeros(),
            udp_bv: BitVector1024::zeros(),
            icmp_bv: BitVector1024::zeros(),
            proto_wildcard: BitVector1024::zeros(),
            dst_port_buckets: vec![Vec::new(); PORT_BUCKETS],
            dst_port_wildcard: BitVector1024::zeros(),
            dst_cidr_buckets: vec![Vec::new(); IP_BUCKETS],
            active_dst_prefixes: Vec::new(),
            dst_ip_wildcard: BitVector1024::zeros(),
            src_cidr_buckets: vec![Vec::new(); IP_BUCKETS],
            active_src_prefixes: Vec::new(),
            src_ip_wildcard: BitVector1024::zeros(),
        }
    }

    #[inline(always)]
    fn hash_port(port: u16) -> usize {
        ((port as usize) ^ ((port >> 8) as usize)) & (PORT_BUCKETS - 1)
    }

    #[inline(always)]
    fn hash_cidr(net_addr: u32, prefix_len: u8) -> usize {
        let mut h = net_addr ^ (net_addr >> 16) ^ ((prefix_len as u32) << 24);
        h ^= h >> 8;
        (h as usize) & (IP_BUCKETS - 1)
    }

    pub fn build(&mut self) {
        self.in_bv = BitVector1024::zeros();
        self.out_bv = BitVector1024::zeros();
        self.tcp_bv = BitVector1024::zeros();
        self.udp_bv = BitVector1024::zeros();
        self.icmp_bv = BitVector1024::zeros();
        self.proto_wildcard = BitVector1024::zeros();

        for b in &mut self.dst_port_buckets {
            b.clear();
        }
        self.dst_port_wildcard = BitVector1024::zeros();

        for b in &mut self.dst_cidr_buckets {
            b.clear();
        }
        self.active_dst_prefixes.clear();
        self.dst_ip_wildcard = BitVector1024::zeros();

        for b in &mut self.src_cidr_buckets {
            b.clear();
        }
        self.active_src_prefixes.clear();
        self.src_ip_wildcard = BitVector1024::zeros();

        self.rule_hits.clear();
        for _ in 0..self.rules.len() {
            self.rule_hits.push(AtomicU64::new(0));
        }

        for (idx, rule) in self.rules.iter().enumerate() {
            if idx >= 1024 {
                break;
            }

            match rule.direction {
                Some(Direction::Inbound) => self.in_bv.set_bit(idx),
                Some(Direction::Outbound) => self.out_bv.set_bit(idx),
                None => {
                    self.in_bv.set_bit(idx);
                    self.out_bv.set_bit(idx);
                }
            }

            match rule.proto {
                Some(L4Protocol::Tcp) => self.tcp_bv.set_bit(idx),
                Some(L4Protocol::Udp) => self.udp_bv.set_bit(idx),
                Some(L4Protocol::Icmp) => self.icmp_bv.set_bit(idx),
                Some(L4Protocol::Other(_)) => {}
                None => {
                    self.proto_wildcard.set_bit(idx);
                    self.tcp_bv.set_bit(idx);
                    self.udp_bv.set_bit(idx);
                    self.icmp_bv.set_bit(idx);
                }
            }

            if let Some(port) = rule.dst_port {
                let b_idx = Self::hash_port(port);
                let bucket = &mut self.dst_port_buckets[b_idx];
                if let Some(entry) = bucket.iter_mut().find(|(p, _)| *p == port) {
                    entry.1.set_bit(idx);
                } else {
                    let mut bv = BitVector1024::zeros();
                    bv.set_bit(idx);
                    bucket.push((port, bv));
                }
            } else {
                self.dst_port_wildcard.set_bit(idx);
            }

            if let Some(cidr) = rule.dst_cidr {
                let net_u32 = cidr.network_u32();
                let plen = cidr.prefix_len;
                if !self.active_dst_prefixes.contains(&plen) {
                    self.active_dst_prefixes.push(plen);
                }
                let b_idx = Self::hash_cidr(net_u32, plen);
                let bucket = &mut self.dst_cidr_buckets[b_idx];
                if let Some(entry) = bucket.iter_mut().find(|(k, _)| *k == (net_u32, plen)) {
                    entry.1.set_bit(idx);
                } else {
                    let mut bv = BitVector1024::zeros();
                    bv.set_bit(idx);
                    bucket.push(((net_u32, plen), bv));
                }
            } else {
                self.dst_ip_wildcard.set_bit(idx);
            }

            if let Some(cidr) = rule.src_cidr {
                let net_u32 = cidr.network_u32();
                let plen = cidr.prefix_len;
                if !self.active_src_prefixes.contains(&plen) {
                    self.active_src_prefixes.push(plen);
                }
                let b_idx = Self::hash_cidr(net_u32, plen);
                let bucket = &mut self.src_cidr_buckets[b_idx];
                if let Some(entry) = bucket.iter_mut().find(|(k, _)| *k == (net_u32, plen)) {
                    entry.1.set_bit(idx);
                } else {
                    let mut bv = BitVector1024::zeros();
                    bv.set_bit(idx);
                    bucket.push(((net_u32, plen), bv));
                }
            } else {
                self.src_ip_wildcard.set_bit(idx);
            }
        }
    }

    #[inline(always)]
    pub fn classify_dir(&self, pkt: &PacketInfo, dir: Direction) -> FilterVerdict {
        let mut tmp_bv = match dir {
            Direction::Inbound => self.in_bv,
            Direction::Outbound => self.out_bv,
        };
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        let mut port_bv = self.dst_port_wildcard;
        if let Some(dport) = pkt.dst_port {
            let b_idx = Self::hash_port(dport);
            for (p, bv) in &self.dst_port_buckets[b_idx] {
                if *p == dport {
                    port_bv.or_assign(bv);
                    break;
                }
            }
        }
        tmp_bv = tmp_bv.and(&port_bv);
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        let proto_bv = match pkt.proto {
            L4Protocol::Tcp => &self.tcp_bv,
            L4Protocol::Udp => &self.udp_bv,
            L4Protocol::Icmp => &self.icmp_bv,
            L4Protocol::Other(_) => &self.proto_wildcard,
        };
        tmp_bv = tmp_bv.and(proto_bv);
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        let mut dst_ip_bv = self.dst_ip_wildcard;
        if !self.active_dst_prefixes.is_empty() {
            let dst_u32 = u32::from_be_bytes(pkt.dst_ip.octets());
            for &plen in &self.active_dst_prefixes {
                let masked = dst_u32 & Ipv4Cidr::prefix_to_mask(plen);
                let b_idx = Self::hash_cidr(masked, plen);
                for (key, bv) in &self.dst_cidr_buckets[b_idx] {
                    if *key == (masked, plen) {
                        dst_ip_bv.or_assign(bv);
                        break;
                    }
                }
            }
        }
        tmp_bv = tmp_bv.and(&dst_ip_bv);
        if tmp_bv.is_zero() {
            return self.default_policy;
        }

        if !self.active_src_prefixes.is_empty() {
            let mut src_ip_bv = self.src_ip_wildcard;
            let src_u32 = u32::from_be_bytes(pkt.src_ip.octets());
            for &plen in &self.active_src_prefixes {
                let masked = src_u32 & Ipv4Cidr::prefix_to_mask(plen);
                let b_idx = Self::hash_cidr(masked, plen);
                for (key, bv) in &self.src_cidr_buckets[b_idx] {
                    if *key == (masked, plen) {
                        src_ip_bv.or_assign(bv);
                        break;
                    }
                }
            }
            tmp_bv = tmp_bv.and(&src_ip_bv);
            if tmp_bv.is_zero() {
                return self.default_policy;
            }
        }

        if let Some(first_idx) = tmp_bv.find_first_set() {
            if first_idx < self.rule_hits.len() {
                self.rule_hits[first_idx].fetch_add(1, Ordering::Relaxed);
            }
            self.rules[first_idx].verdict
        } else {
            self.default_policy
        }
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

    let (proto, src_port, dst_port, is_syn, is_fin_or_rst, is_anomaly) = match ipv4_packet.next_header() {
        IpProtocol::Tcp => {
            if let Ok(tcp) = TcpPacket::new_checked(payload) {
                let anomaly_verdict = inspector::inspect_tcp(&tcp);
                let is_anomaly = anomaly_verdict.is_drop();
                (
                    L4Protocol::Tcp,
                    Some(tcp.src_port()),
                    Some(tcp.dst_port()),
                    tcp.syn() && !tcp.ack(),
                    tcp.fin() || tcp.rst(),
                    is_anomaly,
                )
            } else {
                (L4Protocol::Tcp, None, None, false, false, false)
            }
        }
        IpProtocol::Udp => {
            if let Ok(udp) = UdpPacket::new_checked(payload) {
                (
                    L4Protocol::Udp,
                    Some(udp.src_port()),
                    Some(udp.dst_port()),
                    false,
                    false,
                    false,
                )
            } else {
                (L4Protocol::Udp, None, None, false, false, false)
            }
        }
        IpProtocol::Icmp => (L4Protocol::Icmp, None, None, false, false, false),
        IpProtocol::Unknown(val) => (L4Protocol::Other(val), None, None, false, false, false),
        _ => (L4Protocol::Other(0), None, None, false, false, false),
    };

    Some(PacketInfo {
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
        is_syn,
        is_fin_or_rst,
        is_anomaly,
    })
}

pub static FIREWALL_ENGINE: RwLock<Option<LbvsEngine>> = RwLock::new(None);
pub static CONNTRACK_TABLE: Mutex<ConntrackTable> = Mutex::new(ConntrackTable::new());

fn get_current_time_secs() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc() / 2_000_000_000
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

pub fn execute_cmd(cmd: &str) -> Result<String, &'static str> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    if trimmed == "flush" || trimmed == "iptables -F" || trimmed == "-F" {
        let mut lock = FIREWALL_ENGINE.write();
        if let Some(ref mut engine) = *lock {
            engine.rules.clear();
            engine.build();
        }
        CONNTRACK_TABLE.lock().entries.clear();
        inspector::ANOMALY_STATS.reset();
        return Ok(String::from("Firewall rules flushed and conntrack cleared.\n"));
    }

    if trimmed == "status" || trimmed == "iptables -L" || trimmed == "-L" {
        return Ok(dump_status());
    }

    if trimmed.starts_with("del ") || trimmed.starts_with("iptables -D ") || trimmed.starts_with("-D ") {
        let tokens: alloc::vec::Vec<&str> = trimmed.split_whitespace().collect();
        let idx_str = tokens.last().ok_or("Missing rule index")?;
        let raw_idx = idx_str.parse::<usize>().map_err(|_| "Invalid rule index")?;
        let idx = if trimmed.contains("-D") { raw_idx.saturating_sub(1) } else { raw_idx };

        let mut lock = FIREWALL_ENGINE.write();
        if let Some(ref mut engine) = *lock {
            if idx < engine.rules.len() {
                engine.rules.remove(idx);
                engine.build();
                return Ok(String::from("Rule removed.\n"));
            } else {
                return Err("Rule index out of range");
            }
        }
        return Err("Firewall engine not initialized");
    }

    if trimmed == "bypass on" {
        BYPASS_FIREWALL.store(true, Ordering::Relaxed);
        return Ok(String::from("Firewall completely bypassed (Pure Baseline Mode).\n"));
    }
    if trimmed == "bypass off" {
        BYPASS_FIREWALL.store(false, Ordering::Relaxed);
        return Ok(String::from("Firewall active.\n"));
    }

    match parser::parse_rule_cmd(trimmed) {
        Ok((insert_idx, rule)) => {
            let is_drop = rule.verdict.is_drop();
            let mut lock = FIREWALL_ENGINE.write();
            if lock.is_none() {
                *lock = Some(LbvsEngine::new(FilterVerdict::Accept));
            }
            if let Some(ref mut engine) = *lock {
                if let Some(idx) = insert_idx {
                    let target = if idx > engine.rules.len() { engine.rules.len() } else { idx };
                    engine.rules.insert(target, rule);
                } else {
                    engine.rules.push(rule);
                }
                engine.build();
            }

            if is_drop {
                CONNTRACK_TABLE.lock().entries.clear();
            }

            Ok(String::from("Rule applied successfully.\n"))
        }
        Err(_) => Err("Failed to parse rule. Format: iptables -A/-I or add/insert ..."),
    }
}

pub fn init_firewall_with_conf(conf: &str) {
    let mut lock = FIREWALL_ENGINE.write();
    if lock.is_none() {
        *lock = Some(LbvsEngine::new(FilterVerdict::Accept));
    }
    drop(lock);

    let _ = execute_cmd("flush");

    match config::load_rules_from_str(conf) {
        Ok(count) => {
            log::info!("[axfirewall-init] Declarative configuration loaded ({} rules applied).", count);
        }
        Err(e) => {
            log::error!("[axfirewall-init] Failed to load declarative configuration: {}", e);
        }
    }
}

pub fn init_firewall() {
    init_firewall_with_conf(config::DEFAULT_FIREWALL_CONF);
}

pub fn dump_status() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n================ axfirewall Status & Telemetry ================");
    let _ = writeln!(
        out,
        "RX Packets: total={}, accepted={}, dropped={}, fastpath={}",
        FIREWALL_STATS.rx_total.load(Ordering::Relaxed),
        FIREWALL_STATS.rx_accepted.load(Ordering::Relaxed),
        FIREWALL_STATS.rx_dropped.load(Ordering::Relaxed),
        FIREWALL_STATS.rx_fastpath.load(Ordering::Relaxed),
    );
    let _ = writeln!(
        out,
        "TX Packets: total={}, accepted={}, dropped={}, fastpath={}",
        FIREWALL_STATS.tx_total.load(Ordering::Relaxed),
        FIREWALL_STATS.tx_accepted.load(Ordering::Relaxed),
        FIREWALL_STATS.tx_dropped.load(Ordering::Relaxed),
        FIREWALL_STATS.tx_fastpath.load(Ordering::Relaxed),
    );

    let total_ano = inspector::ANOMALY_STATS.total_anomaly_dropped.load(Ordering::Relaxed);
    let null_ano = inspector::ANOMALY_STATS.null_scan_dropped.load(Ordering::Relaxed);
    let xmas_ano = inspector::ANOMALY_STATS.xmas_scan_dropped.load(Ordering::Relaxed);
    let synfin_ano = inspector::ANOMALY_STATS.syn_fin_dropped.load(Ordering::Relaxed);
    let _ = writeln!(out, "------------------- Anomaly Inspector Stats ------------------");
    let _ = writeln!(
        out,
        "Total Blocked: {} (Null Scan: {}, Xmas Scan: {}, SYN+FIN: {})",
        total_ano, null_ano, xmas_ano, synfin_ano
    );

    let lock = FIREWALL_ENGINE.read();
    if let Some(ref engine) = *lock {
        let _ = writeln!(out, "------------------- Rules & Hit Counters --------------------");
        let _ = writeln!(out, "Idx | Dir  | Proto | Src CIDR          | Dst Port | Verdict | Hits");
        for (idx, r) in engine.rules.iter().enumerate() {
            let hits = engine
                .rule_hits
                .get(idx)
                .map(|h| h.load(Ordering::Relaxed))
                .unwrap_or(0);
            let dir_str = match r.direction {
                Some(Direction::Inbound) => "IN  ",
                Some(Direction::Outbound) => "OUT ",
                None => "BOTH",
            };
            let _ = writeln!(
                out,
                "{:>3} | {} | {:<5?} | {:<17?} | {:<8?} | {:<7?} | {}",
                idx,
                dir_str,
                r.proto,
                r.src_cidr,
                r.dst_port,
                r.verdict,
                hits
            );
        }
    }

    let ct = CONNTRACK_TABLE.lock();
    let _ = writeln!(out, "Active Conntrack Sessions: {}", ct.entries.len());
    let _ = writeln!(out, "===============================================================");
    out
}

pub fn filter_rx_packet(raw_pkt: &[u8]) -> FilterVerdict {
    if BYPASS_FIREWALL.load(Ordering::Relaxed) {
        return FilterVerdict::Accept;
    }
    FIREWALL_STATS.rx_total.fetch_add(1, Ordering::Relaxed);

    let pkt_info = match parse_packet(raw_pkt) {
        Some(info) => info,
        None => {
            FIREWALL_STATS.rx_accepted.fetch_add(1, Ordering::Relaxed);
            return FilterVerdict::Accept;
        }
    };

    if pkt_info.is_anomaly {
        FIREWALL_STATS.rx_dropped.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "[axfirewall-inspector] DROP ANOMALY IN: {:?} {}:{} -> {}:{}",
            pkt_info.proto,
            pkt_info.src_ip,
            pkt_info.src_port.unwrap_or(0),
            pkt_info.dst_ip,
            pkt_info.dst_port.unwrap_or(0),
        );
        return FilterVerdict::Drop;
    }

    let flow_key = FlowKey::from_packet(&pkt_info);
    let now = get_current_time_secs();

    if let Some(ref key) = flow_key {
        let mut ct = CONNTRACK_TABLE.lock();
        if let Some(cached_verdict) = ct.get_established_verdict(key) {
            if pkt_info.is_fin_or_rst {
                ct.track_packet(
                    *key,
                    pkt_info.proto == L4Protocol::Tcp,
                    pkt_info.is_syn,
                    true,
                    cached_verdict,
                    now,
                );
            }
            drop(ct);
            FIREWALL_STATS.rx_fastpath.fetch_add(1, Ordering::Relaxed);
            FIREWALL_STATS.rx_accepted.fetch_add(1, Ordering::Relaxed);
            return cached_verdict;
        }
    }

    let lock = FIREWALL_ENGINE.read();
    let verdict = if let Some(ref engine) = *lock {
        engine.classify_dir(&pkt_info, Direction::Inbound)
    } else {
        FilterVerdict::Accept
    };
    drop(lock);

    if verdict.is_drop() {
        FIREWALL_STATS.rx_dropped.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "[axfirewall-lbvs] DROP IN: {:?} {}:{} -> {}:{}",
            pkt_info.proto,
            pkt_info.src_ip,
            pkt_info.src_port.unwrap_or(0),
            pkt_info.dst_ip,
            pkt_info.dst_port.unwrap_or(0),
        );
    } else {
        FIREWALL_STATS.rx_accepted.fetch_add(1, Ordering::Relaxed);
        if let Some(key) = flow_key {
            let mut ct = CONNTRACK_TABLE.lock();
            ct.track_packet(
                key,
                pkt_info.proto == L4Protocol::Tcp,
                pkt_info.is_syn,
                pkt_info.is_fin_or_rst,
                verdict,
                now,
            );
            ct.maybe_gc(now);
        }
    }

    verdict
}

pub fn filter_tx_packet(raw_pkt: &[u8]) -> FilterVerdict {
    if BYPASS_FIREWALL.load(Ordering::Relaxed) {
        return FilterVerdict::Accept;
    }
    FIREWALL_STATS.tx_total.fetch_add(1, Ordering::Relaxed);

    let pkt_info = match parse_packet(raw_pkt) {
        Some(info) => info,
        None => {
            FIREWALL_STATS.tx_accepted.fetch_add(1, Ordering::Relaxed);
            return FilterVerdict::Accept;
        }
    };

    let flow_key = FlowKey::from_packet(&pkt_info);
    let now = get_current_time_secs();

    if let Some(ref key) = flow_key {
        let mut ct = CONNTRACK_TABLE.lock();
        if let Some(cached_verdict) = ct.get_established_verdict(key) {
            ct.track_packet(
                *key,
                pkt_info.proto == L4Protocol::Tcp,
                pkt_info.is_syn,
                pkt_info.is_fin_or_rst,
                cached_verdict,
                now,
            );
            FIREWALL_STATS.tx_fastpath.fetch_add(1, Ordering::Relaxed);
            FIREWALL_STATS.tx_accepted.fetch_add(1, Ordering::Relaxed);
            return cached_verdict;
        }
    }

    let lock = FIREWALL_ENGINE.read();
    let verdict = if let Some(ref engine) = *lock {
        engine.classify_dir(&pkt_info, Direction::Outbound)
    } else {
        FilterVerdict::Accept
    };
    drop(lock);

    if verdict.is_drop() {
        FIREWALL_STATS.tx_dropped.fetch_add(1, Ordering::Relaxed);
    } else {
        FIREWALL_STATS.tx_accepted.fetch_add(1, Ordering::Relaxed);
        if let Some(key) = flow_key {
            let mut ct = CONNTRACK_TABLE.lock();
            ct.track_packet(
                key,
                pkt_info.proto == L4Protocol::Tcp,
                pkt_info.is_syn,
                pkt_info.is_fin_or_rst,
                verdict,
                now,
            );
        }
    }

    verdict
}