use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::wire::TcpPacket;

pub struct AnomalyStats {
    pub null_scan_dropped: AtomicU64,
    pub xmas_scan_dropped: AtomicU64,
    pub syn_fin_dropped: AtomicU64,
    pub total_anomaly_dropped: AtomicU64,
}

impl AnomalyStats {
    pub const fn new() -> Self {
        Self {
            null_scan_dropped: AtomicU64::new(0),
            xmas_scan_dropped: AtomicU64::new(0),
            syn_fin_dropped: AtomicU64::new(0),
            total_anomaly_dropped: AtomicU64::new(0),
        }
    }

    pub fn reset(&self) {
        self.null_scan_dropped.store(0, Ordering::Relaxed);
        self.xmas_scan_dropped.store(0, Ordering::Relaxed);
        self.syn_fin_dropped.store(0, Ordering::Relaxed);
        self.total_anomaly_dropped.store(0, Ordering::Relaxed);
    }
}

pub static ANOMALY_STATS: AnomalyStats = AnomalyStats::new();

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AnomalyVerdict {
    Pass,
    DropNullScan,
    DropXmasScan,
    DropSynFinScan,
}

impl AnomalyVerdict {
    #[inline]
    pub fn is_drop(&self) -> bool {
        !matches!(self, AnomalyVerdict::Pass)
    }
}

const TCP_FLAG_FIN: u8 = 0b0000_0001;
const TCP_FLAG_SYN: u8 = 0b0000_0010;
const TCP_FLAG_RST: u8 = 0b0000_0100;
const TCP_FLAG_PSH: u8 = 0b0000_1000;
const TCP_FLAG_ACK: u8 = 0b0001_0000;
const TCP_FLAG_URG: u8 = 0b0010_0000;

pub fn inspect_tcp(tcp_pkt: &TcpPacket<&[u8]>) -> AnomalyVerdict {
    let mut flags = 0u8;
    if tcp_pkt.fin() { flags |= TCP_FLAG_FIN; }
    if tcp_pkt.syn() { flags |= TCP_FLAG_SYN; }
    if tcp_pkt.rst() { flags |= TCP_FLAG_RST; }
    if tcp_pkt.psh() { flags |= TCP_FLAG_PSH; }
    if tcp_pkt.ack() { flags |= TCP_FLAG_ACK; }
    if tcp_pkt.urg() { flags |= TCP_FLAG_URG; }

    if flags == 0 {
        ANOMALY_STATS.null_scan_dropped.fetch_add(1, Ordering::Relaxed);
        ANOMALY_STATS.total_anomaly_dropped.fetch_add(1, Ordering::Relaxed);
        return AnomalyVerdict::DropNullScan;
    }

    let xmas_mask = TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG;
    if (flags & xmas_mask) == xmas_mask {
        ANOMALY_STATS.xmas_scan_dropped.fetch_add(1, Ordering::Relaxed);
        ANOMALY_STATS.total_anomaly_dropped.fetch_add(1, Ordering::Relaxed);
        return AnomalyVerdict::DropXmasScan;
    }

    if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) == (TCP_FLAG_SYN | TCP_FLAG_FIN) {
        ANOMALY_STATS.syn_fin_dropped.fetch_add(1, Ordering::Relaxed);
        ANOMALY_STATS.total_anomaly_dropped.fetch_add(1, Ordering::Relaxed);
        return AnomalyVerdict::DropSynFinScan;
    }

    AnomalyVerdict::Pass
}