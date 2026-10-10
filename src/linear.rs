use alloc::vec::Vec;
use crate::{FilterVerdict, PacketInfo, Rule};

pub struct LinearEngine {
    pub rules: Vec<Rule>,
    pub default_policy: FilterVerdict,
}

impl LinearEngine {
    pub fn new(rules: Vec<Rule>, default_policy: FilterVerdict) -> Self {
        Self { rules, default_policy }
    }

    #[inline(never)]
    pub fn classify(&self, pkt: &PacketInfo) -> FilterVerdict {
        for rule in &self.rules {
            if let Some(proto) = rule.proto {
                if proto != pkt.proto {
                    continue;
                }
            }
            if let Some(src_ip) = rule.src_ip {
                if src_ip != pkt.src_ip {
                    continue;
                }
            }
            if let Some(dst_ip) = rule.dst_ip {
                if dst_ip != pkt.dst_ip {
                    continue;
                }
            }
            if let Some(dst_port) = rule.dst_port {
                if pkt.dst_port != Some(dst_port) {
                    continue;
                }
            }
            return rule.verdict;
        }
        self.default_policy
    }
}