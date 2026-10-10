use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;
use crate::linear::LinearEngine;
use crate::{FilterVerdict, L4Protocol, LbvsEngine, PacketInfo, Rule};

#[inline(always)]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

pub fn run_evaluation() {
    log::info!("================== axfirewall 效果评估基准测试 ==================");

    let rule_scales = [10, 50, 100, 500, 1000];

    let test_pkt_normal = PacketInfo {
        src_ip: Ipv4Address::new(10, 0, 2, 2),
        dst_ip: Ipv4Address::new(10, 0, 2, 10),
        proto: L4Protocol::Tcp,
        src_port: Some(40000),
        dst_port: Some(8000),
    };

    let test_pkt_scan = PacketInfo {
        src_ip: Ipv4Address::new(10, 0, 2, 2),
        dst_ip: Ipv4Address::new(10, 0, 2, 10),
        proto: L4Protocol::Tcp,
        src_port: Some(40000),
        dst_port: Some(9999),
    };

    log::info!("【实验 1：多维规则规模扩展性】Linear 线性遍历 vs LBVS 位向量匹配:");
    log::info!("规则数(N) | 传统线性遍历(Cycles) | LBVS位向量(Cycles) | 加速比(Speedup)");

    for &n in &rule_scales {
        let mut rules = Vec::with_capacity(n);

        for i in 0..n {
            let port = 8000 + ((i % 16) as u16);
            let ip_last = ((i % 200) + 1) as u8;
            rules.push(Rule {
                proto: Some(L4Protocol::Tcp),
                src_ip: None,
                dst_ip: Some(Ipv4Address::new(10, 0, 2, ip_last)),
                dst_port: Some(port),
                verdict: FilterVerdict::Accept,
            });
        }

        let linear_eng = LinearEngine::new(rules.clone(), FilterVerdict::Accept);
        let mut lbvs_eng = LbvsEngine::new(FilterVerdict::Accept);
        lbvs_eng.rules = rules;
        lbvs_eng.build();

        const ITERS: u64 = 10000;

        let start = read_tsc();
        for _ in 0..ITERS {
            core::hint::black_box(linear_eng.classify(&test_pkt_normal));
        }
        let linear_cycles = (read_tsc() - start) / ITERS;

        let start = read_tsc();
        for _ in 0..ITERS {
            core::hint::black_box(lbvs_eng.classify(&test_pkt_normal));
        }
        let lbvs_cycles = (read_tsc() - start) / ITERS;

        let speedup = if lbvs_cycles > 0 {
            linear_cycles as f64 / lbvs_cycles as f64
        } else {
            1.0
        };

        log::info!("{:>8} | {:>20} | {:>18} | {:>12.2}x", n, linear_cycles, lbvs_cycles, speedup);
    }

    log::info!("---------------------------------------------------------------");
    log::info!("【实验 2：Early-Break 短路优化收益验证 (N = 1000, 多维流水线)】:");

    let mut rules_1000 = Vec::with_capacity(1000);
    for i in 0..1000 {
        let port = 8000 + ((i % 16) as u16);
        let ip_last = ((i % 200) + 1) as u8;
        rules_1000.push(Rule {
            proto: Some(L4Protocol::Tcp),
            src_ip: None,
            dst_ip: Some(Ipv4Address::new(10, 0, 2, ip_last)),
            dst_port: Some(port),
            verdict: FilterVerdict::Accept,
        });
    }

    let mut lbvs_eng = LbvsEngine::new(FilterVerdict::Accept);
    lbvs_eng.rules = rules_1000;
    lbvs_eng.build();

    const ITERS_EXP2: u64 = 20000;

    let start = read_tsc();
    for _ in 0..ITERS_EXP2 {
        core::hint::black_box(lbvs_eng.classify(&test_pkt_normal));
    }
    let full_pipeline_cycles = (read_tsc() - start) / ITERS_EXP2;

    let start = read_tsc();
    for _ in 0..ITERS_EXP2 {
        core::hint::black_box(lbvs_eng.classify(&test_pkt_scan));
    }
    let early_break_cycles = (read_tsc() - start) / ITERS_EXP2;

    let drop_ratio = if full_pipeline_cycles > 0 && full_pipeline_cycles > early_break_cycles {
        (1.0 - early_break_cycles as f64 / full_pipeline_cycles as f64) * 100.0
    } else {
        0.0
    };

    log::info!("全流水线匹配耗时 (Full Pipeline): {} cycles", full_pipeline_cycles);
    log::info!("Early-Break 短路耗时 (Port Break):  {} cycles", early_break_cycles);
    log::info!("优化效益: 拦截扫描/非法报文开销降低 {:.1}%", drop_ratio);
    log::info!("===============================================================");
}