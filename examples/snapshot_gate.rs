//! Measure bounded lock-free snapshot publication and retirement.
//!
//! This is an evidence tool, not a performance claim. RSS is process-wide and
//! may include allocator retention and unrelated activity; the output records
//! that provenance explicitly.

use blackhole::snapshot::{PolicyStore, ReloadState};
use blackhole::{Action, RuleConfig};
use std::time::Instant;

fn rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn rule(id: u32) -> RuleConfig {
    RuleConfig {
        enabled: true,
        id,
        domain: format!("generation-{id}.example"),
        action: Action::Reject,
        priority: 0,
        qtype: None,
        qtypes: Vec::new(),
        qclass: None,
        qclasses: Vec::new(),
        client: None,
        client_cidr: None,
        client_cidrs: Vec::new(),
        client_identity: None,
    }
}

fn percentile(samples: &mut [u128], numerator: usize, denominator: usize) -> u128 {
    samples.sort_unstable();
    let index = ((samples.len() * numerator).div_ceil(denominator)).saturating_sub(1);
    samples[index.min(samples.len() - 1)]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SAMPLES: u32 = 256;
    let store = PolicyStore::new(&[rule(0)])?;
    let rss_before = rss_kib();
    let mut latencies = Vec::with_capacity(SAMPLES as usize);
    for id in 1..=SAMPLES {
        let started = Instant::now();
        assert_eq!(store.reload(&[rule(id)])?, ReloadState::Published);
        latencies.push(started.elapsed().as_nanos());
    }
    let rss_after = rss_kib();
    let p50 = percentile(&mut latencies, 50, 100);
    let p95 = percentile(&mut latencies, 95, 100);
    let p99 = percentile(&mut latencies, 99, 100);
    println!(
        "snapshot_samples={SAMPLES} rss_before_kib={rss_before:?} rss_after_kib={rss_after:?}"
    );
    println!("snapshot_reload_ns p50={p50} p95={p95} p99={p99}");
    match (rss_before, rss_after) {
        (Some(before), Some(after)) => println!(
            "snapshot_rss_delta_kib=MEASURED {} provenance=process-wide-rss",
            after.saturating_sub(before)
        ),
        _ => println!("snapshot_rss_delta_kib=UNMEASURED provenance=/proc-unavailable"),
    }
    Ok(())
}
