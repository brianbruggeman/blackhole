//! B14 discipline gate. This is an executable Rust measurement, not a shell
//! script. It records allocator activity around the current scalar path so a
//! SIMD or WASM change cannot be described as zero-copy by inspection.

#[cfg(feature = "perf-instrument")]
use blackhole::perf;
use blackhole::policy::{Action, QueryContext, ReferencePolicy, RuleConfig};
use blackhole::query::QueryView;
use proxima_protocols::dns::encode;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct CountingAllocator;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(size.saturating_sub(layout.size()) as u64, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn rules(count: usize) -> Vec<RuleConfig> {
    (0..count)
        .map(|id| RuleConfig {
            id: id as u32,
            domain: format!("host{id}.shared.example"),
            action: Action::Nxdomain,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
        })
        .collect()
}

fn main() {
    println!(
        "source_commit={} package_version={} target_os={} target_arch={}",
        option_env!("BLACKHOLE_SOURCE_COMMIT").unwrap_or("working-tree"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!(
        "rustc_version={}",
        String::from_utf8_lossy(
            &std::process::Command::new("rustc")
                .arg("--version")
                .output()
                .map(|output| output.stdout)
                .unwrap_or_default()
        )
        .trim()
    );
    let configs = rules(10_000);
    let sample_count = 25;
    assert!(sample_count > 0);
    let build = measure(sample_count, || {
        let before = snapshot();
        let start = Instant::now();
        let policy = ReferencePolicy::new(&configs).expect("generated rules are valid");
        black_box(policy);
        (start.elapsed().as_nanos(), snapshot().bytes - before.bytes)
    });

    let policy = ReferencePolicy::new(&configs).expect("generated rules are valid");

    let query = QueryContext {
        name: "host5000.shared.example.",
        qtype: 1,
        qclass: 1,
        client: None,
    };
    let matches_per_sample: usize = 100;
    let matching = measure(sample_count, || {
        let before = snapshot();
        let start = Instant::now();
        for _ in 0..matches_per_sample {
            black_box(policy.decide(query));
        }
        (
            start.elapsed().as_nanos() / matches_per_sample as u128,
            snapshot().bytes - before.bytes,
        )
    });

    // Proxima's borrowed parser is intentionally measured separately: it
    // validates wire input and exposes borrowed names without materializing a
    // dotted String. Encoding remains in the owned listener facade and is not
    // duplicated here.
    let short_packet = wire_query("example.com.");
    let long_name = (0..24)
        .map(|index| format!("label{index:02}"))
        .collect::<Vec<_>>()
        .join(".");
    let long_packet = wire_query(&format!("{long_name}."));
    let adversarial_packet = {
        let mut packet = vec![
            0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
        ];
        packet.shrink_to_fit();
        packet
    };
    let parsing_short = parse_measure(sample_count, &short_packet);
    let parsing_long = parse_measure(sample_count, &long_packet);
    let parsing_adversarial = parse_measure(sample_count, &adversarial_packet);
    let mixed_packets = [&short_packet, &long_packet, &adversarial_packet];
    let mut mixed_index = 0usize;
    let parsing_mixed = measure(sample_count, || {
        let before = snapshot();
        let start = Instant::now();
        let packet = mixed_packets[mixed_index % mixed_packets.len()];
        mixed_index += 1;
        let _ = black_box(QueryView::parse(packet));
        (start.elapsed().as_nanos(), snapshot().bytes - before.bytes)
    });

    let owned_packet = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let owning = measure(sample_count, || {
        let before = snapshot();
        let start = Instant::now();
        let owned = QueryView::parse(&owned_packet)
            .expect("valid query")
            .to_owned();
        black_box(owned);
        (start.elapsed().as_nanos(), snapshot().bytes - before.bytes)
    });

    // Measure the same owned response encoder used by the listener. The
    // listener's transport adapter records the subsequent write boundary;
    // this workload isolates encoding so a transport result cannot be
    // mistaken for codec work.
    let answer_name = "example.com.";
    let answer_rdata = encode::ipv4_rdata(std::net::Ipv4Addr::new(192, 0, 2, 42));
    let answer_record = encode::AnswerRecord {
        name: answer_name,
        rtype: 1,
        rclass: 1,
        ttl: 30,
        rdata: &answer_rdata,
    };
    let encoding = measure(sample_count, || {
        let before = snapshot();
        let start = Instant::now();
        let mut output = Vec::with_capacity(owned_packet.len());
        encode::encode_response(
            0x1234,
            proxima_protocols::dns::Flags::for_response(true, false, true, 0),
            encode::EncodeQuestion {
                name: answer_name,
                qtype: 1,
                qclass: 1,
            },
            std::slice::from_ref(&answer_record),
            &mut output,
        )
        .expect("benchmark response fits DNS wire limits");
        black_box(output);
        (start.elapsed().as_nanos(), snapshot().bytes - before.bytes)
    });

    #[cfg(feature = "perf-instrument")]
    let boundary_bytes = {
        let stats = perf::snapshot();
        stats
    };

    println!("gate=b14 implementation=scalar-reference rules=10000 samples={sample_count}");
    report("build", &build, configs.len());
    report("match", &matching, sample_count * matches_per_sample);
    report("parse_short", &parsing_short, sample_count);
    report("parse_long", &parsing_long, sample_count);
    report("parse_adversarial", &parsing_adversarial, sample_count);
    report("parse_mixed", &parsing_mixed, sample_count);
    report("owned", &owning, sample_count);
    report("encode_response", &encoding, sample_count);
    #[cfg(feature = "perf-instrument")]
    println!(
        "boundary_bytes=MEASURED policy_canonicalize={} borrowed_to_owned={} tcp_frame_buffer={} encode_output={} transport_write={}",
        boundary_bytes.policy_canonicalize,
        boundary_bytes.borrowed_to_owned,
        boundary_bytes.tcp_frame_buffer,
        boundary_bytes.encode_output,
        boundary_bytes.transport_write,
    );
    #[cfg(not(feature = "perf-instrument"))]
    println!("copy_count=not-instrumented decision=do-not-claim-zero-copy");
    println!(
        "rss_kib=MEASURED {:?} loadavg=MEASURED {:?}",
        rss_kib(),
        load_average()
    );
    println!("arms=scalar-retained memchr-not-added simd-not-added wasm-not-built");
}

struct Measurements {
    nanos: Vec<u128>,
    allocs: u64,
    alloc_bytes: u64,
}

fn measure<F>(count: usize, mut operation: F) -> Measurements
where
    F: FnMut() -> (u128, u64),
{
    assert!(count > 0);
    let mut nanos = Vec::with_capacity(count);
    let mut allocs = 0;
    let mut alloc_bytes = 0;
    for _ in 0..count {
        let before = snapshot();
        let (elapsed, bytes) = operation();
        let after = snapshot();
        nanos.push(elapsed);
        allocs += after.allocs - before.allocs;
        alloc_bytes += bytes;
    }
    Measurements {
        nanos,
        allocs,
        alloc_bytes,
    }
}

fn report(label: &str, measurements: &Measurements, operations: usize) {
    assert!(!measurements.nanos.is_empty());
    assert!(operations > 0);
    let mut sorted = measurements.nanos.clone();
    sorted.sort_unstable();
    let sum: u128 = sorted.iter().sum();
    let mean = sum as f64 / sorted.len() as f64;
    let variance = sorted
        .iter()
        .map(|value| {
            let difference = *value as f64 - mean;
            difference * difference
        })
        .sum::<f64>()
        / sorted.len() as f64;
    let cov = if mean == 0.0 {
        0.0
    } else {
        variance.sqrt() / mean
    };
    let throughput = operations as f64 / (sum as f64 / 1_000_000_000.0);
    println!(
        "{label}_ns=MEASURED p50={} p95={} p99={} min={} max={} cov={cov:.6} n={} throughput_ops_s=DERIVED {throughput:.2} allocs=MEASURED {} alloc_bytes=MEASURED {}",
        percentile(&sorted, 50),
        percentile(&sorted, 95),
        percentile(&sorted, 99),
        sorted[0],
        sorted[sorted.len() - 1],
        measurements.nanos.len(),
        measurements.allocs,
        measurements.alloc_bytes,
    );
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let index = ((sorted.len() - 1) * percentile).div_ceil(100);
    sorted[index]
}

fn parse_measure(sample_count: usize, packet: &[u8]) -> Measurements {
    measure(sample_count, || {
        let before = snapshot();
        let start = Instant::now();
        let _ = black_box(QueryView::parse(packet));
        (start.elapsed().as_nanos(), snapshot().bytes - before.bytes)
    })
}

fn wire_query(name: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    encode::encode_query(
        0x1234,
        true,
        encode::EncodeQuestion {
            name,
            qtype: 1,
            qclass: 1,
        },
        &mut packet,
    )
    .expect("benchmark query name fits DNS wire limits");
    packet
}

fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        return status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn load_average() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|value| value.split_whitespace().next().map(str::to_owned));
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[derive(Clone, Copy)]
struct Snapshot {
    allocs: u64,
    bytes: u64,
}

fn snapshot() -> Snapshot {
    Snapshot {
        allocs: ALLOCS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    }
}
