//! B14 discipline gate. This is an executable Rust measurement, not a shell
//! script. It records allocator activity around the current scalar path so a
//! SIMD or WASM change cannot be described as zero-copy by inspection.

#[cfg(feature = "perf-instrument")]
use blackhole::perf;
use blackhole::policy::{Action, QueryContext, ReferencePolicy, RuleConfig};
use blackhole::query::QueryView;
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
    let before_build = snapshot();
    let configs = rules(10_000);
    let build_start = Instant::now();
    let policy = ReferencePolicy::new(&configs).expect("generated rules are valid");
    let build_ns = build_start.elapsed().as_nanos();
    let after_build = snapshot();

    let query = QueryContext {
        name: "host5000.shared.example.",
        qtype: 1,
        qclass: 1,
        client: None,
    };
    let before_match = snapshot();
    let match_start = Instant::now();
    for _ in 0..100 {
        black_box(policy.decide(query));
    }
    let match_ns = match_start.elapsed().as_nanos() / 100;
    let after_match = snapshot();

    // Proxima's borrowed parser is intentionally measured separately: it
    // validates wire input and exposes borrowed names without materializing a
    // dotted String. Encoding remains in the owned listener facade and is not
    // duplicated here.
    let packet = [0u8; 12];
    let before_parse = snapshot();
    let parse_start = Instant::now();
    let parse_result = QueryView::parse(&packet);
    let parse_ns = parse_start.elapsed().as_nanos();
    let after_parse = snapshot();

    let owned_packet = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let owned_start = Instant::now();
    let owned = QueryView::parse(&owned_packet)
        .expect("valid query")
        .to_owned();
    let owned_ns = owned_start.elapsed().as_nanos();
    black_box(owned);

    #[cfg(feature = "perf-instrument")]
    let boundary_bytes = {
        let stats = perf::snapshot();
        stats
    };

    println!("gate=b14 implementation=scalar-reference rules=10000 samples=100");
    println!("build_ns={build_ns} {}", delta(before_build, after_build));
    println!("match_ns={match_ns} {}", delta(before_match, after_match));
    println!(
        "parse_ns={parse_ns} result={parse_result:?} {}",
        delta(before_parse, after_parse)
    );
    println!("owned_ns={owned_ns}");
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
    println!("arms=scalar-retained memchr-not-added simd-not-added wasm-not-built");
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

fn delta(before: Snapshot, after: Snapshot) -> String {
    format!(
        "allocs={} alloc_bytes={}",
        after.allocs - before.allocs,
        after.bytes - before.bytes
    )
}
