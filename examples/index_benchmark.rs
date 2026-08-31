//! B8 incumbent benchmark. This measures the correctness reference only; it
//! does not make a production-index claim.

use blackhole::policy::{Action, MAX_RULES, QueryContext, ReferencePolicy, RuleConfig};
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

fn rules(count: usize) -> Vec<RuleConfig> {
    (0..count)
        .map(|index| RuleConfig {
            id: index as u32,
            domain: format!("host{index}.shared.example"),
            action: Action::Nxdomain,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
        })
        .collect()
}

fn measure(policy: &ReferencePolicy, count: usize, hit: bool, samples: usize) -> u128 {
    let query_name = if hit {
        format!("host{}.shared.example.", count / 2)
    } else {
        "absent.shared.example.".to_owned()
    };
    let query = QueryContext {
        name: &query_name,
        qtype: 1,
        qclass: 1,
        client: None,
    };
    let start = Instant::now();
    let mut observed = 0u32;
    for _ in 0..samples {
        if black_box(policy.decide(query)).is_some() {
            observed = observed.wrapping_add(1);
        }
    }
    black_box(observed);
    start.elapsed().as_nanos() / samples as u128
}

fn benchmark(mut sink: impl Write) -> std::io::Result<()> {
    writeln!(
        sink,
        "source_commit={} package_version={} target_os={} target_arch={}",
        option_env!("BLACKHOLE_SOURCE_COMMIT").unwrap_or("working-tree"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )?;
    writeln!(
        sink,
        "rustc_version={}",
        String::from_utf8_lossy(
            &std::process::Command::new("rustc")
                .arg("--version")
                .output()
                .map(|output| output.stdout)
                .unwrap_or_default()
        )
        .trim()
    )?;
    writeln!(
        sink,
        "implementation=reference-linear; workload=shared-suffix"
    )?;
    for count in [100usize, 10_000, MAX_RULES] {
        let configs = rules(count);
        let build_start = Instant::now();
        let policy = ReferencePolicy::new(&configs).expect("generated rules are valid");
        let build_nanos = build_start.elapsed().as_nanos();
        let samples = if count >= MAX_RULES { 1 } else { 100 };
        let hit_nanos = measure(&policy, count, true, samples);
        let miss_nanos = measure(&policy, count, false, samples);
        writeln!(
            sink,
            "rules={count} samples={samples} build_ns={build_nanos} hit_ns={hit_nanos} miss_ns={miss_nanos}"
        )?;
    }
    Ok(())
}

fn main() {
    if let Some(path) = std::env::args().nth(1) {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create benchmark artifact directory");
        }
        let file = fs::File::create(path).expect("create benchmark artifact");
        benchmark(file).expect("write benchmark artifact");
    } else {
        benchmark(std::io::stdout()).expect("write benchmark output");
    }
}
