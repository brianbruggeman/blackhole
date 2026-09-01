//! Bounded real-client listener measurement.
//!
//! This complements `performance_gate`: the latter isolates pure parser,
//! policy, and encoder work, while this executable measures a real UDP client
//! crossing the Proxima listener and Blackhole protocol adapter.

use blackhole::listener::UdpProtocol;
use blackhole::{Action, Config, Policy, RewriteConfig};
use bytes::Bytes;
use proxima::pipe::into_handle;
use proxima::{Listener, ListenerBuilderEntry, ProximaError, Request, Response, SendPipe};
use proxima_net::prime::PrimeDatagramFactory;
use proxima_primitives::stream::{DatagramFactory, DatagramSocket};
use proxima_protocols::dns::{encode, parse_message};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Instant;

const SAMPLES: usize = 100;

struct Passthrough;

impl SendPipe for Passthrough {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    async fn call(&self, request: Self::In) -> Result<Self::Out, Self::Err> {
        Ok(Response::ok(request.payload))
    }
}

#[proxima::main(cores = 1)]
async fn main() -> Result<(), ProximaError> {
    let source_commit = option_env!("BLACKHOLE_SOURCE_COMMIT").unwrap_or("working-tree");
    println!(
        "source_commit={source_commit} package_version={} target_os={} target_arch={}",
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

    let listener_addr = reserve_local_port();
    let mut config = Config::default();
    config.server.listen = listener_addr.to_string();
    config.policy.default_action = Action::Pass;
    // Keep the benchmark workload below the configured admission ceiling;
    // this is a measurement of the listener path, not of rate shedding.
    config.admission.max_queries_per_client_per_second = 1_000;
    config.policy.rewrites = vec![RewriteConfig {
        name: "benchmark.example".into(),
        ipv4: Some(Ipv4Addr::new(192, 0, 2, 42)),
        ipv6: None,
        cname: None,
        ttl: 30,
    }];
    let policy = std::sync::Arc::new(
        Policy::new(config)
            .map_err(|error| ProximaError::Config(format!("benchmark policy: {error}")))?,
    );
    let server = Listener::builder()
        .bind(listener_addr)
        .any()
        .protocol(UdpProtocol::new(std::sync::Arc::clone(&policy)))
        .handle(into_handle(Passthrough))
        .serve()
        .await?;

    let mut client = PrimeDatagramFactory
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|error| ProximaError::Config(format!("benchmark client: {error}")))?;
    let mut query = Vec::new();
    encode::encode_query(
        0x4242,
        true,
        encode::EncodeQuestion {
            name: "benchmark.example.",
            qtype: 1,
            qclass: 1,
        },
        &mut query,
    )
    .map_err(|error| ProximaError::Config(format!("benchmark query: {error}")))?;

    for id in 0..10_u16 {
        let _ = exchange(&mut *client, listener_addr, &query, id).await?;
    }
    let clock_ticks = clock_ticks_per_second();
    let before_cpu = process_cpu_ticks();
    let before = Instant::now();
    let single_request_start = Instant::now();
    exchange(&mut *client, listener_addr, &query, 10).await?;
    let single_request_ns = single_request_start.elapsed().as_nanos();
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut errors = 0_usize;
    let mut first_error = None;
    for id in 11..(11 + SAMPLES as u16) {
        let start = Instant::now();
        if let Err(error) = exchange(&mut *client, listener_addr, &query, id).await {
            errors += 1;
            if first_error.is_none() {
                first_error = Some(error.to_string());
            }
        }
        samples.push(start.elapsed().as_nanos());
    }
    let elapsed_ns = before.elapsed().as_nanos();
    let after_cpu = process_cpu_ticks();
    let rss = rss_kib();
    server.stop();

    samples.sort_unstable();
    let sum: u128 = samples.iter().sum();
    let mean = sum as f64 / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| {
            let difference = *sample as f64 - mean;
            difference * difference
        })
        .sum::<f64>()
        / samples.len() as f64;
    let cov = variance.sqrt() / mean;
    let throughput = SAMPLES as f64 / (elapsed_ns as f64 / 1_000_000_000.0);
    let cpu_percent = before_cpu.zip(after_cpu).and_then(|(start, end)| {
        let ticks = end.saturating_sub(start) as f64;
        (elapsed_ns > 0)
            .then_some(ticks / clock_ticks as f64 / (elapsed_ns as f64 / 1_000_000_000.0) * 100.0)
    });
    println!(
        "listener_udp samples={SAMPLES} errors={errors} first_error={first_error:?} single_request_ns=MEASURED {single_request_ns}"
    );
    println!(
        "listener_latency_ns=MEASURED p50={} p95={} p99={} min={} max={} cov={cov:.6} n={SAMPLES}",
        percentile(&samples, 50),
        percentile(&samples, 95),
        percentile(&samples, 99),
        samples[0],
        samples[samples.len() - 1]
    );
    println!(
        "listener_throughput_ops_s=DERIVED {throughput:.2} cpu_percent=MEASURED {:?} cpu_clock_ticks_s=MEASURED {clock_ticks} rss_kib=MEASURED {:?} loadavg=MEASURED {:?}",
        cpu_percent,
        rss,
        load_average()
    );
    assert_eq!(errors, 0, "real-client listener errors must be zero");
    Ok(())
}

async fn exchange(
    client: &mut dyn DatagramSocket,
    listener_addr: SocketAddr,
    query: &[u8],
    id: u16,
) -> Result<(), ProximaError> {
    let mut query = query.to_vec();
    query[..2].copy_from_slice(&id.to_be_bytes());
    poll_fn(|cx| client.poll_send_to(cx, &query, listener_addr)).await?;
    let mut response = [0_u8; 4096];
    let (len, _) = poll_fn(|cx| client.poll_recv_from(cx, &mut response)).await?;
    let message = parse_message(&response[..len])
        .map_err(|error| ProximaError::Decode(format!("benchmark response: {error}")))?;
    let answer_count = message.answers().count();
    if message.header.id != id || answer_count != 1 {
        return Err(ProximaError::Decode(format!(
            "benchmark response mismatch id={} expected_id={id} answers={answer_count}",
            message.header.id
        )));
    }
    Ok(())
}

fn reserve_local_port() -> SocketAddr {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve benchmark listener port")
        .local_addr()
        .expect("reserved benchmark listener address")
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    sorted[((sorted.len() - 1) * percentile).div_ceil(100)]
}

fn process_cpu_ticks() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let fields = stat
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn clock_ticks_per_second() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(100)
    }
    #[cfg(not(target_os = "linux"))]
    {
        100
    }
}

fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn load_average() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|value| value.split_whitespace().next().map(str::to_owned))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
