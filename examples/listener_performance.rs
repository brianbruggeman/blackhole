//! Bounded real-client listener measurement.
//!
//! This complements `performance_gate`: the latter isolates pure parser,
//! policy, and encoder work, while this executable measures a real UDP client
//! crossing the Proxima listener and Blackhole protocol adapter.

use blackhole::listener::{TcpProtocol, UdpProtocol};
#[cfg(feature = "perf-instrument")]
use blackhole::perf;
use blackhole::{Action, Config, Policy, RewriteConfig};
use bytes::Bytes;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use proxima::pipe::into_handle;
use proxima::{Listener, ListenerBuilderEntry, ProximaError, Request, Response, SendPipe};
use proxima_net::prime::{PrimeDatagramFactory, PrimeTcpUpstream};
use proxima_primitives::stream::{DatagramFactory, DatagramSocket, StreamUpstreamExt};
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
        .protocol(TcpProtocol::new(std::sync::Arc::clone(&policy)))
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

    let tcp_upstream = PrimeTcpUpstream::new(listener_addr);
    let mut tcp = tcp_upstream.connect().await?;
    let mut tcp_samples = Vec::with_capacity(SAMPLES);
    let mut tcp_errors = 0_usize;
    let mut tcp_single_request_ns = 0;
    let tcp_before = Instant::now();
    for id in 0..SAMPLES as u16 {
        let start = Instant::now();
        if tcp_exchange(&mut tcp, &query, id).await.is_err() {
            tcp_errors += 1;
        }
        let elapsed = start.elapsed().as_nanos();
        if id == 0 {
            tcp_single_request_ns = elapsed;
        }
        tcp_samples.push(elapsed);
    }
    let tcp_elapsed_ns = tcp_before.elapsed().as_nanos();
    tcp_samples.sort_unstable();
    let tcp_sum: u128 = tcp_samples.iter().sum();
    let tcp_mean = tcp_sum as f64 / tcp_samples.len() as f64;
    let tcp_variance = tcp_samples
        .iter()
        .map(|sample| {
            let difference = *sample as f64 - tcp_mean;
            difference * difference
        })
        .sum::<f64>()
        / tcp_samples.len() as f64;
    let tcp_cov = tcp_variance.sqrt() / tcp_mean;
    let tcp_throughput = SAMPLES as f64 / (tcp_elapsed_ns as f64 / 1_000_000_000.0);
    println!(
        "listener_tcp samples={SAMPLES} errors={tcp_errors} single_request_ns=MEASURED {tcp_single_request_ns}"
    );
    println!(
        "listener_tcp_latency_ns=MEASURED p50={} p95={} p99={} min={} max={} cov={tcp_cov:.6} n={SAMPLES}",
        percentile(&tcp_samples, 50),
        percentile(&tcp_samples, 95),
        percentile(&tcp_samples, 99),
        tcp_samples[0],
        tcp_samples[tcp_samples.len() - 1]
    );
    println!(
        "listener_tcp_throughput_ops_s=DERIVED {tcp_throughput:.2} errors=MEASURED {tcp_errors}"
    );
    assert_eq!(
        tcp_errors, 0,
        "real-client TCP listener errors must be zero"
    );
    #[cfg(feature = "perf-instrument")]
    println!("listener_boundary_bytes=MEASURED {:?}", perf::snapshot());
    server.stop();
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

async fn tcp_exchange(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    query: &[u8],
    id: u16,
) -> Result<(), ProximaError> {
    let mut query = query.to_vec();
    query[..2].copy_from_slice(&id.to_be_bytes());
    let frame_length = u16::try_from(query.len())
        .map_err(|_| ProximaError::Encode("benchmark query frame is too large".into()))?;
    stream.write_all(&frame_length.to_be_bytes()).await?;
    stream.write_all(&query).await?;
    let mut response_length = [0_u8; 2];
    stream.read_exact(&mut response_length).await?;
    let response_length = usize::from(u16::from_be_bytes(response_length));
    let mut response = vec![0_u8; response_length];
    stream.read_exact(&mut response).await?;
    let message = parse_message(&response)
        .map_err(|error| ProximaError::Decode(format!("benchmark TCP response: {error}")))?;
    if message.header.id != id || message.answers().count() != 1 {
        return Err(ProximaError::Decode(
            "benchmark TCP response mismatch".into(),
        ));
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
