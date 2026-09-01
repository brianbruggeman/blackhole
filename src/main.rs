#![cfg(feature = "std")]

use blackhole::admin::{authenticated_handle, validate_bind};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use blackhole::linux_capture::{CaptureController, FileOwnershipStore};
#[cfg(target_os = "linux")]
use blackhole::linux_capture::{NftRulePlan, native::NftCommandBackend};
#[cfg(feature = "std")]
use blackhole::listener::{TcpProtocol, UdpProtocol};
#[cfg(target_os = "macos")]
use blackhole::pf_capture::{PfRulePlan, native::PfctlCommandBackend};
#[cfg(feature = "std")]
use blackhole::{Config, Policy, UpstreamTransport};
#[cfg(feature = "std")]
use bytes::Bytes;
#[cfg(feature = "std")]
use proxima::pipe::into_handle;
#[cfg(feature = "std")]
use proxima::{H1ClientUpstream, Request, Response, SendPipe};
#[cfg(feature = "std")]
use proxima::{Listener, ListenerBuilderEntry, ProximaError};
#[cfg(feature = "std")]
use proxima_net::prime::{PrimeDatagramFactory, PrimeTcpUpstream};
use proxima_primitives::pipe::{
    IntervalPipe, ProducerLifecycle, Request as PipeRequest, Response as PipeResponse,
    into_handle as into_pipe_handle, into_source_handle,
};
#[cfg(feature = "std")]
use proxima_primitives::stream::{StreamConnection, StreamUpstream};
#[cfg(feature = "doq")]
use proxima_quic::QuicUpstream;
#[cfg(feature = "std")]
use proxima_tls::{TlsClientConfig, TlsStreamUpstream};
#[cfg(feature = "std")]
use std::{
    env, io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(feature = "doq")]
fn doq_tls_config() -> Result<rustls::ClientConfig, ProximaError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ProximaError::Config(format!("invalid DoQ TLS versions: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    Ok(config)
}

#[cfg(feature = "std")]
struct BoxedTlsUpstream {
    inner: TlsStreamUpstream<PrimeTcpUpstream>,
}

#[cfg(feature = "std")]
impl StreamUpstream for BoxedTlsUpstream {
    type Conn = Box<dyn StreamConnection>;

    fn poll_connect(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Conn>> {
        match self.inner.poll_connect(cx) {
            Poll::Ready(Ok(connection)) => Poll::Ready(Ok(Box::new(connection))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(target_os = "linux")]
struct CaptureGuard {
    controller: CaptureController<NftCommandBackend, FileOwnershipStore>,
    plan: NftRulePlan,
}

#[cfg(target_os = "macos")]
struct CaptureGuard {
    controller: CaptureController<PfctlCommandBackend, FileOwnershipStore>,
    plan: PfRulePlan,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl CaptureGuard {
    fn cleanup(&mut self) -> Result<(), ProximaError> {
        self.controller
            .cleanup(&self.plan)
            .map_err(|error| ProximaError::Config(format!("capture cleanup failed: {error}")))
    }
}

#[cfg(feature = "std")]
struct AnyHandler;

#[cfg(feature = "std")]
struct BlocklistReloadHandler {
    policy: Arc<Policy>,
}

#[cfg(feature = "std")]
impl SendPipe for BlocklistReloadHandler {
    type In = PipeRequest<Bytes>;
    type Out = PipeResponse<Bytes>;
    type Err = ProximaError;

    async fn call(&self, _request: Self::In) -> Result<Self::Out, Self::Err> {
        match self.policy.reload_blocklists_if_changed() {
            Ok(_) => Ok(PipeResponse::ok(Bytes::new())),
            Err(error) => Err(ProximaError::Config(format!(
                "background blocklist reload failed: {error}"
            ))),
        }
    }
}

fn admin_endpoint(
    config: &blackhole::AdminConfig,
) -> Result<Option<(SocketAddr, String)>, ProximaError> {
    match (&config.listen, &config.token) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ProximaError::Config(
            "admin.token requires admin.listen".into(),
        )),
        (Some(_), None) => Err(ProximaError::Config(
            "admin.listen requires admin.token".into(),
        )),
        (Some(listen), Some(token)) => {
            let bind = listen
                .parse()
                .map_err(|error| ProximaError::Config(format!("invalid admin.listen: {error}")))?;
            validate_bind(bind)?;
            Ok(Some((bind, token.clone())))
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<(), ProximaError> {
    if !config.enabled {
        return Ok(());
    }
    NftRulePlan::for_ports(&config.chain, config.inbound_port, listen_port, config.mark)
        .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<Option<CaptureGuard>, ProximaError> {
    if !config.enabled {
        return Ok(None);
    }
    let plan = NftRulePlan::for_ports(&config.chain, config.inbound_port, listen_port, config.mark)
        .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    let store = FileOwnershipStore::new(&config.ownership_path);
    let mut controller = CaptureController::with_store(NftCommandBackend::default(), store);
    controller
        .recover(&plan)
        .map_err(|error| ProximaError::Config(format!("capture recovery failed: {error}")))?;
    controller
        .install(&plan)
        .map_err(|error| ProximaError::Config(format!("capture install failed: {error}")))?;
    Ok(Some(CaptureGuard { controller, plan }))
}

#[cfg(target_os = "macos")]
fn validate_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<(), ProximaError> {
    if !config.enabled {
        return Ok(());
    }
    let original_destination = config.original_destination.parse().map_err(|error| {
        ProximaError::Config(format!("invalid capture original_destination: {error}"))
    })?;
    PfRulePlan::new(&config.chain, original_destination, listen_port)
        .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<Option<CaptureGuard>, ProximaError> {
    if !config.enabled {
        return Ok(None);
    }
    let original_destination = config.original_destination.parse().map_err(|error| {
        ProximaError::Config(format!("invalid capture original_destination: {error}"))
    })?;
    let plan = PfRulePlan::new(&config.chain, original_destination, listen_port)
        .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    let store = FileOwnershipStore::new(&config.ownership_path);
    let mut controller = CaptureController::with_store(PfctlCommandBackend::default(), store);
    controller
        .recover(&plan)
        .map_err(|error| ProximaError::Config(format!("capture recovery failed: {error}")))?;
    controller
        .install(&plan)
        .map_err(|error| ProximaError::Config(format!("capture install failed: {error}")))?;
    Ok(Some(CaptureGuard { controller, plan }))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn validate_capture(
    config: &blackhole::CaptureConfig,
    _listen_port: u16,
) -> Result<(), ProximaError> {
    if config.enabled {
        Err(ProximaError::Config(
            "capture is unsupported on this platform".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct CaptureGuard;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl CaptureGuard {
    fn cleanup(&mut self) -> Result<(), ProximaError> {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn install_capture(
    config: &blackhole::CaptureConfig,
    _listen_port: u16,
) -> Result<Option<CaptureGuard>, ProximaError> {
    if config.enabled {
        Err(ProximaError::Config(
            "capture is unsupported on this platform".into(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "std")]
impl SendPipe for AnyHandler {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    async fn call(&self, request: Self::In) -> Result<Self::Out, Self::Err> {
        Ok(Response::ok(request.payload))
    }
}

#[cfg(feature = "std")]
#[proxima::main]
async fn main() -> Result<(), ProximaError> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let (check_only, explicit_config_path) = match arguments.as_slice() {
        [] => (false, None),
        [flag] if flag == "--check" => (true, None),
        [flag, path] if flag == "--check" => (true, Some(path.as_str())),
        [path] => (false, Some(path.as_str())),
        _ => {
            return Err(ProximaError::Config(
                "usage: blackhole [--check] [config.toml]".into(),
            ));
        }
    };
    let config = if let Some(config_path) = explicit_config_path {
        Config::from_file(Path::new(&config_path))
            .map_err(|error| ProximaError::Config(format!("cannot load {config_path}: {error}")))?
    } else {
        Config::default()
    };
    let bind: SocketAddr = config
        .server
        .listen
        .parse()
        .map_err(|error| ProximaError::Config(format!("invalid server.listen: {error}")))?;
    let admin_endpoint = admin_endpoint(&config.admin)?;
    if check_only {
        validate_capture(&config.capture, bind.port())?;
        let policy =
            Arc::new(Policy::new(config).map_err(|error| {
                ProximaError::Config(format!("invalid configuration: {error}"))
            })?);
        if let Some((_, token)) = admin_endpoint {
            authenticated_handle(policy, token)?;
        }
        println!("configuration valid (listener bind: {bind})");
        return Ok(());
    }
    let capture_config = config.capture.clone();
    let blocklist_reload_interval = config.policy.blocklist_reload_interval_secs;
    let blocklist_reload_enabled =
        blocklist_reload_interval != 0 && !config.policy.blocklists.is_empty();
    let mut capture = install_capture(&capture_config, bind.port())?;
    let upstream = config.upstream.clone();
    let mut policy = Policy::new(config)
        .map_err(|error| ProximaError::Config(format!("invalid policy rule: {error}")))?;
    if let Some(upstream) = upstream {
        let resolver = Policy::resolver_config(&upstream);
        let resolver_addr = SocketAddr::new(
            upstream.resolver_ip.parse().map_err(|error| {
                ProximaError::Config(format!("invalid upstream resolver address: {error}"))
            })?,
            upstream.port,
        );
        policy = policy.with_upstream(
            Arc::new(PrimeDatagramFactory),
            resolver,
            upstream.max_outstanding,
        );
        if matches!(upstream.transport, UpstreamTransport::Doh) {
            let server_name = upstream.tls_server_name.clone().ok_or_else(|| {
                ProximaError::Config("tls_server_name is required for DoH upstreams".into())
            })?;
            let tls = TlsStreamUpstream::with_webpki_roots(
                PrimeTcpUpstream::new(resolver_addr),
                server_name.clone(),
            )
            .map_err(|error| ProximaError::Config(format!("invalid DoH TLS upstream: {error}")))?;
            let http = H1ClientUpstream::new(tls, server_name, "blackhole.doh");
            policy = policy.with_doh_upstream(into_handle(http));
        } else {
            let tcp_upstream: Arc<dyn StreamUpstream<Conn = Box<dyn StreamConnection>>> =
                match upstream.transport {
                    UpstreamTransport::Udp | UpstreamTransport::Tcp => {
                        PrimeTcpUpstream::boxed(resolver_addr)
                    }
                    UpstreamTransport::Tls => {
                        let server_name = upstream.tls_server_name.ok_or_else(|| {
                            ProximaError::Config(
                                "tls_server_name is required for TLS upstreams".into(),
                            )
                        })?;
                        let tls_config = TlsClientConfig {
                            server_name,
                            // DNS-over-TLS does not require an HTTP ALPN token.
                            alpn_protocols: Vec::new(),
                        };
                        let tls = TlsStreamUpstream::from_config(
                            PrimeTcpUpstream::new(resolver_addr),
                            &tls_config,
                        )
                        .map_err(|error| {
                            ProximaError::Config(format!("invalid TLS upstream: {error}"))
                        })?;
                        Arc::new(BoxedTlsUpstream { inner: tls })
                    }
                    UpstreamTransport::Doq => {
                        #[cfg(feature = "doq")]
                        {
                            let server_name = upstream.tls_server_name.ok_or_else(|| {
                                ProximaError::Config(
                                    "tls_server_name is required for DoQ upstreams".into(),
                                )
                            })?;
                            let tls = doq_tls_config()?;
                            Arc::new(
                                QuicUpstream::with_client_config(resolver_addr, server_name, tls)
                                    .map_err(|error| {
                                    ProximaError::Config(format!("invalid DoQ upstream: {error}"))
                                })?,
                            )
                        }
                        #[cfg(not(feature = "doq"))]
                        {
                            return Err(ProximaError::Config(
                                "DoQ upstreams require the `doq` feature".into(),
                            ));
                        }
                    }
                    UpstreamTransport::Doh => unreachable!("DoH handled above"),
                };
            policy = policy.with_tcp_upstream(tcp_upstream);
            if !matches!(upstream.transport, UpstreamTransport::Udp) {
                policy = policy.with_tcp_only();
            }
        }
    }
    let policy = Arc::new(policy);
    let admin_server = if let Some((admin_bind, token)) = admin_endpoint {
        let handle = authenticated_handle(Arc::clone(&policy), token)?;
        let server = match Listener::http(admin_bind).handle(handle).serve().await {
            Ok(server) => server,
            Err(error) => {
                if let Some(capture) = capture.as_mut() {
                    let _ = capture.cleanup();
                }
                return Err(error);
            }
        };
        println!("blackhole admin listening on {admin_bind} (HTTP bearer auth)");
        Some(server)
    } else {
        None
    };
    let mut source_lifecycle = ProducerLifecycle::new();
    if blocklist_reload_enabled {
        let reload_handler = into_pipe_handle(BlocklistReloadHandler {
            policy: Arc::clone(&policy),
        });
        let reload_source = into_source_handle(IntervalPipe::new(
            std::time::Duration::from_secs(blocklist_reload_interval),
            reload_handler,
            IntervalPipe::empty_request_factory(),
            "blackhole-blocklist-reload",
        ));
        source_lifecycle.spawn_from_source("blocklist-reload", &reload_source);
        println!(
            "blackhole blocklist reload enabled ({}s)",
            blocklist_reload_interval
        );
    }
    let server = match Listener::builder()
        .bind(bind)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .protocol(TcpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(AnyHandler))
        .serve()
        .await
    {
        Ok(server) => server,
        Err(error) => {
            if let Some(admin_server) = admin_server {
                admin_server.stop();
            }
            source_lifecycle
                .shutdown(std::time::Duration::from_secs(2))
                .await;
            if let Some(capture) = capture.as_mut() {
                let _ = capture.cleanup();
            }
            return Err(error);
        }
    };
    println!("blackhole listening on {bind} (UDP+TCP DNS)");
    if let Some(admin_server) = admin_server {
        futures::future::join(server.run_until_signal(), admin_server.run_until_signal()).await;
    } else {
        server.run_until_signal().await;
    }
    source_lifecycle
        .shutdown(std::time::Duration::from_secs(2))
        .await;
    if let Some(capture) = capture.as_mut() {
        capture.cleanup()?;
    }
    Ok(())
}
