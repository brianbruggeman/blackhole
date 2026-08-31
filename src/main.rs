#![cfg(feature = "std")]

#[cfg(target_os = "macos")]
use blackhole::linux_capture::FileOwnershipStore;
#[cfg(target_os = "linux")]
use blackhole::linux_capture::{
    CaptureController, FileOwnershipStore, NftRulePlan, native::NftCommandBackend,
};
#[cfg(feature = "std")]
use blackhole::listener::{TcpProtocol, UdpProtocol};
#[cfg(target_os = "macos")]
use blackhole::pf_capture::{PfRulePlan, native::PfctlCommandBackend};
#[cfg(feature = "std")]
use blackhole::{Config, Policy};
#[cfg(feature = "std")]
use bytes::Bytes;
#[cfg(feature = "std")]
use proxima::pipe::into_handle;
#[cfg(feature = "std")]
use proxima::{Listener, ListenerBuilderEntry, ProximaError};
#[cfg(feature = "std")]
use proxima::{Request, Response, SendPipe};
#[cfg(feature = "std")]
use proxima_net::prime::PrimeDatagramFactory;
#[cfg(feature = "std")]
use std::{env, net::SocketAddr, path::Path, sync::Arc};

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
    if check_only {
        Policy::new(config)
            .map_err(|error| ProximaError::Config(format!("invalid configuration: {error}")))?;
        println!("configuration valid (listener bind: {bind})");
        return Ok(());
    }
    let capture_config = config.capture.clone();
    let mut capture = install_capture(&capture_config, bind.port())?;
    let upstream = config.upstream.clone();
    let mut policy = Policy::new(config)
        .map_err(|error| ProximaError::Config(format!("invalid policy rule: {error}")))?;
    if let Some(upstream) = upstream {
        let resolver = Policy::resolver_config(&upstream);
        policy = policy.with_upstream(
            Arc::new(PrimeDatagramFactory),
            resolver,
            upstream.max_outstanding,
        );
    }
    let policy = Arc::new(policy);
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
            if let Some(capture) = capture.as_mut() {
                let _ = capture.cleanup();
            }
            return Err(error);
        }
    };
    println!("blackhole listening on {bind} (UDP+TCP DNS)");
    server.run_until_signal().await;
    if let Some(capture) = capture.as_mut() {
        capture.cleanup()?;
    }
    Ok(())
}
