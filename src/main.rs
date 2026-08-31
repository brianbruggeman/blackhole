use blackhole::listener::{TcpProtocol, UdpProtocol};
use blackhole::{Config, Policy};
use bytes::Bytes;
use proxima::pipe::into_handle;
use proxima::{Listener, ListenerBuilderEntry, ProximaError};
use proxima::{Request, Response, SendPipe};
use proxima_net::prime::PrimeDatagramFactory;
use std::{env, net::SocketAddr, path::Path, sync::Arc};

struct AnyHandler;

impl SendPipe for AnyHandler {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    async fn call(&self, request: Self::In) -> Result<Self::Out, Self::Err> {
        Ok(Response::ok(request.payload))
    }
}

#[proxima::main]
async fn main() -> Result<(), ProximaError> {
    let explicit_config_path = env::args().nth(1);
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
    let server = Listener::builder()
        .bind(bind)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .protocol(TcpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(AnyHandler))
        .serve()
        .await?;
    println!("blackhole listening on {bind} (UDP+TCP DNS)");
    server.run_until_signal().await;
    Ok(())
}
