use blackhole::{Config, Policy};
use bytes::Bytes;
use proxima::pipe::into_handle;
use proxima::{Listener, ListenerBuilderEntry, ListenerProtocolExt, ProximaError};
use proxima::{Request, Response, SendPipe};
use proxima_dns::into_dns_handle;
use proxima_net::prime::PrimeDatagramFactory;
use std::{env, net::SocketAddr, path::Path, sync::Arc};

struct Passthrough;

impl SendPipe for Passthrough {
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
    let mode = config.policy.mode;
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
    let server = Listener::builder()
        .bind(bind)
        .dns(into_dns_handle(policy))
        .handle(into_handle(Passthrough))
        .serve()
        .await?;
    println!("blackhole listening on {bind} (mode={mode:?}, UDP+TCP DNS)");
    server.run_until_signal().await;
    Ok(())
}
