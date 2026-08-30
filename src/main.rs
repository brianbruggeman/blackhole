use blackhole::{Config, Policy};
use proxima::{Listener, ListenerBuilderEntry, ListenerProtocolExt, ProximaError};
use proxima_dns::into_dns_handle;
use std::{env, net::SocketAddr, path::Path};

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
    let policy = Policy::new(config)
        .map_err(|error| ProximaError::Config(format!("invalid policy rule: {error}")))?;
    let server = Listener::builder()
        .bind(bind)
        .dns(into_dns_handle(policy))
        .serve()
        .await?;
    println!("blackhole listening on {bind} (mode={mode:?}, UDP+TCP DNS)");
    server.run_until_signal().await;
    Ok(())
}
