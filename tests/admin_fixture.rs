use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use blackhole::admin::authenticated_handle;
use blackhole::{Config, Policy};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use proxima::StreamUpstreamExt;
use proxima::{Listener, ListenerBuilderEntry};
use proxima_net::prime::PrimeTcpUpstream;

static NEXT_ADMIN_SLOT: AtomicU16 = AtomicU16::new(0);

fn admin_addr() -> SocketAddr {
    let process_slot = (std::process::id() % 19_000) as u16;
    let slot = NEXT_ADMIN_SLOT.fetch_add(1, Ordering::Relaxed) % 20;
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        45_000 + process_slot + slot,
    )
}

async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> io::Result<Vec<u8>> {
    let mut stream = PrimeTcpUpstream::new(addr)
        .connect()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(authorization) = authorization {
        request.push_str("Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

#[proxima::test]
async fn admin_http_listener_enforces_bearer_auth() {
    let policy = Arc::new(Policy::new(Config::default()).expect("default policy"));
    let handle = authenticated_handle(Arc::clone(&policy), "integration-secret".into())
        .expect("admin handle");
    let addr = admin_addr();
    let server = Listener::http(addr)
        .handle(handle)
        .serve()
        .await
        .expect("admin listener");

    let unauthorized = request(addr, "GET", "/health", None, None)
        .await
        .expect("unauthorized response");
    assert!(String::from_utf8_lossy(&unauthorized).starts_with("HTTP/1.1 401"));
    let authorized = request(
        addr,
        "GET",
        "/health",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("authorized response");
    let authorized = String::from_utf8_lossy(&authorized);
    assert!(authorized.starts_with("HTTP/1.1 200"));
    assert!(authorized.contains("{\"status\":\"ok\"}"));
    let reloaded = request(
        addr,
        "POST",
        "/reload/blocklists",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("reload response");
    let reloaded = String::from_utf8_lossy(&reloaded);
    assert!(reloaded.starts_with("HTTP/1.1 200"));
    assert!(reloaded.contains("{\"status\":\"reloaded\"}"));
    let policy = request(
        addr,
        "POST",
        "/reload/policy",
        Some("Bearer integration-secret"),
        Some(
            r#"[{"id":7,"domain":"blocked.example","action":"nxdomain","priority":0,"qtype":null,"qclass":null,"client":null,"client_cidr":null}]"#,
        ),
    )
    .await
    .expect("policy reload response");
    let policy = String::from_utf8_lossy(&policy);
    assert!(policy.starts_with("HTTP/1.1 200"));
    assert!(policy.contains("{\"status\":\"reloaded\"}"));
    server.stop();
}
