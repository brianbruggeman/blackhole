use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use blackhole::admin::authenticated_handle;
use blackhole::{ClientGroupConfig, Config, Policy, ServiceProfileConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use proxima::StreamUpstreamExt;
use proxima::{Listener, ListenerBuilderEntry};
use proxima_net::prime::PrimeTcpUpstream;

fn admin_addr() -> SocketAddr {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve an ephemeral admin port")
        .local_addr()
        .expect("ephemeral admin address")
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
    let initial_blocklist = std::env::temp_dir().join(format!(
        "blackhole-admin-blocklist-{}-initial.txt",
        std::process::id()
    ));
    let replacement_blocklist = std::env::temp_dir().join(format!(
        "blackhole-admin-blocklist-{}-replacement.txt",
        std::process::id()
    ));
    fs::write(&initial_blocklist, "initial.example\n").expect("write initial blocklist");
    fs::write(&replacement_blocklist, "replacement.example\n")
        .expect("write replacement blocklist");
    let mut config = Config::default();
    config.policy.blocklists = vec![initial_blocklist.to_string_lossy().into_owned()];
    config.policy.client_groups = vec![ClientGroupConfig {
        name: "home".into(),
        client_cidrs: vec!["192.0.2.0/24".into()],
    }];
    config.policy.profiles = vec![ServiceProfileConfig {
        id: 400,
        name: "family".into(),
        domains: vec!["ads.example".into()],
        action: blackhole::Action::Nxdomain,
        groups: vec!["home".into()],
        priority: 10,
        client_cidrs: Vec::new(),
        qtype: None,
        qclass: None,
    }];
    let policy = Arc::new(Policy::new(config).expect("default policy"));
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
    let status = request(
        addr,
        "GET",
        "/status",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("status response");
    let status = String::from_utf8_lossy(&status);
    assert!(status.starts_with("HTTP/1.1 200"));
    assert!(status.contains("\"cache_entries\":0"));
    let policy_status = request(
        addr,
        "GET",
        "/policy/status",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("policy status response");
    let policy_status = String::from_utf8_lossy(&policy_status);
    assert!(policy_status.starts_with("HTTP/1.1 200"));
    assert!(policy_status.contains("\"profiles\":1"));
    assert!(policy_status.contains("\"blocklist_sources\":1"));
    assert!(!policy_status.contains("initial_blocklist"));
    let profiles = request(
        addr,
        "GET",
        "/profiles",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("profiles response");
    let profiles = String::from_utf8_lossy(&profiles);
    assert!(profiles.starts_with("HTTP/1.1 200"));
    assert!(profiles.contains("\"name\":\"family\""));
    let groups = request(
        addr,
        "GET",
        "/client-groups",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("client groups response");
    let groups = String::from_utf8_lossy(&groups);
    assert!(groups.starts_with("HTTP/1.1 200"));
    assert!(groups.contains("\"name\":\"home\""));
    let replacement = request(
        addr,
        "POST",
        "/reload/profiles",
        Some("Bearer integration-secret"),
        Some(r#"{"profiles":[{"id":500,"name":"new-family","domains":["new.example"],"action":"reject","groups":[],"priority":8,"client_cidrs":[],"qtype":null,"qclass":null}],"client_groups":[]}"#),
    )
    .await
    .expect("profile replacement response");
    let replacement = String::from_utf8_lossy(&replacement);
    assert!(replacement.starts_with("HTTP/1.1 200"));
    let profiles = request(
        addr,
        "GET",
        "/profiles",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("replacement profiles response");
    let profiles = String::from_utf8_lossy(&profiles);
    assert!(profiles.contains("\"name\":\"new-family\""));
    let bundle = request(
        addr,
        "POST",
        "/reload/policy-bundle",
        Some("Bearer integration-secret"),
        Some(
            &format!(
                r#"{{"rules":[],"regex_rules":[],"profiles":[{{"id":700,"name":"bundle-family","domains":["bundle.example"],"action":"nxdomain"}}],"client_groups":[],"blocklists":["{}"]}}"#,
                replacement_blocklist.display()
            ),
        ),
    )
    .await
    .expect("policy bundle response");
    let bundle = String::from_utf8_lossy(&bundle);
    assert!(bundle.starts_with("HTTP/1.1 200"));
    let profiles = request(
        addr,
        "GET",
        "/profiles",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("bundle profiles response");
    let profiles = String::from_utf8_lossy(&profiles);
    assert!(profiles.contains("\"name\":\"bundle-family\""));
    let query = |name: &str| proxima_dns::DnsQuery {
        id: 1,
        recursion_desired: true,
        name: name.into(),
        qtype: 1,
        qclass: 1,
    };
    assert_eq!(
        policy.evaluate(&query("initial.example.")).unwrap().rcode,
        0
    );
    assert_eq!(
        policy
            .evaluate(&query("replacement.example."))
            .unwrap()
            .rcode,
        3
    );
    let logs = request(
        addr,
        "GET",
        "/logs",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("query log response");
    let logs = String::from_utf8_lossy(&logs);
    assert!(logs.starts_with("HTTP/1.1 200"));
    assert!(logs.contains("{\"enabled\":false,\"entries\":[]}"));
    let cleared_logs = request(
        addr,
        "POST",
        "/logs/clear",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("query log clear response");
    let cleared_logs = String::from_utf8_lossy(&cleared_logs);
    assert!(cleared_logs.starts_with("HTTP/1.1 200"));
    assert!(cleared_logs.contains("\"entries\":0"));
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
    let country = request(
        addr,
        "POST",
        "/reload/country",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("country reload response");
    let country = String::from_utf8_lossy(&country);
    assert!(country.starts_with("HTTP/1.1 200"));
    assert!(country.contains("{\"status\":\"reloaded\"}"));
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
    let rules = request(
        addr,
        "GET",
        "/rules",
        Some("Bearer integration-secret"),
        None,
    )
    .await
    .expect("rules response");
    let rules = String::from_utf8_lossy(&rules);
    assert!(rules.starts_with("HTTP/1.1 200"));
    assert!(rules.contains("\"domain\":\"blocked.example\""));
    assert!(rules.contains("\"action\":\"nxdomain\""));
    let regex = request(
        addr,
        "POST",
        "/reload/regex",
        Some("Bearer integration-secret"),
        Some(
            r#"[{"id":9,"pattern":"^blocked\\.example$","action":"nxdomain","priority":0,"qtype":null,"qclass":null,"client":null}]"#,
        ),
    )
    .await
    .expect("regex reload response");
    let regex = String::from_utf8_lossy(&regex);
    assert!(regex.starts_with("HTTP/1.1 200"));
    assert!(regex.contains("{\"status\":\"reloaded\"}"));
    server.stop();
    fs::remove_file(initial_blocklist).expect("remove initial blocklist");
    fs::remove_file(replacement_blocklist).expect("remove replacement blocklist");
}
