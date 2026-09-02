use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use proxima_protocols::dns::{Flags, encode, parse_message};
use tempfile::NamedTempFile;

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    encode::encode_query(
        id,
        true,
        encode::EncodeQuestion {
            name,
            qtype: 1,
            qclass: 1,
        },
        &mut packet,
    )
    .expect("encode DNS query");
    packet
}

fn wait_for_tcp(addr: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "blackhole TCP listener did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 256];
    while request.len() < 2048 {
        let size = stream.read(&mut chunk).expect("read HTTP request");
        if size == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..size]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    request
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn shipped_binary_serves_udp_datagrams_and_tcp_frames() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set upstream timeout");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        for _ in 0..5 {
            let (length, peer) = upstream
                .recv_from(&mut packet)
                .expect("receive upstream query");
            let message = parse_message(&packet[..length]).expect("parse upstream query");
            let question = message
                .questions()
                .next()
                .expect("upstream question")
                .expect("valid upstream question");
            let name = question.name.to_dotted();
            let address = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 53));
            let answer = encode::AnswerRecord {
                name: &name,
                rtype: 1,
                rclass: question.qclass,
                ttl: 30,
                rdata: &address,
            };
            let negative = name == "negative.example.";
            let records = if negative { Vec::new() } else { vec![answer] };
            let mut response = Vec::new();
            encode::encode_response(
                message.header.id,
                Flags::for_response(true, false, true, if negative { 3 } else { 0 }),
                encode::EncodeQuestion {
                    name: &name,
                    qtype: question.qtype,
                    qclass: question.qclass,
                },
                &records,
                &mut response,
            )
            .expect("encode upstream response");
            upstream
                .send_to(&response, peer)
                .expect("send upstream response");
        }
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\n\n[[policy.rules]]\nid = 9001\ndomain = \"blocked.example.\"\naction = \"reject\"\n\n[[policy.rules]]\nid = 9002\ndomain = \"nxdomain.example.\"\naction = \"nxdomain\"\n\n[[policy.rules]]\nid = 9003\ndomain = \"drop.example.\"\naction = \"drop\"\n\n[[policy.rules]]\nid = 9004\ndomain = \"pass.example.\"\naction = \"pass\"\n\n[[policy.rules]]\nid = 9005\ndomain = \"observe.example.\"\naction = \"observe\"\n\n[[policy.rules]]\nid = 9006\ndomain = \"sink.example.\"\naction = \"sink\"\n\n[[policy.rules]]\nid = 9007\ndomain = \"honeypot.example.\"\naction = \"honeypot\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1",
        upstream_addr.port()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );

    let mut malformed_tcp = wait_for_tcp(listener_addr);
    malformed_tcp
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set malformed TCP timeout");
    malformed_tcp
        .write_all(&3u16.to_be_bytes())
        .expect("write malformed TCP length");
    malformed_tcp
        .write_all(&[0, 1, 0])
        .expect("write malformed TCP frame");
    let mut malformed_tcp_response = [0u8; 2];
    let malformed_tcp_result = malformed_tcp.read(&mut malformed_tcp_response);
    assert!(match malformed_tcp_result {
        Ok(0) => true,
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::UnexpectedEof
        ),
        Ok(_) => false,
    });
    drop(malformed_tcp);

    let mut tcp = wait_for_tcp(listener_addr);
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set TCP timeout");

    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");

    udp.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set malformed-query timeout");
    udp.send_to(&[0, 1, 0], listener_addr)
        .expect("send malformed UDP query");
    let mut malformed_response = [0u8; 4096];
    let malformed_result = udp.recv_from(&mut malformed_response);
    assert!(matches!(
        malformed_result,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    let mut response_shaped_query = query(0x1009, "response-shaped.example.");
    response_shaped_query[2] |= 0x80;
    udp.send_to(&response_shaped_query, listener_addr)
        .expect("send response-shaped UDP query");
    let response_shaped_result = udp.recv_from(&mut malformed_response);
    assert!(matches!(
        response_shaped_result,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    udp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("restore UDP timeout");

    let blocked_query = query(0x1000, "blocked.example.");
    udp.send_to(&blocked_query, listener_addr)
        .expect("send blocked UDP query");
    let mut blocked_response = [0u8; 4096];
    let (blocked_length, _) = udp
        .recv_from(&mut blocked_response)
        .expect("receive blocked UDP response");
    let blocked_message =
        parse_message(&blocked_response[..blocked_length]).expect("parse blocked UDP response");
    assert_eq!(blocked_message.header.id, 0x1000);
    assert_eq!(blocked_message.header.flags.rcode(), 5);
    assert!(blocked_message.answers().next().is_none());

    let nxdomain_query = query(0x1003, "nxdomain.example.");
    udp.send_to(&nxdomain_query, listener_addr)
        .expect("send NXDOMAIN UDP query");
    let (nxdomain_length, _) = udp
        .recv_from(&mut blocked_response)
        .expect("receive NXDOMAIN UDP response");
    let nxdomain_message =
        parse_message(&blocked_response[..nxdomain_length]).expect("parse NXDOMAIN response");
    assert_eq!(nxdomain_message.header.id, 0x1003);
    assert_eq!(nxdomain_message.header.flags.rcode(), 3);
    assert!(nxdomain_message.answers().next().is_none());

    udp.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set drop timeout");
    let drop_query = query(0x1004, "drop.example.");
    udp.send_to(&drop_query, listener_addr)
        .expect("send drop UDP query");
    let drop_result = udp.recv_from(&mut blocked_response);
    assert!(matches!(
        drop_result,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    udp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("restore UDP timeout");

    let sink_query = query(0x100A, "sink.example.");
    udp.send_to(&sink_query, listener_addr)
        .expect("send sink UDP query");
    let (sink_length, _) = udp
        .recv_from(&mut blocked_response)
        .expect("receive sink UDP response");
    let sink_message =
        parse_message(&blocked_response[..sink_length]).expect("parse sink UDP response");
    assert_eq!(sink_message.header.id, 0x100A);
    assert_eq!(sink_message.header.flags.rcode(), 0);
    assert!(sink_message.answers().next().is_none());

    let honeypot_query = query(0x100B, "honeypot.example.");
    udp.send_to(&honeypot_query, listener_addr)
        .expect("send honeypot UDP query");
    let (honeypot_length, _) = udp
        .recv_from(&mut blocked_response)
        .expect("receive honeypot UDP response");
    let honeypot_message =
        parse_message(&blocked_response[..honeypot_length]).expect("parse honeypot response");
    assert_eq!(honeypot_message.header.id, 0x100B);
    assert_eq!(honeypot_message.answers().count(), 1);

    for (id, name) in [(0x100C, "pass.example."), (0x100D, "observe.example.")] {
        let policy_query = query(id, name);
        udp.send_to(&policy_query, listener_addr)
            .expect("send pass-through UDP query");
        let (policy_length, _) = udp
            .recv_from(&mut blocked_response)
            .expect("receive pass-through UDP response");
        let policy_message =
            parse_message(&blocked_response[..policy_length]).expect("parse pass-through response");
        assert_eq!(policy_message.header.id, id);
        assert_eq!(policy_message.answers().count(), 1);
    }

    let udp_query = query(0x1001, "udp.example.");
    udp.send_to(&udp_query, listener_addr)
        .expect("send UDP query");
    let mut udp_response = [0u8; 4096];
    let (udp_length, _) = udp
        .recv_from(&mut udp_response)
        .expect("receive UDP response");
    let udp_message = parse_message(&udp_response[..udp_length]).expect("parse UDP response");
    assert_eq!(udp_message.header.id, 0x1001);
    assert_eq!(udp_message.answers().count(), 1);

    let cached_query = query(0x1008, "udp.example.");
    udp.send_to(&cached_query, listener_addr)
        .expect("send cached UDP query");
    let (cached_length, _) = udp
        .recv_from(&mut udp_response)
        .expect("receive cached UDP response");
    let cached_message =
        parse_message(&udp_response[..cached_length]).expect("parse cached UDP response");
    assert_eq!(cached_message.header.id, 0x1008);
    assert_eq!(cached_message.answers().count(), 1);

    let negative_query = query(0x100E, "negative.example.");
    udp.send_to(&negative_query, listener_addr)
        .expect("send negative UDP query");
    let (negative_length, _) = udp
        .recv_from(&mut udp_response)
        .expect("receive negative UDP response");
    let negative_message =
        parse_message(&udp_response[..negative_length]).expect("parse negative UDP response");
    assert_eq!(negative_message.header.id, 0x100E);
    assert_eq!(negative_message.header.flags.rcode(), 3);
    assert!(negative_message.answers().next().is_none());

    let cached_negative_query = query(0x100F, "negative.example.");
    udp.send_to(&cached_negative_query, listener_addr)
        .expect("send cached negative UDP query");
    let (cached_negative_length, _) = udp
        .recv_from(&mut udp_response)
        .expect("receive cached negative UDP response");
    let cached_negative_message = parse_message(&udp_response[..cached_negative_length])
        .expect("parse cached negative UDP response");
    assert_eq!(cached_negative_message.header.id, 0x100F);
    assert_eq!(cached_negative_message.header.flags.rcode(), 3);
    assert!(cached_negative_message.answers().next().is_none());

    let tcp_reject_query = query(0x1005, "blocked.example.");
    tcp.write_all(
        &(u16::try_from(tcp_reject_query.len())
            .expect("TCP reject query fits")
            .to_be_bytes()),
    )
    .expect("write TCP reject length");
    tcp.write_all(&tcp_reject_query)
        .expect("write TCP reject query");
    let mut tcp_frame_length = [0u8; 2];
    tcp.read_exact(&mut tcp_frame_length)
        .expect("read TCP reject length");
    let tcp_response_length = usize::from(u16::from_be_bytes(tcp_frame_length));
    let mut tcp_response = vec![0u8; tcp_response_length];
    tcp.read_exact(&mut tcp_response)
        .expect("read TCP reject response");
    let tcp_message = parse_message(&tcp_response).expect("parse TCP reject response");
    assert_eq!(tcp_message.header.id, 0x1005);
    assert_eq!(tcp_message.header.flags.rcode(), 5);

    let tcp_nxdomain_query = query(0x1006, "nxdomain.example.");
    tcp.write_all(
        &(u16::try_from(tcp_nxdomain_query.len())
            .expect("TCP NXDOMAIN query fits")
            .to_be_bytes()),
    )
    .expect("write TCP NXDOMAIN length");
    tcp.write_all(&tcp_nxdomain_query)
        .expect("write TCP NXDOMAIN query");
    tcp.read_exact(&mut tcp_frame_length)
        .expect("read TCP NXDOMAIN length");
    let tcp_response_length = usize::from(u16::from_be_bytes(tcp_frame_length));
    tcp_response.resize(tcp_response_length, 0);
    tcp.read_exact(&mut tcp_response)
        .expect("read TCP NXDOMAIN response");
    let tcp_message = parse_message(&tcp_response).expect("parse TCP NXDOMAIN response");
    assert_eq!(tcp_message.header.id, 0x1006);
    assert_eq!(tcp_message.header.flags.rcode(), 3);

    let tcp_drop_query = query(0x1007, "drop.example.");
    tcp.write_all(
        &(u16::try_from(tcp_drop_query.len())
            .expect("TCP drop query fits")
            .to_be_bytes()),
    )
    .expect("write TCP drop length");
    tcp.write_all(&tcp_drop_query)
        .expect("write TCP drop query");
    tcp.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set TCP drop timeout");
    let mut drop_probe = [0u8; 2];
    let drop_result = tcp.read(&mut drop_probe);
    assert!(matches!(
        drop_result,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("restore TCP timeout");

    let tcp_query = query(0x1002, "tcp.example.");
    tcp.write_all(&(u16::try_from(tcp_query.len()).expect("TCP query fits")).to_be_bytes())
        .expect("write TCP length");
    tcp.write_all(&tcp_query).expect("write TCP query");
    tcp.read_exact(&mut tcp_frame_length)
        .expect("read TCP length");
    let tcp_response_length = usize::from(u16::from_be_bytes(tcp_frame_length));
    tcp_response.resize(tcp_response_length, 0);
    tcp.read_exact(&mut tcp_response)
        .expect("read TCP response");
    let tcp_message = parse_message(&tcp_response).expect("parse TCP response");
    assert_eq!(tcp_message.header.id, 0x1002);
    assert_eq!(tcp_message.answers().count(), 1);

    upstream_thread.join().expect("reap upstream");
}

#[test]
fn shipped_binary_applies_a_configured_blocklist_and_exception() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set upstream timeout");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        let (length, peer) = upstream
            .recv_from(&mut packet)
            .expect("receive allowlisted upstream query");
        let message = parse_message(&packet[..length]).expect("parse upstream query");
        let question = message
            .questions()
            .next()
            .expect("upstream question")
            .expect("valid upstream question");
        let name = question.name.to_dotted();
        let address = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 77));
        let answer = encode::AnswerRecord {
            name: &name,
            rtype: 1,
            rclass: question.qclass,
            ttl: 30,
            rdata: &address,
        };
        let mut response = Vec::new();
        encode::encode_response(
            message.header.id,
            Flags::for_response(true, false, true, 0),
            encode::EncodeQuestion {
                name: &name,
                qtype: question.qtype,
                qclass: question.qclass,
            },
            &[answer],
            &mut response,
        )
        .expect("encode upstream response");
        upstream
            .send_to(&response, peer)
            .expect("send upstream response");
    });

    let blocklist = NamedTempFile::new().expect("create blocklist");
    std::fs::write(blocklist.path(), "||ads.example^\n@@||safe.ads.example^\n")
        .expect("write blocklist");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\nblocklists = [\"{}\"]\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1",
        blocklist.path().display(),
        upstream_addr.port()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");
    let mut response = [0u8; 4096];
    client
        .send_to(&query(0x5100, "ads.example."), listener_addr)
        .expect("send blocked query");
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive blocked response");
    let blocked = parse_message(&response[..length]).expect("parse blocked response");
    assert_eq!(blocked.header.id, 0x5100);
    assert_eq!(blocked.header.flags.rcode(), 3);

    client
        .send_to(&query(0x5101, "safe.ads.example."), listener_addr)
        .expect("send allowlisted query");
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive allowlisted response");
    let allowed = parse_message(&response[..length]).expect("parse allowlisted response");
    assert_eq!(allowed.header.id, 0x5101);
    assert_eq!(allowed.header.flags.rcode(), 0);
    assert!(allowed.answers().next().is_some());

    upstream_thread.join().expect("reap upstream");
}

#[test]
fn shipped_binary_reloads_a_blocklist_while_serving_queries() {
    let blocklist = NamedTempFile::new().expect("create blocklist");
    std::fs::write(blocklist.path(), "||initial.example^\n").expect("write initial blocklist");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"pass\"\nblocklists = [\"{}\"]\nblocklist_reload_interval_secs = 1",
        blocklist.path().display()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set UDP timeout");
    let mut response = [0u8; 4096];
    client
        .send_to(&query(0x5300, "initial.example."), listener_addr)
        .expect("send initial blocked query");
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive initial blocked response");
    let initial = parse_message(&response[..length]).expect("parse initial blocked response");
    assert_eq!(initial.header.flags.rcode(), 3);

    std::fs::write(blocklist.path(), "||reloaded.example^\n").expect("replace blocklist");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client
            .send_to(&query(0x5301, "reloaded.example."), listener_addr)
            .expect("send reloaded query");
        if let Ok((length, _)) = client.recv_from(&mut response)
            && let Ok(message) = parse_message(&response[..length])
            && message.header.flags.rcode() == 3
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "blocklist reload was not observed"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn shipped_binary_applies_a_client_filtering_override() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set upstream timeout");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        let (length, peer) = upstream
            .recv_from(&mut packet)
            .expect("receive filtering-override query");
        let message = parse_message(&packet[..length]).expect("parse upstream query");
        let question = message
            .questions()
            .next()
            .expect("upstream question")
            .expect("valid upstream question");
        let name = question.name.to_dotted();
        let address = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 88));
        let answer = encode::AnswerRecord {
            name: &name,
            rtype: 1,
            rclass: question.qclass,
            ttl: 30,
            rdata: &address,
        };
        let mut response = Vec::new();
        encode::encode_response(
            message.header.id,
            Flags::for_response(true, false, true, 0),
            encode::EncodeQuestion {
                name: &name,
                qtype: question.qtype,
                qclass: question.qclass,
            },
            &[answer],
            &mut response,
        )
        .expect("encode upstream response");
        upstream
            .send_to(&response, peer)
            .expect("send upstream response");
    });

    let blocklist = NamedTempFile::new().expect("create blocklist");
    std::fs::write(blocklist.path(), "||filtered.example^\n").expect("write blocklist");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\nblocklists = [\"{}\"]\n\n[[policy.client_identities]]\nname = \"unfiltered\"\nfiltering_enabled = false\nclients = [\"127.0.0.2\"]\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1",
        blocklist.path().display(),
        upstream_addr.port()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    let client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind UDP client");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");
    client
        .send_to(&query(0x5400, "filtered.example."), listener_addr)
        .expect("send filtering-override query");
    let mut response = [0u8; 4096];
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive filtering-override response");
    let message = parse_message(&response[..length]).expect("parse filtering-override response");
    assert_eq!(message.header.id, 0x5400);
    assert_eq!(message.header.flags.rcode(), 0);
    assert!(message.answers().next().is_some());
    upstream_thread.join().expect("reap upstream");
}

#[test]
fn shipped_binary_serves_ipv6_udp_datagrams_and_tcp_frames() {
    let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("reserve IPv6 listener port");
    let listener_addr = listener.local_addr().expect("IPv6 listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"pass\"\n\n[[policy.rules]]\nid = 1100\ndomain = \"ipv6-udp.example.\"\naction = \"nxdomain\"\n\n[[policy.rules]]\nid = 1101\ndomain = \"ipv6-tcp.example.\"\naction = \"nxdomain\""
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    let udp = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind IPv6 UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set IPv6 UDP timeout");
    udp.send_to(&query(0x1100, "ipv6-udp.example."), listener_addr)
        .expect("send IPv6 UDP query");
    let mut response = [0u8; 4096];
    let (length, _) = udp
        .recv_from(&mut response)
        .expect("receive IPv6 UDP response");
    let message = parse_message(&response[..length]).expect("parse IPv6 UDP response");
    assert_eq!(message.header.id, 0x1100);
    assert_eq!(message.header.flags.rcode(), 3);

    let mut tcp = TcpStream::connect(listener_addr).expect("connect IPv6 TCP client");
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set IPv6 TCP timeout");
    let tcp_query = query(0x1101, "ipv6-tcp.example.");
    let frame_length = u16::try_from(tcp_query.len()).expect("IPv6 TCP query fits frame");
    tcp.write_all(&frame_length.to_be_bytes())
        .expect("write IPv6 TCP query length");
    tcp.write_all(&tcp_query).expect("write IPv6 TCP query");
    let mut response_length = [0u8; 2];
    tcp.read_exact(&mut response_length)
        .expect("read IPv6 TCP response length");
    let response_length = usize::from(u16::from_be_bytes(response_length));
    let mut tcp_response = vec![0u8; response_length];
    tcp.read_exact(&mut tcp_response)
        .expect("read IPv6 TCP response");
    let message = parse_message(&tcp_response).expect("parse IPv6 TCP response");
    assert_eq!(message.header.id, 0x1101);
    assert_eq!(message.header.flags.rcode(), 3);
}

#[test]
fn shipped_binary_applies_client_admission_to_real_udp_peers() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);

    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[admission]\ndeny_client_cidrs = [\"127.0.0.2/32\"]"
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    let udp = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind client UDP socket");
    udp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set client UDP timeout");
    udp.send_to(&query(0x4010, "udp-client.example."), listener_addr)
        .expect("send UDP query");
    let mut response = [0u8; 4096];
    let (length, _) = udp.recv_from(&mut response).expect("receive UDP refusal");
    let message = parse_message(&response[..length]).expect("parse UDP refusal");
    assert_eq!(message.header.id, 0x4010);
    assert_eq!(message.header.flags.rcode(), 5);
    assert!(message.answers().next().is_none());
}

#[test]
fn shipped_binary_restores_persisted_global_abuse_after_restart() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set upstream timeout");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let exchanges = Arc::new(AtomicUsize::new(0));
    let exchanges_for_thread = Arc::clone(&exchanges);
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        for exchange in 0..2 {
            let (length, peer) = match upstream.recv_from(&mut packet) {
                Ok(value) => value,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("receive upstream query: {error}"),
            };
            exchanges_for_thread.fetch_add(1, Ordering::Release);
            let message = parse_message(&packet[..length]).expect("parse upstream query");
            let question = message
                .questions()
                .next()
                .expect("upstream question")
                .expect("valid upstream question");
            let name = question.name.to_dotted();
            let address = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 53));
            let large_records = (0..16)
                .map(|_| encode::AnswerRecord {
                    name: &name,
                    rtype: 1,
                    rclass: question.qclass,
                    ttl: 30,
                    rdata: &address,
                })
                .collect::<Vec<_>>();
            let records = if exchange == 0 {
                large_records
            } else {
                large_records.into_iter().take(1).collect()
            };
            let mut response = Vec::new();
            encode::encode_response(
                message.header.id,
                Flags::for_response(true, false, true, 0),
                encode::EncodeQuestion {
                    name: &name,
                    qtype: question.qtype,
                    qclass: question.qclass,
                },
                &records,
                &mut response,
            )
            .expect("encode upstream response");
            upstream
                .send_to(&response, peer)
                .expect("send upstream response");
        }
    });

    let recording = NamedTempFile::new().expect("create recording");
    let recording_path = recording.path().to_string_lossy();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1\n\n[admission]\nmax_response_bytes_per_second = 64\nmax_response_amplification = 100\n\n[admission.ddos]\npersist_incidents = true\nmax_global_abuse_violations = 1\nglobal_abuse_window_secs = 60\nglobal_abuse_cooldown_secs = 60\n\n[privacy]\nquery_recording_path = \"{recording_path}\"\nquery_recording_max_bytes = 1048576",
        upstream_addr.port()
    )
    .expect("write config");

    let client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind client UDP socket");
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set client timeout");

    let mut first = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start first blackhole process"),
    );
    drop(wait_for_tcp(listener_addr));
    client
        .send_to(&query(0x4020, "persisted-abuse.example."), listener_addr)
        .expect("send first query");
    let mut response = [0u8; 4096];
    assert!(matches!(
        client.recv_from(&mut response),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    ));
    let recording_deadline = Instant::now() + Duration::from_secs(10);
    let recording_contents = loop {
        let contents = std::fs::read_to_string(recording.path()).expect("read recording");
        if contents.contains("temporary_global_blacklist") {
            break contents;
        }
        assert!(
            Instant::now() < recording_deadline,
            "first process must persist the global incident: {contents}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(recording_contents.contains("temporary_global_blacklist"));
    first.0.kill().expect("stop first blackhole process");
    first.0.wait().expect("wait for first blackhole process");

    let mut second = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start second blackhole process"),
    );
    drop(wait_for_tcp(listener_addr));
    client
        .send_to(&query(0x4021, "persisted-abuse.example."), listener_addr)
        .expect("send second query");
    let second_result = client.recv_from(&mut response);
    second.0.kill().expect("stop second blackhole process");
    second.0.wait().expect("wait for second blackhole process");
    let (length, _) = second_result.expect("restored global incident response");
    let message = parse_message(&response[..length]).expect("parse restored-breaker response");
    assert_eq!(message.header.id, 0x4021);
    assert_eq!(message.header.flags.rcode(), 2);
    upstream_thread.join().expect("join upstream");
    assert_eq!(exchanges.load(Ordering::Acquire), 1);
}

#[test]
fn shipped_binary_restores_persisted_client_abuse_after_restart() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    upstream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set upstream timeout");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let recording = NamedTempFile::new().expect("create recording");
    let recording_path = recording.path().to_string_lossy();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"reject\"\n\n[[policy.rules]]\nid = 9101\ndomain = \"client-rate-one.example.\"\naction = \"reject\"\n\n[[policy.rules]]\nid = 9102\ndomain = \"client-rate-two.example.\"\naction = \"reject\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1\n\n[admission]\nmax_queries_per_client_per_second = 1\nmax_client_abuse_violations = 1\nclient_abuse_window_secs = 60\nclient_abuse_cooldown_secs = 60\n\n[admission.ddos]\npersist_incidents = true\n\n[privacy]\nquery_recording_path = \"{recording_path}\"\nquery_recording_max_bytes = 1048576",
        upstream_addr.port()
    )
    .expect("write config");

    let client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind client");
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set client timeout");
    let mut first = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start first blackhole process"),
    );
    drop(wait_for_tcp(listener_addr));

    let mut response = [0u8; 4096];
    client
        .send_to(&query(0x4030, "client-rate-one.example."), listener_addr)
        .expect("send first client query");
    client
        .recv_from(&mut response)
        .expect("receive first client response");
    client
        .send_to(&query(0x4031, "client-rate-two.example."), listener_addr)
        .expect("send rate-overflow query");
    let deadline = Instant::now() + Duration::from_secs(3);
    let recording_contents = loop {
        let contents = std::fs::read_to_string(recording.path()).expect("read recording");
        if contents.contains("temporary_blacklist") {
            break contents;
        }
        assert!(
            Instant::now() < deadline,
            "first process must persist the client incident: {contents}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(recording_contents.contains("\"scope\":\"client\""));
    first.0.kill().expect("stop first blackhole process");
    first.0.wait().expect("wait for first blackhole process");

    let _second = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start second blackhole process"),
    );
    drop(wait_for_tcp(listener_addr));
    client
        .send_to(&query(0x4031, "restored-client.example."), listener_addr)
        .expect("send query from restored client");
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive restored client refusal");
    let message = parse_message(&response[..length]).expect("parse restored client response");
    assert_eq!(message.header.id, 0x4031);
    assert_eq!(message.header.flags.rcode(), 2);
    assert!(matches!(
        upstream.recv_from(&mut response),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
}

#[test]
fn shipped_binary_retries_truncated_upstream_over_tcp() {
    let upstream_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream TCP");
    let upstream_addr = upstream_tcp.local_addr().expect("upstream address");
    let upstream_udp = UdpSocket::bind(upstream_addr).expect("bind upstream UDP");
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        let (length, peer) = upstream_udp
            .recv_from(&mut packet)
            .expect("receive UDP query");
        let message = parse_message(&packet[..length]).expect("parse UDP query");
        let question = message
            .questions()
            .next()
            .expect("upstream question")
            .expect("valid upstream question");
        let name = question.name.to_dotted();
        let mut truncated = Vec::new();
        encode::encode_response(
            message.header.id,
            Flags(Flags::for_response(true, false, true, 0).0 | 0x0200),
            encode::EncodeQuestion {
                name: &name,
                qtype: question.qtype,
                qclass: question.qclass,
            },
            &[],
            &mut truncated,
        )
        .expect("encode truncated response");
        upstream_udp
            .send_to(&truncated, peer)
            .expect("send truncated response");

        let (mut stream, _) = upstream_tcp.accept().expect("accept TCP fallback");
        let mut frame_length = [0u8; 2];
        stream
            .read_exact(&mut frame_length)
            .expect("read TCP query length");
        let tcp_length = usize::from(u16::from_be_bytes(frame_length));
        let mut tcp_query = vec![0u8; tcp_length];
        stream.read_exact(&mut tcp_query).expect("read TCP query");
        let tcp_message = parse_message(&tcp_query).expect("parse TCP query");
        let tcp_question = tcp_message
            .questions()
            .next()
            .expect("TCP question")
            .expect("valid TCP question");
        let tcp_name = tcp_question.name.to_dotted();
        let rdata = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 99));
        let answer = encode::AnswerRecord {
            name: &tcp_name,
            rtype: 1,
            rclass: tcp_question.qclass,
            ttl: 30,
            rdata: &rdata,
        };
        let mut complete = Vec::new();
        encode::encode_response(
            tcp_message.header.id,
            Flags::for_response(true, false, true, 0),
            encode::EncodeQuestion {
                name: &tcp_name,
                qtype: tcp_question.qtype,
                qclass: tcp_question.qclass,
            },
            &[answer],
            &mut complete,
        )
        .expect("encode TCP response");
        stream
            .write_all(
                &(u16::try_from(complete.len())
                    .expect("TCP response fits")
                    .to_be_bytes()),
            )
            .expect("write TCP response length");
        stream.write_all(&complete).expect("write TCP response");
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1",
        upstream_addr.port()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set UDP timeout");
    let query = query(0x2001, "fallback.example.");
    udp.send_to(&query, listener_addr)
        .expect("send fallback query");
    let mut response = [0u8; 4096];
    let (length, _) = udp
        .recv_from(&mut response)
        .expect("receive fallback response");
    let message = parse_message(&response[..length]).expect("parse fallback response");
    assert_eq!(message.header.id, 0x2001);
    assert_eq!(message.answers().count(), 1);

    upstream_thread.join().expect("reap upstream");
}

#[test]
fn shipped_binary_serves_bounded_stale_cache_during_upstream_timeout() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let exchanges = Arc::new(AtomicUsize::new(0));
    let observed_exchanges = Arc::clone(&exchanges);
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        let (length, peer) = upstream
            .recv_from(&mut packet)
            .expect("receive initial query");
        observed_exchanges.fetch_add(1, Ordering::Release);
        let message = parse_message(&packet[..length]).expect("parse initial query");
        let question = message
            .questions()
            .next()
            .expect("initial question")
            .expect("valid initial question");
        let name = question.name.to_dotted();
        let address = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 77));
        let answer = encode::AnswerRecord {
            name: &name,
            rtype: 1,
            rclass: question.qclass,
            ttl: 30,
            rdata: &address,
        };
        let mut response = Vec::new();
        encode::encode_response(
            message.header.id,
            Flags::for_response(true, false, true, 0),
            encode::EncodeQuestion {
                name: &name,
                qtype: question.qtype,
                qclass: question.qclass,
            },
            &[answer],
            &mut response,
        )
        .expect("encode initial response");
        upstream
            .send_to(&response, peer)
            .expect("send initial response");
        upstream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set stale exchange timeout");
        if upstream.recv_from(&mut packet).is_ok() {
            observed_exchanges.fetch_add(1, Ordering::Release);
        }
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 200\nmax_attempts = 1\n\n[cache]\nmax_ttl_secs = 1\nstale_ttl_secs = 5",
        upstream_addr.port()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set UDP timeout");
    let initial_query = query(0x3001, "stale.example.");
    udp.send_to(&initial_query, listener_addr)
        .expect("send initial stale query");
    let mut response = [0u8; 4096];
    let (length, _) = udp
        .recv_from(&mut response)
        .expect("receive initial stale response");
    let message = parse_message(&response[..length]).expect("parse initial stale response");
    assert_eq!(message.header.id, 0x3001);
    assert_eq!(message.answers().count(), 1);

    thread::sleep(Duration::from_millis(1_100));
    let stale_query = query(0x3002, "stale.example.");
    udp.send_to(&stale_query, listener_addr)
        .expect("send stale query");
    let (stale_length, _) = udp
        .recv_from(&mut response)
        .expect("receive stale response");
    let stale_message = parse_message(&response[..stale_length]).expect("parse stale response");
    assert_eq!(stale_message.header.id, 0x3002);
    assert_eq!(stale_message.answers().count(), 1);
    upstream_thread.join().expect("reap upstream");
    assert_eq!(exchanges.load(Ordering::Acquire), 2);
}

#[test]
fn shipped_binary_fails_closed_on_malformed_upstream_reply() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_thread = thread::spawn(move || {
        let mut query = [0u8; 4096];
        let (_, peer) = upstream
            .recv_from(&mut query)
            .expect("receive upstream query");
        upstream
            .send_to(&[0u8; 12], peer)
            .expect("send malformed upstream reply");
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1",
        upstream_addr.port()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");
    let query = query(0x4001, "malformed-upstream.example.");
    udp.send_to(&query, listener_addr)
        .expect("send malformed-upstream query");
    udp.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set malformed-upstream response timeout");
    let mut response = [0u8; 4096];
    let result = udp.recv_from(&mut response);
    assert!(matches!(
        result,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    upstream_thread.join().expect("reap upstream");
}

#[test]
fn shipped_binary_applies_country_policy_to_real_udp_and_tcp_peers() {
    let map = NamedTempFile::new().expect("create country map");
    std::fs::write(map.path(), "US 127.0.0.0/8 US-LOCAL AS64500\n").expect("write country map");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"reject\"\n\n[country_policy]\nmap_path = \"{}\"\ndeny = [\"US\"]",
        map.path().to_string_lossy()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    let client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind UDP client");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set UDP timeout");
    client
        .send_to(&query(0x4040, "country-denied.example."), listener_addr)
        .expect("send country-denied query");
    let mut response = [0u8; 4096];
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive country denial");
    let message = parse_message(&response[..length]).expect("parse country denial");
    assert_eq!(message.header.id, 0x4040);
    assert_eq!(message.header.flags.rcode(), 5);
    assert!(message.answers().next().is_none());

    let mut tcp = TcpStream::connect(listener_addr).expect("connect TCP client");
    tcp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set TCP timeout");
    let tcp_query = query(0x4041, "country-denied.example.");
    let tcp_length = u16::try_from(tcp_query.len()).expect("TCP query fits frame");
    tcp.write_all(&tcp_length.to_be_bytes())
        .expect("write TCP query length");
    tcp.write_all(&tcp_query).expect("write TCP query");
    let mut tcp_response_length = [0u8; 2];
    tcp.read_exact(&mut tcp_response_length)
        .expect("read TCP response length");
    let tcp_response_length = usize::from(u16::from_be_bytes(tcp_response_length));
    let mut tcp_response = vec![0u8; tcp_response_length];
    tcp.read_exact(&mut tcp_response)
        .expect("read TCP response");
    let tcp_message = parse_message(&tcp_response).expect("parse TCP country denial");
    assert_eq!(tcp_message.header.id, 0x4041);
    assert_eq!(tcp_message.header.flags.rcode(), 5);
    assert!(tcp_message.answers().next().is_none());
}

#[test]
fn shipped_binary_recovers_country_policy_from_last_good_after_restart() {
    let source = NamedTempFile::new().expect("create country map");
    std::fs::write(source.path(), "US 127.0.0.0/8\n").expect("write country map");
    let last_good = NamedTempFile::new().expect("create last-good map");
    std::fs::write(last_good.path(), b"").expect("clear last-good map");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"pass\"\n\n[country_policy]\nmap_path = \"{}\"\nlast_good_path = \"{}\"\ndeny = [\"US\"]",
        source.path().display(),
        last_good.path().display()
    )
    .expect("write config");

    let client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind UDP client");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");
    let mut response = [0u8; 4096];
    let mut first = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start first blackhole process"),
    );
    drop(wait_for_tcp(listener_addr));
    client
        .send_to(&query(0x5200, "country-recovery.example."), listener_addr)
        .expect("send first country query");
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive first country response");
    let first_message = parse_message(&response[..length]).expect("parse first country response");
    assert_eq!(first_message.header.flags.rcode(), 5);
    assert_eq!(
        std::fs::read_to_string(last_good.path()).expect("read persisted country map"),
        "US 127.0.0.0/8\n"
    );
    first.0.kill().expect("stop first blackhole process");
    first.0.wait().expect("wait for first blackhole process");
    std::fs::write(source.path(), "not a country map\n").expect("corrupt primary country map");

    let mut second = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start recovered blackhole process"),
    );
    drop(wait_for_tcp(listener_addr));
    client
        .send_to(&query(0x5201, "country-recovery.example."), listener_addr)
        .expect("send recovered country query");
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive recovered country response");
    let recovered = parse_message(&response[..length]).expect("parse recovered response");
    assert_eq!(recovered.header.id, 0x5201);
    assert_eq!(recovered.header.flags.rcode(), 5);
    second.0.kill().expect("stop recovered blackhole process");
    second
        .0
        .wait()
        .expect("wait for recovered blackhole process");
}

#[test]
fn shipped_binary_loads_a_remote_country_map_through_proxima_http() {
    let map_server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind country map server");
    let map_addr = map_server.local_addr().expect("country map server address");
    let map_thread = thread::spawn(move || {
        let (mut stream, _) = map_server.accept().expect("accept country map request");
        let request = String::from_utf8_lossy(&read_http_request(&mut stream)).into_owned();
        let body = b"US 127.0.0.0/8 US-LOCAL AS64500\n";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let _ = stream.write_all(&response);
        request
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"pass\"\n\n[country_policy]\nmap_path = \"http://{map_addr}/country.txt\"\ndeny = [\"US\"]"
    )
    .expect("write config");
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect_timeout(&listener_addr, Duration::from_millis(100)).is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            let status = child.0.try_wait().expect("inspect blackhole process");
            let _ = child.0.kill();
            let _ = child.0.wait();
            panic!("blackhole did not start: status={status:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }

    let client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("bind UDP client");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");
    client
        .send_to(&query(0x5500, "remote-country.example."), listener_addr)
        .expect("send remote country query");
    let mut response = [0u8; 4096];
    let (length, _) = client
        .recv_from(&mut response)
        .expect("receive remote country response");
    let message = parse_message(&response[..length]).expect("parse remote country response");
    assert_eq!(message.header.id, 0x5500);
    assert_eq!(message.header.flags.rcode(), 5);

    let mut tcp = TcpStream::connect(listener_addr).expect("connect remote country TCP client");
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set remote country TCP timeout");
    let tcp_query = query(0x5501, "remote-country.example.");
    let tcp_length = u16::try_from(tcp_query.len()).expect("remote country TCP query fits");
    tcp.write_all(&tcp_length.to_be_bytes())
        .expect("write remote country TCP query length");
    tcp.write_all(&tcp_query)
        .expect("write remote country TCP query");
    let mut tcp_response_length = [0u8; 2];
    tcp.read_exact(&mut tcp_response_length)
        .expect("read remote country TCP response length");
    let tcp_response_length = usize::from(u16::from_be_bytes(tcp_response_length));
    let mut tcp_response = vec![0u8; tcp_response_length];
    tcp.read_exact(&mut tcp_response)
        .expect("read remote country TCP response");
    let tcp_message = parse_message(&tcp_response).expect("parse remote country TCP response");
    assert_eq!(tcp_message.header.id, 0x5501);
    assert_eq!(tcp_message.header.flags.rcode(), 5);

    let request = map_thread.join().expect("reap country map server");
    assert!(
        request.contains("/country.txt"),
        "unexpected map request: {request}"
    );
}

#[test]
fn shipped_binary_applies_region_and_asn_policy_to_real_udp_peers() {
    let map = NamedTempFile::new().expect("create country map");
    std::fs::write(
        map.path(),
        "US 127.0.0.0/8 US-LOCAL AS64500\nCA 127.0.1.0/24 CA-LOCAL AS64501\n",
    )
    .expect("write country map");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[country_policy]\nmap_path = \"{}\"\ndeny_regions = [\"US-LOCAL\"]\ndeny_asns = [64501]",
        map.path().to_string_lossy()
    )
    .expect("write config");

    let _child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_blackhole"))
            .arg(config.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped blackhole binary"),
    );
    drop(wait_for_tcp(listener_addr));

    for (client_ip, id) in [
        (Ipv4Addr::new(127, 0, 0, 2), 0x4050),
        (Ipv4Addr::new(127, 0, 1, 2), 0x4051),
    ] {
        let client = UdpSocket::bind((client_ip, 0)).expect("bind UDP client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set UDP timeout");
        client
            .send_to(&query(id, "region-asn-denied.example."), listener_addr)
            .expect("send region or ASN query");
        let mut response = [0u8; 4096];
        let (length, _) = client
            .recv_from(&mut response)
            .expect("receive region or ASN denial");
        let message = parse_message(&response[..length]).expect("parse region or ASN denial");
        assert_eq!(message.header.id, id);
        assert_eq!(message.header.flags.rcode(), 5);
        assert!(message.answers().next().is_none());
    }

    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, listener_addr.port()))
        .expect("connect TCP client");
    tcp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set TCP timeout");
    let tcp_query = query(0x4052, "region-asn-denied.example.");
    let tcp_length = u16::try_from(tcp_query.len()).expect("TCP query fits frame");
    tcp.write_all(&tcp_length.to_be_bytes())
        .expect("write TCP query length");
    tcp.write_all(&tcp_query).expect("write TCP query");
    let mut tcp_response_length = [0u8; 2];
    tcp.read_exact(&mut tcp_response_length)
        .expect("read TCP denial length");
    let tcp_response_length = usize::from(u16::from_be_bytes(tcp_response_length));
    let mut tcp_response = vec![0u8; tcp_response_length];
    tcp.read_exact(&mut tcp_response).expect("read TCP denial");
    let tcp_message = parse_message(&tcp_response).expect("parse TCP region denial");
    assert_eq!(tcp_message.header.id, 0x4052);
    assert_eq!(tcp_message.header.flags.rcode(), 5);
    assert!(tcp_message.answers().next().is_none());
}
