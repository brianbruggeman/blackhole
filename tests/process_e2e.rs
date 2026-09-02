use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
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

#[test]
fn shipped_binary_serves_udp_datagrams_and_tcp_frames() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set upstream timeout");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_thread = thread::spawn(move || {
        let mut packet = [0u8; 4096];
        for _ in 0..2 {
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
        }
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    let listener_addr = listener.local_addr().expect("listener address");
    drop(listener);
    let mut config = NamedTempFile::new().expect("create config");
    writeln!(
        config,
        "[server]\nlisten = \"{listener_addr}\"\n\n[policy]\ndefault_action = \"forward\"\n\n[[policy.rules]]\nid = 9001\ndomain = \"blocked.example.\"\naction = \"reject\"\n\n[[policy.rules]]\nid = 9002\ndomain = \"nxdomain.example.\"\naction = \"nxdomain\"\n\n[[policy.rules]]\nid = 9003\ndomain = \"drop.example.\"\naction = \"drop\"\n\n[upstream]\nresolver_ip = \"127.0.0.1\"\nport = {}\ntransport = \"udp\"\nquery_timeout_ms = 500\nmax_attempts = 1",
        upstream_addr.port()
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_blackhole"))
        .arg(config.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start shipped blackhole binary");

    let mut tcp = wait_for_tcp(listener_addr);
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set TCP timeout");

    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set UDP timeout");

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

    let tcp_query = query(0x1002, "tcp.example.");
    tcp.write_all(&(u16::try_from(tcp_query.len()).expect("TCP query fits")).to_be_bytes())
        .expect("write TCP length");
    tcp.write_all(&tcp_query).expect("write TCP query");
    let mut tcp_length = [0u8; 2];
    tcp.read_exact(&mut tcp_length).expect("read TCP length");
    let tcp_length = usize::from(u16::from_be_bytes(tcp_length));
    let mut tcp_response = vec![0u8; tcp_length];
    tcp.read_exact(&mut tcp_response)
        .expect("read TCP response");
    let tcp_message = parse_message(&tcp_response).expect("parse TCP response");
    assert_eq!(tcp_message.header.id, 0x1002);
    assert_eq!(tcp_message.answers().count(), 1);

    child.kill().expect("stop shipped binary");
    child.wait().expect("reap shipped binary");
    upstream_thread.join().expect("reap upstream");
}
