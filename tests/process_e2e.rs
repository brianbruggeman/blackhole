use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
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
