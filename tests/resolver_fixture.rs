use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;

use blackhole::listener::{TcpProtocol, UdpProtocol};
use blackhole::{Action, Config, Policy, RewriteConfig, RuleConfig, UpstreamConfig};
use bytes::Bytes;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use proxima::pipe::into_handle;
use proxima::{Listener, ListenerBuilderEntry};
use proxima::{ProximaError, Request, Response, SendPipe};
use proxima_net::prime::{PrimeDatagramFactory, PrimeTcpUpstream};
use proxima_primitives::stream::DatagramFactory;
use proxima_primitives::stream::StreamUpstreamExt;
use proxima_protocols::dns::{Flags, encode, parse_message};

fn test_listener_addr() -> SocketAddr {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve listener port");
    probe.local_addr().expect("reserved listener address")
}

struct Passthrough;

impl SendPipe for Passthrough {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    async fn call(&self, request: Self::In) -> Result<Self::Out, Self::Err> {
        Ok(Response::ok(request.payload))
    }
}

#[proxima::test]
async fn listener_forwards_allowed_query_to_loopback_upstream() {
    #[cfg(feature = "perf-instrument")]
    blackhole::perf::reset();

    let upstream_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    let upstream_addr = upstream_socket.local_addr().expect("upstream address");
    let upstream_thread = std::thread::spawn(move || {
        for _ in 0..3 {
            let mut query = [0u8; 4096];
            let (len, peer) = upstream_socket
                .recv_from(&mut query)
                .expect("receive upstream query");
            let message = parse_message(&query[..len]).expect("parse upstream query");
            let question = message
                .questions()
                .next()
                .expect("question present")
                .expect("valid question");
            let name = question.name.to_dotted();
            let rdata = encode::ipv4_rdata(Ipv4Addr::new(192, 0, 2, 42));
            let answer = encode::AnswerRecord {
                name: &name,
                rtype: 1,
                rclass: 1,
                ttl: 30,
                rdata: &rdata,
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
            upstream_socket
                .send_to(&response, peer)
                .expect("send upstream response");
        }
    });

    let mut config = Config::default();
    config.server.listen = "127.0.0.1:0".into();
    config.policy.default_action = Action::Forward;
    config.policy.rules = vec![RuleConfig {
        id: 1,
        domain: "blocked.example".into(),
        action: Action::Nxdomain,
        priority: 0,
        qtype: None,
        qclass: None,
        client: None,
        client_cidr: None,
        client_cidrs: Vec::new(),
        client_identity: None,
    }];
    config.upstream = Some(UpstreamConfig {
        resolver_ip: upstream_addr.ip().to_string(),
        port: upstream_addr.port(),
        ..UpstreamConfig::default()
    });

    let upstream = config.upstream.clone().expect("upstream config");
    let policy = Arc::new(Policy::new(config).expect("valid policy").with_upstream(
        Arc::new(PrimeDatagramFactory),
        Policy::resolver_config(&upstream),
        upstream.max_outstanding,
    ));
    let listener_addr = test_listener_addr();
    let server = Listener::builder()
        .bind(listener_addr)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .protocol(TcpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(Passthrough))
        .serve()
        .await
        .expect("serve listener");

    let mut client = PrimeDatagramFactory
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind client");
    let mut query = Vec::new();
    encode::encode_query(
        0x1234,
        true,
        encode::EncodeQuestion {
            name: "allowed.example.",
            qtype: 1,
            qclass: 1,
        },
        &mut query,
    )
    .expect("encode client query");
    std::future::poll_fn(|cx| client.poll_send_to(cx, &query, listener_addr))
        .await
        .expect("send client query");
    let mut response = [0u8; 4096];
    let (len, _) = std::future::poll_fn(|cx| client.poll_recv_from(cx, &mut response))
        .await
        .expect("receive client response");
    let message = parse_message(&response[..len]).expect("parse client response");
    assert_eq!(message.header.id, 0x1234);
    assert_eq!(message.header.flags.rcode(), 0);
    assert_eq!(message.answers().count(), 1);

    let tcp_client = PrimeTcpUpstream::new(listener_addr);
    let mut tcp = tcp_client.connect().await.expect("connect TCP listener");
    let mut tcp_query = Vec::new();
    encode::encode_query(
        0x1235,
        true,
        encode::EncodeQuestion {
            name: "tcp.example.",
            qtype: 1,
            qclass: 1,
        },
        &mut tcp_query,
    )
    .expect("encode TCP query");
    let frame_len = u16::try_from(tcp_query.len()).expect("DNS query fits TCP frame");
    tcp.write_all(&frame_len.to_be_bytes())
        .await
        .expect("write TCP frame length");
    tcp.write_all(&tcp_query).await.expect("write TCP query");
    let mut response_len = [0u8; 2];
    tcp.read_exact(&mut response_len)
        .await
        .expect("read TCP response length");
    let response_len = usize::from(u16::from_be_bytes(response_len));
    let mut tcp_response = vec![0u8; response_len];
    tcp.read_exact(&mut tcp_response)
        .await
        .expect("read TCP response");
    let message = parse_message(&tcp_response).expect("parse TCP response");
    assert_eq!(message.header.id, 0x1235);
    assert_eq!(message.header.flags.rcode(), 0);
    assert_eq!(message.answers().count(), 1);

    let mut second_query = Vec::new();
    encode::encode_query(
        0x1236,
        true,
        encode::EncodeQuestion {
            name: "tcp-second.example.",
            qtype: 1,
            qclass: 1,
        },
        &mut second_query,
    )
    .expect("encode second TCP query");
    let second_len = u16::try_from(second_query.len()).expect("second DNS query fits TCP frame");
    tcp.write_all(&second_len.to_be_bytes())
        .await
        .expect("write second TCP frame length");
    tcp.write_all(&second_query)
        .await
        .expect("write second TCP query");
    let mut second_response_len = [0u8; 2];
    tcp.read_exact(&mut second_response_len)
        .await
        .expect("read second TCP response length");
    let second_response_len = usize::from(u16::from_be_bytes(second_response_len));
    let mut second_response = vec![0u8; second_response_len];
    tcp.read_exact(&mut second_response)
        .await
        .expect("read second TCP response");
    let second_message = parse_message(&second_response).expect("parse second TCP response");
    assert_eq!(second_message.header.id, 0x1236);
    assert_eq!(second_message.header.flags.rcode(), 0);
    assert_eq!(second_message.answers().count(), 1);

    server.stop();
    upstream_thread.join().expect("upstream thread");

    #[cfg(feature = "perf-instrument")]
    {
        let boundaries = blackhole::perf::snapshot();
        println!("listener_boundary_bytes={boundaries:?}");
        assert!(boundaries.policy_canonicalize > 0);
        assert!(boundaries.borrowed_to_owned > 0);
        assert!(boundaries.tcp_frame_buffer > 0);
        assert!(boundaries.encode_output > 0);
        assert!(boundaries.transport_write > 0);
    }
}

#[proxima::test]
async fn listener_retries_a_truncated_upstream_reply_over_tcp() {
    let upstream_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream udp");
    let upstream_addr = upstream_udp.local_addr().expect("upstream address");
    let upstream_tcp = TcpListener::bind(upstream_addr).expect("bind upstream tcp");
    let upstream_thread = std::thread::spawn(move || {
        let mut query = [0u8; 4096];
        let (len, peer) = upstream_udp
            .recv_from(&mut query)
            .expect("receive truncated udp query");
        let udp_message = parse_message(&query[..len]).expect("parse udp query");
        let question = udp_message
            .questions()
            .next()
            .expect("udp question")
            .expect("valid udp question");
        let name = question.name.to_dotted();
        let mut truncated = Vec::new();
        encode::encode_response(
            udp_message.header.id,
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

        let (mut stream, _) = upstream_tcp.accept().expect("accept tcp fallback");
        let mut frame_len = [0u8; 2];
        stream.read_exact(&mut frame_len).expect("read tcp length");
        let mut tcp_query = vec![0u8; usize::from(u16::from_be_bytes(frame_len))];
        stream.read_exact(&mut tcp_query).expect("read tcp query");
        let tcp_message = parse_message(&tcp_query).expect("parse tcp query");
        let tcp_question = tcp_message
            .questions()
            .next()
            .expect("tcp question")
            .expect("valid tcp question");
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
        .expect("encode tcp response");
        stream
            .write_all(&(u16::try_from(complete.len()).expect("tcp response fits")).to_be_bytes())
            .expect("write tcp length");
        stream.write_all(&complete).expect("write tcp response");
    });

    let mut config = Config::default();
    config.server.listen = "127.0.0.1:0".into();
    config.policy.default_action = Action::Forward;
    config.upstream = Some(UpstreamConfig {
        resolver_ip: upstream_addr.ip().to_string(),
        port: upstream_addr.port(),
        query_timeout_ms: 500,
        max_attempts: 1,
        ..UpstreamConfig::default()
    });
    let upstream = config.upstream.clone().expect("upstream config");
    let policy = Arc::new(
        Policy::new(config)
            .expect("valid policy")
            .with_upstream(
                Arc::new(PrimeDatagramFactory),
                Policy::resolver_config(&upstream),
                upstream.max_outstanding,
            )
            .with_tcp_upstream(PrimeTcpUpstream::boxed(upstream_addr)),
    );
    let listener_addr = test_listener_addr();
    let server = Listener::builder()
        .bind(listener_addr)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(Passthrough))
        .serve()
        .await
        .expect("serve listener");

    let mut client = PrimeDatagramFactory
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind client");
    let mut query = Vec::new();
    encode::encode_query(
        0x4321,
        true,
        encode::EncodeQuestion {
            name: "fallback.example.",
            qtype: 1,
            qclass: 1,
        },
        &mut query,
    )
    .expect("encode client query");
    std::future::poll_fn(|cx| client.poll_send_to(cx, &query, listener_addr))
        .await
        .expect("send client query");
    let mut response = [0u8; 4096];
    let (len, _) = std::future::poll_fn(|cx| client.poll_recv_from(cx, &mut response))
        .await
        .expect("receive client response");
    let message = parse_message(&response[..len]).expect("parse client response");
    assert_eq!(message.header.id, 0x4321);
    assert_eq!(message.header.flags.rcode(), 0);
    assert_eq!(message.answers().count(), 1);

    server.stop();
    upstream_thread.join().expect("upstream thread");
}

#[proxima::test]
async fn listener_serves_local_rewrite_on_the_real_udp_path() {
    let mut config = Config::default();
    config.policy.rewrites = vec![RewriteConfig {
        name: "router.home.arpa".into(),
        ipv4: Some(Ipv4Addr::new(192, 0, 2, 53)),
        ipv6: None,
        ttl: 30,
    }];
    let policy = Arc::new(Policy::new(config).expect("valid rewrite policy"));
    let listener_addr = test_listener_addr();
    let server = Listener::builder()
        .bind(listener_addr)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .protocol(TcpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(Passthrough))
        .serve()
        .await
        .expect("serve listener");

    let mut client = PrimeDatagramFactory
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind client");
    let mut query = Vec::new();
    encode::encode_query(
        0x4321,
        true,
        encode::EncodeQuestion {
            name: "router.home.arpa.",
            qtype: 1,
            qclass: 1,
        },
        &mut query,
    )
    .expect("encode rewrite query");
    std::future::poll_fn(|cx| client.poll_send_to(cx, &query, listener_addr))
        .await
        .expect("send rewrite query");
    let mut response = [0u8; 4096];
    let (len, _) = std::future::poll_fn(|cx| client.poll_recv_from(cx, &mut response))
        .await
        .expect("receive rewrite response");
    let message = parse_message(&response[..len]).expect("parse rewrite response");
    let answer = message
        .answers()
        .next()
        .expect("rewrite answer present")
        .expect("valid rewrite answer");
    assert_eq!(message.header.id, 0x4321);
    assert_eq!(message.header.flags.rcode(), 0);
    assert_eq!(
        answer.rdata,
        proxima_protocols::dns::RData::A(Ipv4Addr::new(192, 0, 2, 53))
    );
    server.stop();
}

#[proxima::test]
async fn listener_enforces_service_profile_on_the_real_udp_path() {
    let mut config = Config::default();
    config.policy.client_groups = vec![blackhole::ClientGroupConfig {
        name: "loopback".into(),
        enabled: true,
        client_addresses: Vec::new(),
        client_cidrs: vec!["127.0.0.0/8".into()],
    }];
    config.policy.profiles = vec![blackhole::ServiceProfileConfig {
        id: 40_000,
        name: "telemetry".into(),
        enabled: true,
        domains: vec!["ads.example".into()],
        action: Action::Nxdomain,
        groups: vec!["loopback".into()],
        client_identity: None,
        priority: 10,
        client_cidrs: Vec::new(),
        qtype: None,
        qclass: None,
    }];
    let policy = Arc::new(Policy::new(config).expect("valid profile policy"));
    let listener_addr = test_listener_addr();
    let server = Listener::builder()
        .bind(listener_addr)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .protocol(TcpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(Passthrough))
        .serve()
        .await
        .expect("serve listener");

    let mut client = PrimeDatagramFactory
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind client");
    let mut query = Vec::new();
    encode::encode_query(
        0x4322,
        true,
        encode::EncodeQuestion {
            name: "ads.example.",
            qtype: 1,
            qclass: 1,
        },
        &mut query,
    )
    .expect("encode profile query");
    std::future::poll_fn(|cx| client.poll_send_to(cx, &query, listener_addr))
        .await
        .expect("send profile query");
    let mut response = [0u8; 4096];
    let (len, _) = std::future::poll_fn(|cx| client.poll_recv_from(cx, &mut response))
        .await
        .expect("receive profile response");
    let message = parse_message(&response[..len]).expect("parse profile response");
    assert_eq!(message.header.id, 0x4322);
    assert_eq!(message.header.flags.rcode(), 3);
    assert_eq!(message.answers().count(), 0);
    server.stop();
}
