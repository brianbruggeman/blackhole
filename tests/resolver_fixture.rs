use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use blackhole::{Action, Config, Policy, RuleConfig, UpstreamConfig};
use bytes::Bytes;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use proxima::pipe::into_handle;
use proxima::{Listener, ListenerBuilderEntry, ListenerProtocolExt};
use proxima::{ProximaError, Request, Response, SendPipe};
use proxima_dns::into_dns_handle;
use proxima_net::prime::{PrimeDatagramFactory, PrimeTcpUpstream};
use proxima_primitives::stream::DatagramFactory;
use proxima_primitives::stream::StreamUpstreamExt;
use proxima_protocols::dns::{Flags, encode, parse_message};

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
    let upstream_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
    let upstream_addr = upstream_socket.local_addr().expect("upstream address");
    let upstream_thread = std::thread::spawn(move || {
        for _ in 0..2 {
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
    }];
    config.upstream = Some(UpstreamConfig {
        resolver_ip: upstream_addr.ip().to_string(),
        port: upstream_addr.port(),
        ..UpstreamConfig::default()
    });

    let upstream = config.upstream.clone().expect("upstream config");
    let listener_probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe listener port");
    let listener_port = listener_probe
        .local_addr()
        .expect("listener probe address")
        .port();
    drop(listener_probe);
    let policy = Policy::new(config).expect("valid policy").with_upstream(
        Arc::new(PrimeDatagramFactory),
        Policy::resolver_config(&upstream),
        upstream.max_outstanding,
    );
    let server = Listener::builder()
        .bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            listener_port,
        ))
        .dns(into_dns_handle(policy))
        .handle(into_handle(Passthrough))
        .serve()
        .await
        .expect("serve listener");
    let listener_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener_port);

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

    server.stop();
    upstream_thread.join().expect("upstream thread");
}
