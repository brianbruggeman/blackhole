use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use blackhole::policy::Action;
use blackhole::{Config, Policy, RuleConfig, UpstreamConfig};
use proxima::pipe::SendPipe;
use proxima_dns::DnsResolverConfig;
use proxima_primitives::stream::{DatagramFactory, DatagramSocket};
use proxima_protocols::dns::{Flags, encode, parse_message};

#[derive(Clone, Copy)]
enum ReplyMode {
    Valid,
    WrongId,
    Malformed,
    WrongSender,
    Timeout,
}

struct FakeState {
    mode: ReplyMode,
    inbound: VecDeque<(Vec<u8>, SocketAddr)>,
    sent: Vec<Vec<u8>>,
    waker: Option<Waker>,
}

#[derive(Clone)]
struct FakeSocket {
    state: Arc<Mutex<FakeState>>,
}

impl FakeSocket {
    fn new(mode: ReplyMode) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                mode,
                inbound: VecDeque::new(),
                sent: Vec::new(),
                waker: None,
            })),
        }
    }

    fn queue_reply(&self) {
        let mut state = self.state.lock().expect("fake state");
        let Some(query) = state.sent.last() else {
            return;
        };
        let mode = state.mode;
        let resolver = resolver_addr();
        let reply = match mode {
            ReplyMode::Malformed => vec![0; 12],
            ReplyMode::Timeout => return,
            ReplyMode::Valid | ReplyMode::WrongId | ReplyMode::WrongSender => {
                let message = parse_message(query).expect("fake query");
                let question = message
                    .questions()
                    .next()
                    .expect("fake question")
                    .expect("valid fake question");
                let name = question.name.to_dotted();
                let rdata = encode::ipv4_rdata(Ipv4Addr::new(93, 184, 216, 34));
                let record = encode::AnswerRecord {
                    name: &name,
                    rtype: 1,
                    rclass: question.qclass,
                    ttl: 30,
                    rdata: &rdata,
                };
                let mut response = Vec::new();
                let id = if matches!(mode, ReplyMode::WrongId) {
                    message.header.id.wrapping_add(1)
                } else {
                    message.header.id
                };
                encode::encode_response(
                    id,
                    Flags::for_response(true, false, true, 0),
                    encode::EncodeQuestion {
                        name: &name,
                        qtype: question.qtype,
                        qclass: question.qclass,
                    },
                    &[record],
                    &mut response,
                )
                .expect("fake response");
                response
            }
        };
        let sender = if matches!(mode, ReplyMode::WrongSender) {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 53)
        } else {
            resolver
        };
        state.inbound.push_back((reply, sender));
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

impl DatagramSocket for FakeSocket {
    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut state = self.state.lock().expect("fake state");
        if let Some((bytes, sender)) = state.inbound.pop_front() {
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            return Poll::Ready(Ok((len, sender)));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_send_to(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        _peer: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.state
            .lock()
            .expect("fake state")
            .sent
            .push(buf.to_vec());
        self.queue_reply();
        Poll::Ready(Ok(buf.len()))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }
}

struct FakeFactory {
    socket: FakeSocket,
}

impl DatagramFactory for FakeFactory {
    fn bind(&self, _addr: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
        Ok(Box::new(self.socket.clone()))
    }
}

fn resolver_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)), 53)
}

fn policy(mode: ReplyMode) -> Policy {
    let mut config = Config::default();
    config.policy.rules = vec![RuleConfig {
        id: 1,
        domain: "example.com".into(),
        action: Action::Forward,
        priority: 0,
        qtype: None,
        qclass: None,
        client: None,
    }];
    config.upstream = Some(UpstreamConfig {
        resolver_ip: resolver_addr().ip().to_string(),
        port: resolver_addr().port(),
        query_timeout_ms: 10,
        max_attempts: 1,
        ..UpstreamConfig::default()
    });
    let upstream = config.upstream.clone().expect("upstream config");
    Policy::new(config).expect("valid config").with_upstream(
        Arc::new(FakeFactory {
            socket: FakeSocket::new(mode),
        }),
        DnsResolverConfig::builder()
            .resolver_ip(upstream.resolver_ip)
            .port(upstream.port)
            .query_timeout_ms(upstream.query_timeout_ms)
            .max_attempts(upstream.max_attempts)
            .build(),
        upstream.max_outstanding,
    )
}

fn request() -> proxima_dns::DnsPipeRequest {
    proxima_dns::DnsPipeRequest {
        method: proxima_primitives::pipe::method::Method::from_wire(bytes::Bytes::from_static(
            b"DNS",
        )),
        path: bytes::Bytes::from_static(b"/"),
        query: proxima_primitives::pipe::header_list::HeaderList::new(),
        metadata: proxima_primitives::pipe::header_list::HeaderList::new(),
        payload: proxima_dns::DnsQuery {
            id: 7,
            recursion_desired: true,
            name: "example.com.".into(),
            qtype: 1,
            qclass: 1,
        },
        stream: None,
        context: proxima_primitives::pipe::request::RequestContext::default(),
    }
}

#[proxima::test]
async fn fake_upstream_success_flows_through_policy() {
    let answer = policy(ReplyMode::Valid).call(request()).await.unwrap();
    assert_eq!(answer.payload.rcode, 0);
    assert_eq!(answer.payload.records.len(), 1);
}

#[proxima::test]
async fn fake_upstream_malformed_reply_fails_closed() {
    let result = policy(ReplyMode::Malformed).call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_wrong_id_fails_closed() {
    let result = policy(ReplyMode::WrongId).call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_spoofed_sender_fails_closed() {
    let result = policy(ReplyMode::WrongSender).call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_timeout_fails_closed() {
    let result = policy(ReplyMode::Timeout).call(request()).await;
    assert!(result.is_err());
}
