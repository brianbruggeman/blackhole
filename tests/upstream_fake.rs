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
    Negative,
    Servfail,
    WrongId,
    Malformed,
    WrongSender,
    Timeout,
    Overflow,
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
            ReplyMode::Valid
            | ReplyMode::Negative
            | ReplyMode::Servfail
            | ReplyMode::WrongId
            | ReplyMode::WrongSender
            | ReplyMode::Overflow => {
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
                let records = if matches!(mode, ReplyMode::Negative | ReplyMode::Servfail) {
                    Vec::new()
                } else if matches!(mode, ReplyMode::Overflow) {
                    (0..65)
                        .map(|_| encode::AnswerRecord {
                            name: &name,
                            rtype: 1,
                            rclass: question.qclass,
                            ttl: 30,
                            rdata: &rdata,
                        })
                        .collect()
                } else {
                    vec![record]
                };
                encode::encode_response(
                    id,
                    Flags::for_response(
                        true,
                        false,
                        true,
                        if matches!(mode, ReplyMode::Negative) {
                            3
                        } else if matches!(mode, ReplyMode::Servfail) {
                            2
                        } else {
                            0
                        },
                    ),
                    encode::EncodeQuestion {
                        name: &name,
                        qtype: question.qtype,
                        qclass: question.qclass,
                    },
                    &records,
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

fn policy(mode: ReplyMode) -> (Policy, FakeSocket) {
    policy_with_action(mode, Action::Forward)
}

fn policy_with_action(mode: ReplyMode, action: Action) -> (Policy, FakeSocket) {
    let mut config = Config::default();
    config.admission.max_response_records = 1;
    config.policy.rules = vec![RuleConfig {
        id: 1,
        domain: "example.com".into(),
        action,
        priority: 0,
        qtype: None,
        qclass: None,
        client: None,
        client_cidr: None,
        client_cidrs: Vec::new(),
    }];
    config.upstream = Some(UpstreamConfig {
        resolver_ip: resolver_addr().ip().to_string(),
        port: resolver_addr().port(),
        query_timeout_ms: 10,
        max_attempts: 1,
        ..UpstreamConfig::default()
    });
    let upstream = config.upstream.clone().expect("upstream config");
    let socket = FakeSocket::new(mode);
    let policy = Policy::new(config).expect("valid config").with_upstream(
        Arc::new(FakeFactory {
            socket: socket.clone(),
        }),
        DnsResolverConfig::builder()
            .resolver_ip(upstream.resolver_ip)
            .port(upstream.port)
            .query_timeout_ms(upstream.query_timeout_ms)
            .max_attempts(upstream.max_attempts)
            .build(),
        upstream.max_outstanding,
    );
    (policy, socket)
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
    let (policy, _) = policy(ReplyMode::Valid);
    let answer = policy.call(request()).await.unwrap();
    assert_eq!(answer.payload.rcode, 0);
    assert_eq!(answer.payload.records.len(), 1);
}

#[proxima::test]
async fn pass_through_uses_the_configured_upstream() {
    let (policy, socket) = policy_with_action(ReplyMode::Valid, Action::Pass);
    let answer = policy.call(request()).await.expect("pass-through exchange");
    assert_eq!(answer.payload.rcode, 0);
    assert_eq!(answer.payload.records.len(), 1);
    assert_eq!(socket.state.lock().expect("fake state").sent.len(), 1);
}

#[proxima::test]
async fn observe_pass_through_uses_the_configured_upstream() {
    let (policy, socket) = policy_with_action(ReplyMode::Valid, Action::Observe);
    let answer = policy.call(request()).await.expect("observe exchange");
    assert_eq!(answer.payload.rcode, 0);
    assert_eq!(answer.payload.records.len(), 1);
    assert_eq!(socket.state.lock().expect("fake state").sent.len(), 1);
}

#[proxima::test]
async fn fake_upstream_malformed_reply_fails_closed() {
    let (policy, _) = policy(ReplyMode::Malformed);
    let result = policy.call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_wrong_id_fails_closed() {
    let (policy, _) = policy(ReplyMode::WrongId);
    let result = policy.call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_spoofed_sender_fails_closed() {
    let (policy, _) = policy(ReplyMode::WrongSender);
    let result = policy.call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_timeout_fails_closed() {
    let (policy, _) = policy(ReplyMode::Timeout);
    let result = policy.call(request()).await;
    assert!(result.is_err());
}

#[proxima::test]
async fn fake_upstream_overflow_fails_closed() {
    let (policy, _) = policy(ReplyMode::Overflow);
    let answer = policy.call(request()).await.expect("fail-closed response");
    assert_eq!(answer.payload.rcode, 2, "overflow must become SERVFAIL");
    assert!(answer.payload.records.is_empty());
}

#[proxima::test]
async fn fake_upstream_cache_hit_avoids_a_second_exchange() {
    let (policy, socket) = policy(ReplyMode::Valid);
    policy.call(request()).await.expect("first exchange");
    policy.call(request()).await.expect("cached exchange");
    assert_eq!(
        socket.state.lock().expect("fake state").sent.len(),
        1,
        "fresh cache entry must avoid a second upstream query"
    );
}

#[proxima::test]
async fn fake_upstream_negative_cache_hit_avoids_a_second_exchange() {
    let (policy, socket) = policy(ReplyMode::Negative);
    let first = policy.call(request()).await.expect("first exchange");
    assert_eq!(first.payload.rcode, 3);
    let second = policy.call(request()).await.expect("cached exchange");
    assert_eq!(second.payload.rcode, 3);
    assert_eq!(
        socket.state.lock().expect("fake state").sent.len(),
        1,
        "fresh negative cache entry must avoid a second upstream query"
    );
}

#[proxima::test]
async fn fake_upstream_servfail_is_not_cached() {
    let (policy, socket) = policy(ReplyMode::Servfail);
    let first = policy.call(request()).await.expect("first exchange");
    assert_eq!(first.payload.rcode, 2);
    let second = policy.call(request()).await.expect("second exchange");
    assert_eq!(second.payload.rcode, 2);
    assert_eq!(
        socket.state.lock().expect("fake state").sent.len(),
        2,
        "SERVFAIL must not become a reusable negative cache entry"
    );
}
