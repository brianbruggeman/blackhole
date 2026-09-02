use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use blackhole::policy::Action;
use blackhole::{ClientIdentityConfig, Config, Policy, RuleConfig, UpstreamConfig};
use bytes::Bytes;
use proxima::pipe::SendPipe;
use proxima::pipe::into_handle;
use proxima_core::ProximaError;
use proxima_dns::DnsResolverConfig;
use proxima_primitives::pipe::request::{Request, Response};
use proxima_primitives::stream::{DatagramFactory, DatagramSocket, PeerInfo};
use proxima_protocols::dns::{Flags, encode, parse_message};

#[derive(Clone, Copy)]
enum ReplyMode {
    Valid,
    Negative,
    Servfail,
    WrongId,
    WrongQuestion,
    NotResponse,
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
            | ReplyMode::Overflow
            | ReplyMode::WrongQuestion
            | ReplyMode::NotResponse => {
                let message = parse_message(query).expect("fake query");
                let question = message
                    .questions()
                    .next()
                    .expect("fake question")
                    .expect("valid fake question");
                let name = question.name.to_dotted();
                let response_name = if matches!(mode, ReplyMode::WrongQuestion) {
                    "other.example.".to_owned()
                } else {
                    name.clone()
                };
                let rdata = encode::ipv4_rdata(Ipv4Addr::new(93, 184, 216, 34));
                let record = encode::AnswerRecord {
                    name: &response_name,
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
                        name: &response_name,
                        qtype: question.qtype,
                        qclass: question.qclass,
                    },
                    &records,
                    &mut response,
                )
                .expect("fake response");
                if matches!(mode, ReplyMode::NotResponse) {
                    response[2] &= 0x7f;
                }
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
        enabled: true,
        id: 1,
        domain: "example.com".into(),
        action,
        priority: 0,
        qtype: None,
        qtypes: Vec::new(),
        qclass: None,
        qclasses: Vec::new(),
        client: None,
        client_cidr: None,
        client_cidrs: Vec::new(),
        client_identity: None,
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

fn request_from_client(client: IpAddr) -> proxima_dns::DnsPipeRequest {
    let mut request = request();
    request.context.peer = Some(PeerInfo::Tcp(SocketAddr::new(client, 53_000)));
    request
}

struct FakeDoh {
    calls: Arc<AtomicUsize>,
    malformed: bool,
}

impl SendPipe for FakeDoh {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    fn call(
        &self,
        request: Request<Bytes>,
    ) -> impl std::future::Future<Output = Result<Response<Bytes>, ProximaError>> + Send {
        let calls = Arc::clone(&self.calls);
        let malformed = self.malformed;
        async move {
            assert_eq!(request.method.as_bytes(), b"POST");
            assert_eq!(request.path.as_ref(), b"/dns-query");
            calls.fetch_add(1, Ordering::SeqCst);

            if malformed {
                return Ok(Response::ok(Bytes::from_static(&[0; 12])));
            }

            let message = parse_message(request.payload.as_ref())
                .map_err(|_| ProximaError::Upstream("fake DoH received malformed query".into()))?;
            let question = message
                .questions()
                .next()
                .ok_or_else(|| ProximaError::Upstream("fake DoH received no question".into()))?
                .map_err(|_| ProximaError::Upstream("fake DoH question was malformed".into()))?;
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
            encode::encode_response(
                message.header.id,
                Flags::for_response(true, false, true, 0),
                encode::EncodeQuestion {
                    name: &name,
                    qtype: question.qtype,
                    qclass: question.qclass,
                },
                &[record],
                &mut response,
            )
            .map_err(|_| ProximaError::Upstream("fake DoH response encoding failed".into()))?;
            Ok(Response::ok(response))
        }
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
async fn named_client_upstream_route_and_cache_bypass_use_proxima_exchange() {
    let socket = FakeSocket::new(ReplyMode::Valid);
    let mut config = Config::default();
    config.policy.rules = vec![RuleConfig {
        enabled: true,
        id: 2,
        domain: "example.com".into(),
        action: Action::Forward,
        priority: 0,
        qtype: None,
        qtypes: Vec::new(),
        qclass: None,
        qclasses: Vec::new(),
        client: None,
        client_cidr: None,
        client_cidrs: Vec::new(),
        client_identity: None,
    }];
    config.upstreams.insert(
        "family".into(),
        UpstreamConfig {
            resolver_ip: resolver_addr().ip().to_string(),
            port: resolver_addr().port(),
            query_timeout_ms: 10,
            max_attempts: 1,
            ..UpstreamConfig::default()
        },
    );
    config.policy.client_identities = vec![ClientIdentityConfig {
        name: "family-router".into(),
        enabled: true,
        query_log_enabled: true,
        statistics_enabled: true,
        cache_enabled: false,
        filtering_enabled: true,
        default_action: None,
        upstream: Some("family".into()),
        clients: vec!["192.0.2.10".parse().expect("client address")],
        max_queries_per_second: None,
        max_response_bytes_per_second: None,
        max_inflight_requests: None,
        client_cidrs: Vec::new(),
    }];
    let upstream = config.upstreams["family"].clone();
    let policy = Policy::new(config)
        .expect("valid named upstream config")
        .with_named_upstream(
            "family",
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
        )
        .expect("attach named upstream");
    let answer = policy
        .call(request_from_client(
            "192.0.2.10".parse().expect("client address"),
        ))
        .await
        .expect("named upstream exchange");
    assert_eq!(answer.payload.records.len(), 1);
    policy
        .call(request_from_client(
            "192.0.2.10".parse().expect("client address"),
        ))
        .await
        .expect("uncached named upstream exchange");
    assert_eq!(socket.state.lock().expect("fake state").sent.len(), 2);
}

#[proxima::test]
async fn doh_upstream_flows_through_policy_and_cache() {
    let (policy, socket) = policy(ReplyMode::Timeout);
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = policy.with_doh_upstream(into_handle(FakeDoh {
        calls: Arc::clone(&calls),
        malformed: false,
    }));

    let first = policy.call(request()).await.expect("DoH exchange");
    let second = policy.call(request()).await.expect("cached DoH exchange");
    assert_eq!(first.payload.rcode, 0);
    assert_eq!(first.payload.records.len(), 1);
    assert_eq!(second.payload.records.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(socket.state.lock().expect("fake state").sent.is_empty());
}

#[proxima::test]
async fn doh_upstream_malformed_payload_fails_closed() {
    let (policy, _) = policy(ReplyMode::Timeout);
    let policy = policy.with_doh_upstream(into_handle(FakeDoh {
        calls: Arc::new(AtomicUsize::new(0)),
        malformed: true,
    }));

    assert!(policy.call(request()).await.is_err());
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
async fn fake_upstream_wrong_question_fails_closed() {
    let (policy, _) = policy(ReplyMode::WrongQuestion);
    let answer = policy.call(request()).await.expect("fail-closed response");
    assert_eq!(answer.payload.rcode, 2);
    assert!(answer.payload.records.is_empty());
}

#[proxima::test]
async fn fake_upstream_response_bit_failure_is_fail_closed() {
    let (policy, _) = policy(ReplyMode::NotResponse);
    assert!(policy.call(request()).await.is_err());
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
