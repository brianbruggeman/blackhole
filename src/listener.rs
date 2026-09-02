//! Proxima listener adapters for the borrowed Blackhole wire path.

use bytes::{Bytes, BytesMut};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use proxima::ProximaError;
use proxima_listen::admission::ConnAdmission;
use proxima_listen::any::{AnyHandler, AnyProtocol, ProbeVerdict};
use proxima_primitives::pipe::header_list::HeaderList;
use proxima_primitives::pipe::method::Method;
use proxima_primitives::pipe::request::{Request, RequestContext};
use proxima_primitives::stream::{PeerInfo, StreamConnection};
use proxima_protocols::dns::encode;
use serde_json::Value;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use crate::Policy;
use crate::fsm::{DecisionState, DropReason, Event};
use crate::query::{MAX_QUERY_BYTES, QueryView, valid_query_flags};

const MAX_TCP_FRAME: usize = 4096;
const UDP_HEADER: usize = 12;
const TCP_PREFIX: usize = 14;
const ORIGINAL_DESTINATION_METADATA: &str = "blackhole-original-destination";

pub struct UdpProtocol {
    policy: Arc<Policy>,
    original_destination: Option<SocketAddr>,
}

pub struct TcpProtocol {
    policy: Arc<Policy>,
    original_destination: Option<SocketAddr>,
}

impl UdpProtocol {
    #[must_use]
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            original_destination: None,
        }
    }

    #[must_use]
    pub fn with_original_destination(mut self, destination: SocketAddr) -> Self {
        self.original_destination = Some(destination);
        self
    }
}

impl TcpProtocol {
    #[must_use]
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            original_destination: None,
        }
    }

    #[must_use]
    pub fn with_original_destination(mut self, destination: SocketAddr) -> Self {
        self.original_destination = Some(destination);
        self
    }
}

fn is_query(prefix: &[u8]) -> bool {
    prefix.len() >= UDP_HEADER
        && valid_query_flags(prefix)
        && u16::from_be_bytes([prefix[4], prefix[5]]) == 1
}

fn request(
    query: proxima_dns::DnsQuery,
    tcp: bool,
    peer: Option<PeerInfo>,
    original_destination: Option<SocketAddr>,
) -> proxima_dns::DnsPipeRequest {
    let mut metadata = HeaderList::new();
    if let Some(destination) = original_destination {
        metadata.insert(ORIGINAL_DESTINATION_METADATA, destination.to_string());
    }
    Request {
        method: Method::from_wire(if tcp {
            Bytes::from_static(b"DNS-TCP")
        } else {
            Bytes::from_static(b"DNS")
        }),
        path: Bytes::from_static(b"/"),
        query: HeaderList::new(),
        metadata,
        payload: query,
        stream: None,
        context: RequestContext {
            peer,
            ..RequestContext::default()
        },
    }
}

struct ListenerLatency<'policy> {
    policy: &'policy Policy,
    started: Instant,
}

impl Drop for ListenerLatency<'_> {
    fn drop(&mut self) {
        self.policy.observe_listener_latency(self.started.elapsed());
    }
}

async fn decide<'a>(
    policy: &Policy,
    mut state: DecisionState<'a>,
    packet: &'a [u8],
    peer: Option<PeerInfo>,
    tcp: bool,
    original_destination: Option<SocketAddr>,
) -> Result<Option<(Vec<u8>, DecisionState<'a>)>, ProximaError> {
    let _latency = ListenerLatency {
        policy,
        started: Instant::now(),
    };
    state = state.transition(Event::BeginParse).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    let view = match QueryView::parse(packet) {
        Ok(view) => view,
        Err(error) => {
            policy.observe_failure(error.telemetry_cause());
            let client = match peer.as_ref() {
                Some(PeerInfo::Tcp(address)) => Some(address.ip()),
                _ => None,
            };
            policy
                .record_adapter_abuse(client, error.telemetry_cause())
                .await;
            let _ = state.transition(Event::Drop(DropReason::Malformed));
            return Ok(None);
        }
    };
    state = state.transition(Event::Parsed(view)).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    let client = match peer.as_ref() {
        Some(PeerInfo::Tcp(address)) => Some(address.ip()),
        _ => None,
    };
    let action = policy.action_for_view_with_client(view, client);
    let query = view.to_owned();
    policy
        .record_decision_for_client(action, &query, client)
        .await;
    state = state.transition(Event::Matched(action)).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    if matches!(action, crate::Action::Drop | crate::Action::Ignore) {
        policy.observe_for_client(action, client);
        let _ = state.transition(Event::Drop(DropReason::PolicyFailure));
        return Ok(None);
    }
    if action == crate::Action::Forward {
        state = state.transition(Event::Forward).map_err(|error| {
            policy.observe_failure("fsm_transition");
            ProximaError::Config(error.to_string())
        })?;
    }

    let request = request(query.clone(), tcp, peer.clone(), original_destination);
    let answer = policy
        .call_owned(request, action)
        .await
        .map_err(|error| {
            policy.observe_failure("policy_call");
            ProximaError::Io(std::io::Error::other(error.to_string()))
        })?
        .payload;
    let mut output = Vec::with_capacity(packet.len());
    let flags = proxima_protocols::dns::Flags::for_response(
        query.recursion_desired,
        answer.authoritative,
        answer.recursion_available,
        answer.rcode,
    );
    let records: Vec<encode::AnswerRecord<'_>> = answer
        .records
        .iter()
        .map(|record| encode::AnswerRecord {
            name: &record.name,
            rtype: record.rtype,
            rclass: record.rclass,
            ttl: record.ttl,
            rdata: &record.rdata,
        })
        .collect();
    encode::encode_response(
        query.id,
        flags,
        encode::EncodeQuestion {
            name: &query.name,
            qtype: query.qtype,
            qclass: query.qclass,
        },
        &records,
        &mut output,
    )
    .map_err(|error| {
        policy.observe_failure("encode_failure");
        ProximaError::Config(error.to_string())
    })?;
    let client_ip = match peer.as_ref() {
        Some(PeerInfo::Tcp(address)) => Some(address.ip()),
        _ => None,
    };
    if policy.response_amplification_capped(packet.len(), output.len()) {
        policy.observe_failure("response_amplification_cap");
        if policy.record_client_abuse(client_ip) {
            policy.observe_failure("client_abuse_breaker_open");
            if let Some(client) = client_ip {
                policy
                    .record_abuse_incident(client, "response_amplification_cap")
                    .await;
            }
        }
    }
    if !policy.allow_global_response_bytes(output.len()) {
        policy.observe_failure("global_response_budget");
        if policy.record_global_abuse("global_response_budget") {
            policy
                .record_global_abuse_incident("global_response_budget")
                .await;
        }
        let _ = state.transition(Event::Drop(DropReason::PolicyFailure));
        return Ok(None);
    }
    if !policy.allow_client_response_bytes(client_ip, output.len()) {
        policy.observe_failure("client_response_budget");
        if policy.record_client_abuse(client_ip) {
            policy.observe_failure("client_abuse_breaker_open");
            if let Some(client) = client_ip {
                policy
                    .record_abuse_incident(client, "client_response_budget")
                    .await;
            }
        }
        let _ = state.transition(Event::Drop(DropReason::PolicyFailure));
        return Ok(None);
    }
    if !policy.allow_network_response_bytes(client_ip, output.len()) {
        policy.observe_failure("network_response_budget");
        if policy.record_client_abuse(client_ip) {
            policy.observe_failure("client_abuse_breaker_open");
            if let Some(client) = client_ip {
                policy
                    .record_abuse_incident(client, "network_response_budget")
                    .await;
            }
        }
        let _ = state.transition(Event::Drop(DropReason::PolicyFailure));
        return Ok(None);
    }
    #[cfg(feature = "perf-instrument")]
    crate::perf::record_copy(crate::perf::Boundary::EncodeOutput, output.len());
    let event = if action == crate::Action::Forward {
        Event::Forwarded(output.len())
    } else {
        Event::Respond(output.len())
    };
    state = state.transition(event).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    Ok(Some((output, state)))
}

fn advance_partial_tcp_state(policy: &Policy, input: &[u8]) -> Result<(), ProximaError> {
    let state = DecisionState::received(input)
        .transition(Event::BeginParse)
        .and_then(|state| state.transition(Event::NeedMore(input)))
        .map_err(|error| {
            policy.observe_failure("fsm_transition");
            ProximaError::Config(error.to_string())
        })?;
    // The state borrows the bounded input only for this transition. The
    // adapter drops it before the next read can grow the buffer.
    let _ = state;
    Ok(())
}

fn probe_udp(prefix: &[u8]) -> ProbeVerdict {
    if prefix.len() < UDP_HEADER {
        ProbeVerdict::NeedMore {
            at_least: UDP_HEADER,
        }
    } else if is_query(prefix) {
        ProbeVerdict::Match { consumed: 0 }
    } else {
        ProbeVerdict::No
    }
}

fn probe_tcp(prefix: &[u8]) -> ProbeVerdict {
    if prefix.len() < TCP_PREFIX {
        return ProbeVerdict::NeedMore {
            at_least: TCP_PREFIX,
        };
    }
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if !(12..=MAX_TCP_FRAME).contains(&length) || !is_query(&prefix[2..]) {
        ProbeVerdict::No
    } else {
        ProbeVerdict::Match { consumed: 0 }
    }
}

impl AnyProtocol for UdpProtocol {
    fn name(&self) -> &str {
        "blackhole-udp"
    }
    fn max_prefix_bytes(&self) -> usize {
        UDP_HEADER
    }
    fn wants_datagram(&self) -> bool {
        true
    }
    fn probe(&self, prefix: &[u8]) -> ProbeVerdict {
        probe_udp(prefix)
    }
    fn drive<'a>(
        &'a self,
        mut stream: Box<dyn StreamConnection>,
        _handler: AnyHandler,
        _spec: &'a Value,
        peer: Option<PeerInfo>,
        _admission: &'a ConnAdmission,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProximaError>> + Send + 'a>> {
        Box::pin(async move {
            // `.any()` replays the classifier's prefix before the datagram
            // adapter's remaining bytes. Drain that one-shot stream through
            // a bounded reader so a split replay cannot be mistaken for a
            // complete DNS message.
            let mut packet = Vec::with_capacity(MAX_QUERY_BYTES + 1);
            (&mut *stream)
                .take((MAX_QUERY_BYTES + 1) as u64)
                .read_to_end(&mut packet)
                .await
                .map_err(|error| {
                    self.policy.observe_failure("transport_read");
                    ProximaError::Io(error)
                })?;
            if packet.len() > MAX_QUERY_BYTES {
                self.policy.observe_failure("query_oversized");
                return Ok(());
            }
            let state = DecisionState::received(&packet);
            if let Some((reply, state)) = decide(
                &self.policy,
                state,
                &packet,
                peer,
                false,
                self.original_destination,
            )
            .await?
            {
                stream.write_all(&reply).await.map_err(|error| {
                    self.policy.observe_failure("transport_write");
                    ProximaError::Io(error)
                })?;
                #[cfg(feature = "perf-instrument")]
                crate::perf::record_copy(crate::perf::Boundary::TransportWrite, reply.len());
                state.transition(Event::Sent).map_err(|error| {
                    self.policy.observe_failure("fsm_transition");
                    ProximaError::Config(error.to_string())
                })?;
            }
            stream.close().await.map_err(|error| {
                self.policy.observe_failure("transport_close");
                ProximaError::Io(error)
            })
        })
    }
}

impl AnyProtocol for TcpProtocol {
    fn name(&self) -> &str {
        "blackhole-tcp"
    }
    fn max_prefix_bytes(&self) -> usize {
        TCP_PREFIX
    }
    fn probe(&self, prefix: &[u8]) -> ProbeVerdict {
        probe_tcp(prefix)
    }
    fn drive<'a>(
        &'a self,
        mut stream: Box<dyn StreamConnection>,
        _handler: AnyHandler,
        _spec: &'a Value,
        peer: Option<PeerInfo>,
        _admission: &'a ConnAdmission,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProximaError>> + Send + 'a>> {
        Box::pin(async move {
            let mut input = BytesMut::new();
            let mut scratch = [0u8; 1024];
            let mut response_sent = false;
            loop {
                while input.len() < 2
                    || input.len() < 2 + usize::from(u16::from_be_bytes([input[0], input[1]]))
                {
                    let read = stream.read(&mut scratch).await.map_err(|error| {
                        self.policy.observe_failure("transport_read");
                        ProximaError::Io(error)
                    })?;
                    if read == 0 {
                        return Ok(());
                    }
                    if input.len() + read > 2 + MAX_TCP_FRAME {
                        self.policy.observe_failure("frame_overflow");
                        return Ok(());
                    }
                    #[cfg(feature = "perf-instrument")]
                    crate::perf::record_copy(crate::perf::Boundary::TcpFrameBuffer, read);
                    input.extend_from_slice(&scratch[..read]);
                    if input.len() < 2
                        || input.len() < 2 + usize::from(u16::from_be_bytes([input[0], input[1]]))
                    {
                        advance_partial_tcp_state(&self.policy, &input)?;
                    }
                }
                let length = usize::from(u16::from_be_bytes([input[0], input[1]]));
                let frame = input.split_to(2 + length).split_off(2);
                let state = if response_sent {
                    DecisionState::sent()
                        .transition(Event::NextMessage(&frame))
                        .map_err(|error| {
                            self.policy.observe_failure("fsm_transition");
                            ProximaError::Config(error.to_string())
                        })?
                } else {
                    DecisionState::received(&frame)
                };
                if let Some((reply, responding)) = decide(
                    &self.policy,
                    state,
                    &frame,
                    peer.clone(),
                    true,
                    self.original_destination,
                )
                .await?
                {
                    let length = u16::try_from(reply.len()).map_err(|_| {
                        self.policy.observe_failure("frame_overflow");
                        ProximaError::Config("DNS response exceeds TCP framing".into())
                    })?;
                    stream
                        .write_all(&length.to_be_bytes())
                        .await
                        .map_err(|error| {
                            self.policy.observe_failure("transport_write");
                            ProximaError::Io(error)
                        })?;
                    stream.write_all(&reply).await.map_err(|error| {
                        self.policy.observe_failure("transport_write");
                        ProximaError::Io(error)
                    })?;
                    #[cfg(feature = "perf-instrument")]
                    crate::perf::record_copy(crate::perf::Boundary::TransportWrite, reply.len());
                    responding.transition(Event::Sent).map_err(|error| {
                        self.policy.observe_failure("fsm_transition");
                        ProximaError::Config(error.to_string())
                    })?;
                    response_sent = true;
                } else {
                    response_sent = false;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Policy};
    use futures::io::{AsyncRead, AsyncWrite};
    use proxima::Telemetry;
    use proxima_primitives::pipe::telemetry_surface::Labels;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    struct TestConnection {
        input: std::io::Cursor<Vec<u8>>,
        output: Arc<Mutex<Vec<u8>>>,
        peer: Option<PeerInfo>,
    }

    impl AsyncRead for TestConnection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let _ = cx;
            let offset = self.input.position() as usize;
            let input = self.input.get_ref();
            if offset >= input.len() {
                return Poll::Ready(Ok(0));
            }
            let count = output.len().min(input.len() - offset);
            output[..count].copy_from_slice(&input[offset..offset + count]);
            self.input.set_position((offset + count) as u64);
            Poll::Ready(Ok(count))
        }
    }

    impl AsyncWrite for TestConnection {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.output
                .lock()
                .expect("test output lock")
                .extend_from_slice(input);
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl StreamConnection for TestConnection {
        fn peer(&self) -> Option<PeerInfo> {
            self.peer.clone()
        }
    }

    fn test_query() -> Vec<u8> {
        let mut packet = Vec::new();
        encode::encode_query(
            0x1234,
            true,
            encode::EncodeQuestion {
                name: "example.com.",
                qtype: 1,
                qclass: 1,
            },
            &mut packet,
        )
        .expect("test query");
        packet
    }

    struct FailureCollector(Arc<Mutex<Vec<String>>>);

    impl Telemetry for FailureCollector {
        fn counter_inc(&self, metric: &str, labels: &Labels, by: u64) {
            assert_eq!(metric, "blackhole.failures");
            assert_eq!(by, 1);
            self.0
                .lock()
                .expect("failure labels lock")
                .push(labels.entries()[0].1.clone());
        }

        fn gauge_set(&self, _: &str, _: &Labels, _: i64) {}

        fn histogram_record(&self, _: &str, _: &Labels, _: f64) {}
    }

    struct LatencyCollector(Arc<Mutex<Vec<f64>>>);

    impl Telemetry for LatencyCollector {
        fn counter_inc(&self, _: &str, _: &Labels, _: u64) {}

        fn gauge_set(&self, _: &str, _: &Labels, _: i64) {}

        fn histogram_record(&self, metric: &str, labels: &Labels, value: f64) {
            assert_eq!(metric, "blackhole.listener_latency_ns");
            assert_eq!(
                labels.entries(),
                [("operation".into(), "wire_decide".into())]
            );
            self.0.lock().expect("latency samples lock").push(value);
        }
    }

    #[test]
    fn capture_destination_is_carried_as_request_metadata_for_both_transports() {
        let query = proxima_dns::DnsQuery {
            id: 7,
            recursion_desired: true,
            name: "example.com.".into(),
            qtype: 1,
            qclass: 1,
        };
        let destination = "192.0.2.53:53".parse().expect("destination");
        for tcp in [false, true] {
            let request = request(query.clone(), tcp, None, Some(destination));
            assert_eq!(
                request.metadata.get_str(ORIGINAL_DESTINATION_METADATA),
                Some("192.0.2.53:53")
            );
        }
    }

    #[test]
    fn universal_listener_drives_udp_and_tcp_adapters_into_the_fsm() {
        let policy = Arc::new(Policy::new(Config::default()).expect("default policy"));
        let peer = Some(PeerInfo::Tcp("192.0.2.10:5353".parse().expect("peer")));

        let udp_output = Arc::new(Mutex::new(Vec::new()));
        let udp = UdpProtocol::new(Arc::clone(&policy));
        futures::executor::block_on(udp.drive(
            Box::new(TestConnection {
                input: std::io::Cursor::new(test_query()),
                output: Arc::clone(&udp_output),
                peer: peer.clone(),
            }),
            Arc::new(()),
            &Value::Null,
            peer.clone(),
            &ConnAdmission::unbounded(),
        ))
        .expect("UDP adapter drive");
        let udp_output = udp_output.lock().expect("UDP output");
        assert_eq!(u16::from_be_bytes([udp_output[0], udp_output[1]]), 0x1234);

        let query = test_query();
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        let tcp_output = Arc::new(Mutex::new(Vec::new()));
        let tcp = TcpProtocol::new(Arc::clone(&policy));
        futures::executor::block_on(tcp.drive(
            Box::new(TestConnection {
                input: std::io::Cursor::new(framed),
                output: Arc::clone(&tcp_output),
                peer,
            }),
            Arc::new(()),
            &Value::Null,
            Some(PeerInfo::Tcp("192.0.2.10:5353".parse().expect("peer"))),
            &ConnAdmission::unbounded(),
        ))
        .expect("TCP adapter drive");
        let tcp_output = tcp_output.lock().expect("TCP output");
        assert_eq!(u16::from_be_bytes([tcp_output[2], tcp_output[3]]), 0x1234);
    }

    #[test]
    fn udp_oversized_datagram_is_dropped_before_parsing() {
        let policy = Arc::new(Policy::new(Config::default()).expect("default policy"));
        let output = Arc::new(Mutex::new(Vec::new()));
        let udp = UdpProtocol::new(policy);
        let input = vec![0u8; MAX_QUERY_BYTES + 1];

        futures::executor::block_on(udp.drive(
            Box::new(TestConnection {
                input: std::io::Cursor::new(input),
                output: Arc::clone(&output),
                peer: None,
            }),
            Arc::new(()),
            &Value::Null,
            None,
            &ConnAdmission::unbounded(),
        ))
        .expect("oversized datagram is a dropped request");

        assert!(output.lock().expect("UDP output").is_empty());
    }

    #[test]
    fn listener_records_the_parser_failure_cause() {
        let causes = Arc::new(Mutex::new(Vec::new()));
        let policy = Policy::new(Config::default())
            .expect("default policy")
            .with_telemetry(Arc::new(FailureCollector(Arc::clone(&causes))));

        let result = futures::executor::block_on(decide(
            &policy,
            DecisionState::received(&[0; 11]),
            &[0; 11],
            None,
            false,
            None,
        ))
        .expect("malformed input is a dropped request");
        assert!(result.is_none());
        assert_eq!(
            causes.lock().expect("failure labels lock").as_slice(),
            ["query_wire_short"]
        );
    }

    #[test]
    fn listener_preserves_drop_action_in_aggregate_stats() {
        let mut config = Config::default();
        config.policy.rules = vec![crate::RuleConfig {
            enabled: true,
            id: 1,
            domain: "drop.example".into(),
            action: crate::Action::Drop,
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
        let policy = Policy::new(config).expect("valid drop policy");
        let mut packet = Vec::new();
        encode::encode_query(
            1,
            true,
            encode::EncodeQuestion {
                name: "drop.example.",
                qtype: 1,
                qclass: 1,
            },
            &mut packet,
        )
        .expect("encode drop query");

        let result = futures::executor::block_on(decide(
            &policy,
            DecisionState::received(&packet),
            &packet,
            None,
            false,
            None,
        ))
        .expect("drop is a normal no-response result");
        assert!(result.is_none());
        let stats: serde_json::Value =
            serde_json::from_str(&policy.admin_stats()).expect("stats JSON");
        assert_eq!(stats["actions"]["drop"], 1);
        assert_eq!(stats["actions"]["ignore"], 0);
    }

    #[test]
    fn listener_records_latency_for_a_parser_drop() {
        let samples = Arc::new(Mutex::new(Vec::new()));
        let policy = Policy::new(Config::default())
            .expect("default policy")
            .with_telemetry(Arc::new(LatencyCollector(Arc::clone(&samples))));

        let result = futures::executor::block_on(decide(
            &policy,
            DecisionState::received(&[0; 11]),
            &[0; 11],
            None,
            false,
            None,
        ))
        .expect("malformed input is a dropped request");
        assert!(result.is_none());
        let samples = samples.lock().expect("latency samples lock");
        assert_eq!(samples.len(), 1);
        assert!(samples[0].is_finite());
        assert!(samples[0] >= 0.0);
    }

    #[test]
    fn identified_parser_failures_feed_the_bounded_abuse_breaker() {
        let causes = Arc::new(Mutex::new(Vec::new()));
        let mut config = Config::default();
        config.admission.max_client_abuse_violations = 2;
        let policy = Policy::new(config)
            .expect("valid admission config")
            .with_telemetry(Arc::new(FailureCollector(Arc::clone(&causes))));
        let peer = Some(PeerInfo::Tcp("192.0.2.10:5353".parse().unwrap()));
        for _ in 0..2 {
            let result = futures::executor::block_on(decide(
                &policy,
                DecisionState::received(&[0; 11]),
                &[0; 11],
                peer.clone(),
                false,
                None,
            ))
            .expect("malformed input is dropped");
            assert!(result.is_none());
        }
        assert!(
            causes
                .lock()
                .expect("failure labels lock")
                .iter()
                .any(|cause| cause == "client_abuse_breaker_open")
        );
    }
}
