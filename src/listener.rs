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
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use crate::Policy;
use crate::fsm::{DecisionState, DropReason, Event};
use crate::query::{MAX_QUERY_BYTES, QueryView, valid_query_flags};

const MAX_TCP_FRAME: usize = 4096;
const UDP_HEADER: usize = 12;
const TCP_PREFIX: usize = 14;

pub struct UdpProtocol {
    policy: Arc<Policy>,
}

pub struct TcpProtocol {
    policy: Arc<Policy>,
}

impl UdpProtocol {
    #[must_use]
    pub fn new(policy: Arc<Policy>) -> Self {
        Self { policy }
    }
}

impl TcpProtocol {
    #[must_use]
    pub fn new(policy: Arc<Policy>) -> Self {
        Self { policy }
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
) -> proxima_dns::DnsPipeRequest {
    Request {
        method: Method::from_wire(if tcp {
            Bytes::from_static(b"DNS-TCP")
        } else {
            Bytes::from_static(b"DNS")
        }),
        path: Bytes::from_static(b"/"),
        query: HeaderList::new(),
        metadata: HeaderList::new(),
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
    let action = policy.action_for_view_with_client(
        view,
        match peer.as_ref() {
            Some(PeerInfo::Tcp(address)) => Some(address.ip()),
            _ => None,
        },
    );
    let query = view.to_owned();
    policy.record_decision(action, &query).await;
    state = state.transition(Event::Matched(action)).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    if matches!(action, crate::Action::Drop | crate::Action::Ignore) {
        let _ = state.transition(Event::Drop(DropReason::PolicyFailure));
        return Ok(None);
    }
    if action == crate::Action::Forward {
        state = state.transition(Event::Forward).map_err(|error| {
            policy.observe_failure("fsm_transition");
            ProximaError::Config(error.to_string())
        })?;
    }

    let request = request(query.clone(), tcp, peer.clone());
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
        policy.record_global_abuse("global_response_budget");
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
            if let Some((reply, state)) = decide(&self.policy, state, &packet, peer, false).await? {
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
                if let Some((reply, responding)) =
                    decide(&self.policy, state, &frame, peer.clone(), true).await?
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
    use proxima::Telemetry;
    use proxima_primitives::pipe::telemetry_surface::Labels;
    use std::sync::{Arc, Mutex};

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
        ))
        .expect("malformed input is a dropped request");
        assert!(result.is_none());
        assert_eq!(
            causes.lock().expect("failure labels lock").as_slice(),
            ["query_wire_short"]
        );
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
