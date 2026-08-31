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

use crate::Policy;
use crate::fsm::{DecisionState, DropReason, Event};
use crate::query::QueryView;

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
        && prefix[2] & 0x80 == 0
        && prefix[2] & 0x78 == 0
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

async fn decide<'a>(
    policy: &Policy,
    mut state: DecisionState<'a>,
    packet: &'a [u8],
    peer: Option<PeerInfo>,
    tcp: bool,
) -> Result<Option<(Vec<u8>, DecisionState<'a>)>, ProximaError> {
    state = state.transition(Event::BeginParse).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    let view = match QueryView::parse(packet) {
        Ok(view) => view,
        Err(_) => {
            policy.observe_failure("malformed_query");
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
    state = state.transition(Event::Matched(action)).map_err(|error| {
        policy.observe_failure("fsm_transition");
        ProximaError::Config(error.to_string())
    })?;
    if matches!(action, crate::Action::Drop | crate::Action::Ignore) {
        let _ = state.transition(Event::Drop(DropReason::PolicyFailure));
        return Ok(None);
    }

    let query = view.to_owned();
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
    #[cfg(feature = "perf-instrument")]
    crate::perf::record_copy(crate::perf::Boundary::EncodeOutput, output.len());
    state = state
        .transition(Event::Respond(output.len()))
        .map_err(|error| {
            policy.observe_failure("fsm_transition");
            ProximaError::Config(error.to_string())
        })?;
    Ok(Some((output, state)))
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
            let mut packet = Vec::new();
            stream.read_to_end(&mut packet).await.map_err(|error| {
                self.policy.observe_failure("transport_read");
                ProximaError::Io(error)
            })?;
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
                }
                let length = usize::from(u16::from_be_bytes([input[0], input[1]]));
                let frame = input.split_to(2 + length).split_off(2);
                let state = DecisionState::received(&frame);
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
                }
            }
        })
    }
}
