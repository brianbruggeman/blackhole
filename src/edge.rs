//! Pure no-std policy/codec boundary for edge experiments.
//!
//! This module deliberately stops before the owned runtime and transport
//! facades. It is suitable for compiling the validated query path to a small
//! edge target without introducing a second policy implementation.

use crate::policy::{Decision, PolicyError, QueryContext, ReferencePolicy, RuleConfig};
use crate::query::{QueryParseError, QueryView};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeError {
    Query(QueryParseError),
    Policy(PolicyError),
}

/// Reusable immutable edge policy. Construct this when the configuration
/// changes, not once per packet.
pub struct EdgePolicy {
    policy: ReferencePolicy,
}

impl EdgePolicy {
    pub fn new(rules: &[RuleConfig]) -> Result<Self, PolicyError> {
        Ok(Self {
            policy: ReferencePolicy::new(rules)?,
        })
    }

    /// Parse and match one packet against this already-built snapshot.
    pub fn decide(
        &self,
        packet: &[u8],
        client: Option<core::net::IpAddr>,
    ) -> Result<Option<Decision>, EdgeError> {
        let query = QueryView::parse(packet)?;
        let name = query.name.to_dotted();
        Ok(self.policy.decide(QueryContext {
            name: &name,
            qtype: query.qtype,
            qclass: query.qclass,
            client,
            client_identity: None,
        }))
    }
}

impl core::fmt::Display for EdgeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Query(error) => write!(formatter, "edge query: {error}"),
            Self::Policy(error) => write!(formatter, "edge policy: {error}"),
        }
    }
}

impl core::error::Error for EdgeError {}

impl From<QueryParseError> for EdgeError {
    fn from(error: QueryParseError) -> Self {
        Self::Query(error)
    }
}

impl From<PolicyError> for EdgeError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

/// Parse and match one DNS query without entering the owned runtime. Wire
/// parsing remains borrowed; the existing policy matcher receives its normal
/// canonical string at the explicit policy boundary. The returned decision
/// retains the selected rule ID and complete action identity for the caller's
/// edge adapter.
pub fn decide(
    packet: &[u8],
    rules: &[RuleConfig],
    client: Option<core::net::IpAddr>,
) -> Result<Option<Decision>, EdgeError> {
    EdgePolicy::new(rules)?.decide(packet, client)
}

/// WASM-only probe for the pure edge experiment. It uses the same parser and
/// matcher as the reusable edge path with an empty rule snapshot and returns
/// `1` for a valid query, `0` for a valid unmatched query, and `-1` for an
/// invalid pointer or packet. No transport or owned runtime is linked.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn blackhole_edge_probe(packet_ptr: *const u8, packet_len: usize) -> i32 {
    if packet_ptr.is_null() || packet_len > crate::query::MAX_QUERY_BYTES {
        return -1;
    }
    // The benchmark owns the caller-provided range; the protocol bound keeps
    // malformed lengths from creating an unbounded slice in this experiment.
    let packet = unsafe { core::slice::from_raw_parts(packet_ptr, packet_len) };
    match decide(packet, &[], None) {
        Ok(Some(_)) => 1,
        Ok(None) => 0,
        Err(_) => -1,
    }
}

/// Reset the bounded allocator between isolated WASM benchmark invocations.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn blackhole_edge_reset() {
    crate::wasm_runtime::reset();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;

    #[test]
    fn edge_path_preserves_borrowed_parse_and_policy_action() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let rules = [RuleConfig {
            enabled: true,
            id: 7,
            domain: "www.example".into(),
            action: Action::Nxdomain,
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
        let policy = EdgePolicy::new(&rules).expect("valid edge policy");
        assert_eq!(
            policy.decide(&packet, None).expect("valid edge decision"),
            Some(Decision {
                rule_id: 7,
                action: Action::Nxdomain,
            })
        );
        assert_eq!(
            decide(&packet, &rules, None).expect("valid convenience decision"),
            Some(Decision {
                rule_id: 7,
                action: Action::Nxdomain,
            })
        );
    }
}
