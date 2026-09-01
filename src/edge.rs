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
pub fn decide<'packet>(
    packet: &'packet [u8],
    rules: &[RuleConfig],
    client: Option<core::net::IpAddr>,
) -> Result<Option<Decision>, EdgeError> {
    let query = QueryView::parse(packet)?;
    let policy = ReferencePolicy::new(rules)?;
    let name = query.name.to_dotted();
    Ok(policy.decide(QueryContext {
        name: &name,
        qtype: query.qtype,
        qclass: query.qclass,
        client,
    }))
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
            id: 7,
            domain: "www.example".into(),
            action: Action::Nxdomain,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
        }];
        assert_eq!(
            decide(&packet, &rules, None).expect("valid edge decision"),
            Some(Decision {
                rule_id: 7,
                action: Action::Nxdomain,
            })
        );
    }
}
