//! Deterministic reference policy matcher.

use alloc::collections::BTreeMap;
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};
use core::net::IpAddr;
use serde::Deserialize;

pub const MAX_RULES: usize = 100_000;
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_CLIENT_CIDRS: usize = 64;

/// Actions understood by the reference matcher. Rendering belongs to the
/// transport edge and is deliberately not part of this module.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Ignore,
    Drop,
    Reject,
    Nxdomain,
    Sink,
    Honeypot,
    Forward,
    Observe,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub id: u32,
    pub domain: String,
    pub action: Action,
    #[serde(default)]
    pub priority: i32,
    pub qtype: Option<u16>,
    pub qclass: Option<u16>,
    pub client: Option<IpAddr>,
    #[serde(default)]
    pub client_cidr: Option<String>,
    #[serde(default)]
    pub client_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryContext<'query> {
    pub name: &'query str,
    pub qtype: u16,
    pub qclass: u16,
    pub client: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub rule_id: u32,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    EmptyDomain { id: u32 },
    InvalidWildcard { id: u32, domain: String },
    InvalidClientCidr { id: u32, value: String },
    DuplicateRule { id: u32 },
    TooManyRules { max: usize },
    DomainTooLong { id: u32 },
    InvalidUpstream { reason: String },
    InvalidCache { reason: String },
    InvalidAdmission { reason: String },
    InvalidBlocklist { path: String, reason: String },
    InvalidCountryMap { path: String, reason: String },
    InvalidRewrite { name: String, reason: String },
    InvalidProfile { name: String, reason: String },
    TooManyRegexRules { max: usize },
    InvalidRegex { id: u32, reason: String },
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyDomain { id } => write!(formatter, "rule {id} has an empty domain"),
            Self::InvalidWildcard { id, domain } => {
                write!(formatter, "rule {id} has an invalid wildcard: {domain}")
            }
            Self::InvalidClientCidr { id, value } => {
                write!(formatter, "rule {id} has an invalid client CIDR: {value}")
            }
            Self::DuplicateRule { id } => write!(formatter, "duplicate rule id: {id}"),
            Self::TooManyRules { max } => write!(formatter, "rule count exceeds {max}"),
            Self::DomainTooLong { id } => write!(formatter, "rule {id} domain is too long"),
            Self::InvalidUpstream { reason } => write!(formatter, "invalid upstream: {reason}"),
            Self::InvalidCache { reason } => write!(formatter, "invalid cache: {reason}"),
            Self::InvalidAdmission { reason } => write!(formatter, "invalid admission: {reason}"),
            Self::InvalidBlocklist { path, reason } => {
                write!(formatter, "invalid blocklist {path}: {reason}")
            }
            Self::InvalidCountryMap { path, reason } => {
                write!(formatter, "invalid country map {path}: {reason}")
            }
            Self::InvalidRewrite { name, reason } => {
                write!(formatter, "invalid rewrite {name}: {reason}")
            }
            Self::InvalidProfile { name, reason } => {
                write!(formatter, "invalid service profile {name}: {reason}")
            }
            Self::TooManyRegexRules { max } => {
                write!(formatter, "regex rule count exceeds {max}")
            }
            Self::InvalidRegex { id, reason } => {
                write!(formatter, "invalid regex rule {id}: {reason}")
            }
        }
    }
}

impl core::error::Error for PolicyError {}

#[derive(Debug, Clone)]
struct Rule {
    id: u32,
    domain: String,
    action: Action,
    priority: i32,
    qtype: Option<u16>,
    qclass: Option<u16>,
    client: Option<IpAddr>,
    client_networks: Vec<IpNetwork>,
    wildcard: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let address = address.parse().ok()?;
        let prefix = prefix.parse().ok()?;
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (prefix <= max).then_some(Self { address, prefix })
    }

    pub(crate) fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let network = u32::from(network);
                let candidate = u32::from(candidate);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                network & mask == candidate & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let network = u128::from(network);
                let candidate = u128::from(candidate);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                network & mask == candidate & mask
            }
            _ => false,
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn prefix(self) -> u8 {
        self.prefix
    }
}

/// A simple linear matcher used as the semantic oracle for compact indexes.
#[derive(Debug, Clone, Default)]
pub struct ReferencePolicy {
    rules: Vec<Rule>,
}

/// Candidate compact lookup index. It narrows matching to exact and
/// reverse-label suffix buckets, then reuses the reference predicate and
/// precedence rules for semantic parity.
#[derive(Debug, Clone, Default)]
pub struct IndexedPolicy {
    rules: Vec<Rule>,
    buckets: BTreeMap<String, Vec<usize>>,
}

impl ReferencePolicy {
    pub fn new(configs: &[RuleConfig]) -> Result<Self, PolicyError> {
        if configs.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules { max: MAX_RULES });
        }
        let mut rules = Vec::with_capacity(configs.len());
        for config in configs {
            let canonical = normalize(&config.domain);
            if canonical.len() > MAX_DOMAIN_BYTES {
                return Err(PolicyError::DomainTooLong { id: config.id });
            }
            let wildcard = canonical.starts_with("*.");
            let domain = if wildcard {
                canonical[2..].to_owned()
            } else {
                canonical
            };
            if domain.is_empty() {
                return Err(PolicyError::EmptyDomain { id: config.id });
            }
            if wildcard && (domain.contains('*') || domain == ".") {
                return Err(PolicyError::InvalidWildcard {
                    id: config.id,
                    domain: config.domain.clone(),
                });
            }
            if rules.iter().any(|rule: &Rule| rule.id == config.id) {
                return Err(PolicyError::DuplicateRule { id: config.id });
            }
            if config.client.is_some()
                && (config.client_cidr.is_some() || !config.client_cidrs.is_empty())
            {
                return Err(PolicyError::InvalidClientCidr {
                    id: config.id,
                    value: config.client_cidr.clone().unwrap_or_default(),
                });
            }
            if config.client_cidr.is_some() && !config.client_cidrs.is_empty() {
                return Err(PolicyError::InvalidClientCidr {
                    id: config.id,
                    value: config.client_cidr.clone().unwrap_or_default(),
                });
            }
            if config.client_cidrs.len() > MAX_CLIENT_CIDRS {
                return Err(PolicyError::InvalidClientCidr {
                    id: config.id,
                    value: format!("more than {MAX_CLIENT_CIDRS} networks"),
                });
            }
            let mut client_networks = Vec::with_capacity(
                config.client_cidrs.len() + usize::from(config.client_cidr.is_some()),
            );
            if let Some(value) = config.client_cidr.as_deref() {
                client_networks.push(IpNetwork::parse(value).ok_or_else(|| {
                    PolicyError::InvalidClientCidr {
                        id: config.id,
                        value: value.to_owned(),
                    }
                })?);
            }
            for value in &config.client_cidrs {
                client_networks.push(IpNetwork::parse(value).ok_or_else(|| {
                    PolicyError::InvalidClientCidr {
                        id: config.id,
                        value: value.clone(),
                    }
                })?);
            }
            rules.push(Rule {
                id: config.id,
                domain,
                action: config.action,
                priority: config.priority,
                qtype: config.qtype,
                qclass: config.qclass,
                client: config.client,
                client_networks,
                wildcard,
            });
        }
        Ok(Self { rules })
    }

    #[must_use]
    pub fn compile_indexed(&self) -> IndexedPolicy {
        let mut buckets: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, rule) in self.rules.iter().enumerate() {
            buckets.entry(rule.domain.clone()).or_default().push(index);
        }
        IndexedPolicy {
            rules: self.rules.clone(),
            buckets,
        }
    }

    #[must_use]
    pub fn decide(&self, query: QueryContext<'_>) -> Option<Decision> {
        if query.name.len() > MAX_DOMAIN_BYTES {
            return None;
        }
        #[cfg(feature = "perf-instrument")]
        crate::perf::record_copy(crate::perf::Boundary::PolicyCanonicalize, query.name.len());
        let canonical_name = normalize(query.name);
        self.rules
            .iter()
            .filter(|rule| rule.matches(&canonical_name, query))
            .max_by_key(|rule| rule.precedence())
            .map(|rule| Decision {
                rule_id: rule.id,
                action: rule.action,
            })
    }

    #[cfg(feature = "std")]
    pub(crate) fn rule_ids(&self) -> alloc::collections::BTreeSet<u32> {
        self.rules.iter().map(|rule| rule.id).collect()
    }
}

impl IndexedPolicy {
    #[must_use]
    pub fn decide(&self, query: QueryContext<'_>) -> Option<Decision> {
        if query.name.len() > MAX_DOMAIN_BYTES {
            return None;
        }
        #[cfg(feature = "perf-instrument")]
        crate::perf::record_copy(crate::perf::Boundary::PolicyCanonicalize, query.name.len());
        let canonical_name = normalize(query.name);
        let mut candidates = Vec::new();
        let mut suffix = String::new();
        for label in canonical_name.rsplit('.') {
            if suffix.is_empty() {
                suffix.push_str(label);
            } else {
                suffix.insert(0, '.');
                suffix.insert_str(0, label);
            }
            if let Some(bucket) = self.buckets.get(&suffix) {
                candidates.extend(bucket.iter().copied());
            }
        }
        candidates
            .into_iter()
            .filter_map(|index| self.rules.get(index))
            .filter(|rule| rule.matches(&canonical_name, query))
            .max_by_key(|rule| rule.precedence())
            .map(|rule| Decision {
                rule_id: rule.id,
                action: rule.action,
            })
    }
}

impl Rule {
    fn matches(&self, name: &str, query: QueryContext<'_>) -> bool {
        let name_matches = if self.wildcard {
            name.len() > self.domain.len()
                && name.ends_with(&self.domain)
                && name.as_bytes()[name.len() - self.domain.len() - 1] == b'.'
        } else {
            name == self.domain
        };
        name_matches
            && self.qtype.is_none_or(|qtype| qtype == query.qtype)
            && self.qclass.is_none_or(|qclass| qclass == query.qclass)
            && self
                .client
                .is_none_or(|client| Some(client) == query.client)
            && (self.client_networks.is_empty()
                || query.client.is_some_and(|client| {
                    self.client_networks
                        .iter()
                        .any(|network| network.contains(client))
                }))
    }

    /// Precedence is a lexicographic contract.  Every independent selector
    /// gets its own component: a qtype selector must not accidentally tie
    /// with a qclass selector, and a deeper suffix must beat a shallower one.
    fn precedence(&self) -> (i32, u16, u16, u8, u8, u32) {
        (
            self.priority,
            self.domain_specificity(),
            self.client_specificity(),
            u8::from(self.qclass.is_some()),
            u8::from(self.qtype.is_some()),
            self.id,
        )
    }

    fn client_specificity(&self) -> u16 {
        if self.client.is_some() {
            129
        } else {
            self.client_networks
                .iter()
                .map(|network| u16::from(network.prefix))
                .max()
                .unwrap_or(0)
        }
    }

    fn domain_specificity(&self) -> u16 {
        // Exact rules are more specific than any descendant wildcard.  For
        // wildcards, the number of labels in the suffix makes nested
        // wildcards deterministic (`*.sub.example` beats `*.example`).
        let labels = self.domain.bytes().filter(|byte| *byte == b'.').count() as u16 + 1;
        if self.wildcard {
            labels
        } else {
            labels.saturating_add(1_000)
        }
    }
}

fn normalize(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, domain: &str, action: Action) -> RuleConfig {
        RuleConfig {
            id,
            domain: domain.into(),
            action,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
        }
    }

    fn query(name: &str) -> QueryContext<'_> {
        QueryContext {
            name,
            qtype: 1,
            qclass: 1,
            client: None,
        }
    }

    #[test]
    fn exact_wildcard_and_suffix_boundaries_are_distinct() {
        let rules = vec![
            rule(1, "ads.example", Action::Nxdomain),
            rule(2, "*.telemetry.example", Action::Ignore),
            rule(3, "telemetry.example", Action::Honeypot),
        ];
        let policy = ReferencePolicy::new(&rules).expect("valid rules");
        assert_eq!(
            policy.decide(query("ads.example.")),
            Some(Decision {
                rule_id: 1,
                action: Action::Nxdomain
            })
        );
        assert_eq!(policy.decide(query("x.ads.example.")), None);
        assert_eq!(
            policy.decide(query("telemetry.example.")),
            Some(Decision {
                rule_id: 3,
                action: Action::Honeypot
            })
        );
        assert_eq!(
            policy.decide(query("x.telemetry.example.")),
            Some(Decision {
                rule_id: 2,
                action: Action::Ignore
            })
        );
        assert_eq!(policy.decide(query("notexample.")), None);
    }

    #[test]
    fn filters_and_priority_are_deterministic() {
        let mut type_rule = rule(1, "example", Action::Drop);
        type_rule.qtype = Some(28);
        let mut client_rule = rule(2, "example", Action::Reject);
        client_rule.client = Some("192.0.2.2".parse().expect("address"));
        client_rule.priority = -1;
        let policy = ReferencePolicy::new(&[type_rule, client_rule]).expect("valid rules");
        assert_eq!(policy.decide(query("example")), None);
        assert_eq!(
            policy
                .decide(QueryContext {
                    qtype: 28,
                    ..query("example")
                })
                .map(|decision| decision.rule_id),
            Some(1)
        );
        assert_eq!(
            policy
                .decide(QueryContext {
                    qtype: 28,
                    client: Some("192.0.2.2".parse().expect("address")),
                    ..query("example")
                })
                .map(|decision| decision.rule_id),
            Some(1)
        );
    }

    #[test]
    fn one_rule_can_cover_multiple_client_networks() {
        let mut rule = rule(3, "service.example", Action::Reject);
        rule.client_cidrs = vec!["192.0.2.0/24".into(), "2001:db8::/32".into()];
        let policy = ReferencePolicy::new(&[rule]).expect("valid client networks");
        assert_eq!(
            policy.decide(QueryContext {
                client: Some("192.0.2.44".parse().expect("IPv4 client")),
                ..query("service.example")
            }),
            Some(Decision {
                rule_id: 3,
                action: Action::Reject,
            })
        );
        assert!(
            policy
                .decide(QueryContext {
                    client: Some("198.51.100.44".parse().expect("outside client")),
                    ..query("service.example")
                })
                .is_none()
        );
        assert!(
            policy
                .decide(QueryContext {
                    client: Some("2001:db8::44".parse().expect("IPv6 client")),
                    ..query("service.example")
                })
                .is_some()
        );
    }

    #[test]
    fn narrower_client_network_wins_and_network_limits_fail_closed() {
        let mut broad = rule(4, "service.example", Action::Pass);
        broad.client_cidr = Some("192.0.2.0/24".into());
        let mut narrow = rule(5, "service.example", Action::Reject);
        narrow.client_cidrs = vec!["192.0.2.0/28".into(), "198.51.100.0/24".into()];
        let policy = ReferencePolicy::new(&[broad, narrow]).expect("valid networks");
        assert_eq!(
            policy
                .decide(QueryContext {
                    client: Some("192.0.2.8".parse().expect("narrow client")),
                    ..query("service.example")
                })
                .map(|decision| decision.rule_id),
            Some(5)
        );

        let mut mixed = rule(6, "service.example", Action::Drop);
        mixed.client_cidr = Some("192.0.2.0/24".into());
        mixed.client_cidrs = vec!["198.51.100.0/24".into()];
        assert!(matches!(
            ReferencePolicy::new(&[mixed]),
            Err(PolicyError::InvalidClientCidr { id: 6, .. })
        ));

        let mut too_many = rule(7, "service.example", Action::Drop);
        too_many.client_cidrs = (0..=MAX_CLIENT_CIDRS)
            .map(|_| "192.0.2.0/24".into())
            .collect();
        assert!(matches!(
            ReferencePolicy::new(&[too_many]),
            Err(PolicyError::InvalidClientCidr { id: 7, .. })
        ));
    }

    #[test]
    fn duplicate_ids_and_invalid_wildcards_are_rejected() {
        let duplicate = [
            rule(1, "a.example", Action::Drop),
            rule(1, "b.example", Action::Drop),
        ];
        assert!(matches!(
            ReferencePolicy::new(&duplicate),
            Err(PolicyError::DuplicateRule { id: 1 })
        ));
        let invalid = [rule(2, "*.*.example", Action::Drop)];
        assert!(matches!(
            ReferencePolicy::new(&invalid),
            Err(PolicyError::InvalidWildcard { .. })
        ));
    }

    #[test]
    fn hostile_rule_sizes_are_rejected_before_indexing() {
        let too_long = [rule(1, &"a".repeat(MAX_DOMAIN_BYTES + 1), Action::Drop)];
        assert!(matches!(
            ReferencePolicy::new(&too_long),
            Err(PolicyError::DomainTooLong { id: 1 })
        ));
        let too_many = vec![rule(1, "example", Action::Drop); MAX_RULES + 1];
        assert!(matches!(
            ReferencePolicy::new(&too_many),
            Err(PolicyError::TooManyRules { max: MAX_RULES })
        ));
    }

    #[test]
    fn overlong_queries_cannot_match_a_rule() {
        let policy = ReferencePolicy::new(&[rule(1, "example", Action::Drop)]).unwrap();
        assert_eq!(
            policy.decide(query(&"a".repeat(MAX_DOMAIN_BYTES + 1))),
            None
        );
    }

    #[test]
    fn indexed_candidate_matches_reference_for_fixed_proof() {
        let rules = vec![
            rule(1, "ads.example", Action::Nxdomain),
            rule(2, "*.telemetry.example", Action::Ignore),
            rule(3, "telemetry.example", Action::Honeypot),
        ];
        let reference = ReferencePolicy::new(&rules).expect("valid rules");
        let indexed = reference.compile_indexed();
        for name in [
            "ads.example.",
            "x.ads.example.",
            "telemetry.example.",
            "x.telemetry.example.",
            "notexample.",
        ] {
            assert_eq!(indexed.decide(query(name)), reference.decide(query(name)));
        }
    }

    #[test]
    fn deeper_wildcards_beat_shallower_wildcards() {
        let mut shallow = rule(1, "*.example", Action::Drop);
        shallow.priority = 10;
        let mut deep = rule(2, "*.sub.example", Action::Reject);
        deep.priority = 10;
        let policy = ReferencePolicy::new(&[shallow, deep]).unwrap();
        assert_eq!(policy.decide(query("x.sub.example")).unwrap().rule_id, 2);
    }

    #[test]
    fn exact_name_beats_a_matching_suffix_at_equal_priority() {
        let suffix = rule(1, "*.example", Action::Drop);
        let exact = rule(2, "host.example", Action::Reject);
        let policy = ReferencePolicy::new(&[suffix, exact]).unwrap();
        assert_eq!(policy.decide(query("host.example")).unwrap().rule_id, 2);
    }

    #[test]
    fn qtype_and_qclass_are_ranked_independently() {
        let mut qtype = rule(1, "example", Action::Drop);
        qtype.qtype = Some(28);
        let mut qclass = rule(2, "example", Action::Reject);
        qclass.qclass = Some(3);
        let mut both = rule(3, "example", Action::Nxdomain);
        both.qtype = Some(28);
        both.qclass = Some(3);
        let policy = ReferencePolicy::new(&[qtype, qclass, both]).unwrap();
        assert_eq!(
            policy
                .decide(QueryContext {
                    name: "example",
                    qtype: 28,
                    qclass: 3,
                    client: None
                })
                .unwrap()
                .rule_id,
            3
        );
        assert_eq!(
            policy
                .decide(QueryContext {
                    name: "example",
                    qtype: 28,
                    qclass: 1,
                    client: None
                })
                .unwrap()
                .rule_id,
            1
        );
        assert_eq!(
            policy
                .decide(QueryContext {
                    name: "example",
                    qtype: 1,
                    qclass: 3,
                    client: None
                })
                .unwrap()
                .rule_id,
            2
        );
    }

    #[test]
    fn cidr_scopes_match_only_members_and_rank_by_prefix() {
        let mut broad = rule(1, "example", Action::Drop);
        broad.client_cidr = Some("192.0.2.0/24".into());
        let mut narrow = rule(2, "example", Action::Reject);
        narrow.client_cidr = Some("192.0.2.128/25".into());
        let policy = ReferencePolicy::new(&[broad, narrow]).unwrap();

        assert_eq!(
            policy
                .decide(QueryContext {
                    client: Some("192.0.2.200".parse().unwrap()),
                    ..query("example")
                })
                .unwrap()
                .rule_id,
            2
        );
        assert_eq!(
            policy
                .decide(QueryContext {
                    client: Some("192.0.2.20".parse().unwrap()),
                    ..query("example")
                })
                .unwrap()
                .rule_id,
            1
        );
        assert_eq!(
            policy.decide(QueryContext {
                client: Some("198.51.100.20".parse().unwrap()),
                ..query("example")
            }),
            None
        );
    }

    #[test]
    fn exact_client_scope_beats_cidr_scope() {
        let mut network = rule(1, "example", Action::Drop);
        network.client_cidr = Some("192.0.2.0/24".into());
        let mut exact = rule(2, "example", Action::Reject);
        exact.client = Some("192.0.2.10".parse().unwrap());
        let policy = ReferencePolicy::new(&[network, exact]).unwrap();
        assert_eq!(
            policy
                .decide(QueryContext {
                    client: Some("192.0.2.10".parse().unwrap()),
                    ..query("example")
                })
                .unwrap()
                .rule_id,
            2
        );
    }

    #[test]
    fn invalid_client_scopes_are_rejected() {
        let mut invalid = rule(1, "example", Action::Drop);
        invalid.client_cidr = Some("192.0.2.0/33".into());
        assert!(matches!(
            ReferencePolicy::new(&[invalid]),
            Err(PolicyError::InvalidClientCidr { id: 1, .. })
        ));

        let mut ambiguous = rule(2, "example", Action::Drop);
        ambiguous.client = Some("192.0.2.10".parse().unwrap());
        ambiguous.client_cidr = Some("192.0.2.0/24".into());
        assert!(matches!(
            ReferencePolicy::new(&[ambiguous]),
            Err(PolicyError::InvalidClientCidr { id: 2, .. })
        ));
    }
}
