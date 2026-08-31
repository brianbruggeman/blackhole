//! Policy and configuration for the Blackhole DNS sinkhole.
//!
//! ```
//! let config = blackhole::Config::default();
//! assert_eq!(config.server.listen, "127.0.0.1:5353");
//! ```

use proxima::{Labels, TelemetryHandle};
use proxima_core::ProximaError;
use proxima_dns::{DnsAnswer, DnsAnswerRecord, DnsClientUpstream, DnsPipeReply, DnsPipeRequest};
use proxima_primitives::pipe::SendPipe;
use proxima_primitives::stream::DatagramFactory;
use proxima_primitives::sync::Semaphore;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub mod fsm;
pub mod linux_capture;
pub mod listener;
pub mod pf_capture;
pub mod policy;
pub mod query;
pub mod snapshot;
pub use policy::{Action, RuleConfig};
use policy::{QueryContext, ReferencePolicy};
use query::QueryView;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub honeypot: HoneypotConfig,
    #[serde(default)]
    pub upstream: Option<UpstreamConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_resolver_ip")]
    pub resolver_ip: String,
    #[serde(default = "default_resolver_port")]
    pub port: u16,
    #[serde(default = "default_query_timeout_ms")]
    pub query_timeout_ms: u64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_max_outstanding")]
    pub max_outstanding: usize,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            resolver_ip: default_resolver_ip(),
            port: default_resolver_port(),
            query_timeout_ms: default_query_timeout_ms(),
            max_attempts: default_max_attempts(),
            max_outstanding: default_max_outstanding(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default = "default_action")]
    pub default_action: Action,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            domains: Vec::new(),
            rules: Vec::new(),
            default_action: default_action(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HoneypotConfig {
    #[serde(default = "default_ipv4")]
    pub ipv4: Ipv4Addr,
    #[serde(default = "default_ipv6")]
    pub ipv6: Ipv6Addr,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}
impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            ipv4: default_ipv4(),
            ipv6: default_ipv6(),
            ttl: default_ttl(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Ignore,
    Nxdomain,
    Honeypot,
}
fn default_listen() -> String {
    "127.0.0.1:5353".into()
}
fn default_mode() -> Mode {
    Mode::Nxdomain
}
fn default_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}
fn default_ipv6() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
}
fn default_ttl() -> u32 {
    60
}
fn default_action() -> Action {
    Action::Pass
}
fn default_resolver_ip() -> String {
    "1.1.1.1".into()
}
fn default_resolver_port() -> u16 {
    53
}
fn default_query_timeout_ms() -> u64 {
    2_000
}
fn default_max_attempts() -> u32 {
    2
}
fn default_max_outstanding() -> usize {
    64
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 1_048_576 {
            return Err("configuration exceeds 1 MiB".into());
        }
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }
}

pub struct Policy {
    config: Config,
    reference: ReferencePolicy,
    telemetry: Option<TelemetryHandle>,
    upstream: Option<DnsClientUpstream>,
    upstream_slots: Option<Arc<Semaphore>>,
}

impl Policy {
    pub fn new(mut config: Config) -> Result<Self, policy::PolicyError> {
        config.policy.domains = config.policy.domains.into_iter().map(normalize).collect();
        let reference = ReferencePolicy::new(&config.policy.rules)?;
        let policy = Self {
            config,
            reference,
            telemetry: None,
            upstream: None,
            upstream_slots: None,
        };
        if let Some(upstream) = policy.config.upstream.as_ref() {
            policy.validate_upstream(upstream)?;
        }
        Ok(policy)
    }

    #[must_use]
    pub fn with_telemetry(mut self, telemetry: TelemetryHandle) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Attach Proxima's existing bounded DNS upstream pipe. Forwarding is
    /// deliberately opt-in; a `Forward` rule without an attached upstream is
    /// fail-closed at the transport edge.
    #[must_use]
    pub fn with_upstream(
        mut self,
        factory: std::sync::Arc<dyn DatagramFactory>,
        config: proxima_dns::DnsResolverConfig,
        max_outstanding: usize,
    ) -> Self {
        self.upstream = Some(DnsClientUpstream::new(factory, config));
        self.upstream_slots = Some(Arc::new(Semaphore::new(max_outstanding.max(1))));
        self
    }

    fn validate_upstream(&self, upstream: &UpstreamConfig) -> Result<(), policy::PolicyError> {
        let resolver_ip = upstream
            .resolver_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| policy::PolicyError::InvalidUpstream {
                reason: "resolver_ip must be an IP address literal".into(),
            })?;
        if upstream.port == 0 {
            return Err(policy::PolicyError::InvalidUpstream {
                reason: "port must be non-zero".into(),
            });
        }
        if upstream.query_timeout_ms == 0 {
            return Err(policy::PolicyError::InvalidUpstream {
                reason: "query_timeout_ms must be non-zero".into(),
            });
        }
        if upstream.max_attempts == 0 || upstream.max_outstanding == 0 {
            return Err(policy::PolicyError::InvalidUpstream {
                reason: "max_attempts and max_outstanding must be non-zero".into(),
            });
        }
        let broadcast = matches!(resolver_ip, std::net::IpAddr::V4(ip) if ip.is_broadcast());
        if resolver_ip.is_unspecified() || resolver_ip.is_multicast() || broadcast {
            return Err(policy::PolicyError::InvalidUpstream {
                reason: "resolver must not be unspecified or multicast".into(),
            });
        }
        let resolver = std::net::SocketAddr::new(resolver_ip, upstream.port);
        let listener = self
            .config
            .server
            .listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| policy::PolicyError::InvalidUpstream {
                reason: "server.listen must be a socket address before configuring upstream".into(),
            })?;
        if resolver == listener {
            return Err(policy::PolicyError::InvalidUpstream {
                reason: "upstream must not equal server.listen".into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn resolver_config(upstream: &UpstreamConfig) -> proxima_dns::DnsResolverConfig {
        proxima_dns::DnsResolverConfig {
            resolver_ip: upstream.resolver_ip.clone(),
            port: upstream.port,
            query_timeout_ms: upstream.query_timeout_ms,
            max_attempts: upstream.max_attempts,
        }
    }

    fn decision(&self, query: &proxima_dns::DnsQuery) -> Option<policy::Decision> {
        self.reference.decide(QueryContext {
            name: &query.name,
            qtype: query.qtype,
            qclass: query.qclass,
            client: None,
        })
    }

    /// Return the authoritative action for a validated borrowed query view.
    /// The wire adapter calls this before materializing the owned Proxima DNS
    /// request, so configured rules remain authoritative at the raw boundary.
    #[must_use]
    pub fn action_for_view(&self, query: QueryView<'_>) -> Action {
        let name = query.name.to_dotted();
        if self.config.policy.rules.is_empty() {
            if !self.matches(&name) {
                return Action::Pass;
            }
            return match self.config.policy.mode {
                Mode::Ignore => Action::Ignore,
                Mode::Nxdomain => Action::Nxdomain,
                Mode::Honeypot => Action::Honeypot,
            };
        }
        self.reference
            .decide(QueryContext {
                name: &name,
                qtype: query.qtype,
                qclass: query.qclass,
                client: None,
            })
            .map_or(self.config.policy.default_action, |decision| {
                decision.action
            })
    }
    fn matches(&self, name: &str) -> bool {
        let name = normalize(name);
        self.config.policy.domains.iter().any(|domain| {
            name == *domain
                || (name.len() > domain.len()
                    && name.ends_with(domain)
                    && name.as_bytes()[name.len() - domain.len() - 1] == b'.')
        })
    }

    pub fn evaluate(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
        let decision = self.decision(query);
        if self.config.policy.rules.is_empty() {
            return self.evaluate_legacy(query);
        }
        match decision
            .map(|decision| decision.action)
            .or(Some(self.config.policy.default_action))
        {
            Some(Action::Ignore | Action::Drop | Action::Forward | Action::Honeypot) => None,
            Some(Action::Nxdomain) => Some(DnsAnswer::name_error()),
            Some(Action::Reject) => Some(DnsAnswer::name_error()),
            Some(Action::Sink) => Some(honeypot(&query.name, query.qtype, &self.config.honeypot)),
            Some(Action::Pass | Action::Observe) | None => Some(DnsAnswer::ok(Vec::new())),
        }
    }

    fn evaluate_legacy(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
        if !self.matches(&query.name) {
            return Some(DnsAnswer::ok(Vec::new()));
        }
        match self.config.policy.mode {
            Mode::Ignore => None,
            Mode::Nxdomain => Some(DnsAnswer::name_error()),
            Mode::Honeypot => Some(honeypot(&query.name, query.qtype, &self.config.honeypot)),
        }
    }

    fn observe(&self, action: Action) {
        let Some(telemetry) = self.telemetry.as_ref() else {
            return;
        };
        if !telemetry.is_active() {
            return;
        }
        let labels = Labels::from_pairs(&[("action", action_label(action))]);
        telemetry.counter_inc("blackhole.decisions", &labels, 1);
    }
}

impl SendPipe for Policy {
    type In = DnsPipeRequest;
    type Out = DnsPipeReply;
    type Err = ProximaError;
    async fn call(&self, request: Self::In) -> Result<Self::Out, ProximaError> {
        let query = request.payload;
        // Decide exactly once.  In particular, do not run the rule table to
        // discover forwarding and then run it again to render the outcome.
        let decision = self.decision(&query);
        let action = if self.config.policy.rules.is_empty() {
            None
        } else {
            Some(
                decision.map_or(self.config.policy.default_action, |decision| {
                    decision.action
                }),
            )
        };
        if action == Some(Action::Forward) {
            let Some(slots) = self.upstream_slots.as_ref() else {
                self.observe(Action::Forward);
                return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
            };
            let Ok(_slot) = slots.try_acquire() else {
                self.observe(Action::Forward);
                return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
            };
            let Some(upstream) = self.upstream.as_ref() else {
                self.observe(Action::Forward);
                return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
            };
            let answer = upstream
                .query(&query.name, query.qtype, query.qclass)
                .await
                .map_err(|error| {
                    self.observe(Action::Forward);
                    ProximaError::Io(std::io::Error::other(error.to_string()))
                })?;
            self.observe(Action::Forward);
            return Ok(DnsPipeReply::typed(200, answer));
        }
        let outcome = if self.config.policy.rules.is_empty() {
            self.evaluate_legacy(&query)
        } else {
            match action {
                Some(Action::Ignore | Action::Drop) => None,
                Some(Action::Nxdomain | Action::Reject) => Some(DnsAnswer::name_error()),
                Some(Action::Honeypot) => None,
                Some(Action::Sink) => {
                    Some(honeypot(&query.name, query.qtype, &self.config.honeypot))
                }
                Some(Action::Pass | Action::Observe) | None => Some(DnsAnswer::ok(Vec::new())),
                Some(Action::Forward) => unreachable!("forwarding handled above"),
            }
        };
        self.observe(action.unwrap_or(Action::Pass));
        match outcome {
            Some(answer) => Ok(DnsPipeReply::typed(200, answer)),
            // Compatibility mapping only: semantic policy results are typed;
            // the current owned DNS facade has no silent-response variant.
            None => Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new()))),
        }
    }
}

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Pass => "pass",
        Action::Ignore => "ignore",
        Action::Drop => "drop",
        Action::Reject => "reject",
        Action::Nxdomain => "nxdomain",
        Action::Sink => "sink",
        Action::Honeypot => "honeypot",
        Action::Forward => "forward",
        Action::Observe => "observe",
    }
}

fn honeypot(name: &str, qtype: u16, config: &HoneypotConfig) -> DnsAnswer {
    let record = match qtype {
        1 => Some(DnsAnswerRecord {
            name: name.into(),
            rtype: 1,
            rclass: 1,
            ttl: config.ttl,
            rdata: proxima_protocols::dns::encode::ipv4_rdata(config.ipv4).to_vec(),
        }),
        28 => Some(DnsAnswerRecord {
            name: name.into(),
            rtype: 28,
            rclass: 1,
            ttl: config.ttl,
            rdata: proxima_protocols::dns::encode::ipv6_rdata(config.ipv6).to_vec(),
        }),
        _ => None,
    };
    DnsAnswer::ok(record.into_iter().collect())
}
fn normalize(value: impl AsRef<str>) -> String {
    value.as_ref().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProofAction {
        Ignore,
        Nxdomain,
        Honeypot,
        Pass,
    }

    struct ProofRule {
        pattern: &'static str,
        action: ProofAction,
    }

    fn proof_matches(pattern: &str, query: &str) -> bool {
        let pattern = normalize(pattern);
        let query = normalize(query);
        match pattern.strip_prefix("*.") {
            Some(suffix) => {
                query.ends_with(suffix)
                    && query.len() > suffix.len()
                    && query.as_bytes()[query.len() - suffix.len() - 1] == b'.'
            }
            None => query == pattern,
        }
    }

    fn proof_decide(query: &str, rules: &[ProofRule]) -> ProofAction {
        rules
            .iter()
            .find(|rule| proof_matches(rule.pattern, query))
            .map(|rule| rule.action)
            .unwrap_or(ProofAction::Pass)
    }

    #[test]
    fn policy_proof_preserves_apex_and_wildcard_boundaries() {
        let rules = [
            ProofRule {
                pattern: "ads.example",
                action: ProofAction::Nxdomain,
            },
            ProofRule {
                pattern: "*.telemetry.example",
                action: ProofAction::Ignore,
            },
            ProofRule {
                pattern: "telemetry.example",
                action: ProofAction::Honeypot,
            },
        ];

        let cases = [
            ("ads.example.", ProofAction::Nxdomain),
            ("x.ads.example.", ProofAction::Pass),
            ("telemetry.example.", ProofAction::Honeypot),
            ("x.telemetry.example.", ProofAction::Ignore),
            ("notexample.", ProofAction::Pass),
        ];

        for (query, expected) in cases {
            assert_eq!(proof_decide(query, &rules), expected, "query={query}");
        }
    }

    #[test]
    fn suffix_matching_is_case_insensitive_and_boundary_safe() {
        let mut config = Config::default();
        config.policy.domains = vec!["Example.COM".into()];
        let policy = Policy::new(config).expect("valid default policy");
        assert!(policy.matches("x.example.com."));
        assert!(!policy.matches("notexample.com."));
    }
    #[test]
    fn default_config_is_safe_for_local_testing() {
        assert_eq!(Config::default().server.listen, "127.0.0.1:5353");
    }

    #[test]
    fn typed_drop_maps_to_no_udp_datagram_and_no_tcp_message() {
        let mut config = Config::default();
        config.policy.mode = Mode::Ignore;
        config.policy.domains = vec!["blocked.example".into()];
        let policy = Policy::new(config).expect("valid policy");
        let query = proxima_dns::DnsQuery {
            id: 7,
            recursion_desired: true,
            name: "blocked.example.".into(),
            qtype: 1,
            qclass: 1,
        };
        let outcome = policy.evaluate(&query);
        assert!(outcome.is_none());
    }

    #[test]
    fn forwarding_without_an_upstream_is_fail_closed() {
        let mut config = Config::default();
        config.policy.rules = vec![RuleConfig {
            id: 1,
            domain: "forward.example".into(),
            action: Action::Forward,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
        }];
        let policy = Policy::new(config).expect("valid policy");
        let query = proxima_dns::DnsQuery {
            id: 9,
            recursion_desired: true,
            name: "forward.example.".into(),
            qtype: 1,
            qclass: 1,
        };
        assert_eq!(
            policy.decision(&query).map(|decision| decision.action),
            Some(Action::Forward)
        );
        assert!(policy.evaluate(&query).is_none());
        assert!(policy.upstream.is_none());
    }

    #[test]
    fn upstream_configuration_is_validated_before_listener_use() {
        let config = Config {
            upstream: Some(UpstreamConfig {
                resolver_ip: "255.255.255.255".into(),
                ..UpstreamConfig::default()
            }),
            ..Config::default()
        };
        assert!(matches!(
            Policy::new(config),
            Err(policy::PolicyError::InvalidUpstream { .. })
        ));

        let config = Config {
            upstream: Some(UpstreamConfig {
                resolver_ip: "127.0.0.1".into(),
                port: 5353,
                ..UpstreamConfig::default()
            }),
            ..Config::default()
        };
        assert!(matches!(
            Policy::new(config),
            Err(policy::PolicyError::InvalidUpstream { .. })
        ));
    }

    #[test]
    fn configured_rules_are_authoritative_over_legacy_domains_and_mode() {
        let mut config = Config::default();
        config.policy.mode = Mode::Nxdomain;
        config.policy.domains = vec!["legacy.example".into()];
        config.policy.rules = vec![RuleConfig {
            id: 1,
            domain: "ruled.example".into(),
            action: Action::Drop,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
        }];
        let policy = Policy::new(config).unwrap();
        let query = |name: &str| proxima_dns::DnsQuery {
            id: 1,
            recursion_desired: true,
            name: name.into(),
            qtype: 1,
            qclass: 1,
        };
        assert!(policy.evaluate(&query("ruled.example")).is_none());
        assert!(policy.evaluate(&query("legacy.example")).is_some());
    }

    #[test]
    fn borrowed_view_uses_the_same_authoritative_rule_action() {
        let mut config = Config::default();
        config.policy.default_action = Action::Pass;
        config.policy.rules = vec![RuleConfig {
            id: 1,
            domain: "blocked.example".into(),
            action: Action::Reject,
            priority: 0,
            qtype: Some(1),
            qclass: None,
            client: None,
        }];
        let policy = Policy::new(config).expect("valid policy");
        let packet = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'b', b'l', b'o', b'c', b'k', b'e', b'd', 7,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
        ];
        let view = QueryView::parse(&packet).expect("valid query");
        assert_eq!(policy.action_for_view(view), Action::Reject);
        assert_eq!(view.to_owned().name, "blocked.example.");
    }

    #[test]
    fn telemetry_observes_without_changing_the_policy_output() {
        use proxima::Telemetry;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CounterTelemetry {
            calls: AtomicU64,
        }

        impl Telemetry for CounterTelemetry {
            fn counter_inc(&self, _metric: &str, labels: &Labels, by: u64) {
                assert_eq!(labels.entries().len(), 1);
                assert_eq!(labels.entries()[0].0, "action");
                assert_eq!(labels.entries()[0].1, "drop");
                self.calls.fetch_add(by, Ordering::Relaxed);
            }
            fn gauge_set(&self, _metric: &str, _labels: &Labels, _value: i64) {}
            fn histogram_record(&self, _metric: &str, _labels: &Labels, _value: f64) {}
        }

        let telemetry = Arc::new(CounterTelemetry {
            calls: AtomicU64::new(0),
        });
        let mut config = Config::default();
        config.policy.mode = Mode::Ignore;
        config.policy.domains = vec!["blocked.example".into()];
        let policy = Policy::new(config)
            .expect("valid policy")
            .with_telemetry(telemetry.clone());
        let query = proxima_dns::DnsQuery {
            id: 7,
            recursion_desired: true,
            name: "blocked.example.".into(),
            qtype: 1,
            qclass: 1,
        };
        let outcome = policy.evaluate(&query);
        policy.observe(Action::Drop);
        assert!(outcome.is_none());
        assert_eq!(telemetry.calls.load(Ordering::Relaxed), 1);
    }
}
