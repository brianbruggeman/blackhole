//! Policy and configuration for the Blackhole DNS sinkhole.
//!
//! ```
//! let config = blackhole::Config::default();
//! assert_eq!(config.server.listen, "127.0.0.1:5353");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod fsm;
pub mod policy;
pub mod query;
pub use policy::{Action, RuleConfig};

#[cfg(feature = "std")]
pub mod linux_capture;
#[cfg(feature = "std")]
pub mod listener;
#[cfg(feature = "perf-instrument")]
pub mod perf;
#[cfg(feature = "std")]
pub mod pf_capture;
#[cfg(feature = "std")]
pub mod snapshot;

#[cfg(feature = "std")]
mod runtime {
    use proxima::{Labels, TelemetryHandle};
    use proxima_core::ProximaError;
    use proxima_dns::{
        DnsAnswer, DnsAnswerRecord, DnsClientUpstream, DnsPipeReply, DnsPipeRequest,
    };
    use proxima_primitives::pipe::SendPipe;
    use proxima_primitives::pipe::endpoint::PeerInfo;
    use proxima_primitives::stream::DatagramFactory;
    use proxima_primitives::sync::Semaphore;
    use serde::Deserialize;
    use std::collections::{BTreeSet, HashMap};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::policy;
    use crate::policy::QueryContext;
    use crate::query::QueryView;
    use crate::snapshot::{PolicyStore, ReloadState};
    use crate::{Action, RuleConfig};

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
        #[serde(default)]
        pub cache: CacheConfig,
        #[serde(default)]
        pub admission: AdmissionConfig,
        #[serde(default)]
        pub security: SecurityConfig,
        #[serde(default)]
        pub capture: CaptureConfig,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CacheConfig {
        #[serde(default = "default_cache_entries")]
        pub max_entries: usize,
        #[serde(default = "default_stale_ttl_secs")]
        pub stale_ttl_secs: u64,
        #[serde(default = "default_negative_ttl_secs")]
        pub negative_ttl_secs: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct CacheKey {
        name: String,
        qtype: u16,
        qclass: u16,
    }

    impl CacheKey {
        fn from_query(query: &proxima_dns::DnsQuery) -> Self {
            Self {
                name: normalize(&query.name),
                qtype: query.qtype,
                qclass: query.qclass,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct CacheEntry {
        answer: DnsAnswer,
        expires_at: Instant,
        stale_until: Instant,
    }

    #[derive(Debug)]
    struct DnsCache {
        entries: HashMap<CacheKey, CacheEntry>,
        config: CacheConfig,
    }

    impl DnsCache {
        fn new(config: &CacheConfig) -> Self {
            Self {
                entries: HashMap::new(),
                config: config.clone(),
            }
        }

        fn fresh(&mut self, key: &CacheKey) -> Option<DnsAnswer> {
            let now = Instant::now();
            let entry = self.entries.get(key)?;
            if now < entry.expires_at {
                return Some(entry.answer.clone());
            }
            None
        }

        fn stale(&mut self, key: &CacheKey) -> Option<DnsAnswer> {
            let now = Instant::now();
            let entry = self.entries.get(key)?;
            if now < entry.stale_until {
                return Some(entry.answer.clone());
            }
            self.entries.remove(key);
            None
        }

        fn insert(&mut self, key: CacheKey, answer: DnsAnswer, now: Instant) {
            if self.config.max_entries == 0 {
                return;
            }
            if self.entries.len() >= self.config.max_entries && !self.entries.contains_key(&key) {
                if let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(key, _)| key.clone())
                {
                    self.entries.remove(&oldest);
                }
            }
            let ttl_secs = answer
                .records
                .iter()
                .map(|record| u64::from(record.ttl))
                .min()
                .unwrap_or(self.config.negative_ttl_secs);
            let ttl = Duration::from_secs(ttl_secs);
            let stale = Duration::from_secs(self.config.stale_ttl_secs);
            self.entries.insert(
                key,
                CacheEntry {
                    answer,
                    expires_at: now + ttl,
                    stale_until: now + ttl + stale,
                },
            );
        }
    }

    #[derive(Debug, Clone)]
    struct CircuitBreaker {
        threshold: u32,
        cooldown: Duration,
        failures: u32,
        open_until: Option<Instant>,
    }

    impl CircuitBreaker {
        fn new(threshold: u32, cooldown_secs: u64) -> Self {
            Self {
                threshold: threshold.max(1),
                cooldown: Duration::from_secs(cooldown_secs.max(1)),
                failures: 0,
                open_until: None,
            }
        }

        fn allows(&mut self, now: Instant) -> bool {
            match self.open_until {
                Some(until) if now < until => false,
                Some(_) => {
                    self.open_until = None;
                    self.failures = 0;
                    true
                }
                None => true,
            }
        }

        fn success(&mut self) {
            self.failures = 0;
            self.open_until = None;
        }

        fn failure(&mut self, now: Instant) {
            self.failures = self.failures.saturating_add(1);
            if self.failures >= self.threshold {
                self.open_until = Some(now + self.cooldown);
            }
        }
    }

    impl Default for CacheConfig {
        fn default() -> Self {
            Self {
                max_entries: default_cache_entries(),
                stale_ttl_secs: default_stale_ttl_secs(),
                negative_ttl_secs: default_negative_ttl_secs(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct AdmissionConfig {
        #[serde(default = "default_max_name_bytes")]
        pub max_name_bytes: usize,
        #[serde(default = "default_reject_any")]
        pub reject_any: bool,
        #[serde(default = "default_max_response_records")]
        pub max_response_records: usize,
        #[serde(default = "default_max_response_bytes")]
        pub max_response_bytes: usize,
        #[serde(default = "default_max_inflight_requests")]
        pub max_inflight_requests: usize,
    }

    impl Default for AdmissionConfig {
        fn default() -> Self {
            Self {
                max_name_bytes: default_max_name_bytes(),
                reject_any: default_reject_any(),
                max_response_records: default_max_response_records(),
                max_response_bytes: default_max_response_bytes(),
                max_inflight_requests: default_max_inflight_requests(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct SecurityConfig {
        #[serde(default = "default_reject_private_upstream_addresses")]
        pub reject_private_upstream_addresses: bool,
    }

    impl Default for SecurityConfig {
        fn default() -> Self {
            Self {
                reject_private_upstream_addresses: default_reject_private_upstream_addresses(),
            }
        }
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
        #[serde(default = "default_breaker_failures")]
        pub breaker_failures: u32,
        #[serde(default = "default_breaker_cooldown_secs")]
        pub breaker_cooldown_secs: u64,
    }

    impl Default for UpstreamConfig {
        fn default() -> Self {
            Self {
                resolver_ip: default_resolver_ip(),
                port: default_resolver_port(),
                query_timeout_ms: default_query_timeout_ms(),
                max_attempts: default_max_attempts(),
                max_outstanding: default_max_outstanding(),
                breaker_failures: default_breaker_failures(),
                breaker_cooldown_secs: default_breaker_cooldown_secs(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct ServerConfig {
        #[serde(default = "default_listen")]
        pub listen: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CaptureConfig {
        #[serde(default)]
        pub enabled: bool,
        #[serde(default = "default_capture_inbound_port")]
        pub inbound_port: u16,
        #[serde(default = "default_capture_chain")]
        pub chain: String,
        #[serde(default = "default_capture_mark")]
        pub mark: u32,
        #[serde(default = "default_capture_ownership_path")]
        pub ownership_path: String,
        #[serde(default = "default_capture_original_destination")]
        pub original_destination: String,
    }

    impl Default for CaptureConfig {
        fn default() -> Self {
            Self {
                enabled: false,
                inbound_port: default_capture_inbound_port(),
                chain: default_capture_chain(),
                mark: default_capture_mark(),
                ownership_path: default_capture_ownership_path(),
                original_destination: default_capture_original_destination(),
            }
        }
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
        #[serde(default)]
        pub blocklists: Vec<String>,
        #[serde(default = "default_action")]
        pub default_action: Action,
    }
    impl Default for PolicyConfig {
        fn default() -> Self {
            Self {
                mode: default_mode(),
                domains: Vec::new(),
                rules: Vec::new(),
                blocklists: Vec::new(),
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
    fn default_capture_inbound_port() -> u16 {
        53
    }
    fn default_capture_chain() -> String {
        "capture".into()
    }
    fn default_capture_mark() -> u32 {
        42
    }
    fn default_capture_ownership_path() -> String {
        "/var/lib/blackhole/capture.state".into()
    }
    fn default_capture_original_destination() -> String {
        "127.0.0.1:53".into()
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
    fn default_cache_entries() -> usize {
        1024
    }
    fn default_stale_ttl_secs() -> u64 {
        30
    }
    fn default_negative_ttl_secs() -> u64 {
        30
    }
    fn default_max_name_bytes() -> usize {
        253
    }
    fn default_reject_any() -> bool {
        true
    }
    fn default_max_response_records() -> usize {
        64
    }
    fn default_max_response_bytes() -> usize {
        4096
    }
    fn default_reject_private_upstream_addresses() -> bool {
        true
    }
    fn default_max_inflight_requests() -> usize {
        1024
    }
    const MAX_BLOCKLIST_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_BLOCKLIST_LINE_BYTES: usize = 4096;

    fn load_blocklists(paths: &[String]) -> Result<Vec<RuleConfig>, policy::PolicyError> {
        let mut domains = BTreeSet::new();
        for path in paths {
            let metadata =
                std::fs::metadata(path).map_err(|error| policy::PolicyError::InvalidBlocklist {
                    path: path.clone(),
                    reason: error.to_string(),
                })?;
            if metadata.len() > MAX_BLOCKLIST_BYTES {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: path.clone(),
                    reason: format!("file exceeds {MAX_BLOCKLIST_BYTES} bytes"),
                });
            }
            let contents = std::fs::read_to_string(path).map_err(|error| {
                policy::PolicyError::InvalidBlocklist {
                    path: path.clone(),
                    reason: error.to_string(),
                }
            })?;
            for line in contents.lines() {
                if line.len() > MAX_BLOCKLIST_LINE_BYTES {
                    return Err(policy::PolicyError::InvalidBlocklist {
                        path: path.clone(),
                        reason: format!("line exceeds {MAX_BLOCKLIST_LINE_BYTES} bytes"),
                    });
                }
                let line = line.split('#').next().unwrap_or_default().trim();
                if line.is_empty() || line.starts_with('!') {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                let start = if fields
                    .first()
                    .and_then(|field| field.parse::<std::net::IpAddr>().ok())
                    .is_some()
                {
                    1
                } else {
                    0
                };
                for raw_domain in fields.iter().skip(start) {
                    let mut domain = raw_domain.trim_end_matches('.').to_ascii_lowercase();
                    if let Some(stripped) = domain.strip_prefix("||") {
                        domain = stripped.trim_end_matches('^').to_owned();
                    }
                    if !valid_blocklist_domain(&domain) {
                        return Err(policy::PolicyError::InvalidBlocklist {
                            path: path.clone(),
                            reason: format!("invalid domain {raw_domain}"),
                        });
                    }
                    domains.insert(domain);
                }
            }
        }
        Ok(domains
            .into_iter()
            .enumerate()
            .map(|(index, domain)| RuleConfig {
                id: u32::MAX.saturating_sub(index as u32),
                domain,
                action: Action::Nxdomain,
                priority: i32::MAX,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
            })
            .collect())
    }

    fn valid_blocklist_domain(domain: &str) -> bool {
        !domain.is_empty()
            && domain.len() <= policy::MAX_DOMAIN_BYTES
            && domain
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii())
    }
    fn default_breaker_failures() -> u32 {
        3
    }
    fn default_breaker_cooldown_secs() -> u64 {
        30
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
        reference: PolicyStore,
        rules_configured: AtomicBool,
        telemetry: Option<TelemetryHandle>,
        upstream: Option<DnsClientUpstream>,
        upstream_slots: Option<Arc<Semaphore>>,
        cache: Arc<Mutex<DnsCache>>,
        breaker: Arc<Mutex<CircuitBreaker>>,
        request_slots: Arc<Semaphore>,
    }

    impl Policy {
        pub fn new(mut config: Config) -> Result<Self, policy::PolicyError> {
            if config.admission.max_name_bytes == 0 || config.admission.max_name_bytes > 253 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_name_bytes must be between 1 and 253".into(),
                });
            }
            if config.admission.max_response_records == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_response_records must be non-zero".into(),
                });
            }
            if config.admission.max_response_bytes < 12 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_response_bytes must be at least 12".into(),
                });
            }
            if config.admission.max_inflight_requests == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_inflight_requests must be non-zero".into(),
                });
            }
            let blocklist_rules = load_blocklists(&config.policy.blocklists)?;
            config.policy.rules.extend(blocklist_rules);
            config.policy.domains = config.policy.domains.into_iter().map(normalize).collect();
            let reference = PolicyStore::new(&config.policy.rules)?;
            let cache = Arc::new(Mutex::new(DnsCache::new(&config.cache)));
            let max_inflight_requests = config.admission.max_inflight_requests;
            let breaker = Arc::new(Mutex::new(CircuitBreaker::new(
                config
                    .upstream
                    .as_ref()
                    .map_or(default_breaker_failures(), |upstream| {
                        upstream.breaker_failures
                    }),
                config
                    .upstream
                    .as_ref()
                    .map_or(default_breaker_cooldown_secs(), |upstream| {
                        upstream.breaker_cooldown_secs
                    }),
            )));
            let rules_configured = !config.policy.rules.is_empty();
            let policy = Self {
                config,
                reference,
                rules_configured: AtomicBool::new(rules_configured),
                telemetry: None,
                upstream: None,
                upstream_slots: None,
                cache,
                breaker,
                request_slots: Arc::new(Semaphore::new(max_inflight_requests)),
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

        /// Validate and atomically publish a complete replacement rule table.
        /// Existing readers finish against their old immutable snapshot; new
        /// readers observe the replacement as one generation.
        pub fn reload_rules(
            &self,
            rules: &[RuleConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let published = self.reference.reload(rules)?;
            self.rules_configured
                .store(!rules.is_empty(), Ordering::Release);
            Ok(published)
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
            if upstream.breaker_failures == 0 || upstream.breaker_cooldown_secs == 0 {
                return Err(policy::PolicyError::InvalidUpstream {
                    reason: "breaker_failures and breaker_cooldown_secs must be non-zero".into(),
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
                    reason: "server.listen must be a socket address before configuring upstream"
                        .into(),
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

        fn decision(
            &self,
            query: &proxima_dns::DnsQuery,
            client: Option<std::net::IpAddr>,
        ) -> Option<policy::Decision> {
            self.reference.read(|reference| {
                reference.decide(QueryContext {
                    name: &query.name,
                    qtype: query.qtype,
                    qclass: query.qclass,
                    client,
                })
            })
        }

        fn client_ip(peer: Option<&PeerInfo>) -> Option<std::net::IpAddr> {
            match peer {
                Some(PeerInfo::Tcp(address)) => Some(address.ip()),
                _ => None,
            }
        }

        fn admission_allows(&self, query: &proxima_dns::DnsQuery) -> bool {
            let name = query.name.trim_end_matches('.');
            if name.len() > self.config.admission.max_name_bytes {
                return false;
            }
            if self.config.admission.reject_any && query.qtype == 255 {
                return false;
            }
            if name.is_empty() {
                return true;
            }
            name.split('.')
                .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii())
        }

        fn cap_answer(&self, query: &proxima_dns::DnsQuery, mut answer: DnsAnswer) -> DnsAnswer {
            answer
                .records
                .truncate(self.config.admission.max_response_records);
            let mut bytes = 12usize
                .saturating_add(wire_name_bytes(&query.name))
                .saturating_add(4);
            let max_bytes = self.config.admission.max_response_bytes;
            answer.records.retain(|record| {
                let record_bytes = wire_name_bytes(&record.name)
                    .saturating_add(10)
                    .saturating_add(record.rdata.len());
                let fits = bytes.saturating_add(record_bytes) <= max_bytes;
                if fits {
                    bytes = bytes.saturating_add(record_bytes);
                }
                fits
            });
            answer
        }

        fn validate_upstream_answer(
            &self,
            query: &proxima_dns::DnsQuery,
            answer: &DnsAnswer,
        ) -> Result<(), &'static str> {
            let query_name = normalize(&query.name);
            let mut has_question_owner = false;
            for record in &answer.records {
                let record_name = normalize(&record.name);
                if !valid_dns_name(&record_name)
                    || record.rclass != query.qclass
                    || (query.qtype != 255 && record.rtype != query.qtype && record.rtype != 5)
                {
                    return Err("upstream_question_mismatch");
                }
                if record_name == query_name {
                    has_question_owner = true;
                }
                if record.rtype == 1 && record.rdata.len() != 4 {
                    return Err("upstream_malformed");
                }
                if record.rtype == 28 && record.rdata.len() != 16 {
                    return Err("upstream_malformed");
                }
                if !self.config.security.reject_private_upstream_addresses {
                    continue;
                }
                let blocked = match record.rtype {
                    1 if record.rdata.len() == 4 => {
                        let address = Ipv4Addr::new(
                            record.rdata[0],
                            record.rdata[1],
                            record.rdata[2],
                            record.rdata[3],
                        );
                        address.is_private()
                            || address.is_loopback()
                            || address.is_link_local()
                            || address.is_unspecified()
                            || address.is_multicast()
                            || address.is_broadcast()
                    }
                    28 if record.rdata.len() == 16 => {
                        let mut octets = [0; 16];
                        octets.copy_from_slice(&record.rdata);
                        let address = Ipv6Addr::from(octets);
                        address.is_unique_local()
                            || address.is_loopback()
                            || address.is_unicast_link_local()
                            || address.is_unspecified()
                            || address.is_multicast()
                    }
                    _ => false,
                };
                if blocked {
                    return Err("upstream_rebinding");
                }
            }
            if !answer.records.is_empty() && !has_question_owner {
                return Err("upstream_question_mismatch");
            }
            Ok(())
        }

        /// Return the authoritative action for a validated borrowed query view.
        /// The wire adapter calls this before materializing the owned Proxima DNS
        /// request, so configured rules remain authoritative at the raw boundary.
        #[must_use]
        pub fn action_for_view(&self, query: QueryView<'_>) -> Action {
            self.action_for_view_with_client(query, None)
        }

        /// Return the authoritative action while retaining the listener-owned
        /// client address as a policy input without putting adapter metadata
        /// into the borrowed wire view.
        #[must_use]
        pub fn action_for_view_with_client(
            &self,
            query: QueryView<'_>,
            client: Option<std::net::IpAddr>,
        ) -> Action {
            let name = query.name.to_dotted();
            if !self.rules_configured.load(Ordering::Acquire) {
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
                .read(|reference| {
                    reference.decide(QueryContext {
                        name: &name,
                        qtype: query.qtype,
                        qclass: query.qclass,
                        client,
                    })
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
            if !self.admission_allows(query) {
                return Some(refused_answer());
            }
            let decision = self.decision(query, None);
            if !self.rules_configured.load(Ordering::Acquire) {
                return self
                    .evaluate_legacy(query)
                    .map(|answer| self.cap_answer(query, answer));
            }
            let answer = match decision
                .map(|decision| decision.action)
                .or(Some(self.config.policy.default_action))
            {
                Some(Action::Ignore | Action::Drop | Action::Forward) => None,
                Some(Action::Nxdomain) => Some(DnsAnswer::name_error()),
                Some(Action::Reject) => Some(refused_answer()),
                Some(Action::Sink) => Some(DnsAnswer::ok(Vec::new())),
                Some(Action::Honeypot) => {
                    Some(honeypot(&query.name, query.qtype, &self.config.honeypot))
                }
                Some(Action::Pass | Action::Observe) | None => Some(DnsAnswer::ok(Vec::new())),
            };
            answer.map(|answer| self.cap_answer(query, answer))
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

        pub(crate) fn observe_failure(&self, cause: &'static str) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[("cause", cause)]);
            telemetry.counter_inc("blackhole.failures", &labels, 1);
        }

        fn observe_latency(&self, elapsed: Duration) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[("operation", "dns_request")]);
            telemetry.histogram_record(
                "blackhole.request_latency_ns",
                &labels,
                elapsed.as_nanos() as f64,
            );
        }
    }

    impl Policy {
        async fn call_inner(
            &self,
            request: DnsPipeRequest,
            selected_action: Option<Action>,
        ) -> Result<DnsPipeReply, ProximaError> {
            let Ok(_request_slot) = self.request_slots.try_acquire() else {
                self.observe_failure("admission_overflow");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            };
            let client = Policy::client_ip(request.context.peer.as_ref());
            let query = request.payload;
            if !self.admission_allows(&query) {
                self.observe_failure("admission_rejected");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, refused_answer()));
            }
            // The raw listener supplies its borrowed decision here. The owned
            // facade passes None and performs the single policy lookup itself.
            let action = selected_action.or_else(|| {
                if !self.rules_configured.load(Ordering::Acquire) {
                    None
                } else {
                    Some(
                        self.decision(&query, client)
                            .map_or(self.config.policy.default_action, |decision| {
                                decision.action
                            }),
                    )
                }
            });
            if action == Some(Action::Forward) {
                let Some(slots) = self.upstream_slots.as_ref() else {
                    self.observe_failure("upstream_unconfigured");
                    self.observe(Action::Forward);
                    return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
                };
                let Ok(_slot) = slots.try_acquire() else {
                    self.observe_failure("upstream_overflow");
                    self.observe(Action::Forward);
                    return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
                };
                let Some(upstream) = self.upstream.as_ref() else {
                    self.observe_failure("upstream_unconfigured");
                    self.observe(Action::Forward);
                    return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
                };
                let key = CacheKey::from_query(&query);
                if let Some(answer) = self.cache.lock().expect("cache lock").fresh(&key) {
                    self.observe(Action::Forward);
                    return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                }
                if !self
                    .breaker
                    .lock()
                    .expect("breaker lock")
                    .allows(Instant::now())
                {
                    if let Some(answer) = self.cache.lock().expect("cache lock").stale(&key) {
                        self.observe(Action::Forward);
                        return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                    }
                    self.observe_failure("upstream_circuit_open");
                    self.observe(Action::Forward);
                    return Err(ProximaError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream circuit breaker is open",
                    )));
                }
                let answer = upstream.query(&query.name, query.qtype, query.qclass).await;
                let answer = match answer {
                    Ok(answer) => {
                        if let Err(cause) = self.validate_upstream_answer(&query, &answer) {
                            self.breaker
                                .lock()
                                .expect("breaker lock")
                                .failure(Instant::now());
                            self.observe_failure(cause);
                            self.observe(Action::Forward);
                            return Ok(DnsPipeReply::typed(200, server_failure_answer()));
                        }
                        self.breaker.lock().expect("breaker lock").success();
                        if matches!(answer.rcode, 0 | 3) {
                            self.cache.lock().expect("cache lock").insert(
                                key.clone(),
                                answer.clone(),
                                Instant::now(),
                            );
                        }
                        answer
                    }
                    Err(error) => {
                        self.breaker
                            .lock()
                            .expect("breaker lock")
                            .failure(Instant::now());
                        if let Some(answer) = self.cache.lock().expect("cache lock").stale(&key) {
                            self.observe(Action::Forward);
                            return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                        }
                        self.observe_failure("upstream_error");
                        self.observe(Action::Forward);
                        return Err(ProximaError::Io(std::io::Error::other(error.to_string())));
                    }
                };
                self.observe(Action::Forward);
                return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
            }
            let outcome = if !self.rules_configured.load(Ordering::Acquire) {
                self.evaluate_legacy(&query)
            } else {
                match action {
                    Some(Action::Ignore | Action::Drop) => None,
                    Some(Action::Nxdomain) => Some(DnsAnswer::name_error()),
                    Some(Action::Reject) => Some(refused_answer()),
                    Some(Action::Honeypot) => {
                        Some(honeypot(&query.name, query.qtype, &self.config.honeypot))
                    }
                    Some(Action::Sink) => Some(DnsAnswer::ok(Vec::new())),
                    Some(Action::Pass | Action::Observe) | None => Some(DnsAnswer::ok(Vec::new())),
                    Some(Action::Forward) => unreachable!("forwarding handled above"),
                }
            };
            self.observe(action.unwrap_or(Action::Pass));
            match outcome {
                Some(answer) => Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer))),
                // Compatibility mapping only: semantic policy results are typed;
                // the current owned DNS facade has no silent-response variant.
                None => Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new()))),
            }
        }

        pub(crate) async fn call_owned(
            &self,
            request: DnsPipeRequest,
            action: Action,
        ) -> Result<DnsPipeReply, ProximaError> {
            let started = Instant::now();
            let result = self.call_inner(request, Some(action)).await;
            self.observe_latency(started.elapsed());
            result
        }
    }

    impl SendPipe for Policy {
        type In = DnsPipeRequest;
        type Out = DnsPipeReply;
        type Err = ProximaError;

        async fn call(&self, request: Self::In) -> Result<Self::Out, ProximaError> {
            let started = Instant::now();
            let result = self.call_inner(request, None).await;
            self.observe_latency(started.elapsed());
            result
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

    fn refused_answer() -> DnsAnswer {
        DnsAnswer {
            rcode: 5,
            authoritative: false,
            recursion_available: true,
            records: Vec::new(),
        }
    }

    fn server_failure_answer() -> DnsAnswer {
        DnsAnswer {
            rcode: 2,
            authoritative: false,
            recursion_available: true,
            records: Vec::new(),
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

    fn wire_name_bytes(name: &str) -> usize {
        if name == "." || name.is_empty() {
            return 1;
        }
        name.trim_end_matches('.')
            .split('.')
            .map(|label| label.len().saturating_add(1))
            .sum::<usize>()
            .saturating_add(1)
    }

    fn valid_dns_name(name: &str) -> bool {
        name.is_empty()
            || (name.len() <= 253
                && name
                    .split('.')
                    .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii()))
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
        fn policy_reload_replaces_authoritative_rules_atomically() {
            let query = |name: &str| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype: 1,
                qclass: 1,
            };
            let mut config = Config::default();
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "old.example".into(),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
            }];
            let policy = Policy::new(config).expect("initial policy");
            assert_eq!(
                policy
                    .decision(&query("old.example."), None)
                    .unwrap()
                    .action,
                Action::Drop
            );

            assert_eq!(
                policy.reload_rules(&[RuleConfig {
                    id: 2,
                    domain: "new.example".into(),
                    action: Action::Reject,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidr: None,
                }]),
                Ok(ReloadState::Published)
            );
            assert!(policy.decision(&query("old.example."), None).is_none());
            assert_eq!(
                policy
                    .decision(&query("new.example."), None)
                    .unwrap()
                    .action,
                Action::Reject
            );

            let invalid = [
                RuleConfig {
                    id: 3,
                    domain: "failed.example".into(),
                    action: Action::Pass,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidr: None,
                },
                RuleConfig {
                    id: 3,
                    domain: "other.example".into(),
                    action: Action::Drop,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidr: None,
                },
            ];
            assert_eq!(
                policy.reload_rules(&invalid),
                Err(policy::PolicyError::DuplicateRule { id: 3 })
            );
            assert_eq!(
                policy
                    .decision(&query("new.example."), None)
                    .unwrap()
                    .action,
                Action::Reject
            );
        }

        #[test]
        fn blocklists_are_bounded_normalized_deduplicated_and_authoritative() {
            let path = std::env::temp_dir()
                .join(format!("blackhole-blocklist-{}.txt", std::process::id()));
            std::fs::write(
                &path,
                "# comment\n0.0.0.0 Ads.Example\n||ads.example^\ntelemetry.example.\n",
            )
            .expect("write blocklist");
            let mut config = Config::default();
            config.policy.blocklists = vec![path.to_string_lossy().into_owned()];
            config.policy.default_action = Action::Pass;
            let policy = Policy::new(config).expect("valid blocklist");
            let query = |name: &str| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(policy.evaluate(&query("ads.example.")).unwrap().rcode, 3);
            assert_eq!(
                policy.evaluate(&query("telemetry.example.")).unwrap().rcode,
                3
            );
            assert_eq!(policy.evaluate(&query("clear.example.")).unwrap().rcode, 0);
            std::fs::remove_file(path).expect("remove blocklist");
        }

        #[test]
        fn missing_blocklists_fail_closed_before_policy_publication() {
            let mut config = Config::default();
            config.policy.blocklists = vec!["/definitely/missing/blackhole.list".into()];
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidBlocklist { .. })
            ));
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
                client_cidr: None,
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
                policy
                    .decision(&query, None)
                    .map(|decision| decision.action),
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
                client_cidr: None,
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
                client_cidr: None,
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
        fn client_scoped_rules_use_adapter_owned_peer_metadata() {
            let mut config = Config::default();
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "client.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qclass: None,
                client: Some("192.0.2.10".parse().unwrap()),
                client_cidr: None,
            }];
            let policy = Policy::new(config).expect("valid policy");
            let packet = [
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, b'c', b'l', b'i', b'e', b'n', b't', 7, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
            ];
            let view = QueryView::parse(&packet).expect("valid query");
            assert_eq!(
                policy.action_for_view_with_client(view, Some("192.0.2.10".parse().unwrap())),
                Action::Reject
            );
            assert_eq!(
                policy.action_for_view_with_client(view, Some("192.0.2.11".parse().unwrap())),
                Action::Pass
            );
        }

        #[test]
        fn cache_bounds_entries_and_serves_positive_and_negative_answers() {
            let config = CacheConfig {
                max_entries: 1,
                stale_ttl_secs: 30,
                negative_ttl_secs: 30,
            };
            let mut cache = DnsCache::new(&config);
            let first = CacheKey {
                name: "one.example".into(),
                qtype: 1,
                qclass: 1,
            };
            let second = CacheKey {
                name: "two.example".into(),
                qtype: 1,
                qclass: 1,
            };
            let now = Instant::now();
            cache.insert(first.clone(), DnsAnswer::ok(Vec::new()), now);
            assert!(cache.fresh(&first).is_some());
            cache.insert(second.clone(), DnsAnswer::name_error(), now);
            assert_eq!(cache.entries.len(), 1);
            assert!(cache.fresh(&first).is_none());
            assert_eq!(cache.fresh(&second), Some(DnsAnswer::name_error()));
        }

        #[test]
        fn expired_entries_are_available_only_inside_the_stale_window() {
            let config = CacheConfig::default();
            let mut cache = DnsCache::new(&config);
            let key = CacheKey {
                name: "stale.example".into(),
                qtype: 1,
                qclass: 1,
            };
            let now = Instant::now();
            cache.insert(key.clone(), DnsAnswer::name_error(), now);
            let entry = cache.entries.get_mut(&key).expect("inserted cache entry");
            entry.expires_at = now - Duration::from_secs(1);
            assert!(cache.fresh(&key).is_none());
            assert!(cache.stale(&key).is_some());
            let entry = cache.entries.get_mut(&key).expect("stale entry retained");
            entry.stale_until = Instant::now() - Duration::from_secs(1);
            assert!(cache.stale(&key).is_none());
            assert!(!cache.entries.contains_key(&key));
        }

        #[test]
        fn upstream_breaker_opens_after_bounded_failures_and_recovers() {
            let mut breaker = CircuitBreaker::new(2, 30);
            let now = Instant::now();
            assert!(breaker.allows(now));
            breaker.failure(now);
            assert!(breaker.allows(now));
            breaker.failure(now);
            assert!(!breaker.allows(now));
            breaker.success();
            assert!(breaker.allows(now));
        }

        #[test]
        fn explicit_actions_have_distinct_wire_contracts() {
            let query = |name: &str| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype: 1,
                qclass: 1,
            };
            let actions = [
                ("reject.example", Action::Reject),
                ("nxdomain.example", Action::Nxdomain),
                ("sink.example", Action::Sink),
                ("honeypot.example", Action::Honeypot),
            ];
            for (domain, action) in actions {
                let mut config = Config::default();
                config.policy.rules = vec![RuleConfig {
                    id: 1,
                    domain: domain.into(),
                    action,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidr: None,
                }];
                let policy = Policy::new(config).expect("valid policy");
                let answer = policy.evaluate(&query(domain)).expect("wire answer");
                match action {
                    Action::Reject => assert_eq!(answer.rcode, 5),
                    Action::Nxdomain => assert_eq!(answer.rcode, 3),
                    Action::Sink => assert!(answer.records.is_empty()),
                    Action::Honeypot => assert_eq!(answer.records.len(), 1),
                    _ => unreachable!("test action set"),
                }
            }
        }

        #[test]
        fn admission_rejects_any_and_overlong_or_invalid_names() {
            let policy = Policy::new(Config::default()).expect("valid policy");
            let query = |name: &str, qtype: u16| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype,
                qclass: 1,
            };
            assert_eq!(
                policy.evaluate(&query("example.com.", 255)).unwrap().rcode,
                5
            );
            assert_eq!(
                policy
                    .evaluate(&query(&format!("{}.example.", "a".repeat(250)), 1))
                    .unwrap()
                    .rcode,
                5
            );
            assert_eq!(
                policy.evaluate(&query("bad..example.", 1)).unwrap().rcode,
                5
            );
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_response_records = 0;
                    config
                })
                .is_err()
            );
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_response_bytes = 11;
                    config
                })
                .is_err()
            );
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_inflight_requests = 0;
                    config
                })
                .is_err()
            );
        }

        #[test]
        fn admission_caps_answer_wire_size() {
            let mut config = Config::default();
            config.admission.max_response_bytes = 40;
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "honeypot.example".into(),
                action: Action::Honeypot,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
            }];
            let policy = Policy::new(config).expect("valid policy");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "honeypot.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            let answer = policy.evaluate(&query).expect("wire answer");
            assert!(answer.records.is_empty());
        }

        #[test]
        fn admission_caps_synthetic_answers() {
            let mut config = Config::default();
            config.admission.max_response_records = 1;
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "sink.example".into(),
                action: Action::Honeypot,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
            }];
            let policy = Policy::new(config).expect("valid policy");
            let answer = policy
                .evaluate(&proxima_dns::DnsQuery {
                    id: 1,
                    recursion_desired: true,
                    name: "sink.example.".into(),
                    qtype: 1,
                    qclass: 1,
                })
                .expect("answer");
            assert!(answer.records.len() <= 1);
        }

        #[test]
        fn upstream_rebinding_addresses_fail_closed_before_cache() {
            let policy = Policy::new(Config::default()).expect("valid policy");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "answer.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            let private = DnsAnswer {
                rcode: 0,
                authoritative: false,
                recursion_available: true,
                records: vec![DnsAnswerRecord {
                    name: "answer.example.".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: 30,
                    rdata: vec![10, 0, 0, 1],
                }],
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &private),
                Err("upstream_rebinding")
            );
            let public = DnsAnswer {
                records: vec![DnsAnswerRecord {
                    name: "answer.example.".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: 30,
                    rdata: vec![93, 184, 216, 34],
                }],
                ..private.clone()
            };
            assert_eq!(policy.validate_upstream_answer(&query, &public), Ok(()));
        }

        #[test]
        fn upstream_answer_must_match_question_shape() {
            let policy = Policy::new(Config::default()).expect("valid policy");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "answer.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            let unrelated = DnsAnswer {
                records: vec![DnsAnswerRecord {
                    name: "other.example.".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: 30,
                    rdata: vec![93, 184, 216, 34],
                }],
                ..DnsAnswer::ok(Vec::new())
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &unrelated),
                Err("upstream_question_mismatch")
            );

            let malformed = DnsAnswer {
                records: vec![DnsAnswerRecord {
                    name: "answer.example.".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: 30,
                    rdata: vec![127, 0, 0],
                }],
                ..DnsAnswer::ok(Vec::new())
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &malformed),
                Err("upstream_malformed")
            );
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

        #[test]
        fn telemetry_preserves_failure_cause_and_records_latency_histograms() {
            use proxima::Telemetry;
            use std::sync::Arc;
            use std::sync::atomic::{AtomicU64, Ordering};

            struct FailureLatencyTelemetry {
                failures: AtomicU64,
                latencies: AtomicU64,
            }

            impl Telemetry for FailureLatencyTelemetry {
                fn counter_inc(&self, metric: &str, labels: &Labels, by: u64) {
                    assert_eq!(metric, "blackhole.failures");
                    assert_eq!(labels.entries().len(), 1);
                    assert_eq!(labels.entries()[0].0, "cause");
                    assert_eq!(labels.entries()[0].1, "upstream_error");
                    self.failures.fetch_add(by, Ordering::Relaxed);
                }
                fn gauge_set(&self, _: &str, _: &Labels, _: i64) {}
                fn histogram_record(&self, metric: &str, labels: &Labels, value: f64) {
                    assert_eq!(metric, "blackhole.request_latency_ns");
                    assert_eq!(labels.entries().len(), 1);
                    assert_eq!(labels.entries()[0].0, "operation");
                    assert_eq!(labels.entries()[0].1, "dns_request");
                    assert!(value >= 0.0);
                    self.latencies.fetch_add(1, Ordering::Relaxed);
                }
            }

            let telemetry = Arc::new(FailureLatencyTelemetry {
                failures: AtomicU64::new(0),
                latencies: AtomicU64::new(0),
            });
            let policy = Policy::new(Config::default())
                .expect("valid policy")
                .with_telemetry(telemetry.clone());
            policy.observe_failure("upstream_error");
            policy.observe_latency(Duration::from_nanos(7));
            assert_eq!(telemetry.failures.load(Ordering::Relaxed), 1);
            assert_eq!(telemetry.latencies.load(Ordering::Relaxed), 1);
        }
    }
}

#[cfg(feature = "std")]
pub use runtime::*;
