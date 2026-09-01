//! Policy and configuration for the Blackhole DNS sinkhole.
//!
//! ```
//! let config = blackhole::Config::default();
//! assert_eq!(config.server.listen, "127.0.0.1:5353");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(all(not(feature = "std"), target_arch = "wasm32"))]
mod wasm_runtime {
    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_BYTES: usize = 1024 * 1024;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

    struct BumpAllocator;

    // This allocator is only for the bounded WASM edge experiment. The
    // production scalar path does not use it, and deallocation is intentionally
    // omitted because the module is short-lived for each benchmark instance.
    unsafe impl GlobalAlloc for BumpAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
            let mut current = NEXT.load(Ordering::Relaxed);
            loop {
                let Some(address) = base
                    .checked_add(current)
                    .and_then(|value| value.checked_add(layout.align().saturating_sub(1)))
                else {
                    return core::ptr::null_mut();
                };
                let aligned = address & !(layout.align().saturating_sub(1));
                let Some(offset) = aligned.checked_sub(base) else {
                    return core::ptr::null_mut();
                };
                let Some(next) = offset.checked_add(layout.size()) else {
                    return core::ptr::null_mut();
                };
                if next > HEAP_BYTES {
                    return core::ptr::null_mut();
                }
                match NEXT.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return (base + offset) as *mut u8,
                    Err(observed) => current = observed,
                }
            }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: BumpAllocator = BumpAllocator;

    pub fn reset() {
        NEXT.store(0, Ordering::Relaxed);
    }

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}

pub mod edge;
pub mod fsm;
pub mod policy;
pub mod query;
pub use policy::{Action, RuleConfig};

#[cfg(feature = "std")]
pub mod admin;
#[cfg(feature = "std")]
pub mod dhcp;
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
    use proxima::{
        BoundedRecordingSink, DynRecordingSink, FailMode, InteractionId, Labels, ProtocolEvent,
        RecordingAppendFuture, RecordingEvent, RecordingSink, TelemetryHandle,
    };
    use proxima_core::ProximaError;
    use proxima_core::live::{Live, LiveControl, live};
    use proxima_dns::{
        DnsAnswer, DnsAnswerRecord, DnsAnswerWithMetadata, DnsClientUpstream, DnsPipeReply,
        DnsPipeRequest,
    };
    use proxima_primitives::pipe::CircuitBreaker as ProximaCircuitBreaker;
    use proxima_primitives::pipe::SendPipe;
    use proxima_primitives::pipe::bucket_table::BucketTable;
    use proxima_primitives::pipe::endpoint::PeerInfo;
    use proxima_primitives::stream::DatagramFactory;
    use proxima_primitives::sync::Semaphore;
    use serde::Deserialize;
    use std::collections::{BTreeSet, HashMap, VecDeque};
    use std::hash::Hash;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::{Duration, Instant};

    use crate::policy;
    use crate::policy::QueryContext;
    use crate::query::QueryView;
    use crate::snapshot::{PolicyStore, ReloadState};
    use crate::{Action, RuleConfig};

    const MAX_UPSTREAM_OUTSTANDING: usize = 4096;
    const MAX_UPSTREAM_ATTEMPTS: u32 = 8;
    const MAX_UPSTREAM_TIMEOUT_MS: u64 = 60_000;
    const MAX_REGEX_RULES: usize = 4096;
    const MAX_REGEX_PATTERN_BYTES: usize = 4096;
    const MAX_REGEX_PROGRAM_BYTES: usize = 1 << 20;
    const MAX_ADMIN_RULES_BODY_BYTES: usize = 64 * 1024;
    const MAX_ADMIN_LOG_ENTRIES: usize = 1_024;
    const MAX_BLOCKLIST_RELOAD_INTERVAL_SECS: u64 = 86_400;

    #[derive(Debug, Clone, Deserialize, Default)]
    pub struct Config {
        #[serde(default)]
        pub server: ServerConfig,
        #[serde(default)]
        pub admin: AdminConfig,
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
        pub country_policy: CountryPolicyConfig,
        #[serde(default)]
        pub privacy: PrivacyConfig,
        #[serde(default)]
        pub capture: CaptureConfig,
        #[serde(default)]
        pub dhcp: DhcpConfig,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CacheConfig {
        #[serde(default = "default_cache_entries")]
        pub max_entries: usize,
        #[serde(default = "default_max_cache_ttl_secs")]
        pub max_ttl_secs: u64,
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

    #[derive(Debug, Clone)]
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

        fn fresh(&self, key: &CacheKey) -> Option<DnsAnswer> {
            let now = Instant::now();
            let entry = self.entries.get(key)?;
            if now < entry.expires_at {
                return Some(entry.answer.clone());
            }
            None
        }

        fn stale_answer(&self, key: &CacheKey) -> Option<DnsAnswer> {
            let now = Instant::now();
            let entry = self.entries.get(key)?;
            (now < entry.stale_until).then(|| entry.answer.clone())
        }

        #[cfg(test)]
        fn stale(&mut self, key: &CacheKey) -> Option<DnsAnswer> {
            let now = Instant::now();
            let entry = self.entries.get(key)?;
            if now < entry.stale_until {
                return Some(entry.answer.clone());
            }
            self.entries.remove(key);
            None
        }

        fn clear(&mut self) {
            self.entries.clear();
        }

        fn insert(&mut self, key: CacheKey, answer: DnsAnswer, now: Instant) -> bool {
            if self.config.max_entries == 0 {
                return false;
            }
            let mut evicted = false;
            if self.entries.len() >= self.config.max_entries && !self.entries.contains_key(&key) {
                if let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(key, _)| key.clone())
                {
                    self.entries.remove(&oldest);
                    evicted = true;
                }
            }
            let ttl_secs = answer
                .records
                .iter()
                .map(|record| u64::from(record.ttl))
                .min()
                .unwrap_or(self.config.negative_ttl_secs);
            let ttl = Duration::from_secs(ttl_secs.min(self.config.max_ttl_secs));
            let stale = Duration::from_secs(self.config.stale_ttl_secs);
            self.entries.insert(
                key,
                CacheEntry {
                    answer,
                    expires_at: now + ttl,
                    stale_until: now + ttl + stale,
                },
            );
            evicted
        }
    }

    struct ClientAdmissionBucket {
        active: AtomicU64,
        last_access_micros: AtomicU64,
    }

    impl ClientAdmissionBucket {
        fn new() -> Self {
            Self {
                active: AtomicU64::new(0),
                last_access_micros: AtomicU64::new(0),
            }
        }
    }

    struct ClientPermit {
        bucket: Arc<ClientAdmissionBucket>,
    }

    impl Drop for ClientPermit {
        fn drop(&mut self) {
            self.bucket.active.fetch_sub(1, Ordering::AcqRel);
            self.bucket.last_access_micros.store(0, Ordering::Release);
        }
    }

    struct ClientAdmissionTable {
        buckets: BucketTable<ClientAdmissionBucket>,
    }

    impl ClientAdmissionTable {
        fn new() -> Self {
            Self {
                buckets: BucketTable::with_max_keys(MAX_CLIENT_RATE_ENTRIES),
            }
        }

        fn try_acquire(
            &self,
            client: IpAddr,
            limit: usize,
            epoch: Instant,
        ) -> Option<ClientPermit> {
            let (key, length) = ip_key(client);
            if self.buckets.len() >= MAX_CLIENT_RATE_ENTRIES {
                self.buckets.evict_one_lru(|bucket| {
                    if bucket.active.load(Ordering::Acquire) != 0 {
                        u64::MAX
                    } else {
                        bucket.last_access_micros.load(Ordering::Relaxed)
                    }
                });
            }
            let bucket = self
                .buckets
                .get_or_insert(&key[..length], ClientAdmissionBucket::new);
            let limit = limit.min(u64::MAX as usize) as u64;
            loop {
                let current = bucket.active.load(Ordering::Acquire);
                if current >= limit {
                    return None;
                }
                if bucket
                    .active
                    .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    bucket.last_access_micros.store(
                        epoch.elapsed().as_micros().min(u64::MAX as u128) as u64,
                        Ordering::Relaxed,
                    );
                    return Some(ClientPermit { bucket });
                }
            }
        }
    }

    struct AtomicWindowBucket {
        state: AtomicU64,
        blocked_until: AtomicU64,
        last_access_micros: AtomicU64,
    }

    impl AtomicWindowBucket {
        fn new() -> Self {
            Self {
                state: AtomicU64::new(0),
                blocked_until: AtomicU64::new(0),
                last_access_micros: AtomicU64::new(0),
            }
        }

        fn allow(&self, epoch: Instant, limit: usize, amount: usize) -> bool {
            if limit == 0 || amount > limit {
                return false;
            }
            let window = epoch.elapsed().as_secs() & u32::MAX as u64;
            let limit = limit.min(u32::MAX as usize) as u64;
            let amount = amount.min(u32::MAX as usize) as u64;
            if amount > limit {
                return false;
            }
            loop {
                let current = self.state.load(Ordering::Acquire);
                let current_window = current >> 32;
                let current_count = current & u32::MAX as u64;
                let next = if current_window != window {
                    (window << 32) | amount
                } else if current_count.saturating_add(amount) > limit {
                    return false;
                } else {
                    current + amount
                };
                if self
                    .state
                    .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return true;
                }
            }
        }

        fn abuse_allows(&self, epoch: Instant, window: Duration) -> bool {
            let now = epoch.elapsed().as_secs();
            if self.blocked_until.load(Ordering::Acquire) > now {
                return false;
            }
            let current = self.state.load(Ordering::Acquire);
            if current >> 32 != now {
                let _ = self.state.compare_exchange(
                    current,
                    now << 32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            } else if window.is_zero() {
                return false;
            }
            true
        }

        fn record_abuse(
            &self,
            epoch: Instant,
            window: Duration,
            cooldown: Duration,
            threshold: usize,
        ) -> bool {
            if threshold == 0 {
                return false;
            }
            let now = epoch.elapsed().as_secs();
            let window_secs = window.as_secs().max(1);
            let cooldown_secs = cooldown.as_secs().max(1);
            loop {
                let current = self.state.load(Ordering::Acquire);
                let current_window = current >> 32;
                let current_count = current & u32::MAX as u64;
                let (window_start, count) = if now.saturating_sub(current_window) >= window_secs {
                    (now, 1)
                } else {
                    (current_window, current_count.saturating_add(1))
                };
                let next = (window_start << 32) | count.min(u32::MAX as u64);
                if self
                    .state
                    .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let opened = count >= threshold.min(u32::MAX as usize) as u64;
                    if opened {
                        self.blocked_until
                            .store(now.saturating_add(cooldown_secs), Ordering::Release);
                    }
                    return opened;
                }
            }
        }
    }

    struct KeyedWindowBudgetTable {
        buckets: BucketTable<AtomicWindowBucket>,
    }

    impl KeyedWindowBudgetTable {
        fn new() -> Self {
            Self {
                buckets: BucketTable::with_max_keys(MAX_CLIENT_RATE_ENTRIES),
            }
        }

        fn allow(&self, key: &[u8], epoch: Instant, limit: usize, amount: usize) -> bool {
            if self.buckets.len() >= MAX_CLIENT_RATE_ENTRIES {
                self.buckets
                    .evict_one_lru(|bucket| bucket.last_access_micros.load(Ordering::Relaxed));
            }
            let bucket = self.buckets.get_or_insert(key, AtomicWindowBucket::new);
            bucket.last_access_micros.store(
                epoch.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            bucket.allow(epoch, limit, amount)
        }

        fn abuse_allows(&self, key: &[u8], epoch: Instant, window: Duration) -> bool {
            if self.buckets.len() >= MAX_CLIENT_RATE_ENTRIES {
                self.buckets
                    .evict_one_lru(|bucket| bucket.last_access_micros.load(Ordering::Relaxed));
            }
            let bucket = self.buckets.get_or_insert(key, AtomicWindowBucket::new);
            bucket.last_access_micros.store(
                epoch.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            bucket.abuse_allows(epoch, window)
        }

        fn record_abuse(
            &self,
            key: &[u8],
            epoch: Instant,
            window: Duration,
            cooldown: Duration,
            threshold: usize,
        ) -> bool {
            if self.buckets.len() >= MAX_CLIENT_RATE_ENTRIES {
                self.buckets
                    .evict_one_lru(|bucket| bucket.last_access_micros.load(Ordering::Relaxed));
            }
            let bucket = self.buckets.get_or_insert(key, AtomicWindowBucket::new);
            bucket.last_access_micros.store(
                epoch.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            bucket.record_abuse(epoch, window, cooldown, threshold)
        }
    }

    /// Lock-free fixed-window budget. The upper half stores elapsed seconds
    /// since the policy was created and the lower half stores the admitted
    /// amount in that window. A single CAS makes rollover and the first
    /// admission of the new window one decision.
    struct AtomicWindowBudget(AtomicU64);

    impl AtomicWindowBudget {
        fn new() -> Self {
            Self(AtomicU64::new(0))
        }

        fn allow(&self, epoch: Instant, limit: usize, amount: usize) -> bool {
            if limit == 0 || amount > limit {
                return false;
            }
            let window = epoch.elapsed().as_secs() & u32::MAX as u64;
            let limit = limit.min(u32::MAX as usize) as u64;
            let amount = amount.min(u32::MAX as usize) as u64;
            if amount > limit {
                return false;
            }
            loop {
                let current = self.0.load(Ordering::Acquire);
                let current_window = current >> 32;
                let current_count = current & u32::MAX as u64;
                let next = if current_window != window {
                    (window << 32) | amount
                } else if current_count.saturating_add(amount) > limit {
                    return false;
                } else {
                    current + amount
                };
                if self
                    .0
                    .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return true;
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum AbuseNetworkKey {
        V4(u32, u8),
        V6([u8; 16], u8),
    }

    fn abuse_network_key(client: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> AbuseNetworkKey {
        match client {
            IpAddr::V4(address) => {
                let prefix = ipv4_prefix.min(32);
                let value = u32::from_be_bytes(address.octets());
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                AbuseNetworkKey::V4(value & mask, prefix)
            }
            IpAddr::V6(address) => {
                let prefix = ipv6_prefix.min(128);
                let mut octets = address.octets();
                let full_bytes = usize::from(prefix / 8);
                let remaining_bits = prefix % 8;
                if remaining_bits != 0 && full_bytes < octets.len() {
                    octets[full_bytes] &= 0xff << (8 - remaining_bits);
                }
                let first_zero = full_bytes + usize::from(remaining_bits != 0);
                octets[first_zero..].fill(0);
                AbuseNetworkKey::V6(octets, prefix)
            }
        }
    }

    fn ip_key(client: IpAddr) -> ([u8; 17], usize) {
        let mut key = [0u8; 17];
        let length = match client {
            IpAddr::V4(address) => {
                key[0] = 4;
                key[1..5].copy_from_slice(&address.octets());
                5
            }
            IpAddr::V6(address) => {
                key[0] = 6;
                key[1..].copy_from_slice(&address.octets());
                17
            }
        };
        (key, length)
    }

    fn abuse_network_bytes(key: AbuseNetworkKey) -> ([u8; 18], usize) {
        let mut bytes = [0u8; 18];
        let length = match key {
            AbuseNetworkKey::V4(address, prefix) => {
                bytes[0] = 4;
                bytes[1..5].copy_from_slice(&address.to_be_bytes());
                bytes[5] = prefix;
                6
            }
            AbuseNetworkKey::V6(address, prefix) => {
                bytes[0] = 6;
                bytes[1..17].copy_from_slice(&address);
                bytes[17] = prefix;
                18
            }
        };
        (bytes, length)
    }

    const MAX_CLIENT_RATE_ENTRIES: usize = 4096;
    const MAX_GLOBAL_QUERIES_PER_SECOND: usize = 1_000_000;

    impl Default for CacheConfig {
        fn default() -> Self {
            Self {
                max_entries: default_cache_entries(),
                max_ttl_secs: default_max_cache_ttl_secs(),
                stale_ttl_secs: default_stale_ttl_secs(),
                negative_ttl_secs: default_negative_ttl_secs(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, serde::Serialize)]
    pub struct AdmissionConfig {
        #[serde(default = "default_max_name_bytes")]
        pub max_name_bytes: usize,
        #[serde(default = "default_reject_any")]
        pub reject_any: bool,
        #[serde(default = "default_max_response_records")]
        pub max_response_records: usize,
        #[serde(default = "default_max_response_bytes")]
        pub max_response_bytes: usize,
        #[serde(default = "default_max_response_amplification")]
        pub max_response_amplification: usize,
        #[serde(default = "default_max_inflight_requests")]
        pub max_inflight_requests: usize,
        #[serde(default = "default_max_queries_per_second")]
        pub max_queries_per_second: usize,
        #[serde(default = "default_max_inflight_per_client")]
        pub max_inflight_per_client: usize,
        #[serde(default = "default_max_queries_per_client_per_second")]
        pub max_queries_per_client_per_second: usize,
        #[serde(default = "default_max_response_bytes_per_client_per_second")]
        pub max_response_bytes_per_client_per_second: usize,
        #[serde(default = "default_max_response_bytes_per_network_per_second")]
        pub max_response_bytes_per_network_per_second: usize,
        #[serde(default = "default_max_response_bytes_per_second")]
        pub max_response_bytes_per_second: usize,
        #[serde(default = "default_max_client_abuse_violations")]
        pub max_client_abuse_violations: usize,
        #[serde(default = "default_client_abuse_window_secs")]
        pub client_abuse_window_secs: u64,
        #[serde(default = "default_client_abuse_cooldown_secs")]
        pub client_abuse_cooldown_secs: u64,
        #[serde(default = "default_max_network_abuse_violations")]
        pub max_network_abuse_violations: usize,
        #[serde(default = "default_network_abuse_window_secs")]
        pub network_abuse_window_secs: u64,
        #[serde(default = "default_network_abuse_cooldown_secs")]
        pub network_abuse_cooldown_secs: u64,
        #[serde(default = "default_network_abuse_ipv4_prefix")]
        pub network_abuse_ipv4_prefix: u8,
        #[serde(default = "default_network_abuse_ipv6_prefix")]
        pub network_abuse_ipv6_prefix: u8,
    }

    impl Default for AdmissionConfig {
        fn default() -> Self {
            Self {
                max_name_bytes: default_max_name_bytes(),
                reject_any: default_reject_any(),
                max_response_records: default_max_response_records(),
                max_response_bytes: default_max_response_bytes(),
                max_response_amplification: default_max_response_amplification(),
                max_inflight_requests: default_max_inflight_requests(),
                max_queries_per_second: default_max_queries_per_second(),
                max_inflight_per_client: default_max_inflight_per_client(),
                max_queries_per_client_per_second: default_max_queries_per_client_per_second(),
                max_response_bytes_per_client_per_second:
                    default_max_response_bytes_per_client_per_second(),
                max_response_bytes_per_network_per_second:
                    default_max_response_bytes_per_network_per_second(),
                max_response_bytes_per_second: default_max_response_bytes_per_second(),
                max_client_abuse_violations: default_max_client_abuse_violations(),
                client_abuse_window_secs: default_client_abuse_window_secs(),
                client_abuse_cooldown_secs: default_client_abuse_cooldown_secs(),
                max_network_abuse_violations: default_max_network_abuse_violations(),
                network_abuse_window_secs: default_network_abuse_window_secs(),
                network_abuse_cooldown_secs: default_network_abuse_cooldown_secs(),
                network_abuse_ipv4_prefix: default_network_abuse_ipv4_prefix(),
                network_abuse_ipv6_prefix: default_network_abuse_ipv6_prefix(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
    pub struct CountryPolicyConfig {
        /// Operator-supplied lines of `COUNTRY CIDR`; no database is bundled.
        #[serde(default)]
        pub map_path: Option<String>,
        /// Optional maximum age of the map file. Stale maps fail closed.
        #[serde(default)]
        pub max_age_secs: Option<u64>,
        /// Optional bounded background reload interval. Zero disables polling.
        #[serde(default)]
        pub reload_interval_secs: u64,
        /// Country codes whose clients are denied before DNS policy evaluation.
        #[serde(default)]
        pub deny: Vec<String>,
        /// Country codes whose requests are observed but otherwise unchanged.
        #[serde(default)]
        pub observe: Vec<String>,
        /// Optional region labels from map rows to deny.
        #[serde(default)]
        pub deny_regions: Vec<String>,
        /// Optional region labels from map rows to observe.
        #[serde(default)]
        pub observe_regions: Vec<String>,
        /// Optional autonomous system numbers from map rows to deny.
        #[serde(default)]
        pub deny_asns: Vec<u32>,
        /// Optional autonomous system numbers from map rows to observe.
        #[serde(default)]
        pub observe_asns: Vec<u32>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CountryEntry {
        country: String,
        region: Option<String>,
        asn: Option<u32>,
        network: policy::IpNetwork,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CountryPolicy {
        entries: Vec<CountryEntry>,
        deny: BTreeSet<String>,
        observe: BTreeSet<String>,
        deny_regions: BTreeSet<String>,
        observe_regions: BTreeSet<String>,
        deny_asns: BTreeSet<u32>,
        observe_asns: BTreeSet<u32>,
    }

    impl CountryPolicy {
        fn entry_for(&self, client: IpAddr) -> Option<&CountryEntry> {
            self.entries
                .iter()
                .filter(|entry| entry.network.contains(client))
                .max_by_key(|entry| entry.network.prefix())
        }

        fn denied(&self, client: IpAddr) -> bool {
            self.entry_for(client).is_some_and(|entry| {
                self.deny.contains(&entry.country)
                    || entry
                        .region
                        .as_ref()
                        .is_some_and(|region| self.deny_regions.contains(region))
                    || entry.asn.is_some_and(|asn| self.deny_asns.contains(&asn))
            })
        }

        fn observed(&self, client: IpAddr) -> bool {
            self.entry_for(client).is_some_and(|entry| {
                self.observe.contains(&entry.country)
                    || entry
                        .region
                        .as_ref()
                        .is_some_and(|region| self.observe_regions.contains(region))
                    || entry
                        .asn
                        .is_some_and(|asn| self.observe_asns.contains(&asn))
            })
        }

        fn country_for(&self, client: IpAddr) -> Option<&str> {
            self.entry_for(client).map(|entry| entry.country.as_str())
        }
    }

    #[derive(Debug, Default)]
    struct RewriteTable {
        entries: HashMap<(String, u16), DnsAnswer>,
    }

    impl RewriteTable {
        fn len(&self) -> usize {
            self.entries.len()
        }

        fn answer(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
            self.entries
                .get(&(normalize(&query.name), query.qtype))
                .cloned()
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct SecurityConfig {
        #[serde(default = "default_reject_private_upstream_addresses")]
        pub reject_private_upstream_addresses: bool,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct PrivacyConfig {
        /// Enable the bounded in-memory query-decision log.
        #[serde(default)]
        pub query_log_enabled: bool,
        /// Maximum number of metadata-only entries retained.
        #[serde(default = "default_query_log_entries")]
        pub query_log_max_entries: usize,
        /// Maximum age of a metadata entry in seconds.
        #[serde(default = "default_query_log_retention_secs")]
        pub query_log_retention_secs: u64,
        /// Optional Proxima JSONL recording destination for the same
        /// metadata-only decision events. The file is append-only; operators
        /// must provision rotation and deletion according to their retention
        /// policy before enabling it.
        #[serde(default)]
        pub query_recording_path: Option<String>,
        /// Hard upper bound for the encoded JSONL recording file.
        #[serde(default = "default_query_recording_max_bytes")]
        pub query_recording_max_bytes: u64,
        /// Rotate the durable recording at startup when its byte ceiling is
        /// reached. Rotation retains at most `query_recording_max_files` old
        /// files alongside the active destination.
        #[serde(default)]
        pub query_recording_rotation_enabled: bool,
        /// Number of rotated durable recording files to retain.
        #[serde(default = "default_query_recording_max_files")]
        pub query_recording_max_files: usize,
    }

    impl Default for PrivacyConfig {
        fn default() -> Self {
            Self {
                query_log_enabled: false,
                query_log_max_entries: default_query_log_entries(),
                query_log_retention_secs: default_query_log_retention_secs(),
                query_recording_path: None,
                query_recording_max_bytes: default_query_recording_max_bytes(),
                query_recording_rotation_enabled: false,
                query_recording_max_files: default_query_recording_max_files(),
            }
        }
    }

    /// A Proxima recording sink with an exact encoded-byte ceiling. The
    /// reservation is made before forwarding to the existing sink, so an
    /// overflow never reaches the durable backend.
    pub struct BoundedQueryRecordingSink {
        inner: DynRecordingSink,
        reserved_bytes: AtomicU64,
        max_bytes: u64,
    }

    impl BoundedQueryRecordingSink {
        pub fn new(
            inner: DynRecordingSink,
            path: &std::path::Path,
            max_bytes: u64,
        ) -> Result<Self, ProximaError> {
            let existing_bytes = std::fs::metadata(path)
                .map_or(Ok(0), |metadata| Ok(metadata.len()))
                .map_err(|error: std::io::Error| {
                    ProximaError::Record(format!("inspect query recording: {error}"))
                })?;
            if existing_bytes > max_bytes {
                return Err(ProximaError::Record(format!(
                    "query recording already exceeds configured limit: {existing_bytes} > {max_bytes}"
                )));
            }
            Ok(Self {
                inner,
                reserved_bytes: AtomicU64::new(existing_bytes),
                max_bytes,
            })
        }

        fn reserve(&self, additional: u64) -> Result<(), ProximaError> {
            let mut current = self.reserved_bytes.load(Ordering::Acquire);
            loop {
                let next = current.checked_add(additional).ok_or_else(|| {
                    ProximaError::Record("query recording byte limit overflow".into())
                })?;
                if next > self.max_bytes {
                    return Err(ProximaError::Record(format!(
                        "query recording byte limit reached: {next} > {}",
                        self.max_bytes
                    )));
                }
                match self.reserved_bytes.compare_exchange(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(()),
                    Err(observed) => current = observed,
                }
            }
        }
    }

    impl RecordingSink for BoundedQueryRecordingSink {
        fn append<'lifetime>(
            &'lifetime self,
            event: RecordingEvent,
        ) -> RecordingAppendFuture<'lifetime> {
            let result = proxima::recording::jsonl::encode_jsonl_line(event.clone())
                .map_err(|error| ProximaError::Record(format!("encode query recording: {error}")))
                .and_then(|encoded| self.reserve(encoded.len() as u64 + 1).map(|()| event));
            match result {
                Ok(event) => self.inner.append(event),
                Err(error) => Box::pin(async move { Err(error) }),
            }
        }

        fn flush<'lifetime>(&'lifetime self) -> RecordingAppendFuture<'lifetime> {
            self.inner.flush()
        }
    }

    impl Default for SecurityConfig {
        fn default() -> Self {
            Self {
                reject_private_upstream_addresses: default_reject_private_upstream_addresses(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum UpstreamTransport {
        Udp,
        Tcp,
        Tls,
        Doh,
        /// DNS-over-QUIC; available when the `doq` feature is enabled.
        Doq,
    }

    impl Default for UpstreamTransport {
        fn default() -> Self {
            Self::Udp
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
        #[serde(default)]
        pub transport: UpstreamTransport,
        #[serde(default)]
        pub tls_server_name: Option<String>,
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
                transport: UpstreamTransport::Udp,
                tls_server_name: None,
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

    #[derive(Debug, Clone, Deserialize)]
    pub struct DhcpConfig {
        #[serde(default)]
        pub enabled: bool,
        #[serde(default = "default_dhcp_listen")]
        pub listen: String,
        #[serde(default = "default_dhcp_server")]
        pub server: String,
        #[serde(default = "default_dhcp_subnet_mask")]
        pub subnet_mask: String,
        #[serde(default = "default_dhcp_pool_start")]
        pub pool_start: String,
        #[serde(default = "default_dhcp_pool_end")]
        pub pool_end: String,
        #[serde(default)]
        pub router: Option<String>,
        #[serde(default)]
        pub dns: Option<String>,
        #[serde(default = "default_dhcp_lease_secs")]
        pub lease_secs: u32,
        #[serde(default = "default_dhcp_max_leases")]
        pub max_leases: usize,
    }

    impl Default for DhcpConfig {
        fn default() -> Self {
            Self {
                enabled: false,
                listen: default_dhcp_listen(),
                server: default_dhcp_server(),
                subnet_mask: default_dhcp_subnet_mask(),
                pool_start: default_dhcp_pool_start(),
                pool_end: default_dhcp_pool_end(),
                router: None,
                dns: None,
                lease_secs: default_dhcp_lease_secs(),
                max_leases: default_dhcp_max_leases(),
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

    #[derive(Debug, Clone, Deserialize, Default)]
    pub struct AdminConfig {
        /// Optional HTTP control-plane bind. Disabled when absent.
        pub listen: Option<String>,
        /// Required bearer token when `listen` is configured.
        pub token: Option<String>,
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
        pub regex_rules: Vec<RegexRuleConfig>,
        #[serde(default)]
        pub blocklists: Vec<String>,
        /// Optional bounded background reload interval. Zero disables polling.
        #[serde(default)]
        pub blocklist_reload_interval_secs: u64,
        #[serde(default)]
        pub rewrites: Vec<RewriteConfig>,
        #[serde(default)]
        pub profiles: Vec<ServiceProfileConfig>,
        #[serde(default)]
        pub client_groups: Vec<ClientGroupConfig>,
        #[serde(default)]
        pub client_identities: Vec<ClientIdentityConfig>,
        #[serde(default = "default_action")]
        pub default_action: Action,
    }
    impl Default for PolicyConfig {
        fn default() -> Self {
            Self {
                mode: default_mode(),
                domains: Vec::new(),
                rules: Vec::new(),
                regex_rules: Vec::new(),
                blocklists: Vec::new(),
                blocklist_reload_interval_secs: 0,
                rewrites: Vec::new(),
                profiles: Vec::new(),
                client_groups: Vec::new(),
                client_identities: Vec::new(),
                default_action: default_action(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct RegexRuleConfig {
        pub id: u32,
        pub pattern: String,
        pub action: Action,
        #[serde(default)]
        pub priority: i32,
        #[serde(default)]
        pub qtype: Option<u16>,
        #[serde(default)]
        pub qclass: Option<u16>,
        #[serde(default)]
        pub client: Option<IpAddr>,
        #[serde(default)]
        pub client_cidrs: Vec<String>,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ClientIdentityConfig {
        pub name: String,
        #[serde(default)]
        pub clients: Vec<IpAddr>,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct RewriteConfig {
        pub name: String,
        #[serde(default)]
        pub ipv4: Option<Ipv4Addr>,
        #[serde(default)]
        pub ipv6: Option<Ipv6Addr>,
        #[serde(default = "default_ttl")]
        pub ttl: u32,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ServiceProfileConfig {
        pub id: u32,
        pub name: String,
        pub domains: Vec<String>,
        pub action: Action,
        #[serde(default)]
        pub groups: Vec<String>,
        #[serde(default)]
        pub priority: i32,
        #[serde(default)]
        pub client_cidrs: Vec<String>,
        #[serde(default)]
        pub qtype: Option<u16>,
        #[serde(default)]
        pub qclass: Option<u16>,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ClientGroupConfig {
        pub name: String,
        #[serde(default)]
        pub client_addresses: Vec<IpAddr>,
        #[serde(default)]
        pub client_cidrs: Vec<String>,
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
    fn default_dhcp_listen() -> String {
        "0.0.0.0:67".into()
    }
    fn default_dhcp_server() -> String {
        "192.0.2.1".into()
    }
    fn default_dhcp_subnet_mask() -> String {
        "255.255.255.0".into()
    }
    fn default_dhcp_pool_start() -> String {
        "192.0.2.100".into()
    }
    fn default_dhcp_pool_end() -> String {
        "192.0.2.199".into()
    }
    fn default_dhcp_lease_secs() -> u32 {
        3600
    }
    fn default_dhcp_max_leases() -> usize {
        256
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

    fn default_query_log_entries() -> usize {
        1024
    }

    fn default_query_log_retention_secs() -> u64 {
        86_400
    }

    fn default_query_recording_max_bytes() -> u64 {
        64 * 1024 * 1024
    }

    fn default_query_recording_max_files() -> usize {
        3
    }

    fn default_max_cache_ttl_secs() -> u64 {
        86_400
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
    fn default_max_response_amplification() -> usize {
        4
    }
    fn default_reject_private_upstream_addresses() -> bool {
        true
    }
    fn default_max_inflight_requests() -> usize {
        1024
    }
    fn default_max_inflight_per_client() -> usize {
        64
    }

    fn default_max_client_abuse_violations() -> usize {
        8
    }

    fn default_client_abuse_window_secs() -> u64 {
        10
    }

    fn default_client_abuse_cooldown_secs() -> u64 {
        30
    }
    fn default_max_network_abuse_violations() -> usize {
        32
    }
    fn default_network_abuse_window_secs() -> u64 {
        10
    }
    fn default_network_abuse_cooldown_secs() -> u64 {
        30
    }
    fn default_network_abuse_ipv4_prefix() -> u8 {
        24
    }
    fn default_network_abuse_ipv6_prefix() -> u8 {
        64
    }
    fn default_max_queries_per_client_per_second() -> usize {
        100
    }

    fn default_max_queries_per_second() -> usize {
        10_000
    }
    fn default_max_response_bytes_per_client_per_second() -> usize {
        1_048_576
    }
    fn default_max_response_bytes_per_network_per_second() -> usize {
        4 * 1_048_576
    }
    fn default_max_response_bytes_per_second() -> usize {
        16 * 1_048_576
    }
    const MAX_BLOCKLIST_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_BLOCKLIST_LINE_BYTES: usize = 4096;
    const MAX_BLOCKLIST_PATHS: usize = 4096;
    const MAX_BLOCKLIST_PATH_BYTES: usize = 4096;
    const MAX_BLOCKLIST_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

    fn load_blocklists(paths: &[String]) -> Result<Vec<RuleConfig>, policy::PolicyError> {
        if paths.len() > MAX_BLOCKLIST_PATHS {
            return Err(policy::PolicyError::InvalidBlocklist {
                path: "<table>".into(),
                reason: format!("source count exceeds {MAX_BLOCKLIST_PATHS}"),
            });
        }
        let mut domains = BTreeSet::new();
        let mut exceptions = BTreeSet::new();
        let mut total_bytes = 0_u64;
        for path in paths {
            if path.len() > MAX_BLOCKLIST_PATH_BYTES {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: path.clone(),
                    reason: format!("path exceeds {MAX_BLOCKLIST_PATH_BYTES} bytes"),
                });
            }
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
            total_bytes = total_bytes.saturating_add(metadata.len());
            if total_bytes > MAX_BLOCKLIST_TOTAL_BYTES {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<table>".into(),
                    reason: format!("aggregate files exceed {MAX_BLOCKLIST_TOTAL_BYTES} bytes"),
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
                    let raw_domain = raw_domain.trim_end_matches('.').to_ascii_lowercase();
                    let (exception, domain) =
                        if let Some(stripped) = raw_domain.strip_prefix("@@||") {
                            (true, stripped.trim_end_matches('^').to_owned())
                        } else if let Some(stripped) = raw_domain.strip_prefix("||") {
                            (false, stripped.trim_end_matches('^').to_owned())
                        } else {
                            (false, raw_domain.clone())
                        };
                    if !valid_blocklist_domain(&domain) {
                        return Err(policy::PolicyError::InvalidBlocklist {
                            path: path.clone(),
                            reason: format!("invalid domain {raw_domain}"),
                        });
                    }
                    domains.insert(domain.clone());
                    if exception {
                        exceptions.insert(domain);
                    }
                    if domains.len() > policy::MAX_RULES / 2 {
                        return Err(policy::PolicyError::InvalidBlocklist {
                            path: path.clone(),
                            reason: format!("domain count exceeds {}", policy::MAX_RULES / 2),
                        });
                    }
                }
            }
        }
        let mut rules = Vec::with_capacity(domains.len().saturating_mul(2));
        for (index, domain) in domains.into_iter().enumerate() {
            let exception = exceptions.contains(&domain);
            let action = if exception {
                Action::Pass
            } else {
                Action::Nxdomain
            };
            let priority = if exception { i32::MAX } else { i32::MAX - 1 };
            let id = u32::MAX.saturating_sub((index.saturating_mul(2)) as u32);
            rules.push(RuleConfig {
                id,
                domain: domain.clone(),
                action,
                priority,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            });
            rules.push(RuleConfig {
                id: id.saturating_sub(1),
                domain: format!("*.{domain}"),
                action,
                priority,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            });
        }
        Ok(rules)
    }

    fn valid_blocklist_domain(domain: &str) -> bool {
        !domain.is_empty()
            && domain.len() <= policy::MAX_DOMAIN_BYTES
            && domain
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii())
    }

    const MAX_COUNTRY_MAP_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_COUNTRY_MAP_LINE_BYTES: usize = 256;
    const MAX_COUNTRY_SELECTORS: usize = 256;

    fn country_code(value: &str) -> Option<String> {
        (value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()))
            .then(|| value.to_ascii_uppercase())
    }

    fn region_code(value: &str) -> Option<String> {
        (!value.is_empty()
            && value.len() <= 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        .then(|| value.to_ascii_uppercase())
    }

    fn asn_number(value: &str) -> Option<u32> {
        let value = value.strip_prefix("AS").unwrap_or(value);
        let asn = value.parse::<u32>().ok()?;
        (asn != 0).then_some(asn)
    }

    fn load_country_policy(
        config: &CountryPolicyConfig,
    ) -> Result<Option<CountryPolicy>, policy::PolicyError> {
        if config.map_path.is_none()
            && config.deny.is_empty()
            && config.observe.is_empty()
            && config.deny_regions.is_empty()
            && config.observe_regions.is_empty()
            && config.deny_asns.is_empty()
            && config.observe_asns.is_empty()
        {
            return Ok(None);
        }
        let path =
            config
                .map_path
                .as_deref()
                .ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                    path: "<none>".into(),
                    reason: "map_path is required when country rules are configured".into(),
                })?;
        let deny: BTreeSet<String> = config
            .deny
            .iter()
            .map(|country| {
                country_code(country).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("invalid deny country code: {country}"),
                })
            })
            .collect::<Result<_, _>>()?;
        let observe: BTreeSet<String> = config
            .observe
            .iter()
            .map(|country| {
                country_code(country).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("invalid observe country code: {country}"),
                })
            })
            .collect::<Result<_, _>>()?;
        let deny_regions: BTreeSet<String> = config
            .deny_regions
            .iter()
            .map(|region| {
                region_code(region).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("invalid deny region: {region}"),
                })
            })
            .collect::<Result<_, _>>()?;
        let observe_regions: BTreeSet<String> = config
            .observe_regions
            .iter()
            .map(|region| {
                region_code(region).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("invalid observe region: {region}"),
                })
            })
            .collect::<Result<_, _>>()?;
        if config.deny_regions.len() > MAX_COUNTRY_SELECTORS
            || config.observe_regions.len() > MAX_COUNTRY_SELECTORS
            || config.deny_asns.len() > MAX_COUNTRY_SELECTORS
            || config.observe_asns.len() > MAX_COUNTRY_SELECTORS
        {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: format!("country selector count exceeds {MAX_COUNTRY_SELECTORS}"),
            });
        }
        let deny_asns: BTreeSet<u32> = config.deny_asns.iter().copied().collect();
        let observe_asns: BTreeSet<u32> = config.observe_asns.iter().copied().collect();
        if deny_asns.contains(&0) || observe_asns.contains(&0) {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: "ASN zero is invalid".into(),
            });
        }
        if deny.iter().any(|country| observe.contains(country)) {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: "a country cannot be both denied and observed".into(),
            });
        }
        if deny_regions
            .iter()
            .any(|region| observe_regions.contains(region))
            || deny_asns.iter().any(|asn| observe_asns.contains(asn))
        {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: "a region or ASN cannot be both denied and observed".into(),
            });
        }
        let metadata =
            std::fs::metadata(path).map_err(|error| policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: error.to_string(),
            })?;
        if let Some(max_age_secs) = config.max_age_secs {
            if max_age_secs == 0 {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: "max_age_secs must be non-zero when configured".into(),
                });
            }
            let modified =
                metadata
                    .modified()
                    .map_err(|error| policy::PolicyError::InvalidCountryMap {
                        path: path.into(),
                        reason: format!("cannot read map modification time: {error}"),
                    })?;
            let now = std::time::SystemTime::now();
            if !country_map_is_fresh(modified, now, max_age_secs) {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("map is older than configured {max_age_secs}s freshness bound"),
                });
            }
        }
        if metadata.len() > MAX_COUNTRY_MAP_BYTES {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: format!("file exceeds {MAX_COUNTRY_MAP_BYTES} bytes"),
            });
        }
        let contents = std::fs::read_to_string(path).map_err(|error| {
            policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: error.to_string(),
            }
        })?;
        let mut entries = Vec::new();
        for (line_number, raw_line) in contents.lines().enumerate() {
            if raw_line.len() > MAX_COUNTRY_MAP_LINE_BYTES {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!(
                        "line {} exceeds {MAX_COUNTRY_MAP_LINE_BYTES} bytes",
                        line_number + 1
                    ),
                });
            }
            let line = raw_line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if !(2..=4).contains(&fields.len()) {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!(
                        "line {} must contain COUNTRY CIDR [REGION] [ASN]",
                        line_number + 1
                    ),
                });
            }
            let country =
                country_code(fields[0]).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("line {} has an invalid country code", line_number + 1),
                })?;
            let network = policy::IpNetwork::parse(fields[1]).ok_or_else(|| {
                policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: format!("line {} has an invalid CIDR", line_number + 1),
                }
            })?;
            let region = fields
                .get(2)
                .filter(|value| **value != "-")
                .map(|value| {
                    region_code(value).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                        path: path.into(),
                        reason: format!("line {} has an invalid region", line_number + 1),
                    })
                })
                .transpose()?;
            let asn = fields
                .get(3)
                .filter(|value| **value != "-")
                .map(|value| {
                    asn_number(value).ok_or_else(|| policy::PolicyError::InvalidCountryMap {
                        path: path.into(),
                        reason: format!("line {} has an invalid ASN", line_number + 1),
                    })
                })
                .transpose()?;
            entries.push(CountryEntry {
                country,
                region,
                asn,
                network,
            });
        }
        if entries.is_empty() {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: "map contains no entries".into(),
            });
        }
        if entries.iter().any(|entry| {
            let denied = deny.contains(&entry.country)
                || entry
                    .region
                    .as_ref()
                    .is_some_and(|region| deny_regions.contains(region))
                || entry.asn.is_some_and(|asn| deny_asns.contains(&asn));
            let observed = observe.contains(&entry.country)
                || entry
                    .region
                    .as_ref()
                    .is_some_and(|region| observe_regions.contains(region))
                || entry.asn.is_some_and(|asn| observe_asns.contains(&asn));
            denied && observed
        }) {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: "a mapped entry cannot be both denied and observed".into(),
            });
        }
        Ok(Some(CountryPolicy {
            entries,
            deny,
            observe,
            deny_regions,
            observe_regions,
            deny_asns,
            observe_asns,
        }))
    }

    fn country_map_is_fresh(
        modified: std::time::SystemTime,
        now: std::time::SystemTime,
        max_age_secs: u64,
    ) -> bool {
        max_age_secs != 0
            && now
                .duration_since(modified)
                .map_or(false, |age| age <= Duration::from_secs(max_age_secs))
    }

    const MAX_REWRITES: usize = 10_000;

    const MAX_PROFILES: usize = 256;
    const MAX_CLIENT_GROUPS: usize = 256;
    const MAX_CLIENT_GROUP_ADDRESSES: usize = 1_024;

    #[derive(Clone)]
    struct ClientScope {
        client: Option<IpAddr>,
        client_cidrs: Vec<String>,
    }

    fn compile_profiles(
        profiles: &[ServiceProfileConfig],
        groups: &[ClientGroupConfig],
    ) -> Result<Vec<RuleConfig>, policy::PolicyError> {
        if profiles.len() > MAX_PROFILES {
            return Err(policy::PolicyError::InvalidProfile {
                name: "<table>".into(),
                reason: format!("profile count exceeds {MAX_PROFILES}"),
            });
        }
        let mut group_map = std::collections::BTreeMap::new();
        if groups.len() > MAX_CLIENT_GROUPS {
            return Err(policy::PolicyError::InvalidProfile {
                name: "<groups>".into(),
                reason: format!("client-group count exceeds {MAX_CLIENT_GROUPS}"),
            });
        }
        for group in groups {
            let name = group.name.trim();
            if name.is_empty() || !name.is_ascii() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: group.name.clone(),
                    reason: "group name must be non-empty ASCII".into(),
                });
            }
            if group.client_cidrs.is_empty() && group.client_addresses.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: group.name.clone(),
                    reason: "group must contain at least one client address or CIDR".into(),
                });
            }
            if group.client_addresses.len() > MAX_CLIENT_GROUP_ADDRESSES {
                return Err(policy::PolicyError::InvalidProfile {
                    name: group.name.clone(),
                    reason: format!("client address count exceeds {MAX_CLIENT_GROUP_ADDRESSES}"),
                });
            }
            let mut unique_addresses = BTreeSet::new();
            if group
                .client_addresses
                .iter()
                .any(|address| !unique_addresses.insert(*address))
            {
                return Err(policy::PolicyError::InvalidProfile {
                    name: group.name.clone(),
                    reason: "client addresses must be unique".into(),
                });
            }
            let mut scopes = group
                .client_addresses
                .iter()
                .copied()
                .map(|client| ClientScope {
                    client: Some(client),
                    client_cidrs: Vec::new(),
                })
                .collect::<Vec<_>>();
            if !group.client_cidrs.is_empty() {
                scopes.push(ClientScope {
                    client: None,
                    client_cidrs: group.client_cidrs.clone(),
                });
            }
            if group_map
                .insert(name.to_ascii_lowercase(), scopes)
                .is_some()
            {
                return Err(policy::PolicyError::InvalidProfile {
                    name: group.name.clone(),
                    reason: "group name must be unique".into(),
                });
            }
        }
        let mut names = BTreeSet::new();
        let mut rules = Vec::new();
        let mut total_domains = 0usize;
        for profile in profiles {
            let name = profile.name.trim();
            if name.is_empty() || !name.is_ascii() || !names.insert(name.to_ascii_lowercase()) {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: "name must be non-empty ASCII and unique".into(),
                });
            }
            if profile.domains.is_empty() || profile.domains.len() > policy::MAX_RULES {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: "domains must be non-empty and bounded".into(),
                });
            }
            total_domains = total_domains.saturating_add(profile.domains.len());
            if total_domains > policy::MAX_RULES {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: format!("combined domain count exceeds {}", policy::MAX_RULES),
                });
            }
            if !profile.groups.is_empty() && !profile.client_cidrs.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: "groups and client_cidrs are mutually exclusive".into(),
                });
            }
            let group_scopes = if profile.groups.is_empty() {
                vec![ClientScope {
                    client: None,
                    client_cidrs: profile.client_cidrs.clone(),
                }]
            } else {
                profile
                    .groups
                    .iter()
                    .map(|group| {
                        group_map
                            .get(&group.trim().to_ascii_lowercase())
                            .cloned()
                            .ok_or_else(|| policy::PolicyError::InvalidProfile {
                                name: profile.name.clone(),
                                reason: format!("unknown client group {group}"),
                            })
                    })
                    .collect::<Result<Vec<Vec<_>>, _>>()?
                    .into_iter()
                    .flatten()
                    .collect()
            };
            let expanded_domains = profile
                .domains
                .len()
                .checked_mul(group_scopes.len())
                .ok_or_else(|| policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: "expanded domain count overflows".into(),
                })?;
            if expanded_domains > policy::MAX_RULES {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: format!("expanded domain count exceeds {}", policy::MAX_RULES),
                });
            }
            for (group_index, scope) in group_scopes.iter().enumerate() {
                let group_offset = (group_index * profile.domains.len()) as u32;
                for (offset, raw_domain) in profile.domains.iter().enumerate() {
                    let id = profile
                        .id
                        .checked_add(group_offset)
                        .and_then(|id| id.checked_add(offset as u32))
                        .ok_or_else(|| policy::PolicyError::InvalidProfile {
                            name: profile.name.clone(),
                            reason: "id range overflows".into(),
                        })?;
                    let domain = normalize(raw_domain);
                    if domain.is_empty() || domain.len() > policy::MAX_DOMAIN_BYTES {
                        return Err(policy::PolicyError::InvalidProfile {
                            name: profile.name.clone(),
                            reason: format!("invalid domain {domain}"),
                        });
                    }
                    rules.push(RuleConfig {
                        id,
                        domain,
                        action: profile.action,
                        priority: profile.priority,
                        qtype: profile.qtype,
                        qclass: profile.qclass,
                        client: scope.client,
                        client_cidr: None,
                        client_cidrs: scope.client_cidrs.clone(),
                        client_identity: None,
                    });
                }
            }
        }
        Ok(rules)
    }

    fn compile_rewrites(configs: &[RewriteConfig]) -> Result<RewriteTable, policy::PolicyError> {
        if configs.len() > MAX_REWRITES {
            return Err(policy::PolicyError::InvalidRewrite {
                name: "<table>".into(),
                reason: format!("entry count exceeds {MAX_REWRITES}"),
            });
        }
        let mut entries = HashMap::new();
        for config in configs {
            let name = normalize(&config.name);
            if name.is_empty() || !valid_dns_name(&name) {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: config.name.clone(),
                    reason: "name must be a non-empty ASCII DNS name".into(),
                });
            }
            if config.ipv4.is_none() && config.ipv6.is_none() {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: config.name.clone(),
                    reason: "at least one of ipv4 or ipv6 is required".into(),
                });
            }
            let record_name = format!("{name}.");
            if let Some(address) = config.ipv4 {
                let key = (name.clone(), 1);
                if entries.contains_key(&key) {
                    return Err(policy::PolicyError::InvalidRewrite {
                        name: config.name.clone(),
                        reason: "duplicate A rewrite".into(),
                    });
                }
                entries.insert(
                    key,
                    DnsAnswer::ok(vec![DnsAnswerRecord {
                        name: record_name.clone(),
                        rtype: 1,
                        rclass: 1,
                        ttl: config.ttl,
                        rdata: proxima_protocols::dns::encode::ipv4_rdata(address).to_vec(),
                    }]),
                );
            }
            if let Some(address) = config.ipv6 {
                let key = (name, 28);
                if entries.contains_key(&key) {
                    return Err(policy::PolicyError::InvalidRewrite {
                        name: config.name.clone(),
                        reason: "duplicate AAAA rewrite".into(),
                    });
                }
                entries.insert(
                    key,
                    DnsAnswer::ok(vec![DnsAnswerRecord {
                        name: record_name,
                        rtype: 28,
                        rclass: 1,
                        ttl: config.ttl,
                        rdata: proxima_protocols::dns::encode::ipv6_rdata(address).to_vec(),
                    }]),
                );
            }
        }
        Ok(RewriteTable { entries })
    }
    fn default_breaker_failures() -> u32 {
        3
    }
    fn default_breaker_cooldown_secs() -> u64 {
        30
    }

    fn valid_tls_server_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 253 || !name.is_ascii() {
            return false;
        }
        if name.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
        name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
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

    /// A bounded Proxima recording sink for privacy-safe decision metadata.
    /// Query names, client addresses, credentials, and wire payloads are never
    /// accepted by this sink.
    pub struct QueryLog {
        entries: Live<VecDeque<RecordingEvent>>,
        control: LiveControl<VecDeque<RecordingEvent>>,
        max_entries: usize,
        retention: Duration,
    }

    impl QueryLog {
        fn new(config: &PrivacyConfig) -> Self {
            let (entries, control) = live(VecDeque::with_capacity(config.query_log_max_entries));
            Self {
                entries,
                control,
                max_entries: config.query_log_max_entries,
                retention: Duration::from_secs(config.query_log_retention_secs),
            }
        }

        fn append_event(&self, event: RecordingEvent) {
            let cutoff = event
                .ts_ms
                .saturating_sub(self.retention.as_millis().min(u128::from(u64::MAX)) as u64);
            self.control.update(|current| {
                let mut entries = current.clone();
                while entries.front().is_some_and(|old| old.ts_ms < cutoff) {
                    entries.pop_front();
                }
                entries.push_back(event.clone());
                while entries.len() > self.max_entries {
                    entries.pop_front();
                }
                entries
            });
        }

        pub fn snapshot(&self) -> Vec<RecordingEvent> {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| {
                    duration.as_millis().min(u128::from(u64::MAX)) as u64
                });
            let cutoff =
                now_ms.saturating_sub(self.retention.as_millis().min(u128::from(u64::MAX)) as u64);
            self.control.update(|current| {
                let mut entries = current.clone();
                while entries.front().is_some_and(|old| old.ts_ms < cutoff) {
                    entries.pop_front();
                }
                entries
            });
            self.entries
                .read(|entries| entries.iter().cloned().collect())
        }

        pub fn clear(&self) -> usize {
            let count = self.entries.read(VecDeque::len);
            self.control
                .replace(VecDeque::with_capacity(self.max_entries));
            count
        }
    }

    impl RecordingSink for QueryLog {
        fn append<'lifetime>(
            &'lifetime self,
            event: RecordingEvent,
        ) -> RecordingAppendFuture<'lifetime> {
            Box::pin(async move {
                self.append_event(event);
                Ok(())
            })
        }

        fn flush<'lifetime>(&'lifetime self) -> RecordingAppendFuture<'lifetime> {
            Box::pin(async { Ok(()) })
        }
    }

    pub struct Policy {
        config: Config,
        base_rules: Mutex<Vec<RuleConfig>>,
        explicit_rules: Mutex<Vec<RuleConfig>>,
        blocklist_rules: Mutex<Vec<RuleConfig>>,
        blocklist_paths: Mutex<Vec<String>>,
        profiles: RwLock<Vec<ServiceProfileConfig>>,
        client_groups: RwLock<Vec<ClientGroupConfig>>,
        client_identities: Live<Vec<ClientIdentityConfig>>,
        client_identity_control: LiveControl<Vec<ClientIdentityConfig>>,
        country_policy: Live<Option<CountryPolicy>>,
        country_policy_control: LiveControl<Option<CountryPolicy>>,
        reload_lock: RwLock<()>,
        legacy_domains: RwLock<Vec<String>>,
        legacy_mode: RwLock<Mode>,
        default_action: RwLock<Action>,
        rewrite_configs: RwLock<Vec<RewriteConfig>>,
        rewrites: RwLock<RewriteTable>,
        reference: PolicyStore,
        regex_rules: Mutex<Vec<RegexRule>>,
        domain_rules_configured: AtomicBool,
        rules_configured: AtomicBool,
        policy_generation: AtomicU64,
        telemetry: Option<TelemetryHandle>,
        recording: Option<DynRecordingSink>,
        query_log: Option<Arc<QueryLog>>,
        admission: Live<AdmissionConfig>,
        admission_control: LiveControl<AdmissionConfig>,
        upstream: Option<DnsClientUpstream>,
        upstream_slots: Option<Arc<Semaphore>>,
        cache: Live<DnsCache>,
        cache_control: LiveControl<DnsCache>,
        breaker: Arc<Mutex<ProximaCircuitBreaker>>,
        breaker_epoch: Instant,
        request_slots: Arc<Semaphore>,
        client_admission: ClientAdmissionTable,
        client_rates: KeyedWindowBudgetTable,
        global_rate: AtomicWindowBudget,
        client_response_budgets: KeyedWindowBudgetTable,
        network_response_budgets: KeyedWindowBudgetTable,
        global_response_budget: AtomicWindowBudget,
        client_abuse: KeyedWindowBudgetTable,
        network_abuse: KeyedWindowBudgetTable,
    }

    struct RegexRule {
        id: u32,
        pattern: regex::Regex,
        action: Action,
        priority: i32,
        qtype: Option<u16>,
        qclass: Option<u16>,
        client: Option<IpAddr>,
        client_networks: Vec<policy::IpNetwork>,
        client_cidrs: Vec<String>,
    }

    fn compile_regex_rules(
        configs: &[RegexRuleConfig],
        mut rule_ids: BTreeSet<u32>,
    ) -> Result<Vec<RegexRule>, policy::PolicyError> {
        if configs.len() > MAX_REGEX_RULES {
            return Err(policy::PolicyError::TooManyRegexRules {
                max: MAX_REGEX_RULES,
            });
        }
        let mut regex_rules = Vec::with_capacity(configs.len());
        for rule in configs {
            if rule.pattern.len() > MAX_REGEX_PATTERN_BYTES {
                return Err(policy::PolicyError::InvalidRegex {
                    id: rule.id,
                    reason: format!("pattern exceeds {MAX_REGEX_PATTERN_BYTES} bytes"),
                });
            }
            if !rule_ids.insert(rule.id) {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let pattern = regex::RegexBuilder::new(&rule.pattern)
                .size_limit(MAX_REGEX_PROGRAM_BYTES)
                .dfa_size_limit(MAX_REGEX_PROGRAM_BYTES)
                .build()
                .map_err(|error| policy::PolicyError::InvalidRegex {
                    id: rule.id,
                    reason: error.to_string(),
                })?;
            if rule.client.is_some() && !rule.client_cidrs.is_empty() {
                return Err(policy::PolicyError::InvalidClientCidr {
                    id: rule.id,
                    value: "exact client and client_cidrs are mutually exclusive".into(),
                });
            }
            if rule.client_cidrs.len() > policy::MAX_CLIENT_CIDRS {
                return Err(policy::PolicyError::InvalidClientCidr {
                    id: rule.id,
                    value: format!("more than {} networks", policy::MAX_CLIENT_CIDRS),
                });
            }
            let client_networks = rule
                .client_cidrs
                .iter()
                .map(|value| {
                    policy::IpNetwork::parse(value).ok_or_else(|| {
                        policy::PolicyError::InvalidClientCidr {
                            id: rule.id,
                            value: value.clone(),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            regex_rules.push(RegexRule {
                id: rule.id,
                pattern,
                action: rule.action,
                priority: rule.priority,
                qtype: rule.qtype,
                qclass: rule.qclass,
                client: rule.client,
                client_networks,
                client_cidrs: rule.client_cidrs.clone(),
            });
        }
        Ok(regex_rules)
    }

    impl Policy {
        pub fn new(mut config: Config) -> Result<Self, policy::PolicyError> {
            validate_dhcp(&config.dhcp)?;
            if config.cache.max_ttl_secs == 0 {
                return Err(policy::PolicyError::InvalidCache {
                    reason: "max_ttl_secs must be non-zero".into(),
                });
            }
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
            if config.admission.max_response_amplification == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_response_amplification must be non-zero".into(),
                });
            }
            if config.admission.max_inflight_requests == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_inflight_requests must be non-zero".into(),
                });
            }
            if config.admission.max_queries_per_second == 0
                || config.admission.max_queries_per_second > MAX_GLOBAL_QUERIES_PER_SECOND
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: format!(
                        "max_queries_per_second must be between 1 and {MAX_GLOBAL_QUERIES_PER_SECOND}"
                    ),
                });
            }
            if config.admission.max_inflight_per_client == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_inflight_per_client must be non-zero".into(),
                });
            }
            if config.admission.max_queries_per_client_per_second == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_queries_per_client_per_second must be non-zero".into(),
                });
            }
            if config.admission.max_response_bytes_per_client_per_second == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_response_bytes_per_client_per_second must be non-zero".into(),
                });
            }
            if config.admission.max_response_bytes_per_network_per_second == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_response_bytes_per_network_per_second must be non-zero".into(),
                });
            }
            if config.admission.max_response_bytes_per_second == 0 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_response_bytes_per_second must be non-zero".into(),
                });
            }
            if config.admission.max_network_abuse_violations == 0
                || config.admission.network_abuse_window_secs == 0
                || config.admission.network_abuse_cooldown_secs == 0
                || config.admission.network_abuse_ipv4_prefix > 32
                || config.admission.network_abuse_ipv6_prefix > 128
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "network abuse limits or prefixes are invalid".into(),
                });
            }
            if config.admission.max_client_abuse_violations == 0
                || config.admission.client_abuse_window_secs == 0
                || config.admission.client_abuse_cooldown_secs == 0
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "client abuse limits must be non-zero".into(),
                });
            }
            if config.privacy.query_log_enabled
                && (config.privacy.query_log_max_entries == 0
                    || config.privacy.query_log_max_entries > 65_536
                    || config.privacy.query_log_retention_secs == 0)
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "enabled query log bounds are invalid".into(),
                });
            }
            if config
                .privacy
                .query_recording_path
                .as_deref()
                .is_some_and(|path| path.is_empty() || path.len() > 4_096)
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "query recording path must be between 1 and 4096 bytes".into(),
                });
            }
            if config.privacy.query_recording_path.is_some()
                && (config.privacy.query_recording_max_bytes == 0
                    || config.privacy.query_recording_max_bytes > 1 << 30)
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "query recording max bytes must be between 1 and 1073741824".into(),
                });
            }
            if config.privacy.query_recording_path.is_some()
                && (config.privacy.query_recording_max_files == 0
                    || config.privacy.query_recording_max_files > 16)
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "query recording max files must be between 1 and 16".into(),
                });
            }
            if config.policy.blocklist_reload_interval_secs > MAX_BLOCKLIST_RELOAD_INTERVAL_SECS {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<config>".into(),
                    reason: format!(
                        "reload interval exceeds {MAX_BLOCKLIST_RELOAD_INTERVAL_SECS} seconds"
                    ),
                });
            }
            if config.country_policy.reload_interval_secs > MAX_BLOCKLIST_RELOAD_INTERVAL_SECS {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: "<config>".into(),
                    reason: format!(
                        "reload interval exceeds {MAX_BLOCKLIST_RELOAD_INTERVAL_SECS} seconds"
                    ),
                });
            }
            let profile_rules =
                compile_profiles(&config.policy.profiles, &config.policy.client_groups)?;
            let explicit_rules = config.policy.rules.clone();
            config.policy.rules.extend(profile_rules);
            let base_rules = config.policy.rules.clone();
            let blocklist_rules = load_blocklists(&config.policy.blocklists)?;
            let retained_blocklist_rules = blocklist_rules.clone();
            let country_policy = load_country_policy(&config.country_policy)?;
            let rewrites = compile_rewrites(&config.policy.rewrites)?;
            config.policy.rules.extend(blocklist_rules);
            let mut rule_ids = BTreeSet::new();
            for rule in &config.policy.rules {
                rule_ids.insert(rule.id);
            }
            let regex_rules = compile_regex_rules(&config.policy.regex_rules, rule_ids)?;
            config.policy.domains = config.policy.domains.into_iter().map(normalize).collect();
            let reference = PolicyStore::new(&config.policy.rules)?;
            let (cache, cache_control) = live(DnsCache::new(&config.cache));
            let max_inflight_requests = config.admission.max_inflight_requests;
            let breaker = Arc::new(Mutex::new(ProximaCircuitBreaker::new(
                config
                    .upstream
                    .as_ref()
                    .map_or(default_breaker_failures(), |upstream| {
                        upstream.breaker_failures
                    }),
                Duration::from_secs(
                    config
                        .upstream
                        .as_ref()
                        .map_or(default_breaker_cooldown_secs(), |upstream| {
                            upstream.breaker_cooldown_secs
                        }),
                ),
                1,
            )));
            let rules_configured =
                !config.policy.rules.is_empty() || !config.policy.regex_rules.is_empty();
            let domain_rules_configured = !config.policy.rules.is_empty();
            let query_log = config
                .privacy
                .query_log_enabled
                .then(|| Arc::new(QueryLog::new(&config.privacy)));
            let profiles = config.policy.profiles.clone();
            let client_groups = config.policy.client_groups.clone();
            let client_identities = validate_client_identities(&config.policy.client_identities)?;
            let blocklist_paths = config.policy.blocklists.clone();
            let legacy_domains = config.policy.domains.clone();
            let legacy_mode = config.policy.mode;
            let default_action = config.policy.default_action;
            let rewrite_configs = config.policy.rewrites.clone();
            let admission = config.admission.clone();
            let (client_identities, client_identity_control) = live(client_identities);
            let (country_policy, country_policy_control) = live(country_policy);
            let (admission, admission_control) = live(admission);
            let policy = Self {
                config,
                base_rules: Mutex::new(base_rules),
                explicit_rules: Mutex::new(explicit_rules),
                blocklist_rules: Mutex::new(retained_blocklist_rules),
                blocklist_paths: Mutex::new(blocklist_paths),
                profiles: RwLock::new(profiles),
                client_groups: RwLock::new(client_groups),
                client_identities,
                client_identity_control,
                country_policy,
                country_policy_control,
                reload_lock: RwLock::new(()),
                legacy_domains: RwLock::new(legacy_domains),
                legacy_mode: RwLock::new(legacy_mode),
                default_action: RwLock::new(default_action),
                rewrite_configs: RwLock::new(rewrite_configs),
                rewrites: RwLock::new(rewrites),
                reference,
                regex_rules: Mutex::new(regex_rules),
                domain_rules_configured: AtomicBool::new(domain_rules_configured),
                rules_configured: AtomicBool::new(rules_configured),
                policy_generation: AtomicU64::new(1),
                telemetry: None,
                recording: None,
                query_log,
                admission,
                admission_control,
                upstream: None,
                upstream_slots: None,
                cache,
                cache_control,
                breaker,
                breaker_epoch: Instant::now(),
                request_slots: Arc::new(Semaphore::new(max_inflight_requests)),
                client_admission: ClientAdmissionTable::new(),
                client_rates: KeyedWindowBudgetTable::new(),
                global_rate: AtomicWindowBudget::new(),
                client_response_budgets: KeyedWindowBudgetTable::new(),
                network_response_budgets: KeyedWindowBudgetTable::new(),
                global_response_budget: AtomicWindowBudget::new(),
                client_abuse: KeyedWindowBudgetTable::new(),
                network_abuse: KeyedWindowBudgetTable::new(),
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

        /// Attach Proxima's existing recording sink. Blackhole emits only
        /// action and DNS type metadata; names, client identity, and wire
        /// payloads never enter the recording event.
        #[must_use]
        pub fn with_recording_sink(mut self, recording: DynRecordingSink) -> Self {
            self.recording = Some(recording);
            self
        }

        pub fn query_log(&self) -> Option<Arc<QueryLog>> {
            self.query_log.as_ref().map(Arc::clone)
        }

        /// Attach a Proxima recording backend behind its bounded recording
        /// queue. The newest metadata is retained when the queue is full;
        /// callers must still configure the backend's retention policy.
        #[must_use]
        pub fn with_bounded_recording_sink(
            self,
            backend: DynRecordingSink,
            capacity: usize,
        ) -> Self {
            let bounded = BoundedRecordingSink::new(backend, capacity.max(1), FailMode::DropOldest);
            self.with_recording_sink(Arc::new(bounded))
        }

        /// Validate and atomically publish a complete replacement rule table.
        /// Existing readers finish against their old immutable snapshot; new
        /// readers observe the replacement as one generation.
        pub fn reload_rules(
            &self,
            rules: &[RuleConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let generated = self.current_profile_rules()?;
            let mut combined = rules.to_vec();
            combined.extend(generated);
            self.publish_rules_locked(&combined, rules, &mut base_rules, "rules", started)
        }

        /// Atomically replace the live admission limits. The in-flight
        /// semaphore is intentionally fixed at startup; changing its capacity
        /// would make existing permits ambiguous, so such a replacement is
        /// rejected without changing any live limits.
        pub fn reload_admission(
            &self,
            admission: &AdmissionConfig,
        ) -> Result<ReloadState, policy::PolicyError> {
            if admission.max_inflight_requests != self.config.admission.max_inflight_requests {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_inflight_requests is startup-only".into(),
                });
            }
            if admission.max_name_bytes == 0 || admission.max_name_bytes > 253 {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "max_name_bytes must be between 1 and 253".into(),
                });
            }
            if admission.max_response_records == 0
                || admission.max_response_bytes < 12
                || admission.max_response_amplification == 0
                || admission.max_queries_per_second == 0
                || admission.max_queries_per_second > MAX_GLOBAL_QUERIES_PER_SECOND
                || admission.max_inflight_per_client == 0
                || admission.max_queries_per_client_per_second == 0
                || admission.max_response_bytes_per_client_per_second == 0
                || admission.max_response_bytes_per_network_per_second == 0
                || admission.max_response_bytes_per_second == 0
                || admission.max_network_abuse_violations == 0
                || admission.network_abuse_window_secs == 0
                || admission.network_abuse_cooldown_secs == 0
                || admission.network_abuse_ipv4_prefix > 32
                || admission.network_abuse_ipv6_prefix > 128
                || admission.max_client_abuse_violations == 0
                || admission.client_abuse_window_secs == 0
                || admission.client_abuse_cooldown_secs == 0
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "admission limits are invalid or zero".into(),
                });
            }
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            self.admission_control.replace(admission.clone());
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("admission", started);
            Ok(ReloadState::Published)
        }

        /// Append validated rules to the current authoritative table and
        /// publish the combined snapshot atomically. The base-table lock is
        /// held through validation and publication so concurrent appenders do
        /// not lose one another's updates.
        pub fn append_rules(
            &self,
            additions: &[RuleConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let mut explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            explicit.extend_from_slice(additions);
            let mut combined = explicit.clone();
            combined.extend(self.current_profile_rules()?);
            self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "rules_append",
                started,
            )
        }

        /// Atomically replace or add explicit rules by stable ID. Existing
        /// IDs are edited in place; new IDs are appended. Generated profile
        /// and blocklist rules remain managed by their own tables.
        pub fn upsert_rules(
            &self,
            updates: &[RuleConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if updates.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<rule-upsert>".into(),
                    reason: "at least one rule is required".into(),
                });
            }
            let mut seen = BTreeSet::new();
            for rule in updates {
                if !seen.insert(rule.id) {
                    return Err(policy::PolicyError::DuplicateRule { id: rule.id });
                }
            }
            let mut explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            for update in updates {
                if let Some(existing) = explicit.iter_mut().find(|rule| rule.id == update.id) {
                    *existing = update.clone();
                } else {
                    explicit.push(update.clone());
                }
            }
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let mut combined = explicit.clone();
            combined.extend(self.current_profile_rules()?);
            self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "rules_upsert",
                started,
            )
        }

        /// Remove every cached answer and return the number of entries
        /// deleted. The operation is bounded by the configured cache size.
        pub fn clear_cache(&self) -> usize {
            let removed = self.cache.read(|cache| cache.entries.len());
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            removed
        }

        fn cache_fresh(&self, key: &CacheKey) -> Option<DnsAnswer> {
            self.cache.read(|cache| cache.fresh(key))
        }

        fn cache_stale(&self, key: &CacheKey) -> Option<DnsAnswer> {
            self.cache.read(|cache| cache.stale_answer(key))
        }

        fn cache_insert(&self, key: CacheKey, answer: DnsAnswer, now: Instant) {
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.insert(key.clone(), answer.clone(), now);
                next
            });
        }

        /// Remove rules by stable ID and publish the resulting authoritative
        /// table atomically. Unknown IDs are rejected so an operator cannot
        /// mistake a no-op for a successful destructive update.
        pub fn remove_rules(&self, ids: &[u32]) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let requested = ids.iter().copied().collect::<BTreeSet<_>>();
            if requested.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<rule-removal>".into(),
                    reason: "at least one rule ID is required".into(),
                });
            }
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            let original_len = explicit.len();
            let mut next = explicit.clone();
            next.retain(|rule| !requested.contains(&rule.id));
            if next.len() == original_len {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<rule-removal>".into(),
                    reason: "no requested rule ID exists".into(),
                });
            }
            let mut combined = next.clone();
            combined.extend(self.current_profile_rules()?);
            self.publish_rules_locked(&combined, &next, &mut base_rules, "rules_remove", started)
        }

        fn current_profile_rules(&self) -> Result<Vec<RuleConfig>, policy::PolicyError> {
            compile_profiles(
                &self.profiles.read().expect("profiles lock"),
                &self.client_groups.read().expect("client groups lock"),
            )
        }

        fn publish_rules_locked(
            &self,
            rules: &[RuleConfig],
            explicit_rules: &[RuleConfig],
            base_rules: &mut Vec<RuleConfig>,
            reload_kind: &'static str,
            started: Instant,
        ) -> Result<ReloadState, policy::PolicyError> {
            let mut published_rules = rules.to_vec();
            published_rules.extend(
                self.blocklist_rules
                    .lock()
                    .expect("blocklist rules lock")
                    .iter()
                    .cloned(),
            );
            let regex_ids = self
                .regex_rules
                .lock()
                .expect("regex rules lock")
                .iter()
                .map(|rule| rule.id)
                .collect::<BTreeSet<_>>();
            if let Some(rule) = published_rules
                .iter()
                .find(|rule| regex_ids.contains(&rule.id))
            {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let published = self.reference.reload(&published_rules)?;
            *base_rules = rules.to_vec();
            *self.explicit_rules.lock().expect("explicit rules lock") = explicit_rules.to_vec();
            self.domain_rules_configured
                .store(!published_rules.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !published_rules.is_empty()
                    || !self
                        .regex_rules
                        .lock()
                        .expect("regex rules lock")
                        .is_empty(),
                Ordering::Release,
            );
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency(reload_kind, started);
            Ok(published)
        }

        /// Reload the configured blocklist files and publish their rules as
        /// one immutable snapshot alongside the current explicit rules.
        /// Files are read and validated before the live snapshot is touched,
        /// so an unreadable or malformed update keeps the last good generation.
        pub fn reload_blocklists(&self) -> Result<ReloadState, policy::PolicyError> {
            let paths = self
                .blocklist_paths
                .lock()
                .expect("blocklist paths lock")
                .clone();
            self.replace_blocklist_sources(&paths)
        }

        /// Replace the configured blocklist source paths and publish their
        /// validated rules atomically. A failed read, parse, or compilation
        /// leaves both the previous paths and the previous live rules intact.
        pub fn replace_blocklist_sources(
            &self,
            paths: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let replacement = load_blocklists(&paths)?;
            let base_rules = self.base_rules.lock().expect("base rules lock");
            let mut rules = base_rules.clone();
            rules.extend(replacement.iter().cloned());
            let regex_ids = self
                .regex_rules
                .lock()
                .expect("regex rules lock")
                .iter()
                .map(|rule| rule.id)
                .collect::<BTreeSet<_>>();
            if let Some(rule) = rules.iter().find(|rule| regex_ids.contains(&rule.id)) {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let published = self.reference.reload(&rules)?;
            *self.blocklist_paths.lock().expect("blocklist paths lock") = paths.to_vec();
            *self.blocklist_rules.lock().expect("blocklist rules lock") = replacement;
            self.domain_rules_configured
                .store(!rules.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !rules.is_empty()
                    || !self
                        .regex_rules
                        .lock()
                        .expect("regex rules lock")
                        .is_empty(),
                Ordering::Release,
            );
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("blocklists", started);
            Ok(published)
        }

        /// Reload configured blocklists only when the resulting bounded rule
        /// set changes. This is used by the optional Proxima interval source;
        /// malformed or unreadable replacements still fail closed and retain
        /// the last valid snapshot.
        pub fn reload_blocklists_if_changed(&self) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let paths = self
                .blocklist_paths
                .lock()
                .expect("blocklist paths lock")
                .clone();
            let replacement = load_blocklists(&paths)?;
            if replacement == *self.blocklist_rules.lock().expect("blocklist rules lock") {
                self.observe_reload_latency("blocklists_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let base_rules = self.base_rules.lock().expect("base rules lock");
            let mut rules = base_rules.clone();
            rules.extend(replacement.iter().cloned());
            let regex_ids = self
                .regex_rules
                .lock()
                .expect("regex rules lock")
                .iter()
                .map(|rule| rule.id)
                .collect::<BTreeSet<_>>();
            if let Some(rule) = rules.iter().find(|rule| regex_ids.contains(&rule.id)) {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let published = self.reference.reload(&rules)?;
            *self.blocklist_rules.lock().expect("blocklist rules lock") = replacement;
            self.domain_rules_configured
                .store(!rules.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !rules.is_empty()
                    || !self
                        .regex_rules
                        .lock()
                        .expect("regex rules lock")
                        .is_empty(),
                Ordering::Release,
            );
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("blocklists", started);
            Ok(published)
        }

        /// Reload the configured country/CIDR map and publish it only after
        /// the complete replacement has passed bounded validation.
        pub fn reload_country_policy(&self) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let next = load_country_policy(&self.config.country_policy)?;
            self.country_policy_control.replace(next);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("country", started);
            Ok(ReloadState::Published)
        }

        /// Reload the country map only when its bounded contents changed.
        pub fn reload_country_policy_if_changed(&self) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let next = load_country_policy(&self.config.country_policy)?;
            let unchanged = self.country_policy.snapshot().as_ref() == &next;
            if unchanged {
                self.observe_reload_latency("country_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.country_policy_control.replace(next);
            self.observe_reload_latency("country", started);
            Ok(ReloadState::Published)
        }

        /// Atomically replace the configured service profiles and client
        /// groups. Explicit domain rules remain intact; the generated profile
        /// expansion is validated and published as one immutable snapshot.
        pub fn reload_profiles(
            &self,
            profiles: &[ServiceProfileConfig],
            client_groups: &[ClientGroupConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let generated = compile_profiles(profiles, client_groups)?;
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let published = self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "profiles",
                started,
            )?;
            *self.profiles.write().expect("profiles lock") = profiles.to_vec();
            *self.client_groups.write().expect("client groups lock") = client_groups.to_vec();
            Ok(published)
        }

        /// Validate and atomically publish client-address identity mappings.
        ///
        /// The identity lookup reads the Proxima [`Live`] snapshot without a
        /// table lock; this control-plane operation replaces the complete
        /// immutable table, so readers observe either generation and never a
        /// partial update. The broader reload coordinator still serializes
        /// multi-table policy changes.
        pub fn reload_client_identities(
            &self,
            identities: &[ClientIdentityConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let next = validate_client_identities(identities)?;
            self.client_identity_control.replace(next);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("client_identities", started);
            Ok(ReloadState::Published)
        }

        /// Replace or add client identities by exact name without exposing a
        /// partially updated mapping to readers.
        pub fn upsert_client_identities(
            &self,
            updates: &[ClientIdentityConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if updates.is_empty() {
                return Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: "<client-identities>".into(),
                    reason: "at least one identity is required".into(),
                });
            }
            let mut next = self.client_identities.snapshot().as_ref().clone();
            for update in updates {
                if let Some(existing) = next
                    .iter_mut()
                    .find(|identity| identity.name == update.name)
                {
                    *existing = update.clone();
                } else {
                    next.push(update.clone());
                }
            }
            let next = validate_client_identities(&next)?;
            self.client_identity_control.replace(next);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("client_identities_upsert", started);
            Ok(ReloadState::Published)
        }

        /// Remove client identities by exact name; unknown names fail without
        /// changing the published snapshot.
        pub fn remove_client_identities(
            &self,
            names: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if names.is_empty() || names.iter().any(String::is_empty) {
                return Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: "<client-identities>".into(),
                    reason: "at least one non-empty identity name is required".into(),
                });
            }
            let requested = names.iter().cloned().collect::<BTreeSet<_>>();
            let mut next = self.client_identities.snapshot().as_ref().clone();
            let original_len = next.len();
            next.retain(|identity| !requested.contains(&identity.name));
            if next.len() == original_len {
                return Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: "<client-identities>".into(),
                    reason: "no requested identity exists".into(),
                });
            }
            self.client_identity_control.replace(next);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("client_identities_remove", started);
            Ok(ReloadState::Published)
        }

        /// Atomically replace or add named client groups while preserving the
        /// configured profiles. The resulting profile expansion is validated
        /// before any live snapshot or group metadata is changed.
        pub fn upsert_client_groups(
            &self,
            updates: &[ClientGroupConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if updates.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<client-groups>".into(),
                    reason: "at least one client group is required".into(),
                });
            }
            let mut seen = BTreeSet::new();
            for group in updates {
                let name = group.name.trim().to_ascii_lowercase();
                if !seen.insert(name) {
                    return Err(policy::PolicyError::InvalidProfile {
                        name: group.name.clone(),
                        reason: "group name must be unique within an upsert".into(),
                    });
                }
            }
            let mut groups = self
                .client_groups
                .read()
                .expect("client groups lock")
                .clone();
            for update in updates {
                if let Some(existing) = groups
                    .iter_mut()
                    .find(|group| group.name.trim().eq_ignore_ascii_case(update.name.trim()))
                {
                    *existing = update.clone();
                } else {
                    groups.push(update.clone());
                }
            }
            let profiles = self.profiles.read().expect("profiles lock").clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let published = self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "client_groups_upsert",
                started,
            )?;
            *self.client_groups.write().expect("client groups lock") = groups;
            Ok(published)
        }

        /// Atomically replace or add service profiles by stable ID while
        /// preserving unspecified profiles and the current client groups.
        pub fn upsert_profiles(
            &self,
            updates: &[ServiceProfileConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if updates.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<profiles>".into(),
                    reason: "at least one profile is required".into(),
                });
            }
            let mut seen = BTreeSet::new();
            for profile in updates {
                if !seen.insert(profile.id) {
                    return Err(policy::PolicyError::DuplicateRule { id: profile.id });
                }
            }
            let mut profiles = self.profiles.read().expect("profiles lock").clone();
            for update in updates {
                if let Some(existing) = profiles.iter_mut().find(|profile| profile.id == update.id)
                {
                    *existing = update.clone();
                } else {
                    profiles.push(update.clone());
                }
            }
            let groups = self
                .client_groups
                .read()
                .expect("client groups lock")
                .clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let published = self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "profiles_upsert",
                started,
            )?;
            *self.profiles.write().expect("profiles lock") = profiles;
            Ok(published)
        }

        /// Remove service profiles by stable ID and atomically republish the
        /// remaining profile expansion. Unknown IDs fail without mutation.
        pub fn remove_profiles(&self, ids: &[u32]) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if ids.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<profiles>".into(),
                    reason: "at least one profile ID is required".into(),
                });
            }
            let requested = ids.iter().copied().collect::<BTreeSet<_>>();
            let current = self.profiles.read().expect("profiles lock").clone();
            let mut profiles = current.clone();
            profiles.retain(|profile| !requested.contains(&profile.id));
            if profiles.len() == current.len() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<profiles>".into(),
                    reason: "no requested profile ID exists".into(),
                });
            }
            let groups = self
                .client_groups
                .read()
                .expect("client groups lock")
                .clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let published = self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "profiles_remove",
                started,
            )?;
            *self.profiles.write().expect("profiles lock") = profiles;
            Ok(published)
        }

        /// Remove named client groups only when no configured profile depends
        /// on them. Dependency validation and policy publication are atomic.
        pub fn remove_client_groups(
            &self,
            names: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if names.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<client-groups>".into(),
                    reason: "at least one client group name is required".into(),
                });
            }
            let requested = names
                .iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            if requested.iter().any(String::is_empty) {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<client-groups>".into(),
                    reason: "group names must be non-empty".into(),
                });
            }
            let current = self
                .client_groups
                .read()
                .expect("client groups lock")
                .clone();
            let mut groups = current.clone();
            let original_len = groups.len();
            groups.retain(|group| !requested.contains(&group.name.trim().to_ascii_lowercase()));
            if groups.len() == original_len {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<client-groups>".into(),
                    reason: "no requested group exists".into(),
                });
            }
            let profiles = self.profiles.read().expect("profiles lock").clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self
                .explicit_rules
                .lock()
                .expect("explicit rules lock")
                .clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let mut base_rules = self.base_rules.lock().expect("base rules lock");
            let published = self.publish_rules_locked(
                &combined,
                &explicit,
                &mut base_rules,
                "client_groups_remove",
                started,
            )?;
            *self.client_groups.write().expect("client groups lock") = groups;
            Ok(published)
        }

        /// Atomically replace all operator-managed policy tables while
        /// retaining the current blocklist snapshot. Every generated rule,
        /// regex, and cross-table ID is validated before publication.
        pub fn reload_policy_bundle(
            &self,
            rules: &[RuleConfig],
            regex_configs: &[RegexRuleConfig],
            profiles: &[ServiceProfileConfig],
            client_groups: &[ClientGroupConfig],
            rewrite_configs: &[RewriteConfig],
            country_config: &CountryPolicyConfig,
            blocklist_paths: Option<&[String]>,
        ) -> Result<ReloadState, policy::PolicyError> {
            self.reload_policy_bundle_with_legacy(
                rules,
                regex_configs,
                profiles,
                client_groups,
                &[],
                rewrite_configs,
                country_config,
                blocklist_paths,
                None,
                None,
                None,
            )
        }

        /// Atomically replace the complete policy bundle, including the
        /// legacy fallback fields and the default action when supplied.
        pub fn reload_policy_bundle_with_legacy(
            &self,
            rules: &[RuleConfig],
            regex_configs: &[RegexRuleConfig],
            profiles: &[ServiceProfileConfig],
            client_groups: &[ClientGroupConfig],
            client_identities: &[ClientIdentityConfig],
            rewrite_configs: &[RewriteConfig],
            country_config: &CountryPolicyConfig,
            blocklist_paths: Option<&[String]>,
            legacy_mode: Option<Mode>,
            legacy_domains: Option<&[String]>,
            default_action: Option<Action>,
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let normalized_legacy_domains =
                legacy_domains.map(validate_legacy_domains).transpose()?;
            let generated = compile_profiles(profiles, client_groups)?;
            let client_identities = validate_client_identities(client_identities)?;
            let rewrites = compile_rewrites(rewrite_configs)?;
            let country_policy = load_country_policy(country_config)?;
            let (replacement, selected_paths) = if let Some(paths) = blocklist_paths {
                (load_blocklists(paths)?, Some(paths.to_vec()))
            } else {
                (
                    self.blocklist_rules
                        .lock()
                        .expect("blocklist rules lock")
                        .clone(),
                    None,
                )
            };
            let mut base = rules.to_vec();
            base.extend(generated);
            let mut published = base.clone();
            published.extend(replacement.iter().cloned());
            let rule_ids = published
                .iter()
                .map(|rule| rule.id)
                .collect::<BTreeSet<_>>();
            let compiled_regex = compile_regex_rules(regex_configs, rule_ids)?;
            self.reference.reload(&published)?;
            *self.base_rules.lock().expect("base rules lock") = base;
            *self.explicit_rules.lock().expect("explicit rules lock") = rules.to_vec();
            *self.regex_rules.lock().expect("regex rules lock") = compiled_regex;
            *self.profiles.write().expect("profiles lock") = profiles.to_vec();
            *self.client_groups.write().expect("client groups lock") = client_groups.to_vec();
            self.client_identity_control.replace(client_identities);
            *self.rewrites.write().expect("rewrites lock") = rewrites;
            *self.rewrite_configs.write().expect("rewrite configs lock") = rewrite_configs.to_vec();
            self.country_policy_control.replace(country_policy);
            if let Some(domains) = normalized_legacy_domains {
                *self.legacy_domains.write().expect("legacy domains lock") = domains;
            }
            if let Some(mode) = legacy_mode {
                *self.legacy_mode.write().expect("legacy mode lock") = mode;
            }
            if let Some(action) = default_action {
                *self.default_action.write().expect("default action lock") = action;
            }
            *self.blocklist_rules.lock().expect("blocklist rules lock") = replacement;
            if let Some(paths) = selected_paths {
                *self.blocklist_paths.lock().expect("blocklist paths lock") = paths;
            }
            self.domain_rules_configured
                .store(!published.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !published.is_empty() || !regex_configs.is_empty(),
                Ordering::Release,
            );
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("policy_bundle", started);
            Ok(ReloadState::Published)
        }

        /// Atomically replace or add local rewrites by normalized DNS name.
        /// All entries compile before the live table changes.
        pub fn upsert_rewrites(
            &self,
            updates: &[RewriteConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if updates.is_empty() {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: "<rewrite-upsert>".into(),
                    reason: "at least one rewrite is required".into(),
                });
            }
            let mut seen = BTreeSet::new();
            for rewrite in updates {
                if !seen.insert(normalize(&rewrite.name)) {
                    return Err(policy::PolicyError::InvalidRewrite {
                        name: rewrite.name.clone(),
                        reason: "rewrite name must be unique within an upsert".into(),
                    });
                }
            }
            let mut next = self
                .rewrite_configs
                .read()
                .expect("rewrite configs lock")
                .clone();
            for update in updates {
                let name = normalize(&update.name);
                if let Some(existing) = next
                    .iter_mut()
                    .find(|rewrite| normalize(&rewrite.name) == name)
                {
                    *existing = update.clone();
                } else {
                    next.push(update.clone());
                }
            }
            self.publish_rewrites_locked(&next, "rewrites_upsert", started)
        }

        /// Remove local rewrites by normalized DNS name. Unknown names fail
        /// without changing the published rewrite table.
        pub fn remove_rewrites(
            &self,
            names: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if names.is_empty() {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: "<rewrite-removal>".into(),
                    reason: "at least one rewrite name is required".into(),
                });
            }
            let requested = names
                .iter()
                .map(|name| normalize(name))
                .collect::<BTreeSet<_>>();
            if requested.iter().any(String::is_empty) {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: "<rewrite-removal>".into(),
                    reason: "rewrite names must be non-empty".into(),
                });
            }
            let current = self
                .rewrite_configs
                .read()
                .expect("rewrite configs lock")
                .clone();
            let mut next = current.clone();
            next.retain(|rewrite| !requested.contains(&normalize(&rewrite.name)));
            if next.len() == current.len() {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: "<rewrite-removal>".into(),
                    reason: "no requested rewrite exists".into(),
                });
            }
            self.publish_rewrites_locked(&next, "rewrites_remove", started)
        }

        /// Atomically replace the complete local rewrite table. Invalid
        /// entries leave the previously published table unchanged.
        pub fn reload_rewrites(
            &self,
            configs: &[RewriteConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            self.publish_rewrites_locked(configs, "rewrites", started)
        }

        fn publish_rewrites_locked(
            &self,
            configs: &[RewriteConfig],
            reload_kind: &'static str,
            started: Instant,
        ) -> Result<ReloadState, policy::PolicyError> {
            let compiled = compile_rewrites(configs)?;
            *self.rewrites.write().expect("rewrites lock") = compiled;
            *self.rewrite_configs.write().expect("rewrite configs lock") = configs.to_vec();
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency(reload_kind, started);
            Ok(ReloadState::Published)
        }

        /// Compile and atomically replace regex rules. Invalid updates leave
        /// the last good regex generation in place.
        pub fn reload_regex_rules(
            &self,
            configs: &[RegexRuleConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let rule_ids = self.reference.rule_ids();
            let compiled = compile_regex_rules(configs, rule_ids)?;
            *self.regex_rules.lock().expect("regex rules lock") = compiled;
            self.rules_configured.store(
                self.domain_rules_configured.load(Ordering::Acquire) || !configs.is_empty(),
                Ordering::Release,
            );
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("regex", started);
            Ok(ReloadState::Published)
        }

        /// Atomically replace or add regex rules by stable ID. Existing IDs
        /// are edited in place; new IDs are appended. A failed compilation
        /// leaves the previous regex generation published.
        pub fn upsert_regex_rules(
            &self,
            updates: &[RegexRuleConfig],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if updates.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<regex-upsert>".into(),
                    reason: "at least one regex rule is required".into(),
                });
            }
            let mut seen = BTreeSet::new();
            for rule in updates {
                if !seen.insert(rule.id) {
                    return Err(policy::PolicyError::DuplicateRule { id: rule.id });
                }
            }
            let current = self.regex_rule_configs();
            let mut next = current;
            for update in updates {
                if let Some(existing) = next.iter_mut().find(|rule| rule.id == update.id) {
                    *existing = update.clone();
                } else {
                    next.push(update.clone());
                }
            }
            self.publish_regex_rules_locked(&next, "regex_upsert", started)
        }

        /// Remove regex rules by stable ID. Unknown IDs fail without changing
        /// the published regex generation.
        pub fn remove_regex_rules(&self, ids: &[u32]) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if ids.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<regex-removal>".into(),
                    reason: "at least one regex rule ID is required".into(),
                });
            }
            let requested = ids.iter().copied().collect::<BTreeSet<_>>();
            let current = self.regex_rule_configs();
            let mut next = current.clone();
            next.retain(|rule| !requested.contains(&rule.id));
            if next.len() == current.len() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<regex-removal>".into(),
                    reason: "no requested regex rule ID exists".into(),
                });
            }
            self.publish_regex_rules_locked(&next, "regex_remove", started)
        }

        fn regex_rule_configs(&self) -> Vec<RegexRuleConfig> {
            self.regex_rules
                .lock()
                .expect("regex rules lock")
                .iter()
                .map(|rule| RegexRuleConfig {
                    id: rule.id,
                    pattern: rule.pattern.as_str().to_owned(),
                    action: rule.action,
                    priority: rule.priority,
                    qtype: rule.qtype,
                    qclass: rule.qclass,
                    client: rule.client,
                    client_cidrs: rule.client_cidrs.clone(),
                })
                .collect()
        }

        fn publish_regex_rules_locked(
            &self,
            configs: &[RegexRuleConfig],
            reload_kind: &'static str,
            started: Instant,
        ) -> Result<ReloadState, policy::PolicyError> {
            let rule_ids = self.reference.rule_ids();
            let compiled = compile_regex_rules(configs, rule_ids)?;
            *self.regex_rules.lock().expect("regex rules lock") = compiled;
            self.rules_configured.store(
                self.domain_rules_configured.load(Ordering::Acquire) || !configs.is_empty(),
                Ordering::Release,
            );
            self.cache_control.update(|cache| {
                let mut next = cache.clone();
                next.clear();
                next
            });
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency(reload_kind, started);
            Ok(ReloadState::Published)
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
            self.upstream_slots = Some(Arc::new(Semaphore::new(
                max_outstanding.clamp(1, MAX_UPSTREAM_OUTSTANDING),
            )));
            self
        }

        /// Attach the optional TCP transport used when the UDP resolver sets
        /// the DNS truncation bit. It reuses the same `DnsClientUpstream`
        /// exchange and bounded semaphore; no second upstream abstraction is
        /// introduced.
        #[must_use]
        pub fn with_tcp_upstream(
            mut self,
            tcp_upstream: Arc<
                dyn proxima_primitives::stream::StreamUpstream<
                        Conn = Box<dyn proxima_primitives::stream::StreamConnection>,
                    >,
            >,
        ) -> Self {
            if let Some(upstream) = self.upstream.take() {
                self.upstream = Some(upstream.with_tcp_upstream(tcp_upstream));
            }
            self
        }

        /// Use the configured stream transport for every upstream exchange.
        /// This is required for DNS-over-TLS; it keeps Proxima's bounded
        /// framed DNS client and does not add a second upstream abstraction.
        #[must_use]
        pub fn with_tcp_only(mut self) -> Self {
            if let Some(upstream) = self.upstream.take() {
                self.upstream = Some(upstream.with_tcp_only());
            }
            self
        }

        /// Use an existing Proxima HTTP pipe for every upstream exchange.
        /// The DNS client retains ownership of DNS validation and bounds;
        /// HTTP endpoint and TLS behavior stay in Proxima's pipe.
        #[must_use]
        pub fn with_doh_upstream(
            mut self,
            doh_upstream: proxima_primitives::pipe::handler::PipeHandle,
        ) -> Self {
            if let Some(upstream) = self.upstream.take() {
                self.upstream = Some(upstream.with_doh_upstream(doh_upstream));
            }
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
            if upstream.query_timeout_ms == 0 || upstream.query_timeout_ms > MAX_UPSTREAM_TIMEOUT_MS
            {
                return Err(policy::PolicyError::InvalidUpstream {
                    reason: format!(
                        "query_timeout_ms must be between 1 and {MAX_UPSTREAM_TIMEOUT_MS}"
                    ),
                });
            }
            if upstream.max_attempts == 0
                || upstream.max_attempts > MAX_UPSTREAM_ATTEMPTS
                || upstream.max_outstanding == 0
                || upstream.max_outstanding > MAX_UPSTREAM_OUTSTANDING
            {
                return Err(policy::PolicyError::InvalidUpstream {
                    reason: format!(
                        "max_attempts must be between 1 and {MAX_UPSTREAM_ATTEMPTS}; max_outstanding must be between 1 and {MAX_UPSTREAM_OUTSTANDING}"
                    ),
                });
            }
            if upstream.breaker_failures == 0 || upstream.breaker_cooldown_secs == 0 {
                return Err(policy::PolicyError::InvalidUpstream {
                    reason: "breaker_failures and breaker_cooldown_secs must be non-zero".into(),
                });
            }
            if matches!(
                upstream.transport,
                UpstreamTransport::Tls | UpstreamTransport::Doh | UpstreamTransport::Doq
            ) && upstream
                .tls_server_name
                .as_deref()
                .is_none_or(|name| !valid_tls_server_name(name))
            {
                return Err(policy::PolicyError::InvalidUpstream {
                    reason: "tls_server_name must be a valid ASCII DNS name or IP literal".into(),
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
            let same_listener_endpoint = resolver == listener
                || (resolver.port() == listener.port()
                    && listener.ip().is_unspecified()
                    && resolver_ip.is_ipv4() == listener.ip().is_ipv4());
            if same_listener_endpoint {
                return Err(policy::PolicyError::InvalidUpstream {
                    reason: "upstream must not resolve to the listener endpoint".into(),
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
            let _reload = self.reload_lock.read().expect("reload lock");
            let client_identity = self.client_identity_for(client);
            let reference = self.reference.read(|reference| {
                reference.decide(QueryContext {
                    name: &query.name,
                    qtype: query.qtype,
                    qclass: query.qclass,
                    client,
                    client_identity: client_identity.as_deref(),
                })
            });
            reference.or_else(|| {
                self.regex_decision(&normalize(&query.name), query.qtype, query.qclass, client)
            })
        }

        fn client_ip(peer: Option<&PeerInfo>) -> Option<std::net::IpAddr> {
            match peer {
                Some(PeerInfo::Tcp(address)) => Some(address.ip()),
                _ => None,
            }
        }

        fn breaker_now_nanos(&self) -> u64 {
            self.breaker_epoch
                .elapsed()
                .as_nanos()
                .min(u64::MAX as u128) as u64
        }

        fn client_identity_for(&self, client: Option<std::net::IpAddr>) -> Option<String> {
            let client = client?;
            self.client_identities.read(|identities| {
                identities
                    .iter()
                    .find(|identity| identity.clients.contains(&client))
                    .map(|identity| identity.name.clone())
            })
        }

        fn admission_config(&self) -> AdmissionConfig {
            self.admission.snapshot().as_ref().clone()
        }

        fn try_client_admission(&self, client: Option<IpAddr>) -> Option<ClientPermit> {
            let client = client?;
            let admission = self.admission_config();
            self.client_admission.try_acquire(
                client,
                admission.max_inflight_per_client,
                self.breaker_epoch,
            )
        }

        fn allow_client_rate(&self, client: Option<IpAddr>) -> bool {
            let Some(client) = client else {
                return true;
            };
            let admission = self.admission_config();
            let (key, length) = ip_key(client);
            self.client_rates.allow(
                &key[..length],
                self.breaker_epoch,
                admission.max_queries_per_client_per_second,
                1,
            )
        }

        fn allow_global_rate(&self) -> bool {
            let admission = self.admission_config();
            self.global_rate
                .allow(self.breaker_epoch, admission.max_queries_per_second, 1)
        }

        /// Bound encoded DNS egress per identified client over a one-second
        /// window. This is deliberately enforced at the listener after
        /// encoding, so the budget measures actual wire bytes rather than an
        /// estimate derived from the answer model.
        pub(crate) fn allow_client_response_bytes(
            &self,
            client: Option<IpAddr>,
            bytes: usize,
        ) -> bool {
            let Some(client) = client else {
                return true;
            };
            let admission = self.admission_config();
            let limit = admission.max_response_bytes_per_client_per_second;
            if bytes > limit {
                return false;
            }
            let (key, length) = ip_key(client);
            self.client_response_budgets
                .allow(&key[..length], self.breaker_epoch, limit, bytes)
        }

        /// Bound total encoded DNS egress over a one-second window. Unlike
        /// the per-client budget, this also applies when the adapter cannot
        /// identify a client, preventing aggregate amplification from
        /// bypassing identity-scoped limits.
        pub(crate) fn allow_global_response_bytes(&self, bytes: usize) -> bool {
            let limit = self.admission_config().max_response_bytes_per_second;
            self.global_response_budget
                .allow(self.breaker_epoch, limit, bytes)
        }

        /// Bound encoded DNS egress for an identified client network over a
        /// one-second window. The network key uses the same configured prefix
        /// as the abuse breaker and the table is bounded like other admission
        /// state.
        pub(crate) fn allow_network_response_bytes(
            &self,
            client: Option<IpAddr>,
            bytes: usize,
        ) -> bool {
            let Some(client) = client else {
                return true;
            };
            let admission = self.admission_config();
            let limit = admission.max_response_bytes_per_network_per_second;
            if bytes > limit {
                return false;
            }
            let key = abuse_network_key(
                client,
                admission.network_abuse_ipv4_prefix,
                admission.network_abuse_ipv6_prefix,
            );
            let (key, length) = abuse_network_bytes(key);
            self.network_response_budgets
                .allow(&key[..length], self.breaker_epoch, limit, bytes)
        }

        fn allow_client_abuse(&self, client: Option<IpAddr>) -> bool {
            let Some(client) = client else {
                return true;
            };
            let admission = self.admission_config();
            let (client_key, client_key_len) = ip_key(client);
            let exact_allowed = self.client_abuse.abuse_allows(
                &client_key[..client_key_len],
                self.breaker_epoch,
                Duration::from_secs(admission.client_abuse_window_secs),
            );
            let network = abuse_network_key(
                client,
                admission.network_abuse_ipv4_prefix,
                admission.network_abuse_ipv6_prefix,
            );
            let (network_key, network_key_len) = abuse_network_bytes(network);
            let network_allowed = self.network_abuse.abuse_allows(
                &network_key[..network_key_len],
                self.breaker_epoch,
                Duration::from_secs(admission.network_abuse_window_secs),
            );
            exact_allowed && network_allowed
        }

        pub(crate) fn record_client_abuse(&self, client: Option<IpAddr>) -> bool {
            let Some(client) = client else {
                return false;
            };
            let admission = self.admission_config();
            let (client_key, client_key_len) = ip_key(client);
            let exact_opened = self.client_abuse.record_abuse(
                &client_key[..client_key_len],
                self.breaker_epoch,
                Duration::from_secs(admission.client_abuse_window_secs),
                Duration::from_secs(admission.client_abuse_cooldown_secs),
                admission.max_client_abuse_violations,
            );
            let network = abuse_network_key(
                client,
                admission.network_abuse_ipv4_prefix,
                admission.network_abuse_ipv6_prefix,
            );
            let (network_key, network_key_len) = abuse_network_bytes(network);
            let network_opened = self.network_abuse.record_abuse(
                &network_key[..network_key_len],
                self.breaker_epoch,
                Duration::from_secs(admission.network_abuse_window_secs),
                Duration::from_secs(admission.network_abuse_cooldown_secs),
                admission.max_network_abuse_violations,
            );
            exact_opened || network_opened
        }

        fn admission_allows(&self, query: &proxima_dns::DnsQuery) -> bool {
            let admission = self.admission_config();
            let name = query.name.trim_end_matches('.');
            if name.len() > admission.max_name_bytes || query.qtype == 0 || query.qclass == 0 {
                return false;
            }
            if admission.reject_any && query.qtype == 255 {
                return false;
            }
            if name.is_empty() {
                return true;
            }
            name.split('.')
                .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii())
        }

        fn cap_answer(&self, query: &proxima_dns::DnsQuery, mut answer: DnsAnswer) -> DnsAnswer {
            let admission = self.admission_config();
            answer.records.truncate(admission.max_response_records);
            let mut bytes = 12usize
                .saturating_add(wire_name_bytes(&query.name))
                .saturating_add(4);
            let max_bytes = admission
                .max_response_bytes
                .min(bytes.saturating_mul(admission.max_response_amplification));
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
            if answer.rcode > 0x0f {
                return Err("upstream_malformed");
            }
            if answer.records.len() > self.admission_config().max_response_records {
                return Err("upstream_overflow");
            }
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
                if record.rtype == 5 {
                    let Ok((target, used)) = proxima_protocols::dns::parse_name(&record.rdata, 0)
                    else {
                        return Err("upstream_malformed");
                    };
                    if used != record.rdata.len()
                        || !valid_dns_name(&normalize(&target.to_dotted()))
                    {
                        return Err("upstream_malformed");
                    }
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

        fn validate_upstream_response(
            &self,
            query: &proxima_dns::DnsQuery,
            response: &DnsAnswerWithMetadata,
        ) -> Result<(), &'static str> {
            let Some(question) = response.metadata.question.as_ref() else {
                return Err("upstream_question_mismatch");
            };
            if normalize(&question.name) != normalize(&query.name)
                || question.qtype != query.qtype
                || question.qclass != query.qclass
            {
                return Err("upstream_question_mismatch");
            }
            if response.metadata.truncated {
                return Err("upstream_truncated");
            }
            self.validate_upstream_answer(query, &response.answer)
        }

        /// Return the authoritative action for a validated borrowed query view.
        /// The wire adapter calls this before materializing the owned Proxima DNS
        /// request, so configured rules remain authoritative at the raw boundary.
        #[must_use]
        pub fn action_for_view(&self, query: QueryView<'_>) -> Action {
            self.action_for_view_with_client_identity(query, None, None)
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
            self.action_for_view_with_client_identity(query, client, None)
        }

        /// Return the authoritative action with a listener-owned identity
        /// label. The borrowed label is used only for this decision and is
        /// never retained by policy state, telemetry, or logs.
        #[must_use]
        pub fn action_for_view_with_client_identity(
            &self,
            query: QueryView<'_>,
            client: Option<std::net::IpAddr>,
            client_identity: Option<&str>,
        ) -> Action {
            let _reload = self.reload_lock.read().expect("reload lock");
            let resolved_identity = client_identity
                .map(str::to_owned)
                .or_else(|| self.client_identity_for(client));
            let name = query.name.to_dotted();
            if !self.rules_configured.load(Ordering::Acquire) {
                if !self.matches(&name) {
                    return Action::Pass;
                }
                return match *self.legacy_mode.read().expect("legacy mode lock") {
                    Mode::Ignore => Action::Ignore,
                    Mode::Nxdomain => Action::Nxdomain,
                    Mode::Honeypot => Action::Honeypot,
                };
            }
            let reference = self.reference.read(|reference| {
                reference.decide(QueryContext {
                    name: &name,
                    qtype: query.qtype,
                    qclass: query.qclass,
                    client,
                    client_identity: resolved_identity.as_deref(),
                })
            });
            reference
                .or_else(|| {
                    self.regex_decision(&normalize(&name), query.qtype, query.qclass, client)
                })
                .map_or(
                    *self.default_action.read().expect("default action lock"),
                    |decision| decision.action,
                )
        }

        fn regex_decision(
            &self,
            name: &str,
            qtype: u16,
            qclass: u16,
            client: Option<IpAddr>,
        ) -> Option<policy::Decision> {
            self.regex_rules
                .lock()
                .expect("regex rules lock")
                .iter()
                .filter(|rule| {
                    rule.pattern.is_match(name)
                        && rule.qtype.is_none_or(|value| value == qtype)
                        && rule.qclass.is_none_or(|value| value == qclass)
                        && rule.client.is_none_or(|value| Some(value) == client)
                        && (rule.client_networks.is_empty()
                            || client.is_some_and(|value| {
                                rule.client_networks
                                    .iter()
                                    .any(|network| network.contains(value))
                            }))
                })
                .max_by_key(|rule| {
                    (
                        rule.priority,
                        u8::from(rule.qclass.is_some()),
                        u8::from(rule.qtype.is_some()),
                        u8::from(rule.client.is_some()),
                        rule.client_networks
                            .iter()
                            .map(|network| network.prefix())
                            .max()
                            .unwrap_or(0),
                        rule.id,
                    )
                })
                .map(|rule| policy::Decision {
                    rule_id: rule.id,
                    action: rule.action,
                })
        }
        fn matches(&self, name: &str) -> bool {
            let name = normalize(name);
            self.legacy_domains
                .read()
                .expect("legacy domains lock")
                .iter()
                .any(|domain| {
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
            let answer = match decision.map(|decision| decision.action).or(Some(
                *self.default_action.read().expect("default action lock"),
            )) {
                Some(Action::Ignore | Action::Drop | Action::Forward) => None,
                Some(Action::Nxdomain) => Some(DnsAnswer::name_error()),
                Some(Action::Reject) => Some(refused_answer()),
                Some(Action::Sink) => Some(DnsAnswer::ok(Vec::new())),
                Some(Action::Honeypot) => {
                    Some(honeypot(&query.name, query.qtype, &self.config.honeypot))
                }
                Some(Action::Pass | Action::Observe) => self
                    .rewrites
                    .read()
                    .expect("rewrites lock")
                    .answer(query)
                    .or_else(|| Some(DnsAnswer::ok(Vec::new()))),
                None => Some(DnsAnswer::ok(Vec::new())),
            };
            answer.map(|answer| self.cap_answer(query, answer))
        }

        fn evaluate_legacy(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
            if !self.matches(&query.name) {
                return Some(DnsAnswer::ok(Vec::new()));
            }
            match *self.legacy_mode.read().expect("legacy mode lock") {
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

        fn observe_country(&self, country: &str) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[("country", country)]);
            telemetry.counter_inc("blackhole.country_observations", &labels, 1);
        }

        fn observe_cache(&self, outcome: &'static str) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[("outcome", outcome)]);
            telemetry.counter_inc("blackhole.cache", &labels, 1);
        }

        fn observe_cache_ttl(&self, answer: &DnsAnswer) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[(
                "kind",
                if answer.records.is_empty() {
                    "negative"
                } else {
                    "positive"
                },
            )]);
            let (negative_ttl_secs, max_ttl_secs) = {
                self.cache
                    .read(|cache| (cache.config.negative_ttl_secs, cache.config.max_ttl_secs))
            };
            let ttl = answer
                .records
                .iter()
                .map(|record| u64::from(record.ttl))
                .min()
                .unwrap_or(negative_ttl_secs)
                .min(max_ttl_secs);
            telemetry.histogram_record("blackhole.cache_ttl_seconds", &labels, ttl as f64);
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

        pub(crate) async fn record_decision(&self, action: Action, query: &proxima_dns::DnsQuery) {
            if self.recording.is_none() && self.query_log.is_none() {
                return;
            }
            let event = RecordingEvent {
                id: InteractionId::new(),
                ts_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| {
                        duration.as_millis().min(u128::from(u64::MAX)) as u64
                    }),
                parent: None,
                event: ProtocolEvent::Custom {
                    kind: "blackhole.dns_decision".into(),
                    payload: serde_json::json!({
                        "action": action_label(action),
                        "qtype": query.qtype,
                        "qclass": query.qclass,
                    }),
                },
            };
            if let Some(query_log) = self.query_log.as_ref()
                && query_log.append(event.clone()).await.is_err()
            {
                self.observe_failure("query_log_append");
            }
            if let Some(recording) = self.recording.as_ref()
                && recording.append(event).await.is_err()
            {
                self.observe_failure("recording_append");
            }
        }

        pub(crate) fn admin_query_log(&self) -> String {
            let Some(query_log) = self.query_log.as_ref() else {
                return "{\"enabled\":false,\"entries\":[]}".into();
            };
            let all_entries = query_log
                .snapshot()
                .into_iter()
                .filter_map(|event| match event.event {
                    ProtocolEvent::Custom { kind, payload } if kind == "blackhole.dns_decision" => {
                        Some(payload)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let truncated = all_entries.len() > MAX_ADMIN_LOG_ENTRIES;
            let entries = all_entries
                .into_iter()
                .rev()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>();
            serde_json::json!({"enabled": true, "truncated": truncated, "entries": entries})
                .to_string()
        }

        pub(crate) fn admin_privacy_status(&self) -> String {
            serde_json::json!({
                "query_log_enabled": self.query_log.is_some(),
                "query_log_max_entries": self.config.privacy.query_log_max_entries,
                "query_log_retention_secs": self.config.privacy.query_log_retention_secs,
                "query_recording_enabled": self.recording.is_some()
                    || self.config.privacy.query_recording_path.is_some(),
                "query_recording_max_bytes": self.config.privacy.query_recording_max_bytes,
                "query_recording_rotation_enabled": self
                    .config
                    .privacy
                    .query_recording_rotation_enabled,
                "query_recording_max_files": self.config.privacy.query_recording_max_files,
                "payload_recording": "disabled",
                "client_identity_recording": "disabled",
            })
            .to_string()
        }

        /// Return bounded admission and amplification limits without exposing
        /// client keys, counters, or other request metadata.
        pub(crate) fn admin_admission_status(&self) -> String {
            let admission = self.admission_config();
            serde_json::json!({
                "max_name_bytes": admission.max_name_bytes,
                "reject_any": admission.reject_any,
                "max_response_records": admission.max_response_records,
                "max_response_bytes": admission.max_response_bytes,
                "max_response_amplification": admission.max_response_amplification,
                "max_inflight_requests": admission.max_inflight_requests,
                "max_queries_per_second": admission.max_queries_per_second,
                "max_inflight_per_client": admission.max_inflight_per_client,
                "max_queries_per_client_per_second": admission.max_queries_per_client_per_second,
                "max_response_bytes_per_client_per_second": admission.max_response_bytes_per_client_per_second,
                "max_response_bytes_per_network_per_second": admission.max_response_bytes_per_network_per_second,
                "max_response_bytes_per_second": admission.max_response_bytes_per_second,
                "max_client_abuse_violations": admission.max_client_abuse_violations,
                "client_abuse_window_secs": admission.client_abuse_window_secs,
                "client_abuse_cooldown_secs": admission.client_abuse_cooldown_secs,
                "max_network_abuse_violations": admission.max_network_abuse_violations,
                "network_abuse_window_secs": admission.network_abuse_window_secs,
                "network_abuse_cooldown_secs": admission.network_abuse_cooldown_secs,
                "network_abuse_ipv4_prefix": admission.network_abuse_ipv4_prefix,
                "network_abuse_ipv6_prefix": admission.network_abuse_ipv6_prefix,
            })
            .to_string()
        }

        /// Return country-policy controls and bounded map metadata without
        /// exposing the source path or any client address.
        pub(crate) fn admin_country_status(&self) -> String {
            let country_policy = self.country_policy.snapshot();
            let policy = country_policy.as_ref();
            serde_json::json!({
                "map_configured": policy.is_some(),
                "entries": policy.as_ref().map_or(0, |value| value.entries.len()),
                "deny": self.config.country_policy.deny,
                "observe": self.config.country_policy.observe,
                "deny_regions": self.config.country_policy.deny_regions,
                "observe_regions": self.config.country_policy.observe_regions,
                "deny_asns": self.config.country_policy.deny_asns,
                "observe_asns": self.config.country_policy.observe_asns,
                "max_age_secs": self.config.country_policy.max_age_secs,
                "reload_interval_secs": self.config.country_policy.reload_interval_secs,
            })
            .to_string()
        }

        pub(crate) fn clear_query_log(&self) -> usize {
            self.query_log
                .as_ref()
                .map_or(0, |query_log| query_log.clear())
        }

        pub(crate) fn admin_status(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let cache = self.cache.snapshot();
            serde_json::json!({
                "status": "ok",
                "rules_configured": self.rules_configured.load(Ordering::Acquire),
                "policy_generation": self.policy_generation.load(Ordering::Acquire),
                "profiles_configured": self.profiles.read().expect("profiles lock").len(),
                "client_groups_configured": self.client_groups.read().expect("client groups lock").len(),
                "upstream_configured": self.upstream.is_some(),
                "country_policy_configured": self.country_policy.snapshot().is_some(),
                "country_reload_interval_secs": self.config.country_policy.reload_interval_secs,
                "cache_entries": cache.entries.len(),
                "cache_capacity": cache.config.max_entries,
            })
            .to_string()
        }

        /// Return bounded effective-policy metadata without exposing source
        /// paths, query names, client identities, credentials, or payloads.
        pub(crate) fn admin_policy_status(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let base_rules = self.base_rules.lock().expect("base rules lock");
            let regex_rules = self.regex_rules.lock().expect("regex rules lock");
            let blocklist_rules = self.blocklist_rules.lock().expect("blocklist rules lock");
            let blocklist_paths = self.blocklist_paths.lock().expect("blocklist paths lock");
            let profiles = self.profiles.read().expect("profiles lock");
            let client_groups = self.client_groups.read().expect("client groups lock");
            let identity_rules = base_rules
                .iter()
                .filter(|rule| rule.client_identity.is_some())
                .count();
            let rewrites = self.rewrites.read().expect("rewrites lock");
            let country_policy = self.country_policy.snapshot();
            serde_json::json!({
                "rules_configured": self.rules_configured.load(Ordering::Acquire),
                "domain_rules": base_rules.len(),
                "regex_rules": regex_rules.len(),
                "blocklist_sources": blocklist_paths.len(),
                "blocklist_rules": blocklist_rules.len(),
                "rewrites": rewrites.len(),
                "profiles": profiles.len(),
                "client_groups": client_groups.len(),
                "identity_rules": identity_rules,
                "country_entries": country_policy.as_ref().as_ref().map_or(0, |policy| policy.entries.len()),
                "country_deny_rules": country_policy.as_ref().as_ref().map_or(0, |policy| policy.deny.len()),
                "country_observe_rules": country_policy.as_ref().as_ref().map_or(0, |policy| policy.observe.len()),
                "country_reload_interval_secs": self.config.country_policy.reload_interval_secs,
                "legacy_domain_count": self.legacy_domains.read().expect("legacy domains lock").len(),
                "legacy_mode": mode_label(*self.legacy_mode.read().expect("legacy mode lock")),
                "default_action": action_label(*self.default_action.read().expect("default action lock")),
                "legacy_mode_active": !self.rules_configured.load(Ordering::Acquire),
                "policy_generation": self.policy_generation.load(Ordering::Acquire),
            })
            .to_string()
        }

        /// Return the live operator-managed bundle for the authenticated
        /// editor. The blocklist source field is null intentionally: the
        /// bundle reload contract treats null as retaining the loaded map.
        pub(crate) fn admin_policy_bundle(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let rules = self.explicit_rules.lock().expect("explicit rules lock");
            let regex_rules = self.regex_rules.lock().expect("regex rules lock");
            let profiles = self.profiles.read().expect("profiles lock");
            let client_groups = self.client_groups.read().expect("client groups lock");
            let client_identities = self.client_identities.snapshot();
            let rewrites = self.rewrite_configs.read().expect("rewrite configs lock");
            let value = serde_json::json!({
                "mode": mode_label(*self.legacy_mode.read().expect("legacy mode lock")),
                "domains": self.legacy_domains.read().expect("legacy domains lock").clone(),
                "default_action": action_label(*self.default_action.read().expect("default action lock")),
                "rules": rules.iter().map(|rule| serde_json::json!({
                    "id": rule.id,
                    "domain": rule.domain,
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qclass": rule.qclass,
                    "client": rule.client,
                    "client_cidr": rule.client_cidr,
                    "client_cidrs": rule.client_cidrs,
                    "client_identity": rule.client_identity,
                })).collect::<Vec<_>>(),
                "regex_rules": regex_rules.iter().map(|rule| serde_json::json!({
                    "id": rule.id,
                    "pattern": rule.pattern.as_str(),
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qclass": rule.qclass,
                    "client": rule.client,
                    "client_cidrs": rule.client_cidrs,
                })).collect::<Vec<_>>(),
                "profiles": profiles.iter().map(|profile| serde_json::json!({
                    "id": profile.id,
                    "name": profile.name,
                    "domains": profile.domains,
                    "action": action_label(profile.action),
                    "groups": profile.groups,
                    "priority": profile.priority,
                    "client_cidrs": profile.client_cidrs,
                    "qtype": profile.qtype,
                    "qclass": profile.qclass,
                })).collect::<Vec<_>>(),
                "client_groups": client_groups.iter().map(|group| serde_json::json!({
                    "name": group.name,
                    "client_addresses": group.client_addresses,
                    "client_cidrs": group.client_cidrs,
                })).collect::<Vec<_>>(),
                "client_identities": client_identities.iter().map(|identity| serde_json::json!({
                    "name": identity.name,
                    "clients": identity.clients,
                })).collect::<Vec<_>>(),
                "rewrites": rewrites.iter().map(|rewrite| serde_json::json!({
                    "name": rewrite.name,
                    "ipv4": rewrite.ipv4,
                    "ipv6": rewrite.ipv6,
                    "ttl": rewrite.ttl,
                })).collect::<Vec<_>>(),
                "country_policy": self.config.country_policy,
                "blocklists": serde_json::Value::Null,
            });
            let encoded = value.to_string();
            if encoded.len() <= 64 * 1024 {
                encoded
            } else {
                serde_json::json!({
                    "status": "error",
                    "message": "policy bundle exceeds the bounded editor response"
                })
                .to_string()
            }
        }

        pub(crate) fn admin_rules(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let base_rules = self.base_rules.lock().expect("base rules lock").clone();
            let regex_rules = self.regex_rules.lock().expect("regex rules lock");
            let total = base_rules.len().saturating_add(regex_rules.len());
            let mut rules = Vec::with_capacity(total.min(256));
            for rule in &base_rules {
                rules.push(serde_json::json!({
                    "kind": "domain",
                    "id": rule.id,
                    "domain": rule.domain,
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qclass": rule.qclass,
                    "client": rule.client,
                    "client_cidr": rule.client_cidr,
                    "client_cidrs": rule.client_cidrs,
                }));
            }
            for rule in regex_rules.iter() {
                rules.push(serde_json::json!({
                    "kind": "regex",
                    "id": rule.id,
                    "pattern": rule.pattern.as_str(),
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qclass": rule.qclass,
                    "client": rule.client,
                    "client_cidrs": rule.client_cidrs,
                }));
            }
            let mut truncated = false;
            loop {
                let response = serde_json::json!({
                    "rules": rules,
                    "total": total,
                    "truncated": truncated,
                })
                .to_string();
                if response.len() <= MAX_ADMIN_RULES_BODY_BYTES || rules.len() <= 1 {
                    return response;
                }
                rules.pop();
                truncated = true;
            }
        }

        pub(crate) fn admin_profiles(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let profiles = self.profiles.read().expect("profiles lock");
            let visible = profiles
                .iter()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .map(|profile| {
                    serde_json::json!({
                        "id": profile.id,
                        "name": profile.name,
                        "domains": profile.domains,
                        "action": action_label(profile.action),
                        "groups": profile.groups,
                        "client_cidrs": profile.client_cidrs,
                        "priority": profile.priority,
                        "qtype": profile.qtype,
                        "qclass": profile.qclass,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "profiles": visible,
                "total": profiles.len(),
                "truncated": profiles.len() > MAX_ADMIN_LOG_ENTRIES,
            })
            .to_string()
        }

        pub(crate) fn admin_client_groups(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let groups = self.client_groups.read().expect("client groups lock");
            let visible = groups
                .iter()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .map(|group| {
                    serde_json::json!({
                        "name": group.name,
                        "client_addresses": group.client_addresses,
                        "client_cidrs": group.client_cidrs,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "client_groups": visible,
                "total": groups.len(),
                "truncated": groups.len() > MAX_ADMIN_LOG_ENTRIES,
            })
            .to_string()
        }

        pub(crate) fn admin_client_identities(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            self.client_identities.read(|configured| {
                let identities = configured
                    .iter()
                    .take(MAX_ADMIN_LOG_ENTRIES)
                    .map(|identity| {
                        serde_json::json!({
                            "name": identity.name,
                            "clients": identity.clients.len(),
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "client_identities": identities,
                    "total": configured.len(),
                    "truncated": configured.len() > MAX_ADMIN_LOG_ENTRIES,
                })
                .to_string()
            })
        }

        pub(crate) fn admin_rewrites(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let rewrites = self.rewrite_configs.read().expect("rewrite configs lock");
            let visible = rewrites
                .iter()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .map(|rewrite| {
                    serde_json::json!({
                        "name": rewrite.name,
                        "ipv4": rewrite.ipv4,
                        "ipv6": rewrite.ipv6,
                        "ttl": rewrite.ttl,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "rewrites": visible,
                "total": rewrites.len(),
                "truncated": rewrites.len() > MAX_ADMIN_LOG_ENTRIES,
            })
            .to_string()
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

        pub(crate) fn observe_listener_latency(&self, elapsed: Duration) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[("operation", "wire_decide")]);
            telemetry.histogram_record(
                "blackhole.listener_latency_ns",
                &labels,
                elapsed.as_nanos() as f64,
            );
        }

        fn observe_reload_latency(&self, kind: &'static str, started: Instant) {
            let Some(telemetry) = self.telemetry.as_ref() else {
                return;
            };
            if !telemetry.is_active() {
                return;
            }
            let labels = Labels::from_pairs(&[("kind", kind)]);
            telemetry.histogram_record(
                "blackhole.reload_latency_ns",
                &labels,
                started.elapsed().as_nanos() as f64,
            );
        }
    }

    fn validate_dhcp(config: &DhcpConfig) -> Result<(), policy::PolicyError> {
        if !config.enabled {
            return Ok(());
        }
        let listen = config.listen.parse::<std::net::SocketAddr>().map_err(|_| {
            policy::PolicyError::InvalidDhcp {
                reason: "listen must be a socket address".into(),
            }
        })?;
        if !listen.ip().is_ipv4() || listen.port() != 67 {
            return Err(policy::PolicyError::InvalidDhcp {
                reason: "listen must be an IPv4 DHCP server address on port 67".into(),
            });
        }
        let parse_ip = |name: &str, value: &str| {
            value
                .parse::<Ipv4Addr>()
                .map_err(|_| policy::PolicyError::InvalidDhcp {
                    reason: format!("{name} must be an IPv4 address"),
                })
        };
        let server = parse_ip("server", &config.server)?;
        let subnet_mask = parse_ip("subnet_mask", &config.subnet_mask)?;
        let pool_start = parse_ip("pool_start", &config.pool_start)?;
        let pool_end = parse_ip("pool_end", &config.pool_end)?;
        if u32::from(pool_start) > u32::from(pool_end) {
            return Err(policy::PolicyError::InvalidDhcp {
                reason: "pool_start must not be greater than pool_end".into(),
            });
        }
        if config.lease_secs == 0 || config.max_leases == 0 || config.max_leases > 4096 {
            return Err(policy::PolicyError::InvalidDhcp {
                reason: "lease_secs and max_leases must be bounded and non-zero".into(),
            });
        }
        for (name, value) in [
            ("router", config.router.as_deref()),
            ("dns", config.dns.as_deref()),
        ] {
            if let Some(value) = value {
                parse_ip(name, value)?;
            }
        }
        let _ = (server, subnet_mask);
        Ok(())
    }

    fn validate_client_identities(
        identities: &[ClientIdentityConfig],
    ) -> Result<Vec<ClientIdentityConfig>, policy::PolicyError> {
        if identities.len() > 1024 {
            return Err(policy::PolicyError::InvalidClientIdentityMap {
                name: "<config>".into(),
                reason: "identity count exceeds 1024".into(),
            });
        }
        let mut names = BTreeSet::new();
        let mut clients = HashMap::new();
        for identity in identities {
            if identity.name.is_empty()
                || identity.name.len() > policy::MAX_CLIENT_IDENTITY_BYTES
                || !identity.name.is_ascii()
                || !names.insert(identity.name.clone())
            {
                return Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: identity.name.clone(),
                    reason: "names must be unique, non-empty, and bounded ASCII".into(),
                });
            }
            if identity.clients.is_empty() || identity.clients.len() > 256 {
                return Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: identity.name.clone(),
                    reason: "each identity must contain 1 to 256 client addresses".into(),
                });
            }
            for client in &identity.clients {
                if let Some(previous) = clients.insert(*client, identity.name.clone()) {
                    return Err(policy::PolicyError::InvalidClientIdentityMap {
                        name: identity.name.clone(),
                        reason: format!("client already belongs to identity {previous}"),
                    });
                }
            }
        }
        Ok(identities.to_vec())
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
            let _client_slot = self.try_client_admission(client);
            if client.is_some() && _client_slot.is_none() {
                self.observe_failure("client_admission_overflow");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            }
            if !self.allow_client_abuse(client) {
                self.observe_failure("client_abuse_breaker_open");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            }
            if !self.allow_client_rate(client) {
                self.observe_failure("client_rate_overflow");
                if self.record_client_abuse(client) {
                    self.observe_failure("client_abuse_breaker_open");
                }
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            }
            if !self.allow_global_rate() {
                self.observe_failure("global_rate_overflow");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            }
            if let (Some(country_policy), Some(client)) =
                (self.country_policy.snapshot().as_ref(), client)
            {
                if country_policy.denied(client) {
                    self.observe_failure("country_policy_denied");
                    self.observe(Action::Reject);
                    return Ok(DnsPipeReply::typed(200, refused_answer()));
                }
                if let Some(country) = country_policy.country_for(client) {
                    if country_policy.observed(client) {
                        self.observe_country(country);
                    }
                }
            }
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
                    if self.matches(&query.name) {
                        Some(match *self.legacy_mode.read().expect("legacy mode lock") {
                            Mode::Ignore => Action::Ignore,
                            Mode::Nxdomain => Action::Nxdomain,
                            Mode::Honeypot => Action::Honeypot,
                        })
                    } else if self.upstream.is_some() {
                        Some(*self.default_action.read().expect("default action lock"))
                    } else {
                        None
                    }
                } else {
                    Some(self.decision(&query, client).map_or(
                        *self.default_action.read().expect("default action lock"),
                        |decision| decision.action,
                    ))
                }
            });
            // The borrowed listener records the action before handing the
            // already-selected action to this owned facade. Record here only
            // for the normal owned-pipe entry point so one DNS request emits
            // one decision event.
            if selected_action.is_none()
                && let Some(action) = action
            {
                self.record_decision(action, &query).await;
            }
            if matches!(action, Some(Action::Pass | Action::Observe) | None) {
                if let Some(answer) = self.rewrites.read().expect("rewrites lock").answer(&query) {
                    self.observe(action.unwrap_or(Action::Pass));
                    return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                }
            }
            let forwarding_action = match action {
                Some(Action::Pass | Action::Observe | Action::Forward) => action,
                _ => None,
            };
            if let Some(forwarding_action) = forwarding_action {
                let Some(slots) = self.upstream_slots.as_ref() else {
                    if forwarding_action == Action::Forward {
                        self.observe_failure("upstream_unconfigured");
                    }
                    self.observe(forwarding_action);
                    return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
                };
                let Ok(_slot) = slots.try_acquire() else {
                    self.observe_failure("upstream_overflow");
                    self.observe(forwarding_action);
                    return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
                };
                let Some(upstream) = self.upstream.as_ref() else {
                    if forwarding_action == Action::Forward {
                        self.observe_failure("upstream_unconfigured");
                    }
                    self.observe(forwarding_action);
                    return Ok(DnsPipeReply::typed(204, DnsAnswer::ok(Vec::new())));
                };
                let key = CacheKey::from_query(&query);
                if let Some(answer) = self.cache_fresh(&key) {
                    self.observe_cache("fresh_hit");
                    self.observe(forwarding_action);
                    return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                }
                self.observe_cache("miss");
                if !self
                    .breaker
                    .lock()
                    .expect("breaker lock")
                    .allow(self.breaker_now_nanos())
                {
                    if let Some(answer) = self.cache_stale(&key) {
                        self.observe_cache("stale_hit");
                        self.observe(forwarding_action);
                        return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                    }
                    self.observe_failure("upstream_circuit_open");
                    self.observe(forwarding_action);
                    return Err(ProximaError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream circuit breaker is open",
                    )));
                }
                let response = upstream
                    .query_with_metadata(&query.name, query.qtype, query.qclass)
                    .await;
                let answer = match response {
                    Ok(response) => {
                        if let Err(cause) = self.validate_upstream_response(&query, &response) {
                            self.breaker
                                .lock()
                                .expect("breaker lock")
                                .on_failure(self.breaker_now_nanos());
                            self.observe_failure(cause);
                            self.observe(forwarding_action);
                            return Ok(DnsPipeReply::typed(200, server_failure_answer()));
                        }
                        self.breaker.lock().expect("breaker lock").on_success();
                        let answer = response.answer;
                        if matches!(answer.rcode, 0 | 3) {
                            self.observe_cache_ttl(&answer);
                            self.cache_insert(key.clone(), answer.clone(), Instant::now());
                        }
                        answer
                    }
                    Err(error) => {
                        self.breaker
                            .lock()
                            .expect("breaker lock")
                            .on_failure(self.breaker_now_nanos());
                        if let Some(answer) = self.cache_stale(&key) {
                            self.observe_cache("stale_hit");
                            self.observe(forwarding_action);
                            return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                        }
                        self.observe_failure("upstream_error");
                        self.observe(forwarding_action);
                        return Err(ProximaError::Io(std::io::Error::other(error.to_string())));
                    }
                };
                self.observe(forwarding_action);
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

    fn mode_label(mode: Mode) -> &'static str {
        match mode {
            Mode::Ignore => "ignore",
            Mode::Nxdomain => "nxdomain",
            Mode::Honeypot => "honeypot",
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
                && name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.is_ascii()
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }))
    }

    fn validate_legacy_domains(domains: &[String]) -> Result<Vec<String>, policy::PolicyError> {
        if domains.len() > policy::MAX_RULES {
            return Err(policy::PolicyError::InvalidProfile {
                name: "<legacy-domains>".into(),
                reason: format!("domain count exceeds {}", policy::MAX_RULES),
            });
        }
        domains
            .iter()
            .map(|raw| {
                let domain = normalize(raw);
                if domain.is_empty() || !valid_dns_name(&domain) {
                    return Err(policy::PolicyError::InvalidProfile {
                        name: "<legacy-domains>".into(),
                        reason: format!("invalid domain {raw}"),
                    });
                }
                Ok(domain)
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use proxima_primitives::pipe::request::RequestContext;

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
            assert!(!Config::default().dhcp.enabled);
        }

        #[test]
        fn enabled_dhcp_configuration_is_bounded_and_validated() {
            let mut config = Config::default();
            config.dhcp.enabled = true;
            assert!(Policy::new(config.clone()).is_ok());

            config.dhcp.max_leases = 4097;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidDhcp { .. })
            ));
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
                client_cidrs: Vec::new(),
                client_identity: None,
            }];
            let policy = Policy::new(config).expect("initial policy");
            let cached_key = CacheKey {
                name: "cached.example".into(),
                qtype: 1,
                qclass: 1,
            };
            policy.cache_insert(cached_key.clone(), DnsAnswer::name_error(), Instant::now());
            assert!(policy.cache_fresh(&cached_key).is_some());
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
                    client_cidrs: Vec::new(),
                    client_identity: None,
                }]),
                Ok(ReloadState::Published)
            );
            assert!(policy.cache_fresh(&cached_key).is_none());
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
                    client_cidrs: Vec::new(),
                    client_identity: None,
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
                    client_cidrs: Vec::new(),
                    client_identity: None,
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
                "# comment\n0.0.0.0 Ads.Example\n||ads.example^\n@@||safe.ads.example^\ntelemetry.example.\n",
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
                policy.evaluate(&query("sub.ads.example.")).unwrap().rcode,
                3
            );
            assert_eq!(
                policy.evaluate(&query("safe.ads.example.")).unwrap().rcode,
                0
            );
            assert_eq!(
                policy
                    .evaluate(&query("deep.safe.ads.example."))
                    .unwrap()
                    .rcode,
                0
            );
            assert_eq!(
                policy.evaluate(&query("telemetry.example.")).unwrap().rcode,
                3
            );
            assert_eq!(policy.evaluate(&query("clear.example.")).unwrap().rcode, 0);
            std::fs::remove_file(path).expect("remove blocklist");
        }

        #[test]
        fn blocklist_source_count_and_path_length_are_bounded() {
            let mut too_many = Config::default();
            too_many.policy.blocklists = vec!["missing".into(); MAX_BLOCKLIST_PATHS + 1];
            assert!(matches!(
                Policy::new(too_many),
                Err(policy::PolicyError::InvalidBlocklist { path, .. }) if path == "<table>"
            ));

            let mut too_long = Config::default();
            too_long.policy.blocklists = vec!["x".repeat(MAX_BLOCKLIST_PATH_BYTES + 1)];
            assert!(matches!(
                Policy::new(too_long),
                Err(policy::PolicyError::InvalidBlocklist { reason, .. })
                    if reason.contains("path exceeds")
            ));
        }

        #[test]
        fn background_blocklist_reload_interval_is_bounded() {
            let mut config = Config::default();
            config.policy.blocklist_reload_interval_secs = MAX_BLOCKLIST_RELOAD_INTERVAL_SECS + 1;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidBlocklist { path, .. }) if path == "<config>"
            ));
            let mut config = Config::default();
            config.country_policy.reload_interval_secs = MAX_BLOCKLIST_RELOAD_INTERVAL_SECS + 1;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidCountryMap { path, .. }) if path == "<config>"
            ));
        }

        #[test]
        fn blocklist_reload_publishes_atomically_and_keeps_last_good_snapshot() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-blocklist-reload-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&path, "old.example\n").expect("write initial blocklist");
            let mut config = Config::default();
            config.policy.default_action = Action::Pass;
            config.policy.blocklists = vec![path.to_string_lossy().into_owned()];
            let policy = Policy::new(config).expect("valid blocklist");
            let query = |name: &str| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(policy.evaluate(&query("old.example.")).unwrap().rcode, 3);

            assert_eq!(
                policy.reload_rules(&[RuleConfig {
                    id: 901,
                    domain: "local.example".into(),
                    action: Action::Reject,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidr: None,
                    client_cidrs: Vec::new(),
                    client_identity: None,
                }]),
                Ok(ReloadState::Published)
            );
            assert_eq!(policy.evaluate(&query("local.example.")).unwrap().rcode, 5);
            assert_eq!(policy.evaluate(&query("old.example.")).unwrap().rcode, 3);

            std::fs::write(&path, "new.example\n").expect("write replacement blocklist");
            assert_eq!(policy.reload_blocklists(), Ok(ReloadState::Published));
            assert_eq!(policy.evaluate(&query("old.example.")).unwrap().rcode, 0);
            assert_eq!(policy.evaluate(&query("new.example.")).unwrap().rcode, 3);

            let replacement_path = std::env::temp_dir().join(format!(
                "blackhole-blocklist-reload-{}-{}.txt",
                std::process::id(),
                2
            ));
            std::fs::write(&replacement_path, "bundle.example\n").expect("write bundle blocklist");
            let replacement_paths = vec![replacement_path.to_string_lossy().into_owned()];
            assert_eq!(
                policy.reload_policy_bundle(
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &CountryPolicyConfig::default(),
                    Some(&replacement_paths),
                ),
                Ok(ReloadState::Published)
            );
            assert_eq!(policy.evaluate(&query("new.example.")).unwrap().rcode, 0);
            assert_eq!(policy.evaluate(&query("bundle.example.")).unwrap().rcode, 3);

            std::fs::write(&replacement_path, "bad..name\n").expect("write invalid blocklist");
            assert!(policy.reload_blocklists().is_err());
            assert_eq!(policy.evaluate(&query("bundle.example.")).unwrap().rcode, 3);
            std::fs::remove_file(path).expect("remove blocklist");
            std::fs::remove_file(replacement_path).expect("remove replacement blocklist");
        }

        #[test]
        fn unchanged_blocklist_reload_does_not_publish_a_generation() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-blocklist-unchanged-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&path, "stable.example\n").expect("write blocklist");
            let mut config = Config::default();
            config.policy.blocklists = vec![path.to_string_lossy().into_owned()];
            let policy = Policy::new(config).expect("valid blocklist");
            let initial_generation = policy.admin_policy_status();
            let initial_generation: serde_json::Value =
                serde_json::from_str(&initial_generation).expect("valid status");
            let initial_generation = initial_generation["policy_generation"]
                .as_u64()
                .expect("generation");
            assert_eq!(
                policy.reload_blocklists_if_changed(),
                Ok(ReloadState::Unchanged)
            );
            let unchanged: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("valid status");
            assert_eq!(
                unchanged["policy_generation"].as_u64(),
                Some(initial_generation)
            );

            std::fs::write(&path, "changed.example\n").expect("write changed blocklist");
            assert_eq!(
                policy.reload_blocklists_if_changed(),
                Ok(ReloadState::Published)
            );
            assert_eq!(
                policy.reload_blocklists_if_changed(),
                Ok(ReloadState::Unchanged)
            );
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
        fn policy_status_readers_observe_only_published_bundle_generations() {
            let policy =
                std::sync::Arc::new(Policy::new(Config::default()).expect("default policy"));
            let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut readers = Vec::new();
            for _ in 0..4 {
                let policy = std::sync::Arc::clone(&policy);
                let failed = std::sync::Arc::clone(&failed);
                readers.push(std::thread::spawn(move || {
                    for _ in 0..500 {
                        let status: serde_json::Value =
                            serde_json::from_str(&policy.admin_policy_status())
                                .expect("valid status");
                        let generation = status["policy_generation"]
                            .as_u64()
                            .expect("generation in status");
                        let domain_rules = status["domain_rules"].as_u64().expect("domain count");
                        let profiles = status["profiles"].as_u64().expect("profile count");
                        let valid = match generation {
                            1 => domain_rules == 0 && profiles == 0,
                            generation if generation % 2 == 0 => domain_rules == 1 && profiles == 0,
                            _ => domain_rules == 1 && profiles == 1,
                        };
                        if !valid {
                            failed.store(true, std::sync::atomic::Ordering::Release);
                            return;
                        }
                    }
                }));
            }

            let explicit = RuleConfig {
                id: 70_001,
                domain: "explicit.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            };
            let profile = ServiceProfileConfig {
                id: 70_002,
                name: "generated".into(),
                domains: vec!["profile.example".into()],
                action: Action::Nxdomain,
                groups: Vec::new(),
                priority: 0,
                client_cidrs: Vec::new(),
                qtype: None,
                qclass: None,
            };
            for _ in 0..64 {
                assert_eq!(
                    policy.reload_policy_bundle(
                        std::slice::from_ref(&explicit),
                        &[],
                        &[],
                        &[],
                        &[],
                        &CountryPolicyConfig::default(),
                        None,
                    ),
                    Ok(ReloadState::Published)
                );
                assert_eq!(
                    policy.reload_policy_bundle(
                        &[],
                        &[],
                        std::slice::from_ref(&profile),
                        &[],
                        &[],
                        &CountryPolicyConfig::default(),
                        None,
                    ),
                    Ok(ReloadState::Published)
                );
            }
            for reader in readers {
                reader.join().expect("reader completed");
            }
            assert!(!failed.load(std::sync::atomic::Ordering::Acquire));
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
                client_cidrs: Vec::new(),
                client_identity: None,
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

            for transport in [
                UpstreamTransport::Tls,
                UpstreamTransport::Doh,
                UpstreamTransport::Doq,
            ] {
                let config = Config {
                    upstream: Some(UpstreamConfig {
                        transport,
                        ..UpstreamConfig::default()
                    }),
                    ..Config::default()
                };
                assert!(matches!(
                    Policy::new(config),
                    Err(policy::PolicyError::InvalidUpstream { .. })
                ));
            }

            let config = Config {
                upstream: Some(UpstreamConfig {
                    transport: UpstreamTransport::Tls,
                    tls_server_name: Some("resolver.example".into()),
                    ..UpstreamConfig::default()
                }),
                ..Config::default()
            };
            assert!(Policy::new(config).is_ok());

            let config = Config {
                upstream: Some(UpstreamConfig {
                    transport: UpstreamTransport::Doh,
                    tls_server_name: Some("resolver.example".into()),
                    ..UpstreamConfig::default()
                }),
                ..Config::default()
            };
            assert!(Policy::new(config).is_ok());

            let config = Config {
                upstream: Some(UpstreamConfig {
                    transport: UpstreamTransport::Doq,
                    tls_server_name: Some("resolver.example".into()),
                    ..UpstreamConfig::default()
                }),
                ..Config::default()
            };
            assert!(Policy::new(config).is_ok());

            for server_name in ["resolver example", "-resolver.example", "résolveur.example"] {
                let config = Config {
                    upstream: Some(UpstreamConfig {
                        transport: UpstreamTransport::Tls,
                        tls_server_name: Some(server_name.into()),
                        ..UpstreamConfig::default()
                    }),
                    ..Config::default()
                };
                assert!(matches!(
                    Policy::new(config),
                    Err(policy::PolicyError::InvalidUpstream { .. })
                ));
            }

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

            let config = Config {
                upstream: Some(UpstreamConfig {
                    max_outstanding: MAX_UPSTREAM_OUTSTANDING + 1,
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
                    max_attempts: MAX_UPSTREAM_ATTEMPTS + 1,
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
                    query_timeout_ms: MAX_UPSTREAM_TIMEOUT_MS + 1,
                    ..UpstreamConfig::default()
                }),
                ..Config::default()
            };
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidUpstream { .. })
            ));

            let config = Config {
                server: ServerConfig {
                    listen: "0.0.0.0:5353".into(),
                },
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

            let config = Config {
                server: ServerConfig {
                    listen: "[::]:5353".into(),
                },
                upstream: Some(UpstreamConfig {
                    resolver_ip: "::1".into(),
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
                client_cidrs: Vec::new(),
                client_identity: None,
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
                client_cidrs: Vec::new(),
                client_identity: None,
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
                client_cidrs: Vec::new(),
                client_identity: None,
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
        fn identity_scoped_rules_use_borrowed_adapter_metadata() {
            let mut config = Config::default();
            config.policy.rules = vec![RuleConfig {
                id: 2,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: Some("family-router".into()),
            }];
            let policy = Policy::new(config).expect("valid identity policy");
            let packet = [
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 8, b'i', b'd', b'e', b'n', b't', b'i', b't',
                b'y', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
            ];
            let view = QueryView::parse(&packet).expect("valid query");
            assert_eq!(
                policy.action_for_view_with_client_identity(
                    view,
                    Some("192.0.2.10".parse().unwrap()),
                    Some("family-router"),
                ),
                Action::Reject
            );
            assert_eq!(
                policy.action_for_view_with_client_identity(
                    view,
                    Some("192.0.2.10".parse().unwrap()),
                    Some("guest-router"),
                ),
                Action::Pass
            );
            assert_eq!(policy.action_for_view(view), Action::Pass);
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("policy status");
            assert_eq!(status["identity_rules"], 1);
            assert!(!status.to_string().contains("family-router"));
        }

        #[test]
        fn configured_client_identity_reaches_the_listener_decision_path() {
            let mut config = Config::default();
            config.policy.client_identities = vec![ClientIdentityConfig {
                name: "family-router".into(),
                clients: vec!["192.0.2.10".parse().expect("client")],
            }];
            config.policy.rules = vec![RuleConfig {
                id: 3,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: Some("family-router".into()),
            }];
            let policy = Policy::new(config).expect("valid identity map");
            let packet = [
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 8, b'i', b'd', b'e', b'n', b't', b'i', b't',
                b'y', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
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
        fn client_identity_reload_publishes_a_complete_lock_free_snapshot() {
            let mut config = Config::default();
            config.policy.rules = vec![RuleConfig {
                id: 4,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: Some("family-router".into()),
            }];
            let policy = Policy::new(config).expect("valid identity policy");
            let packet = [
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 8, b'i', b'd', b'e', b'n', b't', b'i', b't',
                b'y', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
            ];
            let view = QueryView::parse(&packet).expect("valid query");
            let family = "192.0.2.10".parse().expect("client address");
            let guest = "192.0.2.11".parse().expect("client address");
            assert_eq!(
                policy.action_for_view_with_client(view, Some(family)),
                Action::Pass
            );
            assert_eq!(
                policy.reload_client_identities(&[ClientIdentityConfig {
                    name: "family-router".into(),
                    clients: vec![family],
                }]),
                Ok(ReloadState::Published)
            );
            assert_eq!(
                policy.action_for_view_with_client(view, Some(family)),
                Action::Reject
            );
            assert_eq!(
                policy.action_for_view_with_client(view, Some(guest)),
                Action::Pass
            );
            assert_eq!(
                policy.reload_client_identities(&[ClientIdentityConfig {
                    name: "family-router".into(),
                    clients: Vec::new(),
                }]),
                Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: "family-router".into(),
                    reason: "each identity must contain 1 to 256 client addresses".into(),
                })
            );
            assert_eq!(
                policy.action_for_view_with_client(view, Some(family)),
                Action::Reject
            );
        }

        #[test]
        fn country_map_denies_and_observes_adapter_owned_clients() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-country-map-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(
                &path,
                "US 192.0.2.0/24 US-CA AS64500\nCA 198.51.100.0/24 CA-ON 64501\n",
            )
            .expect("write country map");
            let mut config = Config::default();
            config.country_policy = CountryPolicyConfig {
                map_path: Some(path.to_string_lossy().into_owned()),
                max_age_secs: None,
                reload_interval_secs: 0,
                deny: vec!["us".into()],
                observe: Vec::new(),
                deny_regions: vec!["us-ca".into()],
                observe_regions: Vec::new(),
                deny_asns: Vec::new(),
                observe_asns: vec![64501],
            };
            let policy = Policy::new(config).expect("valid country policy");
            let denied = "192.0.2.10".parse().expect("client address");
            let observed = "198.51.100.10".parse().expect("client address");
            let outside = "203.0.113.10".parse().expect("client address");
            {
                let country_policy = policy
                    .country_policy
                    .snapshot()
                    .as_ref()
                    .clone()
                    .expect("country policy");
                assert!(country_policy.denied(denied));
                assert!(country_policy.observed(observed));
                assert!(!country_policy.denied(outside));
                assert!(!country_policy.observed(outside));
            }
            assert_eq!(
                policy.reload_country_policy_if_changed(),
                Ok(ReloadState::Unchanged)
            );
            std::fs::write(
                &path,
                "US 192.0.2.0/24 US-CA AS64500\nCA 198.51.100.0/24 CA-ON 64501\nGB 203.0.113.0/24 GB-LND 64502\n",
            )
            .expect("change country map");
            assert_eq!(
                policy.reload_country_policy_if_changed(),
                Ok(ReloadState::Published)
            );
            std::fs::write(&path, "not-a-country-map\n").expect("corrupt country map");
            assert!(policy.reload_country_policy().is_err());
            {
                let country_policy = policy
                    .country_policy
                    .snapshot()
                    .as_ref()
                    .clone()
                    .expect("previous country policy");
                assert!(country_policy.denied(denied));
                assert!(country_policy.observed(observed));
            }

            let request = |client| DnsPipeRequest {
                method: proxima_primitives::pipe::method::Method::from_wire(
                    bytes::Bytes::from_static(b"DNS"),
                ),
                path: bytes::Bytes::from_static(b"/"),
                query: proxima_primitives::pipe::header_list::HeaderList::new(),
                metadata: proxima_primitives::pipe::header_list::HeaderList::new(),
                payload: proxima_dns::DnsQuery {
                    id: 1,
                    recursion_desired: true,
                    name: "example.com.".into(),
                    qtype: 1,
                    qclass: 1,
                },
                stream: None,
                context: RequestContext {
                    peer: Some(PeerInfo::Tcp(std::net::SocketAddr::new(client, 1234))),
                    ..RequestContext::default()
                },
            };
            let denied_answer = futures::executor::block_on(policy.call(request(denied)))
                .expect("country deny returns a DNS answer")
                .payload;
            assert_eq!(denied_answer.rcode, 5);
            let outside_answer = futures::executor::block_on(policy.call(request(outside)))
                .expect("outside country map returns a DNS answer")
                .payload;
            assert_eq!(outside_answer.rcode, 0);
            std::fs::remove_file(path).expect("remove country map");
        }

        #[test]
        fn country_map_freshness_is_bounded_and_clock_skew_fails_closed() {
            let now = std::time::UNIX_EPOCH + Duration::from_secs(10_000);
            assert!(country_map_is_fresh(now - Duration::from_secs(60), now, 60));
            assert!(!country_map_is_fresh(
                now - Duration::from_secs(61),
                now,
                60
            ));
            assert!(!country_map_is_fresh(now + Duration::from_secs(1), now, 60));
            assert!(!country_map_is_fresh(now, now, 0));
        }

        #[test]
        fn country_map_rejects_cross_dimension_deny_observe_overlap() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-country-conflict-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&path, "US 192.0.2.0/24 US-CA AS64500\n").expect("write country map");
            let mut config = Config::default();
            config.country_policy = CountryPolicyConfig {
                map_path: Some(path.to_string_lossy().into_owned()),
                max_age_secs: None,
                reload_interval_secs: 0,
                deny: vec!["US".into()],
                observe: Vec::new(),
                deny_regions: Vec::new(),
                observe_regions: vec!["US-CA".into()],
                deny_asns: Vec::new(),
                observe_asns: Vec::new(),
            };
            assert!(Policy::new(config).is_err());
            std::fs::remove_file(path).expect("remove country map");
        }

        #[test]
        fn cache_bounds_entries_and_serves_positive_and_negative_answers() {
            let config = CacheConfig {
                max_entries: 1,
                max_ttl_secs: 60,
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
            assert!(!cache.insert(first.clone(), DnsAnswer::ok(Vec::new()), now));
            assert!(cache.fresh(&first).is_some());
            assert!(cache.insert(second.clone(), DnsAnswer::name_error(), now));
            assert_eq!(cache.entries.len(), 1);
            assert!(cache.fresh(&first).is_none());
            assert_eq!(cache.fresh(&second), Some(DnsAnswer::name_error()));
        }

        #[test]
        fn regex_rules_block_matching_names_and_honor_filters() {
            let mut config = Config::default();
            config.policy.default_action = Action::Pass;
            config.policy.regex_rules = vec![RegexRuleConfig {
                id: 77,
                pattern: r"(^|\.)ads[0-9]*\.example$".into(),
                action: Action::Nxdomain,
                priority: 4,
                qtype: Some(1),
                qclass: Some(1),
                client: None,
                client_cidrs: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid regex rule");
            let query = |name: &str, qtype: u16| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype,
                qclass: 1,
            };
            assert_eq!(policy.evaluate(&query("ads.example.", 1)).unwrap().rcode, 3);
            assert_eq!(
                policy.evaluate(&query("ads2.example.", 1)).unwrap().rcode,
                3
            );
            assert_eq!(
                policy.evaluate(&query("ads.example.", 28)).unwrap().rcode,
                0
            );
            assert_eq!(policy.evaluate(&query("badexample.", 1)).unwrap().rcode, 0);
            let mut wire = Vec::new();
            proxima_protocols::dns::encode::encode_query(
                7,
                true,
                proxima_protocols::dns::encode::EncodeQuestion {
                    name: "ads.example.",
                    qtype: 1,
                    qclass: 1,
                },
                &mut wire,
            )
            .expect("encode regex query");
            let view = QueryView::parse(&wire).expect("parse regex query");
            assert_eq!(policy.action_for_view(view), Action::Nxdomain);
        }

        #[test]
        fn regex_rules_honor_client_network_scopes() {
            let mut config = Config::default();
            config.policy.default_action = Action::Pass;
            config.policy.regex_rules = vec![RegexRuleConfig {
                id: 78,
                pattern: r"(^|\.)ads\.example$".into(),
                action: Action::Nxdomain,
                priority: 4,
                qtype: None,
                qclass: None,
                client: None,
                client_cidrs: vec!["192.0.2.0/24".into()],
            }];
            let policy = Policy::new(config).expect("valid scoped regex rule");
            let mut wire = Vec::new();
            proxima_protocols::dns::encode::encode_query(
                8,
                true,
                proxima_protocols::dns::encode::EncodeQuestion {
                    name: "ads.example.",
                    qtype: 1,
                    qclass: 1,
                },
                &mut wire,
            )
            .expect("encode regex query");
            let view = QueryView::parse(&wire).expect("parse regex query");
            assert_eq!(
                policy.action_for_view_with_client(
                    view,
                    Some("192.0.2.44".parse().expect("client address"))
                ),
                Action::Nxdomain
            );
            assert_eq!(
                policy.action_for_view_with_client(
                    view,
                    Some("198.51.100.44".parse().expect("client address"))
                ),
                Action::Pass
            );
        }

        #[test]
        fn explicit_domain_rules_win_over_matching_regex_rules() {
            let mut config = Config::default();
            config.policy.default_action = Action::Pass;
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "ads.example".into(),
                action: Action::Pass,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            }];
            config.policy.regex_rules = vec![RegexRuleConfig {
                id: 2,
                pattern: r"(^|\.)ads\.example$".into(),
                action: Action::Nxdomain,
                priority: 100,
                qtype: None,
                qclass: None,
                client: None,
                client_cidrs: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid mixed policy");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "ads.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(policy.evaluate(&query).unwrap().rcode, 0);
        }

        #[test]
        fn regex_rules_reject_invalid_or_oversized_patterns() {
            let mut invalid = Config::default();
            invalid.policy.regex_rules = vec![RegexRuleConfig {
                id: 1,
                pattern: "[".into(),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidrs: Vec::new(),
            }];
            assert!(matches!(
                Policy::new(invalid),
                Err(policy::PolicyError::InvalidRegex { id: 1, .. })
            ));

            let mut invalid_scope = Config::default();
            invalid_scope.policy.regex_rules = vec![RegexRuleConfig {
                id: 3,
                pattern: "ads".into(),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidrs: vec!["not-a-cidr".into()],
            }];
            assert!(matches!(
                Policy::new(invalid_scope),
                Err(policy::PolicyError::InvalidClientCidr { id: 3, .. })
            ));

            let mut oversized = Config::default();
            oversized.policy.regex_rules = vec![RegexRuleConfig {
                id: 2,
                pattern: "x".repeat(MAX_REGEX_PATTERN_BYTES + 1),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidrs: Vec::new(),
            }];
            assert!(matches!(
                Policy::new(oversized),
                Err(policy::PolicyError::InvalidRegex { id: 2, .. })
            ));
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
        fn cache_clamps_protocol_ttl_to_the_configured_bound() {
            let config = CacheConfig {
                max_entries: 4,
                max_ttl_secs: 60,
                stale_ttl_secs: 30,
                negative_ttl_secs: 120,
            };
            let mut cache = DnsCache::new(&config);
            let key = CacheKey {
                name: "long.example".into(),
                qtype: 1,
                qclass: 1,
            };
            let now = Instant::now();
            cache.insert(
                key.clone(),
                DnsAnswer::ok(vec![DnsAnswerRecord {
                    name: "long.example.".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: u32::MAX,
                    rdata: vec![192, 0, 2, 1],
                }]),
                now,
            );
            let entry = cache.entries.get(&key).expect("cache entry");
            assert!(entry.expires_at <= now + Duration::from_secs(60));
            assert!(entry.expires_at > now + Duration::from_secs(59));
        }

        #[test]
        fn cache_rejects_a_zero_ttl_ceiling() {
            let mut config = Config::default();
            config.cache.max_ttl_secs = 0;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidCache { .. })
            ));
        }

        #[test]
        fn upstream_breaker_opens_after_bounded_failures_and_recovers() {
            let mut breaker = ProximaCircuitBreaker::new(2, Duration::from_secs(30), 1);
            assert!(breaker.allow(0));
            breaker.on_failure(0);
            assert!(breaker.allow(0));
            breaker.on_failure(0);
            assert!(!breaker.allow(1));
            assert!(breaker.allow(30_000_000_000));
            breaker.on_success();
            assert!(breaker.allow(30_000_000_001));
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
                ("pass.example", Action::Pass),
                ("observe.example", Action::Observe),
                ("ignore.example", Action::Ignore),
                ("drop.example", Action::Drop),
                ("forward.example", Action::Forward),
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
                    client_cidrs: Vec::new(),
                    client_identity: None,
                }];
                let policy = Policy::new(config).expect("valid policy");
                match action {
                    Action::Reject => assert_eq!(policy.evaluate(&query(domain)).unwrap().rcode, 5),
                    Action::Nxdomain => {
                        assert_eq!(policy.evaluate(&query(domain)).unwrap().rcode, 3)
                    }
                    Action::Sink => {
                        assert!(policy.evaluate(&query(domain)).unwrap().records.is_empty())
                    }
                    Action::Honeypot => {
                        assert_eq!(policy.evaluate(&query(domain)).unwrap().records.len(), 1)
                    }
                    Action::Pass | Action::Observe => {
                        assert!(policy.evaluate(&query(domain)).unwrap().records.is_empty())
                    }
                    Action::Ignore | Action::Drop | Action::Forward => {
                        assert!(policy.evaluate(&query(domain)).is_none())
                    }
                }
            }
        }

        #[test]
        fn local_rewrite_answers_pass_queries_but_explicit_policy_wins() {
            let mut config = Config::default();
            config.policy.rewrites = vec![
                RewriteConfig {
                    name: "router.home.arpa".into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    ipv6: Some(Ipv6Addr::LOCALHOST),
                    ttl: 30,
                },
                RewriteConfig {
                    name: "blocked.home.arpa".into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 2)),
                    ipv6: None,
                    ttl: 30,
                },
            ];
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "blocked.home.arpa".into(),
                action: Action::Nxdomain,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            }];
            let policy = Policy::new(config).expect("valid rewrites");
            let query = |name: &str, qtype: u16| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype,
                qclass: 1,
            };
            let answer = policy
                .evaluate(&query("router.home.arpa.", 1))
                .expect("rewrite answer");
            assert_eq!(answer.rcode, 0);
            assert_eq!(answer.records.len(), 1);
            assert_eq!(answer.records[0].rdata, vec![192, 0, 2, 1]);
            let aaaa = policy
                .evaluate(&query("router.home.arpa.", 28))
                .expect("AAAA rewrite answer");
            assert_eq!(aaaa.records.len(), 1);
            assert_eq!(
                aaaa.records[0].rdata.as_slice(),
                Ipv6Addr::LOCALHOST.octets().as_slice()
            );
            let blocked = policy
                .evaluate(&query("blocked.home.arpa.", 1))
                .expect("policy answer");
            assert_eq!(blocked.rcode, 3);
            assert!(blocked.records.is_empty());
        }

        #[test]
        fn local_rewrites_fail_closed_when_invalid_or_oversized() {
            let mut invalid = Config::default();
            invalid.policy.rewrites = vec![RewriteConfig {
                name: "not a dns name".into(),
                ipv4: None,
                ipv6: None,
                ttl: 30,
            }];
            assert!(matches!(
                Policy::new(invalid),
                Err(policy::PolicyError::InvalidRewrite { .. })
            ));

            for name in [
                "has space.example",
                "has_underscore.example",
                "-leading.example",
                "trailing-.example",
            ] {
                let mut invalid = Config::default();
                invalid.policy.rewrites = vec![RewriteConfig {
                    name: name.into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    ipv6: None,
                    ttl: 30,
                }];
                assert!(
                    matches!(
                        Policy::new(invalid),
                        Err(policy::PolicyError::InvalidRewrite { .. })
                    ),
                    "invalid rewrite name must fail closed: {name}"
                );
            }

            let mut oversized = Config::default();
            oversized.policy.rewrites = (0..=MAX_REWRITES)
                .map(|index| RewriteConfig {
                    name: format!("host{index}.home.arpa"),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    ipv6: None,
                    ttl: 30,
                })
                .collect();
            assert!(matches!(
                Policy::new(oversized),
                Err(policy::PolicyError::InvalidRewrite { .. })
            ));
        }

        #[test]
        fn cache_ttl_telemetry_reports_effective_positive_and_negative_ttls() {
            use proxima::Telemetry;
            use std::sync::Arc;
            use std::sync::Mutex;

            struct CacheTtlTelemetry {
                values: Mutex<Vec<(String, f64)>>,
            }

            impl Telemetry for CacheTtlTelemetry {
                fn counter_inc(&self, _: &str, _: &Labels, _: u64) {}
                fn gauge_set(&self, _: &str, _: &Labels, _: i64) {}
                fn histogram_record(&self, metric: &str, labels: &Labels, value: f64) {
                    assert_eq!(metric, "blackhole.cache_ttl_seconds");
                    assert_eq!(labels.entries().len(), 1);
                    assert_eq!(labels.entries()[0].0, "kind");
                    self.values
                        .lock()
                        .expect("cache telemetry lock")
                        .push((labels.entries()[0].1.to_owned(), value));
                }
            }

            let telemetry = Arc::new(CacheTtlTelemetry {
                values: Mutex::new(Vec::new()),
            });
            let mut config = Config::default();
            config.cache.max_ttl_secs = 120;
            config.cache.negative_ttl_secs = 17;
            let policy = Policy::new(config)
                .expect("valid cache config")
                .with_telemetry(telemetry.clone());
            policy.observe_cache_ttl(&DnsAnswer::ok(vec![DnsAnswerRecord {
                name: "answer.example.".into(),
                rtype: 1,
                rclass: 1,
                ttl: 900,
                rdata: vec![93, 184, 216, 34],
            }]));
            policy.observe_cache_ttl(&DnsAnswer::name_error());

            assert_eq!(
                *telemetry.values.lock().expect("cache telemetry lock"),
                vec![("positive".into(), 120.0), ("negative".into(), 17.0)]
            );
        }

        #[test]
        fn named_service_profiles_compile_into_scoped_authoritative_rules() {
            let mut config = Config::default();
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 40_000,
                name: "Adult content".into(),
                domains: vec!["ads.example".into(), "tracking.example".into()],
                action: Action::Nxdomain,
                groups: Vec::new(),
                priority: 10,
                client_cidrs: vec!["192.0.2.0/24".into()],
                qtype: Some(1),
                qclass: Some(1),
            }];
            let policy = Policy::new(config).expect("valid service profile");
            let query = proxima_dns::DnsQuery {
                id: 7,
                recursion_desired: true,
                name: "ads.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(
                policy
                    .decision(&query, Some("192.0.2.53".parse().unwrap()))
                    .expect("scoped profile decision")
                    .action,
                Action::Nxdomain
            );
            assert!(
                policy
                    .decision(&query, Some("198.51.100.53".parse().unwrap()))
                    .is_none()
            );
            assert!(policy.decision(&query, None).is_none());
            let mut wrong_type = query.clone();
            wrong_type.qtype = 28;
            assert!(
                policy
                    .decision(&wrong_type, Some("192.0.2.53".parse().unwrap()))
                    .is_none()
            );
            let mut wrong_class = query;
            wrong_class.qclass = 3;
            assert!(
                policy
                    .decision(&wrong_class, Some("192.0.2.53".parse().unwrap()))
                    .is_none()
            );
        }

        #[test]
        fn client_groups_assign_one_profile_to_multiple_networks() {
            let mut config = Config::default();
            config.policy.client_groups = vec![
                ClientGroupConfig {
                    name: "family".into(),
                    client_addresses: Vec::new(),
                    client_cidrs: vec!["192.0.2.0/24".into(), "2001:db8:1::/64".into()],
                },
                ClientGroupConfig {
                    name: "guest".into(),
                    client_addresses: Vec::new(),
                    client_cidrs: vec!["198.51.100.0/24".into()],
                },
            ];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 50_000,
                name: "family-blocks".into(),
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["FAMILY".into(), "guest".into()],
                priority: 10,
                client_cidrs: Vec::new(),
                qtype: None,
                qclass: None,
            }];
            let policy = Policy::new(config).expect("valid client groups");
            let query = proxima_dns::DnsQuery {
                id: 7,
                recursion_desired: true,
                name: "ads.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            for client in ["192.0.2.53", "2001:db8:1::53", "198.51.100.53"] {
                assert_eq!(
                    policy
                        .decision(&query, Some(client.parse().unwrap()))
                        .expect("group-scoped decision")
                        .action,
                    Action::Nxdomain
                );
            }
            assert!(
                policy
                    .decision(&query, Some("203.0.113.53".parse().unwrap()))
                    .is_none()
            );
        }

        #[test]
        fn client_groups_match_exact_addresses_and_cidrs_without_broadening_exact_scope() {
            let mut config = Config::default();
            config.policy.client_groups = vec![ClientGroupConfig {
                name: "named-clients".into(),
                client_addresses: vec!["192.0.2.53".parse().unwrap()],
                client_cidrs: vec!["198.51.100.0/24".into()],
            }];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 51_000,
                name: "named-policy".into(),
                domains: vec!["ads.example".into()],
                action: Action::Reject,
                groups: vec!["named-clients".into()],
                priority: 0,
                client_cidrs: Vec::new(),
                qtype: None,
                qclass: None,
            }];
            let policy = Policy::new(config).expect("valid exact client group");
            let query = proxima_dns::DnsQuery {
                id: 7,
                recursion_desired: true,
                name: "ads.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(
                policy
                    .decision(&query, Some("192.0.2.53".parse().unwrap()))
                    .expect("exact client decision")
                    .action,
                Action::Reject
            );
            assert!(
                policy
                    .decision(&query, Some("192.0.2.54".parse().unwrap()))
                    .is_none()
            );
            assert_eq!(
                policy
                    .decision(&query, Some("198.51.100.53".parse().unwrap()))
                    .expect("CIDR client decision")
                    .action,
                Action::Reject
            );
        }

        #[test]
        fn client_groups_reject_unknown_or_ambiguous_scopes() {
            let mut unknown = Config::default();
            unknown.policy.profiles = vec![ServiceProfileConfig {
                id: 1,
                name: "ads".into(),
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["missing".into()],
                priority: 0,
                client_cidrs: Vec::new(),
                qtype: None,
                qclass: None,
            }];
            assert!(matches!(
                Policy::new(unknown),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));

            let mut ambiguous = Config::default();
            ambiguous.policy.client_groups = vec![ClientGroupConfig {
                name: "family".into(),
                client_addresses: Vec::new(),
                client_cidrs: vec!["192.0.2.0/24".into()],
            }];
            ambiguous.policy.profiles = vec![ServiceProfileConfig {
                id: 2,
                name: "ads".into(),
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["family".into()],
                priority: 0,
                client_cidrs: vec!["198.51.100.0/24".into()],
                qtype: None,
                qclass: None,
            }];
            assert!(matches!(
                Policy::new(ambiguous),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));

            let mut duplicate_address = Config::default();
            duplicate_address.policy.client_groups = vec![ClientGroupConfig {
                name: "family".into(),
                client_addresses: vec![
                    "192.0.2.53".parse().unwrap(),
                    "192.0.2.53".parse().unwrap(),
                ],
                client_cidrs: Vec::new(),
            }];
            assert!(matches!(
                Policy::new(duplicate_address),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));
        }

        #[test]
        fn service_profiles_reject_duplicate_names_and_invalid_domains() {
            let mut config = Config::default();
            config.policy.profiles = vec![
                ServiceProfileConfig {
                    id: 1,
                    name: "ads".into(),
                    domains: vec!["ads.example".into()],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qclass: None,
                },
                ServiceProfileConfig {
                    id: 2,
                    name: "ADS".into(),
                    domains: vec!["tracking.example".into()],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qclass: None,
                },
            ];
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));
        }

        #[test]
        fn service_profiles_enforce_an_aggregate_rule_bound() {
            let mut config = Config::default();
            let per_profile = policy::MAX_RULES / 2 + 1;
            config.policy.profiles = vec![
                ServiceProfileConfig {
                    id: 10_000,
                    name: "first".into(),
                    domains: vec!["first.example".into(); per_profile],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qclass: None,
                },
                ServiceProfileConfig {
                    id: 200_000,
                    name: "second".into(),
                    domains: vec!["second.example".into(); per_profile],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qclass: None,
                },
            ];
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));
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
            let mut zero_type = query("example.com.", 1);
            zero_type.qtype = 0;
            assert_eq!(policy.evaluate(&zero_type).unwrap().rcode, 5);
            let mut zero_class = query("example.com.", 1);
            zero_class.qclass = 0;
            assert_eq!(policy.evaluate(&zero_class).unwrap().rcode, 5);
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
                    config.admission.max_response_amplification = 0;
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
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_queries_per_second = 0;
                    config
                })
                .is_err()
            );
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_inflight_per_client = 0;
                    config
                })
                .is_err()
            );
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_queries_per_client_per_second = 0;
                    config
                })
                .is_err()
            );
            assert!(
                Policy::new({
                    let mut config = Config::default();
                    config.admission.max_response_bytes_per_second = 0;
                    config
                })
                .is_err()
            );
        }

        #[test]
        fn admission_reload_publishes_limits_and_rejects_capacity_changes() {
            let policy = Policy::new(Config::default()).expect("valid policy");
            let mut replacement = AdmissionConfig::default();
            replacement.reject_any = true;
            replacement.max_queries_per_second = 7;
            assert_eq!(
                policy.reload_admission(&replacement),
                Ok(ReloadState::Published)
            );
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_admission_status()).expect("admission status");
            assert_eq!(status["reject_any"], true);
            assert_eq!(status["max_queries_per_second"], 7);

            let mut capacity_change = replacement.clone();
            capacity_change.max_inflight_requests += 1;
            assert!(matches!(
                policy.reload_admission(&capacity_change),
                Err(policy::PolicyError::InvalidAdmission { .. })
            ));
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_admission_status()).expect("admission status");
            assert_eq!(
                status["max_inflight_requests"],
                AdmissionConfig::default().max_inflight_requests
            );
        }

        #[test]
        fn per_client_admission_is_bounded_and_releases_on_completion() {
            let mut config = Config::default();
            config.admission.max_inflight_per_client = 1;
            let policy = Policy::new(config).expect("valid admission config");
            let client = "192.0.2.10".parse().expect("client address");
            let permit = policy
                .try_client_admission(Some(client))
                .expect("first request admitted");
            assert!(policy.try_client_admission(Some(client)).is_none());
            drop(permit);
            assert!(policy.try_client_admission(Some(client)).is_some());
            assert!(
                policy
                    .try_client_admission(Some("192.0.2.11".parse().unwrap()))
                    .is_some()
            );
            assert!(policy.try_client_admission(None).is_none());
        }

        #[test]
        fn per_client_rate_limit_sheds_repeated_requests() {
            let mut config = Config::default();
            config.admission.max_queries_per_client_per_second = 2;
            let policy = Policy::new(config).expect("valid admission config");
            let client = Some("192.0.2.10".parse().expect("client address"));
            assert!(policy.allow_client_rate(client));
            assert!(policy.allow_client_rate(client));
            assert!(!policy.allow_client_rate(client));
            assert!(policy.allow_client_rate(None));
        }

        #[test]
        fn global_rate_limit_sheds_anonymous_and_identified_requests() {
            let mut config = Config::default();
            config.admission.max_queries_per_second = 2;
            let policy = Policy::new(config).expect("valid admission config");
            assert!(policy.allow_global_rate());
            assert!(policy.allow_global_rate());
            assert!(!policy.allow_global_rate());
        }

        #[test]
        fn repeated_rate_overflow_opens_bounded_client_abuse_breaker() {
            let mut config = Config::default();
            config.admission.max_queries_per_client_per_second = 1;
            config.admission.max_client_abuse_violations = 2;
            config.admission.client_abuse_cooldown_secs = 60;
            let policy = Policy::new(config).expect("valid abuse config");
            let client = Some("192.0.2.44".parse().unwrap());
            assert!(policy.allow_client_rate(client));
            assert!(!policy.allow_client_rate(client));
            assert!(!policy.record_client_abuse(client));
            assert!(policy.allow_client_abuse(client));
            assert!(!policy.allow_client_rate(client));
            assert!(policy.record_client_abuse(client));
            assert!(!policy.allow_client_abuse(client));
            assert!(policy.allow_client_abuse(None));
        }

        #[test]
        fn network_abuse_breaker_sheds_only_the_offending_network() {
            let mut config = Config::default();
            config.admission.max_client_abuse_violations = 100;
            config.admission.max_network_abuse_violations = 2;
            config.admission.network_abuse_cooldown_secs = 60;
            let policy = Policy::new(config).expect("valid network abuse config");
            let first = Some("192.0.2.10".parse().expect("first client"));
            let second = Some("192.0.2.11".parse().expect("second client"));
            let other_network = Some("192.0.3.10".parse().expect("other client"));

            assert!(!policy.record_client_abuse(first));
            assert!(policy.allow_client_abuse(second));
            assert!(policy.record_client_abuse(second));
            assert!(!policy.allow_client_abuse(first));
            assert!(!policy.allow_client_abuse(second));
            assert!(policy.allow_client_abuse(other_network));
            assert!(policy.allow_client_abuse(None));

            assert_eq!(
                abuse_network_key("2001:db8:1:2::10".parse().unwrap(), 24, 64),
                abuse_network_key("2001:db8:1:2::11".parse().unwrap(), 24, 64)
            );
            assert_ne!(
                abuse_network_key("2001:db8:1:2::10".parse().unwrap(), 24, 64),
                abuse_network_key("2001:db8:1:3::10".parse().unwrap(), 24, 64)
            );
        }

        #[test]
        fn response_byte_budget_sheds_a_client_without_affecting_unidentified_callers() {
            let mut config = Config::default();
            config.admission.max_response_bytes_per_client_per_second = 10;
            config.admission.max_client_abuse_violations = 2;
            let policy = Policy::new(config).expect("valid policy");
            let client = Some("192.0.2.10".parse().expect("client address"));
            assert!(policy.allow_client_response_bytes(client, 6));
            assert!(!policy.allow_client_response_bytes(client, 5));
            assert!(!policy.record_client_abuse(client));
            assert!(policy.allow_client_abuse(client));
            assert!(!policy.allow_client_response_bytes(client, 5));
            assert!(policy.record_client_abuse(client));
            assert!(!policy.allow_client_abuse(client));
            assert!(policy.allow_client_response_bytes(None, 4096));
            assert!(policy.allow_client_abuse(None));
        }

        #[test]
        fn network_response_budget_covers_clients_in_the_same_network() {
            let mut config = Config::default();
            config.admission.max_response_bytes_per_network_per_second = 10;
            let policy = Policy::new(config).expect("valid network response budget");
            let first = Some("192.0.2.10".parse().expect("first client"));
            let second = Some("192.0.2.11".parse().expect("second client"));
            let other_network = Some("192.0.3.10".parse().expect("other client"));

            assert!(policy.allow_network_response_bytes(first, 6));
            assert!(!policy.allow_network_response_bytes(second, 5));
            assert!(policy.allow_network_response_bytes(other_network, 5));
            assert!(policy.allow_network_response_bytes(None, 4096));
        }

        #[test]
        fn global_response_budget_covers_unidentified_egress() {
            let mut config = Config::default();
            config.admission.max_response_bytes_per_second = 10;
            let policy = Policy::new(config).expect("valid policy");
            assert!(policy.allow_global_response_bytes(6));
            assert!(!policy.allow_global_response_bytes(5));
            assert!(policy.allow_global_response_bytes(4));
            assert!(!policy.allow_global_response_bytes(3));
        }

        #[test]
        fn zero_response_byte_budget_is_rejected() {
            let mut config = Config::default();
            config.admission.max_response_bytes_per_client_per_second = 0;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidAdmission { .. })
            ));

            let mut config = Config::default();
            config.admission.max_response_bytes_per_network_per_second = 0;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidAdmission { .. })
            ));
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
                client_cidrs: Vec::new(),
                client_identity: None,
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
        fn admission_caps_response_amplification_relative_to_query() {
            let mut config = Config::default();
            config.admission.max_response_bytes = 4096;
            config.admission.max_response_amplification = 1;
            config.policy.rules = vec![RuleConfig {
                id: 1,
                domain: "honeypot.example".into(),
                action: Action::Honeypot,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
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
                client_cidrs: Vec::new(),
                client_identity: None,
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

            let invalid_rcode = DnsAnswer {
                rcode: 16,
                ..DnsAnswer::ok(Vec::new())
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &invalid_rcode),
                Err("upstream_malformed")
            );

            let mut cname_rdata = Vec::new();
            proxima_protocols::dns::encode::encode_name("target.example.", &mut cname_rdata)
                .expect("valid cname target");
            let valid_cname = DnsAnswer {
                records: vec![DnsAnswerRecord {
                    name: "answer.example.".into(),
                    rtype: 5,
                    rclass: 1,
                    ttl: 30,
                    rdata: cname_rdata,
                }],
                ..DnsAnswer::ok(Vec::new())
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &valid_cname),
                Ok(())
            );

            let malformed_cname = DnsAnswer {
                records: vec![DnsAnswerRecord {
                    name: "answer.example.".into(),
                    rtype: 5,
                    rclass: 1,
                    ttl: 30,
                    rdata: vec![0xc0, 0x00],
                }],
                ..DnsAnswer::ok(Vec::new())
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &malformed_cname),
                Err("upstream_malformed")
            );

            let oversized_records = DnsAnswer {
                records: vec![
                    DnsAnswerRecord {
                        name: "answer.example.".into(),
                        rtype: 1,
                        rclass: 1,
                        ttl: 30,
                        rdata: vec![93, 184, 216, 34],
                    };
                    policy.config.admission.max_response_records + 1
                ],
                ..DnsAnswer::ok(Vec::new())
            };
            assert_eq!(
                policy.validate_upstream_answer(&query, &oversized_records),
                Err("upstream_overflow")
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

        #[test]
        fn telemetry_records_reload_latency_by_reload_kind() {
            use proxima::Telemetry;
            use std::sync::{Arc, Mutex};

            struct ReloadTelemetry {
                kinds: Mutex<Vec<String>>,
            }

            impl Telemetry for ReloadTelemetry {
                fn counter_inc(&self, _: &str, _: &Labels, _: u64) {}
                fn gauge_set(&self, _: &str, _: &Labels, _: i64) {}
                fn histogram_record(&self, metric: &str, labels: &Labels, value: f64) {
                    assert_eq!(metric, "blackhole.reload_latency_ns");
                    assert_eq!(labels.entries().len(), 1);
                    assert!(value >= 0.0);
                    self.kinds
                        .lock()
                        .expect("reload telemetry lock")
                        .push(labels.entries()[0].1.to_owned());
                }
            }

            let telemetry = Arc::new(ReloadTelemetry {
                kinds: Mutex::new(Vec::new()),
            });
            let policy = Policy::new(Config::default())
                .expect("valid policy")
                .with_telemetry(telemetry.clone());
            policy
                .reload_rules(&[RuleConfig {
                    id: 1,
                    domain: "blocked.example".into(),
                    action: Action::Nxdomain,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidr: None,
                    client_cidrs: Vec::new(),
                    client_identity: None,
                }])
                .expect("rules reload");
            policy
                .reload_regex_rules(&[RegexRuleConfig {
                    id: 2,
                    pattern: "blocked".into(),
                    action: Action::Drop,
                    priority: 0,
                    qtype: None,
                    qclass: None,
                    client: None,
                    client_cidrs: Vec::new(),
                }])
                .expect("regex reload");

            assert_eq!(
                *telemetry.kinds.lock().expect("reload telemetry lock"),
                vec!["rules".to_owned(), "regex".to_owned()]
            );
        }

        #[test]
        fn recording_sink_receives_only_dns_decision_metadata() {
            use proxima::{RecordingEvent, RecordingSink};
            use std::sync::{Arc, Mutex};

            struct Collector(Arc<Mutex<Vec<RecordingEvent>>>);

            impl RecordingSink for Collector {
                fn append<'lifetime>(
                    &'lifetime self,
                    event: RecordingEvent,
                ) -> proxima::RecordingAppendFuture<'lifetime> {
                    let events = Arc::clone(&self.0);
                    Box::pin(async move {
                        events.lock().expect("recording lock").push(event);
                        Ok(())
                    })
                }

                fn flush<'lifetime>(&'lifetime self) -> proxima::RecordingAppendFuture<'lifetime> {
                    Box::pin(async { Ok(()) })
                }
            }

            let events = Arc::new(Mutex::new(Vec::new()));
            let policy = Policy::new(Config::default())
                .expect("valid policy")
                .with_recording_sink(Arc::new(Collector(Arc::clone(&events))));
            let query = proxima_dns::DnsQuery {
                id: 9,
                recursion_desired: true,
                name: "secret.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            futures::executor::block_on(policy.record_decision(Action::Nxdomain, &query));

            let events = events.lock().expect("recording lock");
            assert_eq!(events.len(), 1);
            let proxima::ProtocolEvent::Custom { kind, payload } = &events[0].event else {
                panic!("expected custom decision event");
            };
            assert_eq!(kind, "blackhole.dns_decision");
            assert_eq!(payload["action"], "nxdomain");
            assert_eq!(payload["qtype"], 1);
            assert_eq!(payload["qclass"], 1);
            assert!(!payload.to_string().contains("secret.example"));
        }

        #[test]
        fn borrowed_listener_handoff_records_selected_action_once() {
            let mut config = Config::default();
            config.privacy.query_log_enabled = true;
            config.privacy.query_log_max_entries = 4;
            let policy = Policy::new(config).expect("valid query log config");
            let query = proxima_dns::DnsQuery {
                id: 9,
                recursion_desired: true,
                name: "example.".into(),
                qtype: 1,
                qclass: 1,
            };
            let request = DnsPipeRequest {
                method: proxima_primitives::pipe::method::Method::from_wire(
                    bytes::Bytes::from_static(b"DNS"),
                ),
                path: bytes::Bytes::from_static(b"/"),
                query: proxima_primitives::pipe::header_list::HeaderList::new(),
                metadata: proxima_primitives::pipe::header_list::HeaderList::new(),
                payload: query.clone(),
                stream: None,
                context: RequestContext::default(),
            };

            futures::executor::block_on(async {
                // This is the exact listener-to-owned-facade handoff: the
                // listener records its borrowed decision, then supplies the
                // selected action to call_owned.
                policy.record_decision(Action::Nxdomain, &query).await;
                policy
                    .call_owned(request, Action::Nxdomain)
                    .await
                    .expect("selected action call");
            });

            assert_eq!(policy.query_log().expect("query log").snapshot().len(), 1);
        }

        #[test]
        fn proxima_jsonl_recording_path_persists_metadata_only() {
            use proxima::RecordingSink;
            use proxima::{AccumulatingSink, FormatKind, LazyFanOut, SinkSpec};
            use std::sync::Arc;

            let directory = std::env::temp_dir().join(format!(
                "blackhole-recording-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock")
                    .as_nanos()
            ));
            std::fs::create_dir(&directory).expect("recording directory");
            let path = directory.join("decisions.jsonl");
            let spigot = proxima::recording::deferred_runtime();
            let durable = Arc::new(LazyFanOut::new(
                vec![SinkSpec::new(
                    path.to_string_lossy().into_owned(),
                    FormatKind::Json,
                )],
                Arc::clone(&spigot),
            ));
            assert!(
                spigot
                    .set(Arc::new(
                        proxima::runtime::PrimeRuntime::new(1).expect("recording runtime"),
                    ))
                    .is_ok()
            );
            let buffered: DynRecordingSink = Arc::new(AccumulatingSink::new(durable, 1));
            let bounded = BoundedQueryRecordingSink::new(buffered, &path, 4_096)
                .expect("bounded recording sink");
            let sink: Arc<dyn RecordingSink> = Arc::new(bounded);
            let policy = Policy::new(Config::default())
                .expect("valid policy")
                .with_recording_sink(Arc::clone(&sink));
            let query = proxima_dns::DnsQuery {
                id: 9,
                recursion_desired: true,
                name: "secret.example.".into(),
                qtype: 1,
                qclass: 1,
            };

            futures::executor::block_on(async {
                policy.record_decision(Action::Nxdomain, &query).await;
                sink.flush().await.expect("flush recording sink");
            });

            let contents = std::fs::read_to_string(&path).expect("read JSONL recording");
            assert!(contents.contains("blackhole.dns_decision"));
            assert!(contents.contains("nxdomain"));
            assert!(!contents.contains("secret.example"));
            assert!(std::fs::metadata(&path).expect("recording metadata").len() <= 4_096);
            std::fs::remove_dir_all(directory).expect("remove recording directory");
        }

        #[test]
        fn bounded_query_log_retains_metadata_only_and_can_be_deleted() {
            let mut config = Config::default();
            config.privacy.query_log_enabled = true;
            config.privacy.query_log_max_entries = 1;
            config.privacy.query_log_retention_secs = 60;
            let policy = Policy::new(config).expect("valid query log config");
            let query = proxima_dns::DnsQuery {
                id: 9,
                recursion_desired: true,
                name: "secret.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            futures::executor::block_on(policy.record_decision(Action::Reject, &query));
            futures::executor::block_on(policy.record_decision(Action::Nxdomain, &query));

            let log = policy.query_log().expect("enabled query log");
            let events = log.snapshot();
            assert_eq!(events.len(), 1, "entry bound is enforced");
            let rendered = policy.admin_query_log();
            assert_eq!(rendered.matches("secret.example").count(), 0);
            assert!(rendered.contains("nxdomain"));
            assert!(rendered.contains("\"truncated\":false"));
            assert_eq!(policy.clear_query_log(), 1);
            assert!(log.snapshot().is_empty());
        }

        #[test]
        fn query_log_admin_projection_is_bounded() {
            let mut config = Config::default();
            config.privacy.query_log_enabled = true;
            config.privacy.query_log_max_entries = 2_000;
            let policy = Policy::new(config).expect("valid query log config");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "bounded.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            for _ in 0..(MAX_ADMIN_LOG_ENTRIES + 1) {
                futures::executor::block_on(policy.record_decision(Action::Reject, &query));
            }
            let rendered: serde_json::Value =
                serde_json::from_str(&policy.admin_query_log()).expect("log JSON");
            assert_eq!(
                rendered["entries"].as_array().expect("entries").len(),
                MAX_ADMIN_LOG_ENTRIES
            );
            assert_eq!(rendered["truncated"], true);
        }

        #[test]
        fn query_log_configuration_is_bounded_and_disabled_by_default() {
            let policy = Policy::new(Config::default()).expect("default policy");
            assert!(policy.query_log().is_none());
            assert_eq!(
                policy.admin_query_log(),
                "{\"enabled\":false,\"entries\":[]}"
            );

            let mut config = Config::default();
            config.privacy.query_log_enabled = true;
            config.privacy.query_log_max_entries = 65_537;
            assert!(Policy::new(config).is_err());

            let mut config = Config::default();
            config.privacy.query_recording_path = Some(String::new());
            assert!(Policy::new(config).is_err());

            let mut config = Config::default();
            config.privacy.query_recording_path = Some("decisions.jsonl".into());
            config.privacy.query_recording_max_bytes = 0;
            assert!(Policy::new(config).is_err());

            let mut config = Config::default();
            config.privacy.query_recording_path = Some("decisions.jsonl".into());
            config.privacy.query_recording_max_files = 17;
            assert!(Policy::new(config).is_err());
        }
    }
}

#[cfg(feature = "std")]
pub use runtime::*;
