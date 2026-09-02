//! Policy and configuration for the Blackhole DNS sinkhole.
//!
//! ```
//! let config = blackhole::Config::default();
//! assert_eq!(config.server.listen, "127.0.0.1:5353");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
mod wasm_runtime {
    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_BYTES: usize = 1024 * 1024;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

    struct BumpAllocator;

    // This allocator is only for the bounded no-std edge experiment. The
    // production std path does not use it, and deallocation is intentionally
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

    #[cfg(target_arch = "wasm32")]
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
    use futures::StreamExt;
    use proxima::runtime::PrimeRuntime;
    use proxima::{
        BoundedRecordingSink, Client, DynRecordingSink, FailMode, InteractionId, Labels,
        ProtocolEvent, RecordingAppendFuture, RecordingEvent, RecordingSink, RecordingSource,
        TelemetryHandle,
    };
    use proxima_core::ProximaError;
    use proxima_core::live::{Live, LiveControl, live};
    use proxima_dns::{
        DnsAnswer, DnsAnswerRecord, DnsAnswerWithMetadata, DnsClientError, DnsClientUpstream,
        DnsPipeReply, DnsPipeRequest,
    };
    use proxima_primitives::pipe::AtomicCircuitBreaker as ProximaCircuitBreaker;
    use proxima_primitives::pipe::SendPipe;
    use proxima_primitives::pipe::bucket_table::BucketTable;
    use proxima_primitives::pipe::endpoint::PeerInfo;
    use proxima_primitives::stream::DatagramFactory;
    use proxima_primitives::sync::AtomicPermitPool;
    use serde::Deserialize;
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
    use std::fs::Metadata;
    use std::hash::Hash;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    use crate::policy;
    use crate::policy::{QueryContext, ReferencePolicy};
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
    const MAX_ABUSE_EXPORT_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_ABUSE_EXPORT_EVENTS: usize = 1_000_000;
    const MAX_BLOCKLIST_RELOAD_INTERVAL_SECS: u64 = 86_400;
    const MAX_BLOCKLIST_DENYALLOW_DOMAINS: usize = 256;

    #[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
    pub struct Config {
        /// Optional bounded background reload interval for policy config.
        #[serde(default)]
        pub reload_interval_secs: u64,
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

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
            if self.entries.len() >= self.config.max_entries
                && !self.entries.contains_key(&key)
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
                evicted = true;
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

        fn is_blocked(&self, epoch: Instant) -> bool {
            self.blocked_until.load(Ordering::Acquire) > epoch.elapsed().as_secs()
        }

        fn restore_blocked(&self, epoch: Instant, remaining: Duration) {
            let now = epoch.elapsed().as_secs();
            self.blocked_until.store(
                now.saturating_add(remaining.as_secs().max(1)),
                Ordering::Release,
            );
            self.last_access_micros.store(
                epoch.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
        }

        fn release_blocked(&self) {
            self.blocked_until.store(0, Ordering::Release);
            self.state.store(0, Ordering::Release);
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

        fn restore_blocked(&self, key: &[u8], epoch: Instant, remaining: Duration) {
            if self.buckets.len() >= MAX_CLIENT_RATE_ENTRIES {
                self.buckets
                    .evict_one_lru(|bucket| bucket.last_access_micros.load(Ordering::Relaxed));
            }
            let bucket = self.buckets.get_or_insert(key, AtomicWindowBucket::new);
            bucket.restore_blocked(epoch, remaining);
        }

        fn release_blocked(&self, key: &[u8]) {
            // BucketTable is lock-free and bounded. A revoke may install an
            // empty bucket when the incident already expired or was evicted;
            // that keeps the operation deterministic without exposing keys.
            let bucket = self.buckets.get_or_insert(key, AtomicWindowBucket::new);
            bucket.release_blocked();
        }

        fn len(&self) -> usize {
            self.buckets.len()
        }

        fn clear(&self) {
            self.buckets.clear();
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

    #[derive(
        Debug, Clone, Deserialize, serde::Serialize, conflaguration::Settings, PartialEq, Eq,
    )]
    #[settings(prefix = "BLACKHOLE_DDOS")]
    pub struct DdosConfig {
        /// Persist abuse-open incidents through the configured Proxima
        /// metadata recording sink so they survive process death.
        #[setting(default = false)]
        #[serde(default)]
        pub persist_incidents: bool,
        /// Disable the global breaker when zero; otherwise open it after this
        /// many aggregate violations in the configured window.
        #[setting(default = 0)]
        #[serde(default)]
        pub max_global_abuse_violations: usize,
        #[setting(default = 10)]
        #[serde(default = "default_global_abuse_window_secs")]
        pub global_abuse_window_secs: u64,
        #[setting(default = 30)]
        #[serde(default = "default_global_abuse_cooldown_secs")]
        pub global_abuse_cooldown_secs: u64,
    }

    impl Default for DdosConfig {
        fn default() -> Self {
            Self {
                persist_incidents: false,
                max_global_abuse_violations: 0,
                global_abuse_window_secs: default_global_abuse_window_secs(),
                global_abuse_cooldown_secs: default_global_abuse_cooldown_secs(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
    pub struct AdmissionConfig {
        /// Client IPv4/IPv6 CIDRs denied before DNS policy evaluation.
        /// Individual addresses use `/32` or `/128`.
        #[serde(default)]
        pub deny_client_cidrs: Vec<String>,
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
        #[serde(default)]
        pub ddos: DdosConfig,
    }

    impl Default for AdmissionConfig {
        fn default() -> Self {
            Self {
                deny_client_cidrs: Vec::new(),
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
                ddos: DdosConfig::default(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, serde::Serialize, Default, PartialEq, Eq)]
    pub struct CountryPolicyConfig {
        /// Operator-supplied lines of `COUNTRY CIDR`; no database is bundled.
        #[serde(default)]
        pub map_path: Option<String>,
        /// Optional lowercase or uppercase 64-digit SHA-256 digest pin
        /// for the complete map contents. A mismatch rejects the refresh and
        /// retains the last good snapshot.
        #[serde(default)]
        pub expected_sha256: Option<String>,
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
        source_fingerprint: u64,
        source_sha256: String,
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

    #[derive(Debug, Clone, Default)]
    struct RewriteTable {
        entries: HashMap<(String, u16), DnsAnswer>,
        wildcard_entries: HashMap<u16, HashMap<String, DnsAnswer>>,
    }

    impl RewriteTable {
        fn len(&self) -> usize {
            self.entries.len()
        }

        fn answer(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
            let name = normalize(&query.name);
            if let Some(answer) = self.entries.get(&(name.clone(), query.qtype)) {
                return Some(answer.clone());
            }
            let suffix = name.split_once('.').map(|(_, suffix)| suffix)?;
            let answer = self
                .wildcard_entries
                .get(&query.qtype)?
                .get(suffix)?
                .clone();
            let query_name = query.name.clone();
            Some(DnsAnswer {
                records: answer
                    .records
                    .into_iter()
                    .map(|mut record| {
                        record.name = query_name.clone();
                        record
                    })
                    .collect(),
                ..answer
            })
        }
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct SecurityConfig {
        #[serde(default = "default_reject_private_upstream_addresses")]
        pub reject_private_upstream_addresses: bool,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
        /// Fields retained in query-decision events. `action_only` removes
        /// question type and class before the event reaches any Proxima sink.
        #[serde(default)]
        pub query_recording_redaction: QueryRecordingRedaction,
    }

    #[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum QueryRecordingRedaction {
        #[default]
        Metadata,
        ActionOnly,
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
                query_recording_redaction: QueryRecordingRedaction::default(),
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

        fn sync<'lifetime>(&'lifetime self) -> RecordingAppendFuture<'lifetime> {
            self.inner.sync()
        }
    }

    impl Default for SecurityConfig {
        fn default() -> Self {
            Self {
                reject_private_upstream_addresses: default_reject_private_upstream_addresses(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum UpstreamTransport {
        #[default]
        Udp,
        Tcp,
        Tls,
        Doh,
        /// DNS-over-QUIC; available when the `doq` feature is enabled.
        Doq,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ServerConfig {
        #[serde(default = "default_listen")]
        pub listen: String,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

    #[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
    pub struct AdminConfig {
        /// Optional HTTP control-plane bind. Disabled when absent.
        pub listen: Option<String>,
        /// Required bearer token when `listen` is configured.
        pub token: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct PolicyConfig {
        /// Disable blocking while retaining the configured policy for a later
        /// atomic re-enable. Rewrites and forwarding remain available.
        #[serde(default = "default_filtering_enabled")]
        pub filtering_enabled: bool,
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
        /// Configured sources that remain retained but are excluded from the
        /// active blocklist snapshot.
        #[serde(default)]
        pub disabled_blocklists: Vec<String>,
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
                filtering_enabled: default_filtering_enabled(),
                mode: default_mode(),
                domains: Vec::new(),
                rules: Vec::new(),
                regex_rules: Vec::new(),
                blocklists: Vec::new(),
                disabled_blocklists: Vec::new(),
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
        /// Keep the rule configured while excluding it from matching.
        #[serde(default = "default_regex_rule_enabled")]
        pub enabled: bool,
        pub id: u32,
        pub pattern: String,
        pub action: Action,
        #[serde(default)]
        pub priority: i32,
        #[serde(default)]
        pub qtype: Option<u16>,
        #[serde(default)]
        pub qtypes: Vec<u16>,
        #[serde(default)]
        pub qclass: Option<u16>,
        #[serde(default)]
        pub qclasses: Vec<u16>,
        #[serde(default)]
        pub client: Option<IpAddr>,
        #[serde(default)]
        pub client_cidrs: Vec<String>,
    }

    fn default_regex_rule_enabled() -> bool {
        true
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ClientIdentityConfig {
        pub name: String,
        /// Keep the identity mapping configured while excluding it from
        /// automatic client classification.
        #[serde(default = "default_identity_enabled")]
        pub enabled: bool,
        #[serde(default)]
        pub clients: Vec<IpAddr>,
        /// Optional bounded networks whose clients receive this identity.
        #[serde(default)]
        pub client_cidrs: Vec<String>,
    }

    fn default_identity_enabled() -> bool {
        true
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct RewriteConfig {
        pub name: String,
        #[serde(default)]
        pub ipv4: Option<Ipv4Addr>,
        #[serde(default)]
        pub ipv6: Option<Ipv6Addr>,
        #[serde(default)]
        pub cname: Option<String>,
        #[serde(default = "default_ttl")]
        pub ttl: u32,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ServiceProfileConfig {
        pub id: u32,
        pub name: String,
        /// Keep the profile configured while excluding its generated rules.
        #[serde(default = "default_profile_enabled")]
        pub enabled: bool,
        pub domains: Vec<String>,
        pub action: Action,
        #[serde(default)]
        pub groups: Vec<String>,
        /// Optional adapter-owned identity label targeted by this profile.
        #[serde(default)]
        pub client_identity: Option<String>,
        #[serde(default)]
        pub priority: i32,
        #[serde(default)]
        pub client_cidrs: Vec<String>,
        #[serde(default)]
        pub qtype: Option<u16>,
        #[serde(default)]
        pub qtypes: Vec<u16>,
        #[serde(default)]
        pub qclass: Option<u16>,
        #[serde(default)]
        pub qclasses: Vec<u16>,
    }

    fn default_profile_enabled() -> bool {
        true
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub struct ClientGroupConfig {
        pub name: String,
        /// Keep the group configured while excluding it from profile scopes.
        #[serde(default = "default_group_enabled")]
        pub enabled: bool,
        #[serde(default)]
        pub client_addresses: Vec<IpAddr>,
        #[serde(default)]
        pub client_cidrs: Vec<String>,
    }

    fn default_group_enabled() -> bool {
        true
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    fn default_filtering_enabled() -> bool {
        true
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

    fn default_global_abuse_window_secs() -> u64 {
        10
    }

    fn default_global_abuse_cooldown_secs() -> u64 {
        30
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

    fn http_source_parts(source: &str) -> Option<(&str, &str)> {
        if !source.starts_with("http://") && !source.starts_with("https://") {
            return None;
        }
        let scheme_end = source.find("://")?;
        let authority_start = scheme_end + 3;
        let path_start = source[authority_start..]
            .find('/')
            .map_or(source.len(), |offset| authority_start + offset);
        let base = &source[..path_start];
        let path = if path_start == source.len() {
            "/"
        } else {
            &source[path_start..]
        };
        (base.len() > authority_start && !base.contains('#') && !path.contains('#'))
            .then_some((base, path))
    }

    fn read_remote_bytes(source: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
        let (base, path) = http_source_parts(source).ok_or_else(|| {
            "remote source must be an absolute http:// or https:// URL".to_owned()
        })?;
        let client =
            Client::http(base).map_err(|error| format!("create Proxima HTTP client: {error}"))?;
        futures::executor::block_on(async {
            let response = client
                .get(path)
                .send()
                .await
                .map_err(|error| format!("fetch through Proxima: {error}"))?;
            if !response.ok() {
                return Err(format!("remote source returned HTTP {}", response.status()));
            }
            let mut stream = response.into_body().into_chunk_stream();
            let mut contents = Vec::new();
            while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
                let chunk = chunk.map_err(|error| format!("read through Proxima: {error}"))?;
                let next_len = contents
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(|| "remote source size overflow".to_owned())?;
                if next_len > max_bytes as usize {
                    return Err(format!("remote source exceeds {max_bytes} bytes"));
                }
                contents.extend_from_slice(&chunk);
            }
            Ok(contents)
        })
    }

    fn read_remote_blocklist(source: &str) -> Result<Vec<u8>, policy::PolicyError> {
        read_remote_bytes(source, MAX_BLOCKLIST_BYTES).map_err(|reason| {
            policy::PolicyError::InvalidBlocklist {
                path: source.into(),
                reason,
            }
        })
    }

    fn read_blocklist_source(source: &str) -> Result<Vec<u8>, policy::PolicyError> {
        if source.starts_with("http://") || source.starts_with("https://") {
            return read_remote_blocklist(source);
        }
        let metadata =
            std::fs::metadata(source).map_err(|error| policy::PolicyError::InvalidBlocklist {
                path: source.into(),
                reason: error.to_string(),
            })?;
        if metadata.len() > MAX_BLOCKLIST_BYTES {
            return Err(policy::PolicyError::InvalidBlocklist {
                path: source.into(),
                reason: format!("file exceeds {MAX_BLOCKLIST_BYTES} bytes"),
            });
        }
        std::fs::read(source).map_err(|error| policy::PolicyError::InvalidBlocklist {
            path: source.into(),
            reason: error.to_string(),
        })
    }

    fn active_blocklist_paths(
        paths: &[String],
        disabled: &[String],
    ) -> Result<Vec<String>, policy::PolicyError> {
        let configured = paths.iter().collect::<BTreeSet<_>>();
        let disabled_set = disabled.iter().collect::<BTreeSet<_>>();
        if disabled_set.len() != disabled.len() {
            return Err(policy::PolicyError::InvalidBlocklist {
                path: "<disabled>".into(),
                reason: "disabled source paths must be unique".into(),
            });
        }
        if let Some(path) = disabled_set.iter().find(|path| !configured.contains(*path)) {
            return Err(policy::PolicyError::InvalidBlocklist {
                path: (*path).clone(),
                reason: "disabled source path is not configured".into(),
            });
        }
        Ok(paths
            .iter()
            .filter(|path| !disabled_set.contains(path))
            .cloned()
            .collect())
    }

    fn load_blocklists(paths: &[String]) -> Result<Vec<RuleConfig>, policy::PolicyError> {
        if paths.len() > MAX_BLOCKLIST_PATHS {
            return Err(policy::PolicyError::InvalidBlocklist {
                path: "<table>".into(),
                reason: format!("source count exceeds {MAX_BLOCKLIST_PATHS}"),
            });
        }
        let mut domains = BTreeSet::new();
        let mut exceptions = BTreeSet::new();
        let mut important_domains = BTreeSet::new();
        let mut badfilter_domains = BTreeSet::new();
        let mut denyallow_domains = BTreeMap::<String, BTreeSet<String>>::new();
        let mut total_bytes = 0_u64;
        for path in paths {
            if path.len() > MAX_BLOCKLIST_PATH_BYTES {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: path.clone(),
                    reason: format!("path exceeds {MAX_BLOCKLIST_PATH_BYTES} bytes"),
                });
            }
            let contents = read_blocklist_source(path)?;
            total_bytes = total_bytes.saturating_add(contents.len() as u64);
            if total_bytes > MAX_BLOCKLIST_TOTAL_BYTES {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<table>".into(),
                    reason: format!("aggregate files exceed {MAX_BLOCKLIST_TOTAL_BYTES} bytes"),
                });
            }
            let contents = String::from_utf8(contents).map_err(|error| {
                policy::PolicyError::InvalidBlocklist {
                    path: path.clone(),
                    reason: format!("source is not UTF-8: {error}"),
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
                    let (raw_domain, modifiers) = raw_domain
                        .split_once('$')
                        .map_or((raw_domain.as_str(), None), |(domain, modifiers)| {
                            (domain, Some(modifiers))
                        });
                    let mut important = false;
                    let mut badfilter = false;
                    let mut denyallow = None;
                    if let Some(modifiers) = modifiers {
                        for modifier in modifiers.split(',') {
                            match modifier {
                                "important" => important = true,
                                "badfilter" => badfilter = true,
                                value if value.strip_prefix("denyallow=").is_some() => {
                                    denyallow = value.strip_prefix("denyallow=")
                                }
                                "" => {
                                    return Err(policy::PolicyError::InvalidBlocklist {
                                        path: path.clone(),
                                        reason: "empty AdGuard filter modifier".into(),
                                    });
                                }
                                _ => {
                                    return Err(policy::PolicyError::InvalidBlocklist {
                                        path: path.clone(),
                                        reason: format!(
                                            "unsupported AdGuard filter modifier {modifier}"
                                        ),
                                    });
                                }
                            }
                        }
                    }
                    let (exception, domain) =
                        if let Some(stripped) = raw_domain.strip_prefix("@@||") {
                            (true, stripped.trim_end_matches('^').to_owned())
                        } else if let Some(stripped) = raw_domain.strip_prefix("||") {
                            (false, stripped.trim_end_matches('^').to_owned())
                        } else {
                            (false, raw_domain.to_owned())
                        };
                    if !valid_blocklist_domain(&domain) {
                        return Err(policy::PolicyError::InvalidBlocklist {
                            path: path.clone(),
                            reason: format!("invalid domain {raw_domain}"),
                        });
                    }
                    if let Some(denyallow) = denyallow {
                        if exception || denyallow.is_empty() {
                            return Err(policy::PolicyError::InvalidBlocklist {
                                path: path.clone(),
                                reason: "denyallow requires a blocking filter and domain list"
                                    .into(),
                            });
                        }
                        let allowed = denyallow_domains.entry(domain.clone()).or_default();
                        for value in denyallow.split('|') {
                            if !valid_blocklist_domain(value)
                                || allowed.len() >= MAX_BLOCKLIST_DENYALLOW_DOMAINS
                            {
                                return Err(policy::PolicyError::InvalidBlocklist {
                                    path: path.clone(),
                                    reason: "denyallow contains an invalid or excessive domain"
                                        .into(),
                                });
                            }
                            allowed.insert(value.to_ascii_lowercase());
                        }
                    }
                    domains.insert(domain.clone());
                    if exception {
                        exceptions.insert(domain.clone());
                    } else if important {
                        important_domains.insert(domain.clone());
                    }
                    if badfilter {
                        badfilter_domains.insert(domain);
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
        for domain in &badfilter_domains {
            domains.remove(domain);
            exceptions.remove(domain);
            important_domains.remove(domain);
            denyallow_domains.remove(domain);
        }
        let mut rules = Vec::with_capacity(
            domains
                .len()
                .saturating_mul(2)
                .saturating_add(denyallow_domains.values().map(BTreeSet::len).sum::<usize>() * 2),
        );
        let mut next_id = u32::MAX;
        for domain in domains {
            let exception = exceptions.contains(&domain);
            let action = if exception {
                Action::Pass
            } else {
                Action::Nxdomain
            };
            let priority = if exception {
                i32::MAX
            } else if important_domains.contains(&domain) {
                i32::MAX - 1
            } else {
                i32::MAX - 2
            };
            let id = next_id;
            next_id = next_id.saturating_sub(2);
            rules.push(RuleConfig {
                enabled: true,
                id,
                domain: domain.clone(),
                action,
                priority,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            });
            rules.push(RuleConfig {
                enabled: true,
                id: id.saturating_sub(1),
                domain: format!("*.{domain}"),
                action,
                priority,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            });
        }
        for allowed in denyallow_domains.values().flatten() {
            for domain in [allowed.clone(), format!("*.{allowed}")] {
                rules.push(RuleConfig {
                    enabled: true,
                    id: next_id,
                    domain,
                    action: Action::Pass,
                    priority: i32::MAX,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
                    client: None,
                    client_cidr: None,
                    client_cidrs: Vec::new(),
                    client_identity: None,
                });
                next_id = next_id.saturating_sub(1);
            }
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

    fn source_fingerprint(contents: &[u8]) -> u64 {
        // FNV-1a is used only as a bounded change indicator in operator
        // status; it is not an authenticity or identity mechanism.
        contents.iter().fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
    }

    fn source_sha256(contents: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(contents);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn valid_sha256(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
        if let Some(expected) = config.expected_sha256.as_deref()
            && !valid_sha256(expected)
        {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: "expected_sha256 must be exactly 64 hexadecimal digits".into(),
            });
        }
        let contents = if http_source_parts(path).is_some() {
            if config.max_age_secs.is_some() {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: "max_age_secs is only supported for local map files".into(),
                });
            }
            let bytes = read_remote_bytes(path, MAX_COUNTRY_MAP_BYTES).map_err(|reason| {
                policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason,
                }
            })?;
            String::from_utf8(bytes).map_err(|error| policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: format!("remote map is not UTF-8: {error}"),
            })?
        } else {
            let metadata = std::fs::metadata(path).map_err(|error| {
                policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: error.to_string(),
                }
            })?;
            let initial_length = metadata.len();
            let initial_modified = metadata.modified().ok();
            if let Some(max_age_secs) = config.max_age_secs {
                if max_age_secs == 0 {
                    return Err(policy::PolicyError::InvalidCountryMap {
                        path: path.into(),
                        reason: "max_age_secs must be non-zero when configured".into(),
                    });
                }
                let modified = metadata.modified().map_err(|error| {
                    policy::PolicyError::InvalidCountryMap {
                        path: path.into(),
                        reason: format!("cannot read map modification time: {error}"),
                    }
                })?;
                if !country_map_is_fresh(modified, std::time::SystemTime::now(), max_age_secs) {
                    return Err(policy::PolicyError::InvalidCountryMap {
                        path: path.into(),
                        reason: format!(
                            "map is older than configured {max_age_secs}s freshness bound"
                        ),
                    });
                }
            }
            if initial_length > MAX_COUNTRY_MAP_BYTES {
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
            let final_metadata = std::fs::metadata(path).map_err(|error| {
                policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: error.to_string(),
                }
            })?;
            if country_map_changed(initial_length, initial_modified, &final_metadata) {
                return Err(policy::PolicyError::InvalidCountryMap {
                    path: path.into(),
                    reason: "map changed while it was being read".into(),
                });
            }
            contents
        };
        let contents_sha256 = source_sha256(contents.as_bytes());
        if let Some(expected) = config.expected_sha256.as_deref()
            && !contents_sha256.eq_ignore_ascii_case(expected)
        {
            return Err(policy::PolicyError::InvalidCountryMap {
                path: path.into(),
                reason: format!("map SHA-256 mismatch: expected {expected}, got {contents_sha256}"),
            });
        }
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
            source_fingerprint: source_fingerprint(contents.as_bytes()),
            source_sha256: contents_sha256,
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
                .is_ok_and(|age| age <= Duration::from_secs(max_age_secs))
    }

    fn country_map_changed(
        initial_length: u64,
        initial_modified: Option<std::time::SystemTime>,
        final_metadata: &Metadata,
    ) -> bool {
        final_metadata.len() != initial_length
            || initial_modified
                .is_some_and(|modified| final_metadata.modified().ok() != Some(modified))
    }

    const MAX_REWRITES: usize = 10_000;

    const MAX_PROFILES: usize = 256;
    const MAX_CLIENT_GROUPS: usize = 256;
    const MAX_CLIENT_GROUP_ADDRESSES: usize = 1_024;

    #[derive(Clone)]
    struct ClientScope {
        client: Option<IpAddr>,
        client_cidrs: Vec<String>,
        client_identity: Option<String>,
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
                    client_identity: None,
                })
                .collect::<Vec<_>>();
            if !group.client_cidrs.is_empty() {
                scopes.push(ClientScope {
                    client: None,
                    client_cidrs: group.client_cidrs.clone(),
                    client_identity: None,
                });
            }
            if group_map
                .insert(
                    name.to_ascii_lowercase(),
                    if group.enabled { scopes } else { Vec::new() },
                )
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
            if !profile.enabled {
                continue;
            }
            if !profile.groups.is_empty() && !profile.client_cidrs.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: "groups and client_cidrs are mutually exclusive".into(),
                });
            }
            if let Some(identity) = profile.client_identity.as_deref()
                && (identity.trim().is_empty()
                    || !identity.is_ascii()
                    || identity.len() > policy::MAX_CLIENT_IDENTITY_BYTES)
            {
                return Err(policy::PolicyError::InvalidProfile {
                    name: profile.name.clone(),
                    reason: "client_identity must be bounded non-empty ASCII".into(),
                });
            }
            let mut group_scopes = if profile.groups.is_empty() {
                vec![ClientScope {
                    client: None,
                    client_cidrs: profile.client_cidrs.clone(),
                    client_identity: None,
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
            for scope in &mut group_scopes {
                scope.client_identity = profile.client_identity.clone();
            }
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
                        enabled: true,
                        id,
                        domain,
                        action: profile.action,
                        priority: profile.priority,
                        qtype: profile.qtype,
                        qtypes: profile.qtypes.clone(),
                        qclass: profile.qclass,
                        qclasses: profile.qclasses.clone(),
                        client: scope.client,
                        client_cidr: None,
                        client_cidrs: scope.client_cidrs.clone(),
                        client_identity: scope.client_identity.clone(),
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
            let wildcard_suffix = name.strip_prefix("*.");
            if name.is_empty()
                || wildcard_suffix.is_some_and(|suffix| {
                    suffix.is_empty() || suffix.contains('*') || !valid_dns_name(suffix)
                })
                || (wildcard_suffix.is_none() && !valid_dns_name(&name))
            {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: config.name.clone(),
                    reason: "name must be a non-empty ASCII DNS name".into(),
                });
            }
            if config.ipv4.is_none() && config.ipv6.is_none() && config.cname.is_none() {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: config.name.clone(),
                    reason: "at least one of ipv4, ipv6, or cname is required".into(),
                });
            }
            if config.cname.is_some() && (config.ipv4.is_some() || config.ipv6.is_some()) {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: config.name.clone(),
                    reason: "cname cannot be combined with ipv4 or ipv6".into(),
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
                let key = (name.clone(), 28);
                if entries.contains_key(&key) {
                    return Err(policy::PolicyError::InvalidRewrite {
                        name: config.name.clone(),
                        reason: "duplicate AAAA rewrite".into(),
                    });
                }
                entries.insert(
                    key,
                    DnsAnswer::ok(vec![DnsAnswerRecord {
                        name: record_name.clone(),
                        rtype: 28,
                        rclass: 1,
                        ttl: config.ttl,
                        rdata: proxima_protocols::dns::encode::ipv6_rdata(address).to_vec(),
                    }]),
                );
            }
            if let Some(target) = config.cname.as_deref() {
                let target = normalize(target);
                if target.is_empty() || !valid_dns_name(&target) {
                    return Err(policy::PolicyError::InvalidRewrite {
                        name: config.name.clone(),
                        reason: "cname must be a non-empty ASCII DNS name".into(),
                    });
                }
                let mut rdata = Vec::new();
                proxima_protocols::dns::encode::encode_name(&target, &mut rdata).map_err(|_| {
                    policy::PolicyError::InvalidRewrite {
                        name: config.name.clone(),
                        reason: "cname exceeds DNS wire limits".into(),
                    }
                })?;
                let key = (name, 5);
                entries.insert(
                    key,
                    DnsAnswer::ok(vec![DnsAnswerRecord {
                        name: record_name,
                        rtype: 5,
                        rclass: 1,
                        ttl: config.ttl,
                        rdata,
                    }]),
                );
            }
        }
        let mut exact_entries = HashMap::new();
        let mut wildcard_entries = HashMap::<u16, HashMap<String, DnsAnswer>>::new();
        for ((name, qtype), answer) in entries {
            if let Some(suffix) = name.strip_prefix("*.") {
                wildcard_entries
                    .entry(qtype)
                    .or_default()
                    .insert(suffix.to_owned(), answer);
            } else {
                exact_entries.insert((name, qtype), answer);
            }
        }
        Ok(RewriteTable {
            entries: exact_entries,
            wildcard_entries,
        })
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
            let initial_length = metadata.len();
            let initial_modified = metadata.modified().ok();
            let contents = std::fs::read_to_string(path)?;
            let final_metadata = std::fs::metadata(path)?;
            if final_metadata.len() != initial_length
                || initial_modified
                    .is_some_and(|modified| final_metadata.modified().ok() != Some(modified))
            {
                return Err("configuration changed while it was being read".into());
            }
            Ok(toml::from_str(&contents)?)
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
        base_rules: Live<Vec<RuleConfig>>,
        base_rules_control: LiveControl<Vec<RuleConfig>>,
        explicit_rules: Live<Vec<RuleConfig>>,
        explicit_rules_control: LiveControl<Vec<RuleConfig>>,
        blocklist_rules: Live<Vec<RuleConfig>>,
        blocklist_rules_control: LiveControl<Vec<RuleConfig>>,
        blocklist_paths: Live<Vec<String>>,
        blocklist_paths_control: LiveControl<Vec<String>>,
        disabled_blocklist_paths: Live<BTreeSet<String>>,
        disabled_blocklist_paths_control: LiveControl<BTreeSet<String>>,
        profiles: Live<Vec<ServiceProfileConfig>>,
        profiles_control: LiveControl<Vec<ServiceProfileConfig>>,
        client_groups: Live<Vec<ClientGroupConfig>>,
        client_groups_control: LiveControl<Vec<ClientGroupConfig>>,
        client_identities: Live<Vec<ClientIdentityConfig>>,
        client_identity_control: LiveControl<Vec<ClientIdentityConfig>>,
        country_policy: Live<Option<CountryPolicy>>,
        country_policy_control: LiveControl<Option<CountryPolicy>>,
        country_policy_config: Live<CountryPolicyConfig>,
        country_policy_config_control: LiveControl<CountryPolicyConfig>,
        reload_lock: RwLock<()>,
        legacy_domains: Live<Vec<String>>,
        legacy_domains_control: LiveControl<Vec<String>>,
        legacy_mode: Live<Mode>,
        legacy_mode_control: LiveControl<Mode>,
        default_action: Live<Action>,
        default_action_control: LiveControl<Action>,
        filtering_enabled: Live<bool>,
        filtering_enabled_control: LiveControl<bool>,
        rewrite_configs: Live<Vec<RewriteConfig>>,
        rewrite_configs_control: LiveControl<Vec<RewriteConfig>>,
        rewrites: Live<RewriteTable>,
        rewrite_control: LiveControl<RewriteTable>,
        reference: PolicyStore,
        regex_rules: Live<Vec<RegexRule>>,
        regex_rules_control: LiveControl<Vec<RegexRule>>,
        domain_rules_configured: AtomicBool,
        rules_configured: AtomicBool,
        policy_generation: AtomicU64,
        telemetry: Option<TelemetryHandle>,
        recording: Option<DynRecordingSink>,
        query_log: Option<Arc<QueryLog>>,
        query_recording_redaction: Live<QueryRecordingRedaction>,
        query_recording_redaction_control: LiveControl<QueryRecordingRedaction>,
        decision_counts: [AtomicU64; 9],
        admission: Live<AdmissionConfig>,
        admission_control: LiveControl<AdmissionConfig>,
        upstream: Option<DnsClientUpstream>,
        upstream_slots: Option<Arc<AtomicPermitPool>>,
        cache: Live<DnsCache>,
        cache_control: LiveControl<DnsCache>,
        breaker: Arc<ProximaCircuitBreaker>,
        breaker_epoch: Instant,
        request_slots: Arc<AtomicPermitPool>,
        client_admission: ClientAdmissionTable,
        client_rates: KeyedWindowBudgetTable,
        global_rate: AtomicWindowBudget,
        client_response_budgets: KeyedWindowBudgetTable,
        network_response_budgets: KeyedWindowBudgetTable,
        global_response_budget: AtomicWindowBudget,
        client_abuse: KeyedWindowBudgetTable,
        network_abuse: KeyedWindowBudgetTable,
        global_abuse: AtomicWindowBucket,
    }

    struct RegexRule {
        enabled: bool,
        id: u32,
        pattern: regex::Regex,
        action: Action,
        priority: i32,
        qtype: Option<u16>,
        qtypes: Vec<u16>,
        qclass: Option<u16>,
        qclasses: Vec<u16>,
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
            let qtypes =
                policy::effective_query_selectors(rule.id, rule.qtype, &rule.qtypes, "qtype")?;
            let qclasses =
                policy::effective_query_selectors(rule.id, rule.qclass, &rule.qclasses, "qclass")?;
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
                enabled: rule.enabled,
                id: rule.id,
                pattern,
                action: rule.action,
                priority: rule.priority,
                qtype: rule.qtype,
                qtypes,
                qclass: rule.qclass,
                qclasses,
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
            if config.admission.deny_client_cidrs.len() > policy::MAX_CLIENT_CIDRS
                || config.admission.deny_client_cidrs.iter().any(|value| {
                    value.len() > policy::MAX_DOMAIN_BYTES
                        || policy::IpNetwork::parse(value).is_none()
                })
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: format!(
                        "deny_client_cidrs must contain at most {} valid IPv4/IPv6 CIDRs",
                        policy::MAX_CLIENT_CIDRS
                    ),
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
                || config.admission.ddos.global_abuse_window_secs == 0
                || config.admission.ddos.global_abuse_cooldown_secs == 0
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
            if config.admission.ddos.persist_incidents
                && config.privacy.query_recording_path.is_none()
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "ddos incident persistence requires privacy.query_recording_path"
                        .into(),
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
            if config.reload_interval_secs > MAX_BLOCKLIST_RELOAD_INTERVAL_SECS {
                return Err(policy::PolicyError::InvalidConfigReload {
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
            let active_blocklists = active_blocklist_paths(
                &config.policy.blocklists,
                &config.policy.disabled_blocklists,
            )?;
            let blocklist_rules = load_blocklists(&active_blocklists)?;
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
            let breaker = Arc::new(ProximaCircuitBreaker::new(
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
            ));
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
            let disabled_blocklist_paths =
                config.policy.disabled_blocklists.iter().cloned().collect();
            let legacy_domains = config.policy.domains.clone();
            let legacy_mode = config.policy.mode;
            let default_action = config.policy.default_action;
            let filtering_enabled = config.policy.filtering_enabled;
            let rewrite_configs = config.policy.rewrites.clone();
            let admission = config.admission.clone();
            let country_policy_config = config.country_policy.clone();
            let (client_identities, client_identity_control) = live(client_identities);
            let (country_policy, country_policy_control) = live(country_policy);
            let (country_policy_config, country_policy_config_control) =
                live(country_policy_config);
            let (admission, admission_control) = live(admission);
            let (rewrites, rewrite_control) = live(rewrites);
            let (rewrite_configs, rewrite_configs_control) = live(rewrite_configs);
            let (profiles, profiles_control) = live(profiles);
            let (client_groups, client_groups_control) = live(client_groups);
            let (base_rules, base_rules_control) = live(base_rules);
            let (explicit_rules, explicit_rules_control) = live(explicit_rules);
            let (blocklist_rules, blocklist_rules_control) = live(retained_blocklist_rules);
            let (blocklist_paths, blocklist_paths_control) = live(blocklist_paths);
            let (disabled_blocklist_paths, disabled_blocklist_paths_control) =
                live(disabled_blocklist_paths);
            let (legacy_domains, legacy_domains_control) = live(legacy_domains);
            let (legacy_mode, legacy_mode_control) = live(legacy_mode);
            let (default_action, default_action_control) = live(default_action);
            let (filtering_enabled, filtering_enabled_control) = live(filtering_enabled);
            let (regex_rules, regex_rules_control) = live(regex_rules);
            let (query_recording_redaction, query_recording_redaction_control) =
                live(config.privacy.query_recording_redaction);
            let policy = Self {
                config,
                base_rules,
                base_rules_control,
                explicit_rules,
                explicit_rules_control,
                blocklist_rules,
                blocklist_rules_control,
                blocklist_paths,
                blocklist_paths_control,
                disabled_blocklist_paths,
                disabled_blocklist_paths_control,
                profiles,
                profiles_control,
                client_groups,
                client_groups_control,
                client_identities,
                client_identity_control,
                country_policy,
                country_policy_control,
                country_policy_config,
                country_policy_config_control,
                reload_lock: RwLock::new(()),
                legacy_domains,
                legacy_domains_control,
                legacy_mode,
                legacy_mode_control,
                default_action,
                default_action_control,
                filtering_enabled,
                filtering_enabled_control,
                rewrite_configs,
                rewrite_configs_control,
                rewrites,
                rewrite_control,
                reference,
                regex_rules,
                regex_rules_control,
                domain_rules_configured: AtomicBool::new(domain_rules_configured),
                rules_configured: AtomicBool::new(rules_configured),
                policy_generation: AtomicU64::new(1),
                telemetry: None,
                recording: None,
                query_log,
                query_recording_redaction,
                query_recording_redaction_control,
                decision_counts: core::array::from_fn(|_| AtomicU64::new(0)),
                admission,
                admission_control,
                upstream: None,
                upstream_slots: None,
                cache,
                cache_control,
                breaker,
                breaker_epoch: Instant::now(),
                request_slots: Arc::new(AtomicPermitPool::new(max_inflight_requests)),
                client_admission: ClientAdmissionTable::new(),
                client_rates: KeyedWindowBudgetTable::new(),
                global_rate: AtomicWindowBudget::new(),
                client_response_budgets: KeyedWindowBudgetTable::new(),
                network_response_budgets: KeyedWindowBudgetTable::new(),
                global_response_budget: AtomicWindowBudget::new(),
                client_abuse: KeyedWindowBudgetTable::new(),
                network_abuse: KeyedWindowBudgetTable::new(),
                global_abuse: AtomicWindowBucket::new(),
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
            let generated = self.current_profile_rules()?;
            let mut combined = rules.to_vec();
            combined.extend(generated);
            self.publish_rules_locked(&combined, rules, "rules", started)
        }

        /// Validate a proposed explicit rule table without publishing it.
        /// Generated profile rules remain part of the validation set so a
        /// proposed rule cannot pass here and then fail at publication due to
        /// a cross-table identity collision.
        pub fn validate_rules(&self, rules: &[RuleConfig]) -> Result<(), policy::PolicyError> {
            if rules.is_empty() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<rule-validation>".into(),
                    reason: "at least one rule is required".into(),
                });
            }
            let mut combined = rules.to_vec();
            combined.extend(self.current_profile_rules()?);
            let _ = PolicyStore::new(&combined)?;
            Ok(())
        }

        /// Validate a proposed regex rule table without publishing it. The
        /// current domain IDs are reserved so cross-table collisions fail in
        /// the same way as an actual reload.
        pub fn validate_regex_rules(
            &self,
            configs: &[RegexRuleConfig],
        ) -> Result<(), policy::PolicyError> {
            let _ = compile_regex_rules(configs, self.reference.rule_ids())?;
            Ok(())
        }

        /// Validate a complete proposed policy bundle without publishing it.
        /// This deliberately mirrors the reload validator's cross-table
        /// checks so operators can preflight the exact transaction they plan
        /// to publish.
        #[allow(clippy::too_many_arguments)]
        pub fn validate_policy_bundle_with_legacy_and_admission(
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
            filtering_enabled: Option<bool>,
            disabled_blocklists: Option<&[String]>,
            admission: Option<&AdmissionConfig>,
        ) -> Result<(), policy::PolicyError> {
            if let Some(admission) = admission {
                self.validate_admission(admission)?;
            }
            let _ = legacy_mode;
            let _ = default_action;
            let _ = filtering_enabled;
            legacy_domains.map(validate_legacy_domains).transpose()?;
            let generated = compile_profiles(profiles, client_groups)?;
            let _ = validate_client_identities(client_identities)?;
            let _ = compile_rewrites(rewrite_configs)?;
            let _ = load_country_policy(country_config)?;
            let configured_paths = blocklist_paths.map_or_else(
                || self.blocklist_paths.snapshot().as_ref().clone(),
                <[String]>::to_vec,
            );
            let configured_disabled = disabled_blocklists.map_or_else(
                || {
                    self.disabled_blocklist_paths
                        .snapshot()
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                },
                <[String]>::to_vec,
            );
            let active_paths = active_blocklist_paths(&configured_paths, &configured_disabled)?;
            let replacement = load_blocklists(&active_paths)?;
            let mut published = rules.to_vec();
            published.extend(generated);
            published.extend(replacement);
            let rule_ids = published
                .iter()
                .map(|rule| rule.id)
                .collect::<BTreeSet<_>>();
            let _ = compile_regex_rules(regex_configs, rule_ids)?;
            let _ = ReferencePolicy::new(&published)?;
            Ok(())
        }

        fn validate_admission(
            &self,
            admission: &AdmissionConfig,
        ) -> Result<(), policy::PolicyError> {
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
            if admission.deny_client_cidrs.len() > policy::MAX_CLIENT_CIDRS
                || admission.deny_client_cidrs.iter().any(|value| {
                    value.len() > policy::MAX_DOMAIN_BYTES
                        || policy::IpNetwork::parse(value).is_none()
                })
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: format!(
                        "deny_client_cidrs must contain at most {} valid IPv4/IPv6 CIDRs",
                        policy::MAX_CLIENT_CIDRS
                    ),
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
                || admission.ddos.global_abuse_window_secs == 0
                || admission.ddos.global_abuse_cooldown_secs == 0
            {
                return Err(policy::PolicyError::InvalidAdmission {
                    reason: "admission limits are invalid or zero".into(),
                });
            }
            Ok(())
        }

        /// Atomically replace the live admission limits. The in-flight
        /// semaphore is intentionally fixed at startup; changing its capacity
        /// would make existing permits ambiguous, so such a replacement is
        /// rejected without changing any live limits.
        pub fn reload_admission(
            &self,
            admission: &AdmissionConfig,
        ) -> Result<ReloadState, policy::PolicyError> {
            self.validate_admission(admission)?;
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if self.admission.read(|current| current == admission) {
                self.observe_reload_latency("admission_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.admission_control.replace(admission.clone());
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("admission", started);
            Ok(ReloadState::Published)
        }

        /// Add operator-managed client networks to the live denylist without
        /// replacing any other admission limit. The existing admission
        /// snapshot remains the single authoritative store.
        pub fn add_deny_client_cidrs(
            &self,
            additions: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let mut admission = self.admission_config();
            for cidr in additions {
                if !admission.deny_client_cidrs.contains(cidr) {
                    admission.deny_client_cidrs.push(cidr.clone());
                }
            }
            self.reload_admission(&admission)
        }

        /// Revoke operator-managed client networks from the live denylist.
        /// Removing an unknown entry is idempotent and safe for retries.
        pub fn remove_deny_client_cidrs(
            &self,
            removals: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let mut admission = self.admission_config();
            admission
                .deny_client_cidrs
                .retain(|cidr| !removals.iter().any(|removal| removal == cidr));
            self.reload_admission(&admission)
        }

        /// Replace only the live denylist during startup recovery. All other
        /// admission settings remain untouched and the normal validation path
        /// still guards the bounded CIDR set.
        pub fn replace_deny_client_cidrs(
            &self,
            cidrs: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let mut admission = self.admission_config();
            admission.deny_client_cidrs = cidrs.to_vec();
            self.reload_admission(&admission)
        }

        /// Return the bounded operator-managed denylist for startup recovery
        /// and authenticated control-plane integrations.
        #[must_use]
        pub fn deny_client_cidrs(&self) -> Vec<String> {
            self.admission_config().deny_client_cidrs
        }

        /// Persist an operator denylist mutation through the existing bounded
        /// Proxima recording sink when incident persistence is enabled.
        pub(crate) async fn persist_denylist_change(
            &self,
            operation: &'static str,
            cidrs: &[String],
        ) -> Result<(), String> {
            if !self.config.admission.ddos.persist_incidents {
                return Ok(());
            }
            let recording = self
                .recording
                .as_ref()
                .ok_or_else(|| "denylist persistence sink is not configured".to_owned())?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| {
                    duration.as_millis().min(u128::from(u64::MAX)) as u64
                });
            let event = RecordingEvent {
                id: InteractionId::new(),
                ts_ms: now_ms,
                parent: None,
                event: ProtocolEvent::Custom {
                    kind: "blackhole.ddos_denylist".into(),
                    payload: serde_json::json!({
                        "operation": operation,
                        "cidrs": cidrs,
                    }),
                },
            };
            recording
                .append(event)
                .await
                .map_err(|error| error.to_string())?;
            recording.sync().await.map_err(|error| error.to_string())
        }

        /// Persist an explicit incident revocation through the same bounded
        /// Proxima recording sink used for incident recovery.
        pub(crate) async fn persist_abuse_revocation(
            &self,
            clients: &[IpAddr],
        ) -> Result<(), String> {
            if !self.config.admission.ddos.persist_incidents {
                return Ok(());
            }
            let recording = self
                .recording
                .as_ref()
                .ok_or_else(|| "abuse persistence sink is not configured".to_owned())?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| {
                    duration.as_millis().min(u128::from(u64::MAX)) as u64
                });
            let event = RecordingEvent {
                id: InteractionId::new(),
                ts_ms: now_ms,
                parent: None,
                event: ProtocolEvent::Custom {
                    kind: "blackhole.ddos_revoke".into(),
                    payload: serde_json::json!({
                        "clients": clients.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    }),
                },
            };
            recording
                .append(event)
                .await
                .map_err(|error| error.to_string())?;
            recording.sync().await.map_err(|error| error.to_string())
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
            let mut explicit = self.explicit_rules.snapshot().as_ref().clone();
            explicit.extend_from_slice(additions);
            let mut combined = explicit.clone();
            combined.extend(self.current_profile_rules()?);
            self.publish_rules_locked(&combined, &explicit, "rules_append", started)
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
            let mut explicit = self.explicit_rules.snapshot().as_ref().clone();
            for update in updates {
                if let Some(existing) = explicit.iter_mut().find(|rule| rule.id == update.id) {
                    *existing = update.clone();
                } else {
                    explicit.push(update.clone());
                }
            }
            let mut combined = explicit.clone();
            combined.extend(self.current_profile_rules()?);
            self.publish_rules_locked(&combined, &explicit, "rules_upsert", started)
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
            let explicit = self.explicit_rules.snapshot().as_ref().clone();
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
            self.publish_rules_locked(&combined, &next, "rules_remove", started)
        }

        fn current_profile_rules(&self) -> Result<Vec<RuleConfig>, policy::PolicyError> {
            let profiles = self.profiles.snapshot();
            let client_groups = self.client_groups.snapshot();
            compile_profiles(&profiles, &client_groups)
        }

        fn publish_rules_locked(
            &self,
            rules: &[RuleConfig],
            explicit_rules: &[RuleConfig],
            reload_kind: &'static str,
            started: Instant,
        ) -> Result<ReloadState, policy::PolicyError> {
            let mut published_rules = rules.to_vec();
            published_rules.extend(self.blocklist_rules.snapshot().iter().cloned());
            let regex_ids = self
                .regex_rules
                .read(|rules| rules.iter().map(|rule| rule.id).collect::<BTreeSet<_>>());
            if let Some(rule) = published_rules
                .iter()
                .find(|rule| regex_ids.contains(&rule.id))
            {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let next_reference = ReferencePolicy::new(&published_rules)?;
            if self.reference.read(|current| current == &next_reference)
                && self.base_rules.read(|current| current == rules)
                && self
                    .explicit_rules
                    .read(|current| current == explicit_rules)
            {
                self.observe_reload_latency("rules_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let published = self.reference.reload(&published_rules)?;
            self.base_rules_control.replace(rules.to_vec());
            self.explicit_rules_control.replace(explicit_rules.to_vec());
            self.domain_rules_configured
                .store(!published_rules.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !published_rules.is_empty() || !self.regex_rules.read(|rules| rules.is_empty()),
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

        /// Reload the configured blocklist files and publish only changed
        /// rules as one immutable snapshot alongside the current explicit
        /// rules. Files are read and validated before publication.
        pub fn reload_blocklists(&self) -> Result<ReloadState, policy::PolicyError> {
            self.reload_blocklists_if_changed()
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
            self.replace_blocklist_sources_locked(paths, started, "blocklists")
        }

        /// Atomically add blocklist source paths, preserving existing source
        /// order and ignoring exact duplicates.
        pub fn add_blocklist_sources(
            &self,
            additions: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            if additions.is_empty() {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<sources>".into(),
                    reason: "at least one source path is required".into(),
                });
            }
            let started = Instant::now();
            let mut paths = self.blocklist_paths.snapshot().as_ref().clone();
            for path in additions {
                if !paths.contains(path) {
                    paths.push(path.clone());
                }
            }
            let disabled = self.disabled_blocklist_paths.snapshot().as_ref().clone();
            let active = paths
                .iter()
                .filter(|path| !disabled.contains(*path))
                .cloned()
                .collect::<Vec<_>>();
            let result = self.replace_active_blocklist_rules_locked(
                &active,
                started,
                "blocklists_add",
                true,
            );
            if result.is_ok() {
                self.blocklist_paths_control.replace(paths);
            }
            result
        }

        /// Atomically remove exact blocklist source paths. Unknown paths fail
        /// without changing the current source or rule snapshot.
        pub fn remove_blocklist_sources(
            &self,
            removals: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            if removals.is_empty() {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<sources>".into(),
                    reason: "at least one source path is required".into(),
                });
            }
            let mut paths = self.blocklist_paths.snapshot().as_ref().clone();
            let requested = removals.iter().collect::<BTreeSet<_>>();
            let original_len = paths.len();
            paths.retain(|path| !requested.contains(path));
            if paths.len() == original_len {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<sources>".into(),
                    reason: "no requested source path exists".into(),
                });
            }
            let started = Instant::now();
            let disabled = self.disabled_blocklist_paths.snapshot().as_ref().clone();
            let active = paths
                .iter()
                .filter(|path| !disabled.contains(*path))
                .cloned()
                .collect::<Vec<_>>();
            let result = self.replace_active_blocklist_rules_locked(
                &active,
                started,
                "blocklists_remove",
                true,
            );
            if result.is_ok() {
                self.blocklist_paths_control.replace(paths.clone());
                let configured = self.blocklist_paths.snapshot();
                let mut retained = self.disabled_blocklist_paths.snapshot().as_ref().clone();
                retained.retain(|path| configured.contains(path));
                self.disabled_blocklist_paths_control.replace(retained);
            }
            result
        }

        /// Disable configured blocklist sources without deleting them. The
        /// active rule snapshot is rebuilt before this state is published.
        pub fn disable_blocklist_sources(
            &self,
            paths: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            self.set_blocklist_sources_enabled(paths, false)
        }

        /// Re-enable configured blocklist sources and republish their rules.
        pub fn enable_blocklist_sources(
            &self,
            paths: &[String],
        ) -> Result<ReloadState, policy::PolicyError> {
            self.set_blocklist_sources_enabled(paths, true)
        }

        fn set_blocklist_sources_enabled(
            &self,
            paths: &[String],
            enabled: bool,
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if paths.is_empty() {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<sources>".into(),
                    reason: "at least one source path is required".into(),
                });
            }
            let configured = self.blocklist_paths.snapshot().as_ref().clone();
            if paths.iter().any(|path| !configured.contains(path)) {
                return Err(policy::PolicyError::InvalidBlocklist {
                    path: "<sources>".into(),
                    reason: "all source paths must already be configured".into(),
                });
            }
            let mut disabled = self.disabled_blocklist_paths.snapshot().as_ref().clone();
            for path in paths {
                if enabled {
                    disabled.remove(path);
                } else {
                    disabled.insert(path.clone());
                }
            }
            if self
                .disabled_blocklist_paths
                .read(|current| current == &disabled)
            {
                self.observe_reload_latency("blocklists_enable_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let active = configured
                .iter()
                .filter(|path| !disabled.contains(*path))
                .cloned()
                .collect::<Vec<_>>();
            let result = self.replace_active_blocklist_rules_locked(
                &active,
                started,
                if enabled {
                    "blocklists_enable"
                } else {
                    "blocklists_disable"
                },
                true,
            );
            if result.is_ok() {
                self.disabled_blocklist_paths_control.replace(disabled);
            }
            result
        }

        fn replace_blocklist_sources_locked(
            &self,
            paths: &[String],
            started: Instant,
            reload_kind: &'static str,
        ) -> Result<ReloadState, policy::PolicyError> {
            let state_changed = self.blocklist_paths.read(|current| current != paths)
                || !self.disabled_blocklist_paths.read(BTreeSet::is_empty);
            let result = self.replace_active_blocklist_rules_locked(
                paths,
                started,
                reload_kind,
                state_changed,
            )?;
            self.disabled_blocklist_paths_control
                .replace(BTreeSet::new());
            self.blocklist_paths_control.replace(paths.to_vec());
            Ok(result)
        }

        fn replace_active_blocklist_rules_locked(
            &self,
            paths: &[String],
            started: Instant,
            reload_kind: &'static str,
            state_changed: bool,
        ) -> Result<ReloadState, policy::PolicyError> {
            let replacement = load_blocklists(paths)?;
            if !state_changed
                && self
                    .blocklist_rules
                    .read(|current| current == replacement.as_slice())
            {
                self.observe_reload_latency("blocklists_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let base_rules = self.base_rules.snapshot();
            let mut rules = base_rules.as_ref().clone();
            rules.extend(replacement.iter().cloned());
            let regex_ids = self
                .regex_rules
                .read(|rules| rules.iter().map(|rule| rule.id).collect::<BTreeSet<_>>());
            if let Some(rule) = rules.iter().find(|rule| regex_ids.contains(&rule.id)) {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let published = self.reference.reload(&rules)?;
            self.blocklist_rules_control.replace(replacement);
            self.domain_rules_configured
                .store(!rules.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !rules.is_empty() || !self.regex_rules.read(|rules| rules.is_empty()),
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

        /// Reload configured blocklists only when the resulting bounded rule
        /// set changes. This is used by the optional Proxima interval source;
        /// malformed or unreadable replacements still fail closed and retain
        /// the last valid snapshot.
        pub fn reload_blocklists_if_changed(&self) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let paths = self.blocklist_paths.snapshot().as_ref().clone();
            let disabled = self.disabled_blocklist_paths.snapshot().as_ref().clone();
            let paths = paths
                .into_iter()
                .filter(|path| !disabled.contains(path))
                .collect::<Vec<_>>();
            let replacement = load_blocklists(&paths)?;
            if replacement == *self.blocklist_rules.snapshot() {
                self.observe_reload_latency("blocklists_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let base_rules = self.base_rules.snapshot();
            let mut rules = base_rules.as_ref().clone();
            rules.extend(replacement.iter().cloned());
            let regex_ids = self
                .regex_rules
                .read(|rules| rules.iter().map(|rule| rule.id).collect::<BTreeSet<_>>());
            if let Some(rule) = rules.iter().find(|rule| regex_ids.contains(&rule.id)) {
                return Err(policy::PolicyError::DuplicateRule { id: rule.id });
            }
            let published = self.reference.reload(&rules)?;
            self.blocklist_rules_control.replace(replacement);
            self.domain_rules_configured
                .store(!rules.is_empty(), Ordering::Release);
            self.rules_configured.store(
                !rules.is_empty() || !self.regex_rules.read(|rules| rules.is_empty()),
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

        /// Reload the configured country/CIDR map and publish only a changed
        /// complete replacement after bounded validation.
        pub fn reload_country_policy(&self) -> Result<ReloadState, policy::PolicyError> {
            self.reload_country_policy_if_changed()
        }

        /// Reload the country map only when its bounded contents changed.
        pub fn reload_country_policy_if_changed(&self) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let config = self.country_policy_config.snapshot().as_ref().clone();
            let next = load_country_policy(&config)?;
            let unchanged = self.country_policy.snapshot().as_ref() == &next;
            if unchanged {
                self.observe_reload_latency("country_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.country_policy_control.replace(next);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("country", started);
            Ok(ReloadState::Published)
        }

        /// Atomically replace country selectors and the referenced map. The
        /// validated map is published before the configuration becomes the
        /// source for subsequent background refreshes.
        pub fn replace_country_policy(
            &self,
            config: &CountryPolicyConfig,
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            let next = load_country_policy(config)?;
            if self.country_policy.read(|current| current == &next)
                && self.country_policy_config.read(|current| current == config)
            {
                self.observe_reload_latency("country_replace_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.country_policy_control.replace(next);
            self.country_policy_config_control.replace(config.clone());
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("country_replace", started);
            Ok(ReloadState::Published)
        }

        /// Atomically change only the live filtering gate. The immutable
        /// policy snapshot remains available for a later re-enable.
        pub fn set_filtering_enabled(&self, enabled: bool) -> ReloadState {
            if *self.filtering_enabled.snapshot() == enabled {
                return ReloadState::Unchanged;
            }
            self.filtering_enabled_control.replace(enabled);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            ReloadState::Published
        }

        /// Atomically change the fields retained in decision events. The
        /// setting is published through the same lock-free live cell used by
        /// request readers; recording destinations and transports stay intact.
        pub fn set_query_recording_redaction(
            &self,
            redaction: QueryRecordingRedaction,
        ) -> ReloadState {
            let started = Instant::now();
            if *self.query_recording_redaction.snapshot() == redaction {
                self.observe_reload_latency("recording_redaction_unchanged", started);
                return ReloadState::Unchanged;
            }
            self.query_recording_redaction_control.replace(redaction);
            self.policy_generation.fetch_add(1, Ordering::Relaxed);
            self.observe_reload_latency("recording_redaction", started);
            ReloadState::Published
        }

        /// Reload the policy-bearing portions of a configuration file. The
        /// listener, transport, storage, capture, and process-capacity
        /// settings remain startup-only and must not change underneath the
        /// running process.
        pub fn reload_config(&self, next: &Config) -> Result<ReloadState, policy::PolicyError> {
            let current = &self.config;
            let mut startup_privacy = next.privacy.clone();
            startup_privacy.query_recording_redaction = current.privacy.query_recording_redaction;
            if next.server != current.server
                || next.admin != current.admin
                || next.honeypot != current.honeypot
                || next.upstream != current.upstream
                || next.cache != current.cache
                || next.security != current.security
                || startup_privacy != current.privacy
                || next.capture != current.capture
                || next.dhcp != current.dhcp
            {
                return Err(policy::PolicyError::InvalidConfigReload {
                    reason: "startup-only listener, transport, storage, capture, or service settings changed".into(),
                });
            }
            if next.admission.max_inflight_requests != current.admission.max_inflight_requests
                || next.admission.ddos.persist_incidents != current.admission.ddos.persist_incidents
                || next.policy.blocklist_reload_interval_secs
                    != current.policy.blocklist_reload_interval_secs
                || next.country_policy.reload_interval_secs
                    != current.country_policy.reload_interval_secs
                || next.reload_interval_secs != current.reload_interval_secs
            {
                return Err(policy::PolicyError::InvalidConfigReload {
                    reason: "startup-only capacity, incident-persistence, or reload interval settings changed".into(),
                });
            }
            let redaction_changed = next.privacy.query_recording_redaction
                != *self.query_recording_redaction.snapshot();
            let result = self.reload_policy_bundle_with_legacy_and_admission(
                &next.policy.rules,
                &next.policy.regex_rules,
                &next.policy.profiles,
                &next.policy.client_groups,
                &next.policy.client_identities,
                &next.policy.rewrites,
                &next.country_policy,
                Some(&next.policy.blocklists),
                Some(next.policy.mode),
                Some(&next.policy.domains),
                Some(next.policy.default_action),
                Some(next.policy.filtering_enabled),
                Some(&next.policy.disabled_blocklists),
                Some(&next.admission),
            );
            match result {
                Ok(ReloadState::Published) => {
                    if redaction_changed {
                        self.query_recording_redaction_control
                            .replace(next.privacy.query_recording_redaction);
                    }
                    Ok(ReloadState::Published)
                }
                Ok(ReloadState::Unchanged) if redaction_changed => {
                    self.query_recording_redaction_control
                        .replace(next.privacy.query_recording_redaction);
                    self.policy_generation.fetch_add(1, Ordering::Relaxed);
                    Ok(ReloadState::Published)
                }
                other => other,
            }
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
            if self.profiles.read(|current| current == profiles)
                && self.client_groups.read(|current| current == client_groups)
            {
                self.observe_reload_latency("profiles_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let generated = compile_profiles(profiles, client_groups)?;
            let explicit = self.explicit_rules.snapshot().as_ref().clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let published = self.publish_rules_locked(&combined, &explicit, "profiles", started)?;
            self.profiles_control.replace(profiles.to_vec());
            self.client_groups_control.replace(client_groups.to_vec());
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
            if self.client_identities.read(|current| current == &next) {
                self.observe_reload_latency("client_identities_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
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
            let current_groups = self.client_groups.snapshot().as_ref().clone();
            let mut groups = current_groups.clone();
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
            let profiles = self.profiles.snapshot().as_ref().clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self.explicit_rules.snapshot().as_ref().clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            if groups == current_groups {
                self.observe_reload_latency("client_groups_upsert_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let published =
                self.publish_rules_locked(&combined, &explicit, "client_groups_upsert", started)?;
            self.client_groups_control.replace(groups);
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
            let current_profiles = self.profiles.snapshot().as_ref().clone();
            let mut profiles = current_profiles.clone();
            for update in updates {
                if let Some(existing) = profiles.iter_mut().find(|profile| profile.id == update.id)
                {
                    *existing = update.clone();
                } else {
                    profiles.push(update.clone());
                }
            }
            let groups = self.client_groups.snapshot().as_ref().clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self.explicit_rules.snapshot().as_ref().clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            if profiles == current_profiles {
                self.observe_reload_latency("profiles_upsert_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            let published =
                self.publish_rules_locked(&combined, &explicit, "profiles_upsert", started)?;
            self.profiles_control.replace(profiles);
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
            let current = self.profiles.snapshot().as_ref().clone();
            let mut profiles = current.clone();
            profiles.retain(|profile| !requested.contains(&profile.id));
            if profiles.len() == current.len() {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<profiles>".into(),
                    reason: "no requested profile ID exists".into(),
                });
            }
            let groups = self.client_groups.snapshot().as_ref().clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self.explicit_rules.snapshot().as_ref().clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let published =
                self.publish_rules_locked(&combined, &explicit, "profiles_remove", started)?;
            self.profiles_control.replace(profiles);
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
            let current = self.client_groups.snapshot().as_ref().clone();
            let mut groups = current.clone();
            let original_len = groups.len();
            groups.retain(|group| !requested.contains(&group.name.trim().to_ascii_lowercase()));
            if groups.len() == original_len {
                return Err(policy::PolicyError::InvalidProfile {
                    name: "<client-groups>".into(),
                    reason: "no requested group exists".into(),
                });
            }
            let profiles = self.profiles.snapshot().as_ref().clone();
            let generated = compile_profiles(&profiles, &groups)?;
            let explicit = self.explicit_rules.snapshot().as_ref().clone();
            let mut combined = explicit.clone();
            combined.extend(generated);
            let published =
                self.publish_rules_locked(&combined, &explicit, "client_groups_remove", started)?;
            self.client_groups_control.replace(groups);
            Ok(published)
        }

        /// Atomically replace all operator-managed policy tables while
        /// retaining the current blocklist snapshot. Every generated rule,
        /// regex, and cross-table ID is validated before publication.
        #[allow(clippy::too_many_arguments)]
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
                None,
                None,
            )
        }

        /// Atomically replace the complete policy bundle, including the
        /// legacy fallback fields and the default action when supplied.
        #[allow(clippy::too_many_arguments)]
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
            filtering_enabled: Option<bool>,
            disabled_blocklists: Option<&[String]>,
        ) -> Result<ReloadState, policy::PolicyError> {
            self.reload_policy_bundle_with_legacy_and_admission(
                rules,
                regex_configs,
                profiles,
                client_groups,
                client_identities,
                rewrite_configs,
                country_config,
                blocklist_paths,
                legacy_mode,
                legacy_domains,
                default_action,
                filtering_enabled,
                disabled_blocklists,
                None,
            )
        }

        /// Atomically replace policy tables and live admission limits as one
        /// operator publication. Startup-only capacity remains immutable.
        #[allow(clippy::too_many_arguments)]
        pub fn reload_policy_bundle_with_legacy_and_admission(
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
            filtering_enabled: Option<bool>,
            disabled_blocklists: Option<&[String]>,
            admission: Option<&AdmissionConfig>,
        ) -> Result<ReloadState, policy::PolicyError> {
            let _reload = self.reload_lock.write().expect("reload lock");
            let started = Instant::now();
            if let Some(admission) = admission {
                self.validate_admission(admission)?;
            }
            let normalized_legacy_domains =
                legacy_domains.map(validate_legacy_domains).transpose()?;
            let generated = compile_profiles(profiles, client_groups)?;
            let client_identities = validate_client_identities(client_identities)?;
            let rewrites = compile_rewrites(rewrite_configs)?;
            let country_policy = load_country_policy(country_config)?;
            let configured_paths = blocklist_paths.map_or_else(
                || self.blocklist_paths.snapshot().as_ref().clone(),
                <[String]>::to_vec,
            );
            let configured_disabled = disabled_blocklists.map_or_else(
                || {
                    self.disabled_blocklist_paths
                        .snapshot()
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                },
                <[String]>::to_vec,
            );
            let active_paths = active_blocklist_paths(&configured_paths, &configured_disabled)?;
            let replacement = load_blocklists(&active_paths)?;
            let mut base = rules.to_vec();
            base.extend(generated);
            let mut published = base.clone();
            published.extend(replacement.iter().cloned());
            let rule_ids = published
                .iter()
                .map(|rule| rule.id)
                .collect::<BTreeSet<_>>();
            let compiled_regex = compile_regex_rules(regex_configs, rule_ids)?;
            let next_reference = ReferencePolicy::new(&published)?;
            let unchanged = self.reference.read(|current| current == &next_reference)
                && self.base_rules.read(|current| current == &base)
                && self.explicit_rules.read(|current| current == rules)
                && self.regex_rule_configs() == regex_configs
                && self.profiles.read(|current| current == profiles)
                && self.client_groups.read(|current| current == client_groups)
                && self
                    .client_identities
                    .read(|current| current == &client_identities)
                && self
                    .rewrite_configs
                    .read(|current| current == rewrite_configs)
                && self
                    .country_policy_config
                    .read(|current| current == country_config)
                && self
                    .country_policy
                    .read(|current| current == &country_policy)
                && self.blocklist_rules.read(|current| current == &replacement)
                && self
                    .blocklist_paths
                    .read(|current| current == &configured_paths)
                && self
                    .disabled_blocklist_paths
                    .read(|current| current == &configured_disabled.iter().cloned().collect())
                && admission.is_none_or(|next| self.admission.read(|current| current == next))
                && legacy_domains.is_none_or(|_| {
                    normalized_legacy_domains
                        .as_ref()
                        .is_some_and(|next| self.legacy_domains.read(|current| current == next))
                })
                && legacy_mode.is_none_or(|next| self.legacy_mode.read(|current| current == &next))
                && default_action
                    .is_none_or(|next| self.default_action.read(|current| current == &next))
                && filtering_enabled
                    .is_none_or(|next| self.filtering_enabled.read(|current| current == &next));
            if unchanged {
                self.observe_reload_latency("policy_bundle_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.reference.reload(&published)?;
            self.base_rules_control.replace(base);
            self.explicit_rules_control.replace(rules.to_vec());
            self.regex_rules_control.replace(compiled_regex);
            self.profiles_control.replace(profiles.to_vec());
            self.client_groups_control.replace(client_groups.to_vec());
            self.client_identity_control.replace(client_identities);
            self.rewrite_control.replace(rewrites);
            self.rewrite_configs_control
                .replace(rewrite_configs.to_vec());
            self.country_policy_control.replace(country_policy);
            self.country_policy_config_control
                .replace(country_config.clone());
            if let Some(admission) = admission {
                self.admission_control.replace(admission.clone());
            }
            if let Some(domains) = normalized_legacy_domains {
                self.legacy_domains_control.replace(domains);
            }
            if let Some(mode) = legacy_mode {
                self.legacy_mode_control.replace(mode);
            }
            if let Some(action) = default_action {
                self.default_action_control.replace(action);
            }
            if let Some(enabled) = filtering_enabled {
                self.filtering_enabled_control.replace(enabled);
            }
            self.blocklist_rules_control.replace(replacement);
            if blocklist_paths.is_some() {
                self.blocklist_paths_control.replace(configured_paths);
            }
            if disabled_blocklists.is_some() {
                self.disabled_blocklist_paths_control
                    .replace(configured_disabled.into_iter().collect());
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
            let mut next = self.rewrite_configs.snapshot().as_ref().clone();
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
            let requested = names.iter().map(normalize).collect::<BTreeSet<_>>();
            if requested.iter().any(String::is_empty) {
                return Err(policy::PolicyError::InvalidRewrite {
                    name: "<rewrite-removal>".into(),
                    reason: "rewrite names must be non-empty".into(),
                });
            }
            let current = self.rewrite_configs.snapshot().as_ref().clone();
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
            if self.rewrite_configs.read(|current| current == configs) {
                self.observe_reload_latency("rewrites_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.publish_rewrites_locked(configs, "rewrites", started)
        }

        fn publish_rewrites_locked(
            &self,
            configs: &[RewriteConfig],
            reload_kind: &'static str,
            started: Instant,
        ) -> Result<ReloadState, policy::PolicyError> {
            let compiled = compile_rewrites(configs)?;
            self.rewrite_control.replace(compiled);
            self.rewrite_configs_control.replace(configs.to_vec());
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
            if self.regex_rule_configs() == configs {
                self.observe_reload_latency("regex_unchanged", started);
                return Ok(ReloadState::Unchanged);
            }
            self.regex_rules_control.replace(compiled);
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
            self.regex_rules.read(|rules| {
                rules
                    .iter()
                    .map(|rule| RegexRuleConfig {
                        enabled: true,
                        id: rule.id,
                        pattern: rule.pattern.as_str().to_owned(),
                        action: rule.action,
                        priority: rule.priority,
                        qtype: rule.qtype,
                        qtypes: rule.qtypes.clone(),
                        qclass: rule.qclass,
                        qclasses: rule.qclasses.clone(),
                        client: rule.client,
                        client_cidrs: rule.client_cidrs.clone(),
                    })
                    .collect()
            })
        }

        fn publish_regex_rules_locked(
            &self,
            configs: &[RegexRuleConfig],
            reload_kind: &'static str,
            started: Instant,
        ) -> Result<ReloadState, policy::PolicyError> {
            let rule_ids = self.reference.rule_ids();
            let compiled = compile_regex_rules(configs, rule_ids)?;
            self.regex_rules_control.replace(compiled);
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
            self.upstream_slots = Some(Arc::new(AtomicPermitPool::new(
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
            // Request matching consumes independently published immutable
            // snapshots.  Reload serialization is control-plane state; a
            // reader lock here would put a blocking lock on every query.
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
                Self::client_identity_index(identities, client)
                    .and_then(|index| identities.get(index))
                    .map(|identity| identity.name.clone())
            })
        }

        fn client_identity_index(
            identities: &[ClientIdentityConfig],
            client: std::net::IpAddr,
        ) -> Option<usize> {
            if let Some((index, _)) = identities
                .iter()
                .enumerate()
                .filter(|(_, identity)| identity.enabled)
                .find(|(_, identity)| identity.clients.contains(&client))
            {
                return Some(index);
            }
            identities
                .iter()
                .enumerate()
                .filter(|(_, identity)| identity.enabled)
                .filter_map(|(index, identity)| {
                    identity
                        .client_cidrs
                        .iter()
                        .filter_map(|cidr| policy::IpNetwork::parse(cidr))
                        .filter(|network| network.contains(client))
                        .max_by_key(|network| network.prefix())
                        .map(|network| (network.prefix(), index))
                })
                .max_by_key(|(prefix, _)| *prefix)
                .map(|(_, index)| index)
        }

        pub(crate) fn admission_config(&self) -> AdmissionConfig {
            self.admission.snapshot().as_ref().clone()
        }

        fn deny_client(&self, client: Option<IpAddr>) -> bool {
            let Some(client) = client else {
                return false;
            };
            self.admission_config()
                .deny_client_cidrs
                .iter()
                .any(|cidr| {
                    policy::IpNetwork::parse(cidr).is_some_and(|network| network.contains(client))
                })
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

        fn allow_global_abuse(&self) -> bool {
            let ddos = &self.admission_config().ddos;
            if ddos.max_global_abuse_violations == 0 {
                return true;
            }
            self.global_abuse.abuse_allows(
                self.breaker_epoch,
                Duration::from_secs(ddos.global_abuse_window_secs),
            )
        }

        pub(crate) fn record_global_abuse(&self, cause: &'static str) -> bool {
            let ddos = &self.admission_config().ddos;
            if ddos.max_global_abuse_violations == 0 {
                return false;
            }
            let opened = self.global_abuse.record_abuse(
                self.breaker_epoch,
                Duration::from_secs(ddos.global_abuse_window_secs),
                Duration::from_secs(ddos.global_abuse_cooldown_secs),
                ddos.max_global_abuse_violations,
            );
            if opened {
                self.observe_failure("global_abuse_breaker_open");
                self.observe_failure(cause);
            }
            opened
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

        /// Treat a response that reaches the configured ratio ceiling as an
        /// amplification violation. The listener calls this after encoding,
        /// so the signal is based on actual wire bytes and feeds the existing
        /// bounded client/network abuse breaker.
        pub(crate) fn response_amplification_capped(
            &self,
            query_wire_bytes: usize,
            response_wire_bytes: usize,
        ) -> bool {
            let ratio = self.admission_config().max_response_amplification;
            query_wire_bytes != 0 && response_wire_bytes >= query_wire_bytes.saturating_mul(ratio)
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

        /// Return whether an identified client currently passes both the
        /// exact-client and configured-network abuse breakers.
        #[must_use]
        pub fn allow_client_abuse(&self, client: Option<IpAddr>) -> bool {
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

        /// Feed adapter-level malformed traffic into the same bounded abuse
        /// breaker as rate and response-budget violations. The listener owns
        /// peer attribution, so policy receives only the address and stable
        /// failure cause; no malformed payload is retained.
        pub(crate) async fn record_adapter_abuse(
            &self,
            client: Option<IpAddr>,
            cause: &'static str,
        ) {
            if self.record_client_abuse(client) {
                self.observe_failure("client_abuse_breaker_open");
                self.observe_failure(cause);
                if let Some(client) = client {
                    self.record_abuse_incident(client, cause).await;
                }
            }
        }

        /// Restore an active persisted incident without replaying a violation
        /// window. Both the exact client and its configured network are
        /// blocked so a restart cannot silently reopen the incident's path.
        pub fn restore_abuse_incident(
            &self,
            client: IpAddr,
            expires_at_ms: u64,
            now_ms: u64,
        ) -> bool {
            let Some(remaining_ms) = expires_at_ms.checked_sub(now_ms) else {
                return false;
            };
            if remaining_ms == 0 {
                return false;
            }
            let remaining = Duration::from_millis(remaining_ms);
            let admission = self.admission_config();
            let (client_key, client_key_len) = ip_key(client);
            self.client_abuse.restore_blocked(
                &client_key[..client_key_len],
                self.breaker_epoch,
                remaining,
            );
            let network = abuse_network_key(
                client,
                admission.network_abuse_ipv4_prefix,
                admission.network_abuse_ipv6_prefix,
            );
            let (network_key, network_key_len) = abuse_network_bytes(network);
            self.network_abuse.restore_blocked(
                &network_key[..network_key_len],
                self.breaker_epoch,
                remaining,
            );
            true
        }

        /// Revoke a temporary incident for the exact client and its configured
        /// abuse network. Both keyed tables use Proxima's bounded lock-free
        /// buckets; revocation is idempotent and never changes policy rules.
        pub fn revoke_abuse_incident(&self, client: IpAddr) {
            let admission = self.admission_config();
            let (client_key, client_key_len) = ip_key(client);
            self.client_abuse
                .release_blocked(&client_key[..client_key_len]);
            let network = abuse_network_key(
                client,
                admission.network_abuse_ipv4_prefix,
                admission.network_abuse_ipv6_prefix,
            );
            let (network_key, network_key_len) = abuse_network_bytes(network);
            self.network_abuse
                .release_blocked(&network_key[..network_key_len]);
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
            let max_ttl = self
                .cache
                .read(|cache| cache.config.max_ttl_secs.min(u64::from(u32::MAX)) as u32);
            for record in &mut answer.records {
                record.ttl = record.ttl.min(max_ttl);
            }
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
                    if used != record.rdata.len() || !valid_dns_name(&normalize(target.to_dotted()))
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

        fn upstream_failure_cause(error: &DnsClientError) -> &'static str {
            match error {
                DnsClientError::Timeout(_) => "upstream_timeout",
                DnsClientError::Wire(_) => "upstream_wire_error",
                DnsClientError::IdMismatch { .. } => "upstream_id_mismatch",
                DnsClientError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    "upstream_io_timeout"
                }
                DnsClientError::Io(_) => "upstream_io_error",
                DnsClientError::Config(_) => "upstream_config_error",
                _ => "upstream_error",
            }
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
            if self.deny_client(client) {
                return Action::Reject;
            }
            if !*self.filtering_enabled.snapshot() {
                return Action::Pass;
            }
            let name = query.name.to_dotted();
            if !self.rules_configured.load(Ordering::Acquire) {
                if !self.matches(&name) {
                    return Action::Pass;
                }
                return match *self.legacy_mode.snapshot() {
                    Mode::Ignore => Action::Ignore,
                    Mode::Nxdomain => Action::Nxdomain,
                    Mode::Honeypot => Action::Honeypot,
                };
            }
            let reference = self.client_identities.read(|identities| {
                let resolved_identity = client_identity.or_else(|| {
                    client
                        .and_then(|client| Self::client_identity_index(identities, client))
                        .and_then(|index| identities.get(index))
                        .map(|identity| identity.name.as_str())
                });
                self.reference.read(|reference| {
                    reference.decide(QueryContext {
                        name: &name,
                        qtype: query.qtype,
                        qclass: query.qclass,
                        client,
                        client_identity: resolved_identity,
                    })
                })
            });
            reference
                .or_else(|| {
                    self.regex_decision(&normalize(&name), query.qtype, query.qclass, client)
                })
                .map_or(*self.default_action.snapshot(), |decision| decision.action)
        }

        fn regex_decision(
            &self,
            name: &str,
            qtype: u16,
            qclass: u16,
            client: Option<IpAddr>,
        ) -> Option<policy::Decision> {
            self.regex_rules.read(|rules| {
                rules
                    .iter()
                    .filter(|rule| {
                        rule.enabled
                            && rule.pattern.is_match(name)
                            && (rule.qtypes.is_empty() || rule.qtypes.contains(&qtype))
                            && (rule.qclasses.is_empty() || rule.qclasses.contains(&qclass))
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
                            u8::from(!rule.qclasses.is_empty()),
                            u8::from(!rule.qtypes.is_empty()),
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
            })
        }
        fn matches(&self, name: &str) -> bool {
            let name = normalize(name);
            self.legacy_domains.read(|domains| {
                domains.iter().any(|domain| {
                    name == *domain
                        || (name.len() > domain.len()
                            && name.ends_with(domain)
                            && name.as_bytes()[name.len() - domain.len() - 1] == b'.')
                })
            })
        }

        pub fn evaluate(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
            if !self.admission_allows(query) {
                return Some(refused_answer());
            }
            if !*self.filtering_enabled.snapshot() {
                return self
                    .rewrites
                    .read(|rewrites| rewrites.answer(query))
                    .or_else(|| Some(DnsAnswer::ok(Vec::new())))
                    .map(|answer| self.cap_answer(query, answer));
            }
            if !self.rules_configured.load(Ordering::Acquire) {
                if self.matches(&query.name) {
                    return self
                        .evaluate_legacy(query)
                        .map(|answer| self.cap_answer(query, answer));
                }
                return self
                    .rewrites
                    .read(|rewrites| rewrites.answer(query))
                    .or_else(|| Some(DnsAnswer::ok(Vec::new())))
                    .map(|answer| self.cap_answer(query, answer));
            }
            let decision = self.decision(query, None);
            let answer = match decision
                .map(|decision| decision.action)
                .or(Some(*self.default_action.snapshot()))
            {
                Some(Action::Ignore | Action::Drop | Action::Forward) => None,
                Some(Action::Nxdomain) => Some(DnsAnswer::name_error()),
                Some(Action::Reject) => Some(refused_answer()),
                Some(Action::Sink) => Some(DnsAnswer::ok(Vec::new())),
                Some(Action::Honeypot) => Some(synthetic_honeypot_answer(
                    &query.name,
                    query.qtype,
                    &self.config.honeypot,
                )),
                Some(Action::Pass | Action::Observe) => self
                    .rewrites
                    .read(|rewrites| rewrites.answer(query))
                    .or_else(|| Some(DnsAnswer::ok(Vec::new()))),
                None => Some(DnsAnswer::ok(Vec::new())),
            };
            answer.map(|answer| self.cap_answer(query, answer))
        }

        fn evaluate_legacy(&self, query: &proxima_dns::DnsQuery) -> Option<DnsAnswer> {
            if !self.matches(&query.name) {
                return Some(DnsAnswer::ok(Vec::new()));
            }
            match *self.legacy_mode.snapshot() {
                Mode::Ignore => None,
                Mode::Nxdomain => Some(DnsAnswer::name_error()),
                Mode::Honeypot => Some(synthetic_honeypot_answer(
                    &query.name,
                    query.qtype,
                    &self.config.honeypot,
                )),
            }
        }

        pub(crate) fn observe(&self, action: Action) {
            self.decision_counts[action_index(action)].fetch_add(1, Ordering::Relaxed);
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
            let mut payload = serde_json::json!({
                "action": action_label(action),
                "qtype": query.qtype,
                "qclass": query.qclass,
            });
            if *self.query_recording_redaction.snapshot() == QueryRecordingRedaction::ActionOnly {
                let object = payload
                    .as_object_mut()
                    .expect("decision recording payload is an object");
                object.remove("qtype");
                object.remove("qclass");
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
                    payload,
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

        /// Persist a bounded incident marker through the existing Proxima
        /// recording sink. No DNS name, payload, identity label, or wire data
        /// enters the event; the client address is retained only because it is
        /// the operator's temporary blacklist key.
        pub(crate) async fn record_abuse_incident(&self, client: IpAddr, cause: &'static str) {
            if !self.config.admission.ddos.persist_incidents && self.query_log.is_none() {
                return;
            }
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| {
                    duration.as_millis().min(u128::from(u64::MAX)) as u64
                });
            let expires_at_ms = now_ms.saturating_add(
                self.admission_config()
                    .client_abuse_cooldown_secs
                    .max(self.admission_config().network_abuse_cooldown_secs)
                    .saturating_mul(1_000),
            );
            let review_event = RecordingEvent {
                id: InteractionId::new(),
                ts_ms: now_ms,
                parent: None,
                event: ProtocolEvent::Custom {
                    kind: "blackhole.ddos_incident".into(),
                    payload: serde_json::json!({
                        "cause": cause,
                        "response": "temporary_blacklist",
                        "expires_at_ms": expires_at_ms,
                    }),
                },
            };
            if let Some(query_log) = self.query_log.as_ref()
                && query_log.append(review_event).await.is_err()
            {
                self.observe_failure("query_log_incident_append");
            }
            if !self.config.admission.ddos.persist_incidents {
                return;
            }
            let Some(recording) = self.recording.as_ref() else {
                self.observe_failure("ddos_incident_recording_unconfigured");
                return;
            };
            let event = RecordingEvent {
                id: InteractionId::new(),
                ts_ms: now_ms,
                parent: None,
                event: ProtocolEvent::Custom {
                    kind: "blackhole.ddos_incident".into(),
                    payload: serde_json::json!({
                        "client": client.to_string(),
                        "cause": cause,
                        "response": "temporary_blacklist",
                        "expires_at_ms": expires_at_ms,
                    }),
                },
            };
            if recording.append(event).await.is_err() || recording.sync().await.is_err() {
                self.observe_failure("ddos_incident_recording");
            }
        }

        /// Return the bounded, redacted incident review projection from the
        /// existing in-memory Proxima recording primitive.
        pub(crate) fn admin_abuse_incidents(&self) -> String {
            let Some(query_log) = self.query_log.as_ref() else {
                return "{\"enabled\":false,\"incidents\":[]}".into();
            };
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| {
                    duration.as_millis().min(u128::from(u64::MAX)) as u64
                });
            let incidents = query_log
                .snapshot()
                .into_iter()
                .filter_map(|event| match event.event {
                    ProtocolEvent::Custom { kind, payload }
                        if kind == "blackhole.ddos_incident" =>
                    {
                        Some(serde_json::json!({
                            "ts_ms": event.ts_ms,
                            "cause": payload.get("cause"),
                            "response": payload.get("response"),
                            "expires_at_ms": payload.get("expires_at_ms"),
                            "active": payload
                                .get("expires_at_ms")
                                .and_then(serde_json::Value::as_u64)
                                .is_some_and(|expires_at_ms| expires_at_ms > now_ms),
                        }))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let truncated = incidents.len() > MAX_ADMIN_LOG_ENTRIES;
            let incidents = incidents
                .into_iter()
                .rev()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .collect::<Vec<_>>();
            serde_json::json!({
                "enabled": true,
                "truncated": truncated,
                "incidents": incidents,
                "client_addresses": "redacted",
            })
            .to_string()
        }

        /// Export the bounded durable incident stream through Proxima's
        /// existing JSONL source. This authenticated operator export includes
        /// client keys needed for recovery; the in-memory review stays redacted.
        pub(crate) async fn admin_abuse_incident_export(&self) -> Result<String, ProximaError> {
            let Some(path) = self.config.privacy.query_recording_path.as_deref() else {
                return Ok("{\"enabled\":false,\"events\":[]}".into());
            };
            let metadata = match std::fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok("{\"enabled\":true,\"events\":[]}".into());
                }
                Err(error) => {
                    return Err(ProximaError::Record(format!(
                        "inspect abuse recording: {error}"
                    )));
                }
            };
            if !metadata.is_file() {
                return Err(ProximaError::Record(
                    "abuse recording is not a regular file".into(),
                ));
            }
            let max_bytes = self
                .config
                .privacy
                .query_recording_max_bytes
                .min(MAX_ABUSE_EXPORT_BYTES);
            if metadata.len() > max_bytes {
                return Err(ProximaError::Record(format!(
                    "abuse recording exceeds the {max_bytes} byte export bound"
                )));
            }
            let runtime = Arc::new(PrimeRuntime::new(1)?);
            let source = proxima::JsonlSource::new(path, runtime);
            let mut stream = source.events();
            let mut events = Vec::new();
            let mut seen = 0usize;
            while let Some(event) = stream.next().await {
                seen = seen.checked_add(1).ok_or_else(|| {
                    ProximaError::Record("abuse export event count overflow".into())
                })?;
                if seen > MAX_ABUSE_EXPORT_EVENTS {
                    return Err(ProximaError::Record(
                        "abuse recording exceeds the event export bound".into(),
                    ));
                }
                let event = event?;
                let proxima::ProtocolEvent::Custom { kind, payload } = event.event else {
                    continue;
                };
                if kind != "blackhole.ddos_incident" && kind != "blackhole.ddos_revoke" {
                    continue;
                }
                events.push(serde_json::json!({
                    "ts_ms": event.ts_ms,
                    "kind": kind,
                    "payload": payload,
                }));
                if events.len() > MAX_ADMIN_LOG_ENTRIES {
                    events.remove(0);
                }
            }
            Ok(serde_json::json!({
                "enabled": true,
                "events": events,
                "truncated": seen > MAX_ADMIN_LOG_ENTRIES,
                "client_addresses": "included_for_authenticated_operator_recovery",
            })
            .to_string())
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
                "query_recording_redaction": match *self.query_recording_redaction.snapshot() {
                    QueryRecordingRedaction::Metadata => "metadata",
                    QueryRecordingRedaction::ActionOnly => "action_only",
                },
                "payload_recording": "disabled",
                "client_identity_recording": "disabled",
            })
            .to_string()
        }

        /// Delete the configured durable recording and its bounded rotations.
        ///
        /// The authenticated admin surface uses this operation for an
        /// operator-requested privacy deletion. Every target is preflighted as
        /// a regular file, only the configured recording basename and the
        /// fixed rotation bound are touched, and every deletion is verified.
        pub(crate) fn clear_durable_query_recording(&self) -> Result<usize, String> {
            const MAX_ROTATIONS: usize = 16;
            let path = self
                .config
                .privacy
                .query_recording_path
                .as_deref()
                .ok_or_else(|| "durable query recording is not configured".to_owned())?;
            let destination = Path::new(path);
            let parent = destination
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent_metadata = std::fs::metadata(parent).map_err(|error| {
                format!("inspect recording parent {}: {error}", parent.display())
            })?;
            if !parent_metadata.is_dir() {
                return Err(format!(
                    "recording parent {} is not a directory",
                    parent.display()
                ));
            }

            let mut targets = Vec::with_capacity(MAX_ROTATIONS + 1);
            targets.push(destination.to_owned());
            for index in 1..=MAX_ROTATIONS {
                let mut rotated = destination.as_os_str().to_os_string();
                rotated.push(format!(".{index}"));
                targets.push(std::path::PathBuf::from(rotated));
            }
            for target in &targets {
                match std::fs::metadata(target) {
                    Ok(metadata) if metadata.is_file() => {}
                    Ok(_) => {
                        return Err(format!(
                            "recording target {} is not a regular file",
                            target.display()
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!(
                            "inspect recording target {}: {error}",
                            target.display()
                        ));
                    }
                }
            }

            let mut removed = 0;
            for target in &targets {
                match std::fs::remove_file(target) {
                    Ok(()) => removed += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!(
                            "delete recording target {}: {error}",
                            target.display()
                        ));
                    }
                }
            }
            for target in &targets {
                match std::fs::metadata(target) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        return Err(format!(
                            "recording target {} remains after deletion",
                            target.display()
                        ));
                    }
                    Err(error) => {
                        return Err(format!(
                            "verify recording deletion {}: {error}",
                            target.display()
                        ));
                    }
                }
            }
            Ok(removed)
        }

        /// Return aggregate action counts without exposing names, client
        /// metadata, or payloads. Atomic counters keep this projection off
        /// the request path's lock discipline.
        pub(crate) fn admin_stats(&self) -> String {
            let actions = [
                Action::Pass,
                Action::Ignore,
                Action::Drop,
                Action::Reject,
                Action::Nxdomain,
                Action::Sink,
                Action::Honeypot,
                Action::Forward,
                Action::Observe,
            ];
            let mut total = 0_u64;
            let mut counts = BTreeMap::new();
            for action in actions {
                let count = self.decision_counts[action_index(action)].load(Ordering::Relaxed);
                total = total.saturating_add(count);
                counts.insert(action_label(action), count);
            }
            serde_json::json!({
                "total": total,
                "actions": counts,
            })
            .to_string()
        }

        pub(crate) fn clear_stats(&self) -> u64 {
            let mut removed = 0_u64;
            for count in &self.decision_counts {
                removed = removed.saturating_add(count.swap(0, Ordering::Relaxed));
            }
            removed
        }

        /// Return bounded admission and amplification limits without exposing
        /// client keys, counters, or other request metadata.
        pub(crate) fn admin_admission_status(&self) -> String {
            let admission = self.admission_config();
            serde_json::json!({
                "deny_client_cidr_count": admission.deny_client_cidrs.len(),
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
                "max_global_abuse_violations": admission.ddos.max_global_abuse_violations,
                "global_abuse_window_secs": admission.ddos.global_abuse_window_secs,
                "global_abuse_cooldown_secs": admission.ddos.global_abuse_cooldown_secs,
            })
            .to_string()
        }

        /// Return country-policy controls and bounded map metadata without
        /// exposing the source path or any client address.
        pub(crate) fn admin_country_status(&self) -> String {
            let country_policy = self.country_policy.snapshot();
            let policy = country_policy.as_ref();
            let config = self.country_policy_config.snapshot();
            let source_kind = config.map_path.as_deref().map_or("none", |source| {
                if http_source_parts(source).is_some() {
                    "hosted_http"
                } else {
                    "local_file"
                }
            });
            let (source_status, source_age_secs, freshness_valid) = match config.map_path.as_deref()
            {
                None => ("none", None, None),
                Some(source) if http_source_parts(source).is_some() => ("remote", None, None),
                Some(source) => match std::fs::metadata(source) {
                    Ok(metadata) if metadata.is_file() => match metadata.modified() {
                        Ok(modified) => {
                            let age = std::time::SystemTime::now()
                                .duration_since(modified)
                                .ok()
                                .map(|duration| duration.as_secs());
                            let fresh = config
                                .max_age_secs
                                .map_or(Some(true), |max_age| age.map(|age| age <= max_age));
                            ("ok", age, fresh)
                        }
                        Err(_) => ("unreadable", None, Some(false)),
                    },
                    Ok(_) => ("unreadable", None, Some(false)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        ("missing", None, Some(false))
                    }
                    Err(_) => ("unreadable", None, Some(false)),
                },
            };
            serde_json::json!({
                "map_configured": policy.is_some(),
                "source_kind": source_kind,
                "source_status": source_status,
                "source_age_secs": source_age_secs,
                "freshness_valid": freshness_valid,
                "freshness_contract": if source_kind == "local_file" { "local_mtime" } else { "none" },
                "entries": policy.as_ref().map_or(0, |value| value.entries.len()),
                "source_fingerprint": policy
                    .as_ref()
                    .map(|value| format!("{:016x}", value.source_fingerprint)),
                "source_sha256": policy.as_ref().map(|value| value.source_sha256.clone()),
                "sha256_pin_configured": config.expected_sha256.is_some(),
                "deny": config.deny,
                "observe": config.observe,
                "deny_regions": config.deny_regions,
                "observe_regions": config.observe_regions,
                "deny_asns": config.deny_asns,
                "observe_asns": config.observe_asns,
                "max_age_secs": config.max_age_secs,
                "reload_interval_secs": config.reload_interval_secs,
            })
            .to_string()
        }

        pub(crate) fn clear_query_log(&self) -> usize {
            self.query_log
                .as_ref()
                .map_or(0, |query_log| query_log.clear())
        }

        /// Return bounded abuse-state metadata without exposing client keys.
        pub(crate) fn admin_abuse_status(&self) -> String {
            let admission = self.admission_config();
            serde_json::json!({
                "client_entries": self.client_abuse.len(),
                "network_entries": self.network_abuse.len(),
                "client_state_capacity": MAX_CLIENT_RATE_ENTRIES,
                "network_state_capacity": MAX_CLIENT_RATE_ENTRIES,
                "client_violation_threshold": admission.max_client_abuse_violations,
                "client_window_secs": admission.client_abuse_window_secs,
                "client_cooldown_secs": admission.client_abuse_cooldown_secs,
                "network_violation_threshold": admission.max_network_abuse_violations,
                "network_window_secs": admission.network_abuse_window_secs,
                "network_cooldown_secs": admission.network_abuse_cooldown_secs,
                "global_violation_threshold": admission.ddos.max_global_abuse_violations,
                "global_window_secs": admission.ddos.global_abuse_window_secs,
                "global_cooldown_secs": admission.ddos.global_abuse_cooldown_secs,
                "incident_persistence": admission.ddos.persist_incidents,
                "global_breaker_open": self.global_abuse.is_blocked(self.breaker_epoch),
                "automatic_blacklist": "temporary_cooldown",
                "keys": "not_exposed",
            })
            .to_string()
        }

        /// Export the bounded operator-managed denylist through the already
        /// authenticated admin surface. This is configuration metadata, not
        /// telemetry or query logging.
        pub(crate) fn admin_abuse_denylist(&self) -> String {
            serde_json::to_string(&self.admission_config().deny_client_cidrs)
                .unwrap_or_else(|_| "[]".into())
        }

        pub(crate) fn clear_abuse_state(&self) -> usize {
            let removed = self.client_abuse.len() + self.network_abuse.len();
            self.client_abuse.clear();
            self.network_abuse.clear();
            removed
        }

        pub(crate) fn admin_status(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let cache = self.cache.snapshot();
            serde_json::json!({
                "status": "ok",
                "rules_configured": self.rules_configured.load(Ordering::Acquire),
                "policy_generation": self.policy_generation.load(Ordering::Acquire),
                "profiles_configured": self.profiles.read(Vec::len),
                "client_groups_configured": self.client_groups.read(Vec::len),
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
            let base_rules = self.base_rules.snapshot();
            let regex_rules = self.regex_rules.snapshot();
            let blocklist_rules = self.blocklist_rules.snapshot();
            let blocklist_paths = self.blocklist_paths.snapshot();
            let disabled_blocklists = self.disabled_blocklist_paths.snapshot();
            let profiles = self.profiles.snapshot();
            let client_groups = self.client_groups.snapshot();
            let identity_rules = base_rules
                .iter()
                .filter(|rule| rule.client_identity.is_some())
                .count();
            let rewrites = self.rewrites.snapshot();
            let country_policy = self.country_policy.snapshot();
            let country_config = self.country_policy_config.snapshot();
            serde_json::json!({
                "rules_configured": self.rules_configured.load(Ordering::Acquire),
                "domain_rules": base_rules.len(),
                "regex_rules": regex_rules.len(),
                "blocklist_sources": blocklist_paths.len(),
                "disabled_blocklist_sources": disabled_blocklists.len(),
                "blocklist_rules": blocklist_rules.len(),
                "rewrites": rewrites.len(),
                "profiles": profiles.len(),
                "client_groups": client_groups.len(),
                "identity_rules": identity_rules,
                "country_entries": country_policy.as_ref().as_ref().map_or(0, |policy| policy.entries.len()),
                "country_deny_rules": country_policy.as_ref().as_ref().map_or(0, |policy| policy.deny.len()),
                "country_observe_rules": country_policy.as_ref().as_ref().map_or(0, |policy| policy.observe.len()),
                "country_reload_interval_secs": country_config.reload_interval_secs,
                "legacy_domain_count": self.legacy_domains.read(Vec::len),
                "legacy_mode": mode_label(*self.legacy_mode.snapshot()),
                "default_action": action_label(*self.default_action.snapshot()),
                "filtering_enabled": *self.filtering_enabled.snapshot(),
                "legacy_mode_active": !self.rules_configured.load(Ordering::Acquire),
                "policy_generation": self.policy_generation.load(Ordering::Acquire),
            })
            .to_string()
        }

        /// Return the authenticated operator's bounded blocklist source
        /// configuration and loaded rule count. This is configuration
        /// inspection, not query telemetry; it never returns source contents.
        pub(crate) fn admin_blocklists(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let paths = self.blocklist_paths.snapshot();
            let disabled = self.disabled_blocklist_paths.snapshot();
            let rules = self.blocklist_rules.snapshot();
            let now = std::time::SystemTime::now();
            let sources = paths
                .iter()
                .map(|path| {
                    let remote = http_source_parts(path).is_some();
                    let (status, bytes, modified_age_secs, source_fingerprint) = if remote {
                        ("remote", 0, None, None)
                    } else {
                        match std::fs::metadata(path) {
                            Ok(metadata) if metadata.is_file() => {
                                let age = metadata
                                    .modified()
                                    .ok()
                                    .and_then(|modified| now.duration_since(modified).ok())
                                    .map(|duration| duration.as_secs());
                                let bytes = metadata.len().min(MAX_BLOCKLIST_BYTES);
                                let fingerprint = (metadata.len() <= MAX_BLOCKLIST_BYTES)
                                    .then(|| std::fs::read(path).ok())
                                    .flatten()
                                    .map(|contents| {
                                        format!("{:016x}", source_fingerprint(&contents))
                                    });
                                ("ok", bytes, age, fingerprint)
                            }
                            Ok(_) => ("unreadable", 0, None, None),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                ("missing", 0, None, None)
                            }
                            Err(_) => ("unreadable", 0, None, None),
                        }
                    };
                    let (load_status, source_rule_count) = if disabled.contains(path) {
                        ("disabled", 0)
                    } else if remote {
                        ("configured", 0)
                    } else {
                        match load_blocklists(std::slice::from_ref(path)) {
                            Ok(source_rules) => ("ok", source_rules.len()),
                            Err(_) => ("invalid", 0),
                        }
                    };
                    serde_json::json!({
                        "path": path,
                        "enabled": !disabled.contains(path),
                        "status": status,
                        "load_status": load_status,
                        "rule_count": source_rule_count,
                        "bytes": bytes,
                        "modified_age_secs": modified_age_secs,
                        "source_fingerprint": source_fingerprint,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "sources": sources,
                "source_count": paths.len(),
                "disabled_source_count": disabled.len(),
                "rule_count": rules.len(),
                "reload_interval_secs": self.config.policy.blocklist_reload_interval_secs,
                "policy_generation": self.policy_generation.load(Ordering::Acquire),
            })
            .to_string()
        }

        /// Return the live operator-managed bundle for the authenticated
        /// editor. The blocklist source field is null intentionally: the
        /// bundle reload contract treats null as retaining the loaded map.
        pub(crate) fn admin_policy_bundle(&self) -> String {
            let _reload = self.reload_lock.read().expect("reload lock");
            let rules = self.explicit_rules.snapshot();
            let regex_rules = self.regex_rules.snapshot();
            let profiles = self.profiles.snapshot();
            let client_groups = self.client_groups.snapshot();
            let client_identities = self.client_identities.snapshot();
            let rewrites = self.rewrite_configs.snapshot();
            let value = serde_json::json!({
                "mode": mode_label(*self.legacy_mode.snapshot()),
                "domains": self.legacy_domains.snapshot().as_ref().clone(),
                "default_action": action_label(*self.default_action.snapshot()),
                "filtering_enabled": *self.filtering_enabled.snapshot(),
                "rules": rules.iter().map(|rule| serde_json::json!({
                    "enabled": rule.enabled,
                    "id": rule.id,
                    "domain": rule.domain,
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qtypes": rule.qtypes,
                    "qclass": rule.qclass,
                    "qclasses": rule.qclasses,
                    "client": rule.client,
                    "client_cidr": rule.client_cidr,
                    "client_cidrs": rule.client_cidrs,
                    "client_identity": rule.client_identity,
                })).collect::<Vec<_>>(),
                "regex_rules": regex_rules.iter().map(|rule| serde_json::json!({
                    "enabled": rule.enabled,
                    "id": rule.id,
                    "pattern": rule.pattern.as_str(),
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qtypes": rule.qtypes,
                    "qclass": rule.qclass,
                    "qclasses": rule.qclasses,
                    "client": rule.client,
                    "client_cidrs": rule.client_cidrs,
                })).collect::<Vec<_>>(),
                "profiles": profiles.iter().map(|profile| serde_json::json!({
                    "id": profile.id,
                    "name": profile.name,
                    "enabled": profile.enabled,
                    "domains": profile.domains,
                    "action": action_label(profile.action),
                    "groups": profile.groups,
                    "client_identity": profile.client_identity,
                    "priority": profile.priority,
                    "client_cidrs": profile.client_cidrs,
                    "qtype": profile.qtype,
                    "qclass": profile.qclass,
                    "qtypes": profile.qtypes,
                    "qclasses": profile.qclasses,
                })).collect::<Vec<_>>(),
                "client_groups": client_groups.iter().map(|group| serde_json::json!({
                    "name": group.name,
                    "enabled": group.enabled,
                    "client_addresses": group.client_addresses,
                    "client_cidrs": group.client_cidrs,
                })).collect::<Vec<_>>(),
                "client_identities": client_identities.iter().map(|identity| serde_json::json!({
                    "name": identity.name,
                    "enabled": identity.enabled,
                    "clients": identity.clients,
                    "client_cidrs": identity.client_cidrs,
                })).collect::<Vec<_>>(),
                "rewrites": rewrites.iter().map(|rewrite| serde_json::json!({
                    "name": rewrite.name,
                    "ipv4": rewrite.ipv4,
                    "ipv6": rewrite.ipv6,
                    "cname": rewrite.cname,
                    "ttl": rewrite.ttl,
                })).collect::<Vec<_>>(),
                "country_policy": self.country_policy_config.snapshot().as_ref().clone(),
                "blocklists": serde_json::Value::Null,
                "disabled_blocklists": self
                    .disabled_blocklist_paths
                    .snapshot()
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                "admission": self.admission_config(),
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
            let base_rules = self.base_rules.snapshot();
            let regex_rules = self.regex_rules.snapshot();
            let total = base_rules.len().saturating_add(regex_rules.len());
            let mut rules = Vec::with_capacity(total.min(256));
            for rule in base_rules.as_ref() {
                rules.push(serde_json::json!({
                    "kind": "domain",
                    "enabled": rule.enabled,
                    "id": rule.id,
                    "domain": rule.domain,
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qtypes": rule.qtypes,
                    "qclass": rule.qclass,
                    "qclasses": rule.qclasses,
                    "client": rule.client,
                    "client_cidr": rule.client_cidr,
                    "client_cidrs": rule.client_cidrs,
                }));
            }
            for rule in regex_rules.iter() {
                rules.push(serde_json::json!({
                    "kind": "regex",
                    "enabled": rule.enabled,
                    "id": rule.id,
                    "pattern": rule.pattern.as_str(),
                    "action": action_label(rule.action),
                    "priority": rule.priority,
                    "qtype": rule.qtype,
                    "qtypes": rule.qtypes,
                    "qclass": rule.qclass,
                    "qclasses": rule.qclasses,
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
            let profiles = self.profiles.snapshot();
            let groups = self.client_groups.snapshot();
            let visible = profiles
                .iter()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .map(|profile| {
                    let scope_count = if !profile.enabled {
                        0
                    } else if profile.groups.is_empty() {
                        1
                    } else {
                        profile
                            .groups
                            .iter()
                            .filter_map(|name| {
                                groups
                                    .iter()
                                    .find(|group| group.name.eq_ignore_ascii_case(name))
                            })
                            .map(|group| {
                                if group.enabled {
                                    group
                                        .client_addresses
                                        .len()
                                        .saturating_add(usize::from(!group.client_cidrs.is_empty()))
                                } else {
                                    0
                                }
                            })
                            .sum()
                    };
                    serde_json::json!({
                        "id": profile.id,
                        "name": profile.name,
                        "enabled": profile.enabled,
                        "domains": profile.domains,
                        "action": action_label(profile.action),
                        "groups": profile.groups,
                        "client_identity": profile.client_identity,
                        "client_cidrs": profile.client_cidrs,
                        "priority": profile.priority,
                        "qtype": profile.qtype,
                        "qclass": profile.qclass,
                        "qtypes": profile.qtypes,
                        "qclasses": profile.qclasses,
                        "expanded_rule_count": profile.domains.len().saturating_mul(scope_count),
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
            let groups = self.client_groups.snapshot();
            let visible = groups
                .iter()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .map(|group| {
                    serde_json::json!({
                        "name": group.name,
                        "enabled": group.enabled,
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
                            "enabled": identity.enabled,
                            "clients": identity.clients.len(),
                            "client_cidrs": identity.client_cidrs.len(),
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
            let rewrites = self.rewrite_configs.snapshot();
            let visible = rewrites
                .iter()
                .take(MAX_ADMIN_LOG_ENTRIES)
                .map(|rewrite| {
                    serde_json::json!({
                        "name": rewrite.name,
                        "ipv4": rewrite.ipv4,
                        "ipv6": rewrite.ipv6,
                        "cname": rewrite.cname,
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
        let mut networks = Vec::new();
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
            if (identity.clients.is_empty() && identity.client_cidrs.is_empty())
                || identity.clients.len() > 256
                || identity.client_cidrs.len() > policy::MAX_CLIENT_CIDRS
                || identity
                    .clients
                    .len()
                    .saturating_add(identity.client_cidrs.len())
                    > 256
            {
                return Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: identity.name.clone(),
                    reason: "each identity must contain bounded client addresses or CIDRs".into(),
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
            for value in &identity.client_cidrs {
                let network = policy::IpNetwork::parse(value).ok_or_else(|| {
                    policy::PolicyError::InvalidClientIdentityMap {
                        name: identity.name.clone(),
                        reason: format!("invalid client CIDR {value}"),
                    }
                })?;
                if networks
                    .iter()
                    .any(|(previous, _)| network.overlaps(*previous))
                {
                    return Err(policy::PolicyError::InvalidClientIdentityMap {
                        name: identity.name.clone(),
                        reason: "client CIDR overlaps another identity scope".into(),
                    });
                }
                if clients.iter().any(|(client, previous)| {
                    network.contains(*client) && previous != &identity.name
                }) {
                    return Err(policy::PolicyError::InvalidClientIdentityMap {
                        name: identity.name.clone(),
                        reason: "client CIDR overlaps an address assigned to another identity"
                            .into(),
                    });
                }
                networks.push((network, identity.name.clone()));
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
            let Some(_request_slot) = self.request_slots.try_acquire() else {
                self.observe_failure("admission_overflow");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            };
            let client = Policy::client_ip(request.context.peer.as_ref());
            if self.deny_client(client) {
                self.observe_failure("client_denylist");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, refused_answer()));
            }
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
                    if let Some(client) = client {
                        self.record_abuse_incident(client, "client_rate_overflow")
                            .await;
                    }
                }
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            }
            if !self.allow_global_abuse() {
                self.observe_failure("global_abuse_breaker_open");
                self.observe(Action::Reject);
                return Ok(DnsPipeReply::typed(200, server_failure_answer()));
            }
            if !self.allow_global_rate() {
                self.observe_failure("global_rate_overflow");
                self.record_global_abuse("global_rate_overflow");
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
                if let Some(country) = country_policy.country_for(client)
                    && country_policy.observed(client)
                {
                    self.observe_country(country);
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
                if !*self.filtering_enabled.snapshot() {
                    return Some(Action::Pass);
                }
                if !self.rules_configured.load(Ordering::Acquire) {
                    if self.matches(&query.name) {
                        Some(match *self.legacy_mode.snapshot() {
                            Mode::Ignore => Action::Ignore,
                            Mode::Nxdomain => Action::Nxdomain,
                            Mode::Honeypot => Action::Honeypot,
                        })
                    } else if self.upstream.is_some() {
                        Some(*self.default_action.snapshot())
                    } else {
                        None
                    }
                } else {
                    Some(
                        self.decision(&query, client)
                            .map_or(*self.default_action.snapshot(), |decision| decision.action),
                    )
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
            if matches!(action, Some(Action::Pass | Action::Observe) | None)
                && let Some(answer) = self.rewrites.read(|rewrites| rewrites.answer(&query))
            {
                self.observe(action.unwrap_or(Action::Pass));
                return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
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
                let Some(_slot) = slots.try_acquire() else {
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
                if !self.breaker.allow(self.breaker_now_nanos()) {
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
                            self.breaker.on_failure(self.breaker_now_nanos());
                            self.observe_failure(cause);
                            self.observe(forwarding_action);
                            return Ok(DnsPipeReply::typed(200, server_failure_answer()));
                        }
                        self.breaker.on_success();
                        let answer = response.answer;
                        if matches!(answer.rcode, 0 | 3) {
                            self.observe_cache_ttl(&answer);
                            self.cache_insert(key.clone(), answer.clone(), Instant::now());
                        }
                        answer
                    }
                    Err(error) => {
                        self.breaker.on_failure(self.breaker_now_nanos());
                        if let Some(answer) = self.cache_stale(&key) {
                            self.observe_cache("stale_hit");
                            self.observe(forwarding_action);
                            return Ok(DnsPipeReply::typed(200, self.cap_answer(&query, answer)));
                        }
                        self.observe_failure(Self::upstream_failure_cause(&error));
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
                    Some(Action::Honeypot) => Some(synthetic_honeypot_answer(
                        &query.name,
                        query.qtype,
                        &self.config.honeypot,
                    )),
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

    fn action_index(action: Action) -> usize {
        match action {
            Action::Pass => 0,
            Action::Ignore => 1,
            Action::Drop => 2,
            Action::Reject => 3,
            Action::Nxdomain => 4,
            Action::Sink => 5,
            Action::Honeypot => 6,
            Action::Forward => 7,
            Action::Observe => 8,
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

    /// Build the bounded DNS-only honeypot answer.
    ///
    /// This deliberately has no access to request payloads, client metadata,
    /// storage, or transport state. A future payload terminal must be a
    /// separate opt-in component and cannot be reached through this action.
    fn synthetic_honeypot_answer(name: &str, qtype: u16, config: &HoneypotConfig) -> DnsAnswer {
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
                enabled: true,
                id: 1,
                domain: "old.example".into(),
                action: Action::Drop,
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
                    enabled: true,
                    id: 2,
                    domain: "new.example".into(),
                    action: Action::Reject,
                    priority: 0,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
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
            let generation = policy.policy_generation.load(Ordering::Acquire);
            assert_eq!(
                policy.reload_rules(&[RuleConfig {
                    enabled: true,
                    id: 2,
                    domain: "new.example".into(),
                    action: Action::Reject,
                    priority: 0,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
                    client: None,
                    client_cidr: None,
                    client_cidrs: Vec::new(),
                    client_identity: None,
                }]),
                Ok(ReloadState::Unchanged)
            );
            assert_eq!(policy.policy_generation.load(Ordering::Acquire), generation);

            let invalid = [
                RuleConfig {
                    enabled: true,
                    id: 3,
                    domain: "failed.example".into(),
                    action: Action::Pass,
                    priority: 0,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
                    client: None,
                    client_cidr: None,
                    client_cidrs: Vec::new(),
                    client_identity: None,
                },
                RuleConfig {
                    enabled: true,
                    id: 3,
                    domain: "other.example".into(),
                    action: Action::Drop,
                    priority: 0,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
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
        fn blocklists_apply_safe_adguard_modifiers_order_independently() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-blocklist-modifiers-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(
                &path,
                "||cancel.example^$badfilter\n||important.example^$important\n||cancel.example^\n||scoped.example^$denyallow=allowed.scoped.example|safe.example\n",
            )
            .expect("write blocklist");
            let mut config = Config::default();
            config.policy.blocklists = vec![path.to_string_lossy().into_owned()];
            let policy = Policy::new(config).expect("valid modifier blocklist");
            let query = |name: &str| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(policy.evaluate(&query("cancel.example.")).unwrap().rcode, 0);
            assert_eq!(
                policy.evaluate(&query("important.example.")).unwrap().rcode,
                3
            );
            assert_eq!(policy.evaluate(&query("scoped.example.")).unwrap().rcode, 3);
            assert_eq!(
                policy
                    .evaluate(&query("allowed.scoped.example."))
                    .unwrap()
                    .rcode,
                0
            );
            assert_eq!(
                policy
                    .evaluate(&query("deep.allowed.scoped.example."))
                    .unwrap()
                    .rcode,
                0
            );
            assert_eq!(policy.evaluate(&query("safe.example.")).unwrap().rcode, 0);
            assert_eq!(
                policy
                    .evaluate(&query("other.scoped.example."))
                    .unwrap()
                    .rcode,
                3
            );
            std::fs::remove_file(path).expect("remove blocklist");

            let unsupported = std::env::temp_dir().join(format!(
                "blackhole-blocklist-unsupported-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&unsupported, "||example^$third-party\n").expect("write blocklist");
            let mut config = Config::default();
            config.policy.blocklists = vec![unsupported.to_string_lossy().into_owned()];
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidBlocklist { reason, .. })
                    if reason.contains("unsupported AdGuard filter modifier")
            ));
            std::fs::remove_file(unsupported).expect("remove blocklist");

            let malformed = std::env::temp_dir().join(format!(
                "blackhole-blocklist-denyallow-{}-{}",
                std::process::id(),
                1
            ));
            std::fs::write(&malformed, "||example^$denyallow=").expect("write blocklist");
            let mut config = Config::default();
            config.policy.blocklists = vec![malformed.to_string_lossy().into_owned()];
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidBlocklist { reason, .. })
                    if reason.contains("denyallow requires")
            ));
            std::fs::remove_file(malformed).expect("remove blocklist");
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
        fn hosted_blocklist_sources_use_proxima_http_and_remain_bounded() {
            use std::io::{Read, Write};

            let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind blocklist fixture");
            let address = server.local_addr().expect("blocklist fixture address");
            let thread = std::thread::spawn(move || {
                let (mut stream, _) = server.accept().expect("accept blocklist request");
                let mut request = [0_u8; 2048];
                let size = stream.read(&mut request).expect("read blocklist request");
                assert!(
                    std::str::from_utf8(&request[..size])
                        .expect("request is UTF-8")
                        .contains("GET /filters/list.txt HTTP/1.1")
                );
                let body = b"||remote.example^\n";
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .expect("write blocklist headers");
                stream.write_all(body).expect("write blocklist body");
            });
            let source = format!("http://{address}/filters/list.txt");
            let rules = load_blocklists(&[source]).expect("load hosted blocklist");
            assert!(rules.iter().any(|rule| rule.domain == "remote.example"));
            thread.join().expect("join blocklist fixture");
        }

        #[test]
        fn hosted_country_maps_use_proxima_http_and_reject_file_age_semantics() {
            use std::io::{Read, Write};

            let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind country map fixture");
            let address = server.local_addr().expect("country map fixture address");
            let thread = std::thread::spawn(move || {
                let (mut stream, _) = server.accept().expect("accept country map request");
                let mut request = [0_u8; 2048];
                let size = stream.read(&mut request).expect("read country map request");
                assert!(
                    std::str::from_utf8(&request[..size])
                        .expect("request is UTF-8")
                        .contains("GET /maps/country.txt HTTP/1.1")
                );
                let body = b"US 192.0.2.0/24 US-CA AS64500\n";
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .expect("write country map headers");
                stream.write_all(body).expect("write country map body");
            });
            let source = format!("http://{address}/maps/country.txt");
            let config = CountryPolicyConfig {
                map_path: Some(source),
                deny: vec!["US".into()],
                ..Default::default()
            };
            let loaded = load_country_policy(&config)
                .expect("load hosted country map")
                .expect("country policy");
            assert!(loaded.denied("192.0.2.1".parse().expect("fixture address")));
            thread.join().expect("join country map fixture");

            let mut age_bound = config;
            age_bound.max_age_secs = Some(60);
            assert!(matches!(
                load_country_policy(&age_bound),
                Err(policy::PolicyError::InvalidCountryMap { reason, .. })
                    if reason.contains("only supported for local map files")
            ));
        }

        #[test]
        fn hosted_sources_reject_non_http_schemes() {
            assert!(http_source_parts("ftp://example.test/map.txt").is_none());
            assert!(http_source_parts("file:///etc/hosts").is_none());
            assert!(http_source_parts("https://example.test/map.txt").is_some());
        }

        #[test]
        fn country_map_fingerprint_pin_is_case_insensitive_and_fail_closed() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-country-fingerprint-{}-{}.txt",
                std::process::id(),
                1
            ));
            let contents = "US 192.0.2.0/24 US-CA AS64500\n";
            std::fs::write(&path, contents).expect("write country map");
            let mut config = CountryPolicyConfig {
                map_path: Some(path.to_string_lossy().into_owned()),
                expected_sha256: Some(source_sha256(contents.as_bytes()).to_uppercase()),
                deny: vec!["US".into()],
                ..Default::default()
            };
            assert!(load_country_policy(&config).is_ok());

            config.expected_sha256 = Some("00".repeat(32));
            assert!(matches!(
                load_country_policy(&config),
                Err(policy::PolicyError::InvalidCountryMap { reason, .. })
                    if reason.contains("SHA-256 mismatch")
            ));
            config.expected_sha256 = Some("not-a-sha256".into());
            assert!(matches!(
                load_country_policy(&config),
                Err(policy::PolicyError::InvalidCountryMap { reason, .. })
                    if reason.contains("exactly 64 hexadecimal digits")
            ));
            config.map_path =
                Some("/blackhole/this-map-must-not-be-read-for-an-invalid-pin".into());
            assert!(matches!(
                load_country_policy(&config),
                Err(policy::PolicyError::InvalidCountryMap { reason, .. })
                    if reason.contains("exactly 64 hexadecimal digits")
            ));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn background_blocklist_reload_interval_is_bounded() {
            let config = Config {
                policy: PolicyConfig {
                    blocklist_reload_interval_secs: MAX_BLOCKLIST_RELOAD_INTERVAL_SECS + 1,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidBlocklist { path, .. }) if path == "<config>"
            ));
            let config = Config {
                country_policy: CountryPolicyConfig {
                    reload_interval_secs: MAX_BLOCKLIST_RELOAD_INTERVAL_SECS + 1,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidCountryMap { path, .. }) if path == "<config>"
            ));
            let config = Config {
                reload_interval_secs: MAX_BLOCKLIST_RELOAD_INTERVAL_SECS + 1,
                ..Default::default()
            };
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidConfigReload { .. })
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
                    enabled: true,
                    id: 901,
                    domain: "local.example".into(),
                    action: Action::Reject,
                    priority: 0,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
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
            assert_eq!(policy.reload_blocklists(), Ok(ReloadState::Unchanged));
            let same_paths = vec![path.to_string_lossy().into_owned()];
            assert_eq!(
                policy.replace_blocklist_sources(&same_paths),
                Ok(ReloadState::Unchanged)
            );
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
        fn disabled_blocklists_retain_sources_without_loading_rules() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-disabled-blocklist-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&path, "disabled.example\n").expect("write blocklist");
            let path = path.to_string_lossy().into_owned();
            let mut config = Config::default();
            config.policy.blocklists = vec![path.clone()];
            config.policy.disabled_blocklists = vec![path.clone()];
            let policy = Policy::new(config).expect("disabled blocklist configuration");
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_blocklists()).expect("blocklist status");
            assert_eq!(status["source_count"], 1);
            assert_eq!(status["disabled_source_count"], 1);
            assert_eq!(status["rule_count"], 0);
            assert_eq!(status["sources"][0]["enabled"], false);
            assert_eq!(
                status["sources"][0]["source_fingerprint"],
                format!("{:016x}", source_fingerprint(b"disabled.example\n"))
            );
            std::fs::remove_file(path).expect("remove blocklist");
        }

        #[test]
        fn configuration_reload_publishes_policy_and_rejects_startup_changes() {
            let policy = Policy::new(Config::default()).expect("default policy");
            let mut next = Config::default();
            next.privacy.query_recording_redaction = QueryRecordingRedaction::ActionOnly;
            next.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 77,
                domain: "reload.example".into(),
                action: Action::Reject,
                priority: 3,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            }];
            next.admission.max_queries_per_second = 7;
            assert_eq!(policy.reload_config(&next), Ok(ReloadState::Published));
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("status");
            assert_eq!(status["domain_rules"], 1);
            let admission: serde_json::Value =
                serde_json::from_str(&policy.admin_admission_status()).expect("admission");
            assert_eq!(admission["max_queries_per_second"], 7);
            let privacy: serde_json::Value =
                serde_json::from_str(&policy.admin_privacy_status()).expect("privacy");
            assert_eq!(privacy["query_recording_redaction"], "action_only");
            assert_eq!(policy.reload_config(&next), Ok(ReloadState::Unchanged));
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("status");
            assert_eq!(status["policy_generation"], 2);

            let mut invalid = next.clone();
            invalid.server.listen = "0.0.0.0:53".into();
            assert!(matches!(
                policy.reload_config(&invalid),
                Err(policy::PolicyError::InvalidConfigReload { .. })
            ));
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("status");
            assert_eq!(status["domain_rules"], 1);
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
                enabled: true,
                id: 70_001,
                domain: "explicit.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: None,
            };
            let profile = ServiceProfileConfig {
                id: 70_002,
                name: "generated".into(),
                enabled: true,
                domains: vec!["profile.example".into()],
                action: Action::Nxdomain,
                groups: Vec::new(),
                client_identity: None,
                priority: 0,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                id: 1,
                domain: "forward.example".into(),
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
                enabled: true,
                id: 1,
                domain: "ruled.example".into(),
                action: Action::Drop,
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
                enabled: true,
                id: 1,
                domain: "blocked.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: Some(1),
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                id: 1,
                domain: "client.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                id: 2,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                clients: vec!["192.0.2.10".parse().expect("client")],
                client_cidrs: Vec::new(),
            }];
            config.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 3,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
        fn disabled_client_identity_retains_mapping_without_classifying_clients() {
            let mut config = Config::default();
            config.policy.client_identities = vec![ClientIdentityConfig {
                name: "family-router".into(),
                enabled: false,
                clients: vec!["192.0.2.10".parse().expect("client")],
                client_cidrs: Vec::new(),
            }];
            config.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 31,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: Some("family-router".into()),
            }];
            let policy = Policy::new(config).expect("valid disabled identity map");
            let packet = [
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 8, b'i', b'd', b'e', b'n', b't', b'i', b't',
                b'y', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
            ];
            let view = QueryView::parse(&packet).expect("valid query");
            assert_eq!(
                policy.action_for_view_with_client(view, Some("192.0.2.10".parse().unwrap())),
                Action::Pass
            );
            let identities: serde_json::Value =
                serde_json::from_str(&policy.admin_client_identities()).expect("identity status");
            assert_eq!(identities["client_identities"][0]["enabled"], false);
        }

        #[test]
        fn service_profile_can_target_an_adapter_owned_identity() {
            let mut config = Config::default();
            config.policy.client_identities = vec![ClientIdentityConfig {
                name: "family-router".into(),
                enabled: true,
                clients: vec!["192.0.2.10".parse().expect("client")],
                client_cidrs: Vec::new(),
            }];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 6_000,
                name: "family-policy".into(),
                enabled: true,
                domains: vec!["identity.example".into()],
                action: Action::Reject,
                groups: Vec::new(),
                client_identity: Some("family-router".into()),
                priority: 3,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid identity profile");
            let query = proxima_dns::DnsQuery {
                id: 4,
                recursion_desired: true,
                name: "identity.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(
                policy
                    .decision(&query, Some("192.0.2.10".parse().unwrap()))
                    .expect("identity profile decision")
                    .action,
                Action::Reject
            );
            assert!(
                policy
                    .decision(&query, Some("192.0.2.11".parse().unwrap()))
                    .is_none()
            );
        }

        #[test]
        fn service_profile_combines_identity_and_network_scope() {
            let mut config = Config::default();
            config.policy.client_identities = vec![ClientIdentityConfig {
                name: "family-router".into(),
                enabled: true,
                clients: Vec::new(),
                client_cidrs: vec!["192.0.2.0/24".into()],
            }];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 6_001,
                name: "narrow-family-profile".into(),
                enabled: true,
                domains: vec!["identity.example".into()],
                action: Action::Reject,
                groups: Vec::new(),
                client_identity: Some("family-router".into()),
                priority: 0,
                client_cidrs: vec!["192.0.2.0/25".into()],
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid combined profile");
            let query = proxima_dns::DnsQuery {
                id: 5,
                recursion_desired: true,
                name: "identity.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(
                policy
                    .decision(&query, Some("192.0.2.53".parse().unwrap()))
                    .expect("combined scope decision")
                    .action,
                Action::Reject
            );
            assert!(
                policy
                    .decision(&query, Some("192.0.2.200".parse().unwrap()))
                    .is_none()
            );
        }

        #[test]
        fn client_identity_cidrs_match_and_overlaps_fail_closed() {
            let mut config = Config::default();
            config.policy.client_identities = vec![ClientIdentityConfig {
                name: "family-router".into(),
                enabled: true,
                clients: vec!["192.0.2.10".parse().expect("client")],
                client_cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
            }];
            config.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 5,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidr: None,
                client_cidrs: Vec::new(),
                client_identity: Some("family-router".into()),
            }];
            let policy = Policy::new(config).expect("valid identity CIDRs");
            let packet = [
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 8, b'i', b'd', b'e', b'n', b't', b'i', b't',
                b'y', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
            ];
            let view = QueryView::parse(&packet).expect("valid query");
            assert_eq!(
                policy.action_for_view_with_client(view, Some("192.0.2.11".parse().unwrap())),
                Action::Reject
            );
            assert_eq!(
                policy.action_for_view_with_client(view, Some("2001:db8::11".parse().unwrap())),
                Action::Reject
            );
            assert_eq!(
                policy.action_for_view_with_client(view, Some("198.51.100.11".parse().unwrap())),
                Action::Pass
            );

            let invalid = [
                ClientIdentityConfig {
                    name: "family-router".into(),
                    enabled: true,
                    clients: vec!["192.0.2.10".parse().expect("client")],
                    client_cidrs: vec!["192.0.2.0/24".into()],
                },
                ClientIdentityConfig {
                    name: "guest-router".into(),
                    enabled: true,
                    clients: Vec::new(),
                    client_cidrs: vec!["192.0.2.128/25".into()],
                },
            ];
            assert!(matches!(
                policy.reload_client_identities(&invalid),
                Err(policy::PolicyError::InvalidClientIdentityMap { .. })
            ));
        }

        #[test]
        fn client_identity_reload_publishes_a_complete_lock_free_snapshot() {
            let mut config = Config::default();
            config.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 4,
                domain: "identity.example".into(),
                action: Action::Reject,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                    enabled: true,
                    clients: vec![family],
                    client_cidrs: Vec::new(),
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
                    enabled: true,
                    clients: Vec::new(),
                    client_cidrs: Vec::new(),
                }]),
                Err(policy::PolicyError::InvalidClientIdentityMap {
                    name: "family-router".into(),
                    reason: "each identity must contain bounded client addresses or CIDRs".into(),
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
            let config = Config {
                country_policy: CountryPolicyConfig {
                    map_path: Some(path.to_string_lossy().into_owned()),
                    expected_sha256: None,
                    max_age_secs: None,
                    reload_interval_secs: 0,
                    deny: vec!["us".into()],
                    observe: Vec::new(),
                    deny_regions: vec!["us-ca".into()],
                    observe_regions: Vec::new(),
                    deny_asns: Vec::new(),
                    observe_asns: vec![64501],
                },
                ..Default::default()
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
            assert_eq!(policy.reload_country_policy(), Ok(ReloadState::Unchanged));
            let unchanged_status: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("status");
            let unchanged_country_status: serde_json::Value =
                serde_json::from_str(&policy.admin_country_status()).expect("country status");
            let initial_map = "US 192.0.2.0/24 US-CA AS64500\nCA 198.51.100.0/24 CA-ON 64501\n";
            assert_eq!(
                unchanged_country_status["source_sha256"],
                source_sha256(initial_map.as_bytes())
            );
            let unchanged_fingerprint = unchanged_country_status["source_fingerprint"]
                .as_str()
                .expect("country source fingerprint")
                .to_owned();
            let unchanged_generation = unchanged_status["policy_generation"]
                .as_u64()
                .expect("generation");
            std::fs::write(
                &path,
                "US 192.0.2.0/24 US-CA AS64500\nCA 198.51.100.0/24 CA-ON 64501\nGB 203.0.113.0/24 GB-LND 64502\n",
            )
            .expect("change country map");
            assert_eq!(
                policy.reload_country_policy_if_changed(),
                Ok(ReloadState::Published)
            );
            let changed_status: serde_json::Value =
                serde_json::from_str(&policy.admin_policy_status()).expect("status");
            assert_eq!(
                changed_status["policy_generation"].as_u64(),
                Some(unchanged_generation + 1)
            );
            let changed_country_status: serde_json::Value =
                serde_json::from_str(&policy.admin_country_status()).expect("country status");
            assert_ne!(
                changed_country_status["source_fingerprint"].as_str(),
                Some(unchanged_fingerprint.as_str())
            );
            let mut pinned_config = policy.country_policy_config.snapshot().as_ref().clone();
            pinned_config.expected_sha256 = Some("00".repeat(32));
            assert!(policy.replace_country_policy(&pinned_config).is_err());
            let pinned_failure_status: serde_json::Value =
                serde_json::from_str(&policy.admin_country_status()).expect("country status");
            assert_eq!(
                pinned_failure_status["source_fingerprint"],
                changed_country_status["source_fingerprint"]
            );
            std::fs::write(&path, "not-a-country-map\n").expect("corrupt country map");
            assert!(policy.reload_country_policy().is_err());
            let failed_reload_status: serde_json::Value =
                serde_json::from_str(&policy.admin_country_status()).expect("country status");
            assert_eq!(
                failed_reload_status["source_fingerprint"].as_str(),
                changed_country_status["source_fingerprint"].as_str()
            );
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
        fn country_map_change_detection_rejects_length_changes() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-country-stability-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&path, "US 192.0.2.0/24\n").expect("write initial map");
            let initial = std::fs::metadata(&path).expect("initial metadata");
            std::fs::write(&path, "US 192.0.2.0/24\nCA 198.51.100.0/24\n")
                .expect("write changed map");
            let final_metadata = std::fs::metadata(&path).expect("final metadata");
            assert!(country_map_changed(
                initial.len(),
                initial.modified().ok(),
                &final_metadata
            ));
            std::fs::remove_file(path).expect("remove country map");
        }

        #[test]
        fn country_map_rejects_cross_dimension_deny_observe_overlap() {
            let path = std::env::temp_dir().join(format!(
                "blackhole-country-conflict-{}-{}.txt",
                std::process::id(),
                1
            ));
            std::fs::write(&path, "US 192.0.2.0/24 US-CA AS64500\n").expect("write country map");
            let config = Config {
                country_policy: CountryPolicyConfig {
                    map_path: Some(path.to_string_lossy().into_owned()),
                    expected_sha256: None,
                    max_age_secs: None,
                    reload_interval_secs: 0,
                    deny: vec!["US".into()],
                    observe: Vec::new(),
                    deny_regions: Vec::new(),
                    observe_regions: vec!["US-CA".into()],
                    deny_asns: Vec::new(),
                    observe_asns: Vec::new(),
                },
                ..Default::default()
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
                enabled: true,
                id: 77,
                pattern: r"(^|\.)ads[0-9]*\.example$".into(),
                action: Action::Nxdomain,
                priority: 4,
                qtype: None,
                qtypes: vec![1, 28],
                qclass: None,
                qclasses: vec![1],
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
                3
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
        fn disabled_regex_rules_remain_configured_but_do_not_match() {
            let mut config = Config::default();
            config.policy.default_action = Action::Pass;
            config.policy.regex_rules = vec![RegexRuleConfig {
                enabled: false,
                id: 79,
                pattern: "^disabled\\.example$".into(),
                action: Action::Nxdomain,
                priority: 1,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidrs: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid disabled regex rule");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "disabled.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert_eq!(policy.evaluate(&query).expect("pass answer").rcode, 0);
            assert!(policy.admin_policy_bundle().contains("\"enabled\":false"));
        }

        #[test]
        fn regex_rules_honor_client_network_scopes() {
            let mut config = Config::default();
            config.policy.default_action = Action::Pass;
            config.policy.regex_rules = vec![RegexRuleConfig {
                enabled: true,
                id: 78,
                pattern: r"(^|\.)ads\.example$".into(),
                action: Action::Nxdomain,
                priority: 4,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                id: 1,
                domain: "ads.example".into(),
                action: Action::Pass,
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
            config.policy.regex_rules = vec![RegexRuleConfig {
                enabled: true,
                id: 2,
                pattern: r"(^|\.)ads\.example$".into(),
                action: Action::Nxdomain,
                priority: 100,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                id: 1,
                pattern: "[".into(),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidrs: Vec::new(),
            }];
            assert!(matches!(
                Policy::new(invalid),
                Err(policy::PolicyError::InvalidRegex { id: 1, .. })
            ));

            let mut invalid_scope = Config::default();
            invalid_scope.policy.regex_rules = vec![RegexRuleConfig {
                enabled: true,
                id: 3,
                pattern: "ads".into(),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
                client: None,
                client_cidrs: vec!["not-a-cidr".into()],
            }];
            assert!(matches!(
                Policy::new(invalid_scope),
                Err(policy::PolicyError::InvalidClientCidr { id: 3, .. })
            ));

            let mut oversized = Config::default();
            oversized.policy.regex_rules = vec![RegexRuleConfig {
                enabled: true,
                id: 2,
                pattern: "x".repeat(MAX_REGEX_PATTERN_BYTES + 1),
                action: Action::Drop,
                priority: 0,
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
        fn emitted_answers_clamp_ttl_to_the_configured_bound() {
            let mut config = Config::default();
            config.cache.max_ttl_secs = 60;
            let policy = Policy::new(config).expect("valid cache config");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "ttl.example".into(),
                qtype: 1,
                qclass: 1,
            };
            let answer = policy.cap_answer(
                &query,
                DnsAnswer::ok(vec![DnsAnswerRecord {
                    name: "ttl.example".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: u32::MAX,
                    rdata: vec![192, 0, 2, 1],
                }]),
            );
            assert_eq!(answer.records[0].ttl, 60);
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
            let breaker = ProximaCircuitBreaker::new(2, Duration::from_secs(30), 1);
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
                    enabled: true,
                    id: 1,
                    domain: domain.into(),
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
                    cname: None,
                    ttl: 30,
                },
                RewriteConfig {
                    name: "blocked.home.arpa".into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 2)),
                    ipv6: None,
                    cname: None,
                    ttl: 30,
                },
            ];
            config.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 1,
                domain: "blocked.home.arpa".into(),
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
        fn local_cname_rewrite_encodes_target_and_rejects_mixed_records() {
            let mut config = Config::default();
            config.policy.rewrites = vec![RewriteConfig {
                name: "alias.home.arpa".into(),
                ipv4: None,
                ipv6: None,
                cname: Some("router.home.arpa".into()),
                ttl: 45,
            }];
            let policy = Policy::new(config).expect("valid CNAME rewrite");
            let answer = policy
                .evaluate(&proxima_dns::DnsQuery {
                    id: 1,
                    recursion_desired: true,
                    name: "alias.home.arpa.".into(),
                    qtype: 5,
                    qclass: 1,
                })
                .expect("CNAME answer");
            assert_eq!(answer.records[0].rtype, 5);
            assert_eq!(answer.records[0].ttl, 45);
            assert_eq!(
                answer.records[0].rdata,
                [
                    vec![6],
                    b"router".to_vec(),
                    vec![4],
                    b"home".to_vec(),
                    vec![4],
                    b"arpa".to_vec(),
                    vec![0]
                ]
                .concat()
            );

            let mut mixed = Config::default();
            mixed.policy.rewrites = vec![RewriteConfig {
                name: "mixed.home.arpa".into(),
                ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                ipv6: None,
                cname: Some("router.home.arpa".into()),
                ttl: 30,
            }];
            assert!(matches!(
                Policy::new(mixed),
                Err(policy::PolicyError::InvalidRewrite { .. })
            ));
        }

        #[test]
        fn wildcard_rewrite_matches_one_label_and_exact_wins() {
            let mut config = Config::default();
            config.policy.rewrites = vec![
                RewriteConfig {
                    name: "*.home.arpa".into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    ipv6: None,
                    cname: None,
                    ttl: 30,
                },
                RewriteConfig {
                    name: "router.home.arpa".into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 20)),
                    ipv6: None,
                    cname: None,
                    ttl: 40,
                },
            ];
            let policy = Policy::new(config).expect("valid wildcard rewrites");
            let query = |name: &str| proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: name.into(),
                qtype: 1,
                qclass: 1,
            };
            let wildcard = policy
                .evaluate(&query("client.home.arpa."))
                .expect("wildcard answer");
            assert_eq!(wildcard.records[0].rdata, vec![192, 0, 2, 10]);
            assert_eq!(wildcard.records[0].name, "client.home.arpa.");
            let exact = policy
                .evaluate(&query("router.home.arpa."))
                .expect("exact answer");
            assert_eq!(exact.records[0].rdata, vec![192, 0, 2, 20]);
            assert!(
                policy
                    .evaluate(&query("deep.client.home.arpa."))
                    .is_some_and(|answer| answer.records.is_empty())
            );
        }

        #[test]
        fn local_rewrites_fail_closed_when_invalid_or_oversized() {
            let mut invalid = Config::default();
            invalid.policy.rewrites = vec![RewriteConfig {
                name: "not a dns name".into(),
                ipv4: None,
                ipv6: None,
                cname: None,
                ttl: 30,
            }];
            assert!(matches!(
                Policy::new(invalid),
                Err(policy::PolicyError::InvalidRewrite { .. })
            ));

            for name in ["*", "a.*.example", "*.has space.example"] {
                let mut invalid = Config::default();
                invalid.policy.rewrites = vec![RewriteConfig {
                    name: name.into(),
                    ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    ipv6: None,
                    cname: None,
                    ttl: 30,
                }];
                assert!(
                    matches!(
                        Policy::new(invalid),
                        Err(policy::PolicyError::InvalidRewrite { .. })
                    ),
                    "invalid wildcard rewrite name must fail closed: {name}"
                );
            }

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
                    cname: None,
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
                    cname: None,
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
                enabled: true,
                domains: vec!["ads.example".into(), "tracking.example".into()],
                action: Action::Nxdomain,
                groups: Vec::new(),
                client_identity: None,
                priority: 10,
                client_cidrs: vec!["192.0.2.0/24".into()],
                qtype: None,
                qtypes: vec![1, 28],
                qclass: None,
                qclasses: vec![1],
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
            assert_eq!(
                policy
                    .decision(&wrong_type, Some("192.0.2.53".parse().unwrap()))
                    .expect("second profile qtype")
                    .action,
                Action::Nxdomain
            );
            wrong_type.qtype = 15;
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
        fn disabled_service_profiles_are_retained_but_do_not_generate_rules() {
            let mut config = Config::default();
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 60_000,
                name: "paused-profile".into(),
                enabled: false,
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: Vec::new(),
                client_identity: None,
                priority: 10,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid disabled profile");
            let answer = policy
                .evaluate(&proxima_dns::DnsQuery {
                    id: 1,
                    recursion_desired: true,
                    name: "ads.example.".into(),
                    qtype: 1,
                    qclass: 1,
                })
                .expect("default pass answer");
            assert_eq!(answer.rcode, 0);
            let profiles: serde_json::Value =
                serde_json::from_str(&policy.admin_profiles()).expect("profile status");
            assert_eq!(profiles["profiles"][0]["enabled"], false);
            assert_eq!(profiles["profiles"][0]["expanded_rule_count"], 0);
        }

        #[test]
        fn client_groups_assign_one_profile_to_multiple_networks() {
            let mut config = Config::default();
            config.policy.client_groups = vec![
                ClientGroupConfig {
                    name: "family".into(),
                    enabled: true,
                    client_addresses: Vec::new(),
                    client_cidrs: vec!["192.0.2.0/24".into(), "2001:db8:1::/64".into()],
                },
                ClientGroupConfig {
                    name: "guest".into(),
                    enabled: true,
                    client_addresses: Vec::new(),
                    client_cidrs: vec!["198.51.100.0/24".into()],
                },
            ];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 50_000,
                name: "family-blocks".into(),
                enabled: true,
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["FAMILY".into(), "guest".into()],
                client_identity: None,
                priority: 10,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
        fn disabled_client_group_retains_metadata_but_expands_no_rules() {
            let mut config = Config::default();
            config.policy.client_groups = vec![ClientGroupConfig {
                name: "family".into(),
                enabled: false,
                client_addresses: Vec::new(),
                client_cidrs: vec!["192.0.2.0/24".into()],
            }];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 50_001,
                name: "family-blocks".into(),
                enabled: true,
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["family".into()],
                client_identity: None,
                priority: 10,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
            }];
            let policy = Policy::new(config).expect("valid disabled client group");
            let query = proxima_dns::DnsQuery {
                id: 7,
                recursion_desired: true,
                name: "ads.example.".into(),
                qtype: 1,
                qclass: 1,
            };
            assert!(
                policy
                    .decision(&query, Some("192.0.2.53".parse().unwrap()))
                    .is_none()
            );
            let groups: serde_json::Value =
                serde_json::from_str(&policy.admin_client_groups()).expect("group status");
            assert_eq!(groups["client_groups"][0]["enabled"], false);
            let profiles: serde_json::Value =
                serde_json::from_str(&policy.admin_profiles()).expect("profile status");
            assert_eq!(profiles["profiles"][0]["expanded_rule_count"], 0);
        }

        #[test]
        fn client_groups_match_exact_addresses_and_cidrs_without_broadening_exact_scope() {
            let mut config = Config::default();
            config.policy.client_groups = vec![ClientGroupConfig {
                name: "named-clients".into(),
                enabled: true,
                client_addresses: vec!["192.0.2.53".parse().unwrap()],
                client_cidrs: vec!["198.51.100.0/24".into()],
            }];
            config.policy.profiles = vec![ServiceProfileConfig {
                id: 51_000,
                name: "named-policy".into(),
                enabled: true,
                domains: vec!["ads.example".into()],
                action: Action::Reject,
                groups: vec!["named-clients".into()],
                client_identity: None,
                priority: 0,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
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
                enabled: true,
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["missing".into()],
                client_identity: None,
                priority: 0,
                client_cidrs: Vec::new(),
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
            }];
            assert!(matches!(
                Policy::new(unknown),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));

            let mut ambiguous = Config::default();
            ambiguous.policy.client_groups = vec![ClientGroupConfig {
                name: "family".into(),
                enabled: true,
                client_addresses: Vec::new(),
                client_cidrs: vec!["192.0.2.0/24".into()],
            }];
            ambiguous.policy.profiles = vec![ServiceProfileConfig {
                id: 2,
                name: "ads".into(),
                enabled: true,
                domains: vec!["ads.example".into()],
                action: Action::Nxdomain,
                groups: vec!["family".into()],
                client_identity: None,
                priority: 0,
                client_cidrs: vec!["198.51.100.0/24".into()],
                qtype: None,
                qtypes: Vec::new(),
                qclass: None,
                qclasses: Vec::new(),
            }];
            assert!(matches!(
                Policy::new(ambiguous),
                Err(policy::PolicyError::InvalidProfile { .. })
            ));

            let mut duplicate_address = Config::default();
            duplicate_address.policy.client_groups = vec![ClientGroupConfig {
                name: "family".into(),
                enabled: true,
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
                    enabled: true,
                    domains: vec!["ads.example".into()],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    client_identity: None,
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
                },
                ServiceProfileConfig {
                    id: 2,
                    name: "ADS".into(),
                    enabled: true,
                    domains: vec!["tracking.example".into()],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    client_identity: None,
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
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
                    enabled: true,
                    domains: vec!["first.example".into(); per_profile],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    client_identity: None,
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
                },
                ServiceProfileConfig {
                    id: 200_000,
                    name: "second".into(),
                    enabled: true,
                    domains: vec!["second.example".into(); per_profile],
                    action: Action::Nxdomain,
                    groups: Vec::new(),
                    client_identity: None,
                    priority: 0,
                    client_cidrs: Vec::new(),
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
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
            let replacement = AdmissionConfig {
                reject_any: true,
                max_queries_per_second: 7,
                ..Default::default()
            };
            assert_eq!(
                policy.reload_admission(&replacement),
                Ok(ReloadState::Published)
            );
            assert_eq!(
                policy.reload_admission(&replacement),
                Ok(ReloadState::Unchanged)
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
        fn configured_client_denylist_rejects_exact_addresses_and_networks() {
            let mut config = Config::default();
            config.admission.deny_client_cidrs =
                vec!["192.0.2.10/32".into(), "2001:db8:42::/48".into()];
            let policy = Policy::new(config).expect("valid denylist");
            let query = proxima_dns::DnsQuery {
                id: 1,
                recursion_desired: true,
                name: "example.com.".into(),
                qtype: 1,
                qclass: 1,
            };
            let request = |client| DnsPipeRequest {
                method: proxima_primitives::pipe::method::Method::from_wire(
                    bytes::Bytes::from_static(b"DNS"),
                ),
                path: bytes::Bytes::from_static(b"/"),
                query: proxima_primitives::pipe::header_list::HeaderList::new(),
                metadata: proxima_primitives::pipe::header_list::HeaderList::new(),
                payload: query.clone(),
                stream: None,
                context: RequestContext {
                    peer: Some(PeerInfo::Tcp(std::net::SocketAddr::new(client, 5353))),
                    ..RequestContext::default()
                },
            };
            let exact = "192.0.2.10".parse().unwrap();
            let network = "2001:db8:42::99".parse().unwrap();
            let allowed = "192.0.2.11".parse().unwrap();
            let mut wire = Vec::new();
            proxima_protocols::dns::encode::encode_query(
                1,
                true,
                proxima_protocols::dns::encode::EncodeQuestion {
                    name: "example.com.",
                    qtype: 1,
                    qclass: 1,
                },
                &mut wire,
            )
            .expect("encode query");
            assert_eq!(
                policy.action_for_view_with_client(QueryView::parse(&wire).unwrap(), Some(exact)),
                Action::Reject
            );
            for client in [exact, network] {
                let answer = futures::executor::block_on(policy.call(request(client)))
                    .expect("denylist returns a DNS response")
                    .payload;
                assert_eq!(answer.rcode, 5);
            }
            let answer = futures::executor::block_on(policy.call(request(allowed)))
                .expect("allowed client returns a DNS response")
                .payload;
            assert_eq!(answer.rcode, 0);
            let status: serde_json::Value =
                serde_json::from_str(&policy.admin_admission_status()).expect("status");
            assert_eq!(status["deny_client_cidr_count"], 2);
        }

        #[test]
        fn denylist_reload_rejects_invalid_cidrs_without_publication() {
            let policy = Policy::new(Config::default()).expect("valid policy");
            let replacement = AdmissionConfig {
                deny_client_cidrs: vec!["not-a-cidr".into()],
                ..Default::default()
            };
            assert!(matches!(
                policy.reload_admission(&replacement),
                Err(policy::PolicyError::InvalidAdmission { .. })
            ));
            assert_eq!(
                policy.admission_config().deny_client_cidrs,
                Vec::<String>::new()
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
        fn global_abuse_breaker_sheds_all_callers_after_threshold() {
            let mut config = Config::default();
            config.admission.ddos.max_global_abuse_violations = 2;
            config.admission.ddos.global_abuse_window_secs = 60;
            config.admission.ddos.global_abuse_cooldown_secs = 60;
            let policy = Policy::new(config).expect("valid global abuse config");
            assert!(policy.allow_global_abuse());
            assert!(!policy.record_global_abuse("global_rate_overflow"));
            assert!(policy.allow_global_abuse());
            assert!(policy.record_global_abuse("global_response_budget"));
            assert!(!policy.allow_global_abuse());
            assert!(!policy.allow_global_abuse());
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
        fn persisted_abuse_restores_active_client_and_network_until_expiry() {
            let mut config = Config::default();
            config.admission.client_abuse_cooldown_secs = 60;
            config.admission.network_abuse_cooldown_secs = 60;
            let policy = Policy::new(config).expect("valid abuse config");
            let client = "192.0.2.10".parse().expect("client address");
            let same_network = "192.0.2.11".parse().expect("same network address");
            let other_network = "192.0.3.10".parse().expect("other network address");

            assert!(policy.restore_abuse_incident(client, 61_000, 1_000));
            assert!(!policy.allow_client_abuse(Some(client)));
            assert!(!policy.allow_client_abuse(Some(same_network)));
            assert!(policy.allow_client_abuse(Some(other_network)));
            assert!(!policy.restore_abuse_incident(client, 1_000, 1_000));
        }

        #[test]
        fn abuse_incident_revocation_reopens_exact_client_and_network() {
            let mut config = Config::default();
            config.admission.client_abuse_cooldown_secs = 60;
            config.admission.network_abuse_cooldown_secs = 60;
            let policy = Policy::new(config).expect("valid abuse config");
            let client = "192.0.2.10".parse().expect("client address");
            assert!(policy.restore_abuse_incident(client, 61_000, 1_000));
            assert!(!policy.allow_client_abuse(Some(client)));
            policy.revoke_abuse_incident(client);
            assert!(policy.allow_client_abuse(Some(client)));
            assert!(policy.allow_client_abuse(Some("192.0.2.11".parse().unwrap())));
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
                enabled: true,
                id: 1,
                domain: "honeypot.example".into(),
                action: Action::Honeypot,
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
                enabled: true,
                id: 1,
                domain: "honeypot.example".into(),
                action: Action::Honeypot,
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
        fn response_amplification_boundary_is_reported_from_wire_sizes() {
            let mut config = Config::default();
            config.admission.max_response_amplification = 2;
            let policy = Policy::new(config).expect("valid policy");
            assert!(!policy.response_amplification_capped(50, 99));
            assert!(policy.response_amplification_capped(50, 100));
            assert!(!policy.response_amplification_capped(0, 100));
        }

        #[test]
        fn admission_caps_synthetic_answers() {
            let mut config = Config::default();
            config.admission.max_response_records = 1;
            config.policy.rules = vec![RuleConfig {
                enabled: true,
                id: 1,
                domain: "sink.example".into(),
                action: Action::Honeypot,
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
        fn honeypot_is_dns_only_and_has_no_payload_terminal() {
            let config = HoneypotConfig::default();
            for qtype in [1, 28, 5, 16, 255] {
                let answer = synthetic_honeypot_answer("sink.example.", qtype, &config);
                assert!(answer.records.len() <= 1, "qtype={qtype}");
                assert!(answer.records.iter().all(|record| {
                    (record.rtype == 1 && record.rdata.len() == 4)
                        || (record.rtype == 28 && record.rdata.len() == 16)
                }));
            }
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
        fn upstream_failure_cause_preserves_typed_proxima_errors() {
            assert_eq!(
                Policy::upstream_failure_cause(&DnsClientError::Timeout(250)),
                "upstream_timeout"
            );
            assert_eq!(
                Policy::upstream_failure_cause(&DnsClientError::Wire("bad dns".into())),
                "upstream_wire_error"
            );
            assert_eq!(
                Policy::upstream_failure_cause(&DnsClientError::IdMismatch {
                    expected: 7,
                    reply: 8,
                }),
                "upstream_id_mismatch"
            );
            assert_eq!(
                Policy::upstream_failure_cause(&DnsClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "deadline",
                ))),
                "upstream_io_timeout"
            );
            assert_eq!(
                Policy::upstream_failure_cause(&DnsClientError::Config("bad transport".into())),
                "upstream_config_error"
            );
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
                    enabled: true,
                    id: 1,
                    domain: "blocked.example".into(),
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
                }])
                .expect("rules reload");
            policy
                .reload_regex_rules(&[RegexRuleConfig {
                    enabled: true,
                    id: 2,
                    pattern: "blocked".into(),
                    action: Action::Drop,
                    priority: 0,
                    qtype: None,
                    qtypes: Vec::new(),
                    qclass: None,
                    qclasses: Vec::new(),
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
        fn action_only_recording_redaction_reaches_both_log_sinks() {
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
            let mut config = Config::default();
            config.privacy.query_log_enabled = true;
            config.privacy.query_recording_redaction = QueryRecordingRedaction::ActionOnly;
            let policy = Policy::new(config)
                .expect("valid policy")
                .with_recording_sink(Arc::new(Collector(Arc::clone(&events))));
            let query = proxima_dns::DnsQuery {
                id: 10,
                recursion_desired: true,
                name: "secret.example.".into(),
                qtype: 28,
                qclass: 1,
            };

            futures::executor::block_on(policy.record_decision(Action::Reject, &query));

            let events = events.lock().expect("recording lock");
            let proxima::ProtocolEvent::Custom { payload, .. } = &events[0].event else {
                panic!("expected custom decision event");
            };
            assert_eq!(payload["action"], "reject");
            assert!(payload.get("qtype").is_none());
            assert!(payload.get("qclass").is_none());
            assert_eq!(policy.query_log().expect("query log").snapshot().len(), 1);
            assert!(policy.admin_privacy_status().contains("action_only"));
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
        fn aggregate_decision_statistics_preserve_actions_and_reset_atomically() {
            let policy = Policy::new(Config::default()).expect("valid policy");
            for action in [
                Action::Pass,
                Action::Ignore,
                Action::Drop,
                Action::Reject,
                Action::Nxdomain,
                Action::Sink,
                Action::Honeypot,
                Action::Forward,
                Action::Observe,
            ] {
                policy.observe(action);
            }
            let stats: serde_json::Value =
                serde_json::from_str(&policy.admin_stats()).expect("stats JSON");
            assert_eq!(stats["total"], 9);
            for action in [
                "pass", "ignore", "drop", "reject", "nxdomain", "sink", "honeypot", "forward",
                "observe",
            ] {
                assert_eq!(stats["actions"][action], 1);
            }
            assert_eq!(policy.clear_stats(), 9);
            let cleared: serde_json::Value =
                serde_json::from_str(&policy.admin_stats()).expect("cleared stats JSON");
            assert_eq!(cleared["total"], 0);
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
            let mut config = Config::default();
            config.admission.ddos.persist_incidents = true;
            config.privacy.query_recording_path = Some(path.to_string_lossy().into_owned());
            let policy = Policy::new(config)
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
                policy
                    .record_abuse_incident(
                        "192.0.2.10".parse().expect("incident client"),
                        "client_rate_overflow",
                    )
                    .await;
                sink.flush().await.expect("flush recording sink");
            });

            let contents = std::fs::read_to_string(&path).expect("read JSONL recording");
            assert!(contents.contains("blackhole.dns_decision"));
            assert!(contents.contains("blackhole.ddos_incident"));
            assert!(contents.contains("client_rate_overflow"));
            assert!(contents.contains("192.0.2.10"));
            assert!(contents.contains("nxdomain"));
            assert!(!contents.contains("secret.example"));
            assert!(std::fs::metadata(&path).expect("recording metadata").len() <= 4_096);
            std::fs::remove_dir_all(directory).expect("remove recording directory");
        }

        #[test]
        fn abuse_incident_review_redacts_client_addresses() {
            let mut config = Config::default();
            config.privacy.query_log_enabled = true;
            config.privacy.query_log_max_entries = 4;
            config.privacy.query_log_retention_secs = 60;
            let policy = Policy::new(config).expect("valid query log config");
            futures::executor::block_on(policy.record_abuse_incident(
                "192.0.2.10".parse().expect("client address"),
                "client_rate_overflow",
            ));
            let review: serde_json::Value =
                serde_json::from_str(&policy.admin_abuse_incidents()).expect("review JSON");
            assert_eq!(review["enabled"], true);
            assert_eq!(review["incidents"].as_array().unwrap().len(), 1);
            assert_eq!(review["incidents"][0]["active"], true);
            assert_eq!(review["client_addresses"], "redacted");
            assert!(!policy.admin_abuse_incidents().contains("192.0.2.10"));
        }

        #[test]
        fn durable_abuse_export_uses_proxima_jsonl_and_keeps_only_bounded_events() {
            let directory = std::env::temp_dir().join(format!(
                "blackhole-abuse-export-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock")
                    .as_nanos()
            ));
            std::fs::create_dir(&directory).expect("export directory");
            let path = directory.join("incidents.jsonl");
            let event = proxima::RecordingEvent {
                id: proxima::InteractionId::new(),
                ts_ms: 42,
                parent: None,
                event: proxima::ProtocolEvent::Custom {
                    kind: "blackhole.ddos_incident".into(),
                    payload: serde_json::json!({
                        "client": "192.0.2.10",
                        "cause": "client_rate_overflow",
                        "expires_at_ms": 60_000,
                    }),
                },
            };
            let mut line = proxima::recording::jsonl::encode_jsonl_line(event)
                .expect("encode durable incident");
            line.push(b'\n');
            std::fs::write(&path, line).expect("write durable incident");
            let mut config = Config::default();
            config.privacy.query_recording_path = Some(path.to_string_lossy().into_owned());
            let policy = Policy::new(config).expect("valid export config");
            let export = futures::executor::block_on(policy.admin_abuse_incident_export())
                .expect("export durable incident");
            let export: serde_json::Value = serde_json::from_str(&export).expect("export JSON");
            assert_eq!(export["enabled"], true);
            assert_eq!(export["events"].as_array().unwrap().len(), 1);
            assert_eq!(export["events"][0]["payload"]["client"], "192.0.2.10");
            assert_eq!(
                export["client_addresses"],
                "included_for_authenticated_operator_recovery"
            );
            std::fs::remove_dir_all(directory).expect("remove export directory");
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

        #[test]
        fn ddos_incident_persistence_requires_the_bounded_recording_sink() {
            let mut config = Config::default();
            config.admission.ddos.persist_incidents = true;
            assert!(matches!(
                Policy::new(config),
                Err(policy::PolicyError::InvalidAdmission { reason })
                    if reason.contains("query_recording_path")
            ));
        }
    }
}

#[cfg(feature = "std")]
pub use runtime::*;
