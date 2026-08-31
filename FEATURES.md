# Blackhole features

This is the current, deliberately small prototype surface. It records what is
implemented today; planned capabilities belong in [ROADMAP.md](ROADMAP.md).

## Implemented

- DNS service over UDP and TCP through Proxima, sharing one configured bind.
- Loopback-only default listener at `127.0.0.1:5353`.
- TOML configuration with bounded file size and fail-fast parsing.
- Legacy domain matching with `ignore`, `nxdomain`, and `honeypot` modes.
- Rule-table matching with explicit actions, stable rule identity, priority,
  exact/deep-wildcard specificity, exact-client and CIDR network scopes, qtype,
  and qclass filters.
- Rule-table authority when rules are configured; legacy settings do not
  silently take over.
- Bounded Pi-hole-compatible blocklist ingestion from hosts/domain files with
  comments, normalization, deduplication, and fail-closed startup reloads.
- Synthetic IPv4/IPv6 honeypot answers with configurable TTL.
- Explicit fail-closed behavior when a forward rule has no upstream attached.
- Configured UDP upstream forwarding through Proxima's `DnsClientUpstream`,
  with timeout/retry settings and a bounded outstanding-query limit.
- Bounded positive and negative response caching with a bounded stale-serving
  window for upstream outages.
- A bounded upstream circuit breaker with configurable failure threshold and
  cooldown; open circuits fail closed unless a stale cached answer is usable.
- Bounded admission controls that reject malformed/overlong owned queries,
  optionally reject `ANY`, cap emitted answer records and approximate wire
  size, cap response amplification relative to the query, and shed excess
  in-flight work with bounded global and per-client limits.
- Upstream rebinding protection for private, local, link-local, unspecified,
  multicast, and IPv6 unique-local A/AAAA answers, with fail-closed SERVFAIL.
- A committed libFuzzer target for the borrowed DNS query boundary, with a
  privacy-safe corpus location for minimized wire samples.
- Proxima-native action counters, failure-cause counters, and request-latency
  histograms that preserve the complete action identity.
- Atomic in-process rule-table reloads over Proxima's immutable `Live` snapshot
  primitive, with failed reloads retaining the last valid generation.
- A tested policy/FSM/snapshot core that does not require privileged capture
  APIs.
- Shared capture-controller orchestration with exact ownership journaling,
  rollback on journal failure, corruption-safe restart recovery, and cleanup
  refusal for ownership mismatches.
- Explicit opt-in capture configuration wires the shared controller to the
  native platform backend, recovers ownership before install, and cleans up
  after orderly shutdown.
- Linux builds expose an explicit `nft` command capability; macOS builds
  expose the corresponding `pfctl` capability without including either
  privileged backend in the policy core.
- Proxima consumed from its GitHub source, with Prime as the default runtime
  path and Tokio compatibility supplied by the dependency configuration.
