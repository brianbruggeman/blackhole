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
- Unsupported IDNA/Unicode rule names are rejected explicitly; the resolver
  currently accepts ASCII DNS names only.
- Bounded regular-expression policy rules with startup compilation limits,
  qtype/qclass/exact-client/CIDR-client filters, deterministic priority, and
  explicit domain-rule precedence.
- Rule-table authority when rules are configured; legacy settings do not
  silently take over.
- Client-scoped rules can match one exact address or a bounded list of IPv4
  and IPv6 CIDRs; the most specific matching network wins.
- Bounded Pi-hole/AdGuard-compatible blocklist ingestion from hosts/domain files
  with comments, normalization, deduplication, apex-and-subdomain blocking,
  `@@` exceptions, and fail-closed startup reloads.
- Bounded local A/AAAA rewrites with explicit policy precedence and fail-closed
  validation for malformed, duplicate, or oversized configuration.
- Named service-blocking profiles compile into the authoritative rule table,
  with bounded domains, optional IPv4/IPv6 client-network scopes, stable
  generated IDs, independent qtype/qclass filters, and duplicate-name
  rejection.
- Named client groups assign bounded IPv4/IPv6 CIDR sets to service profiles;
  one profile may target multiple groups, with unknown or ambiguous scopes
  rejected before publication.
- Synthetic IPv4/IPv6 honeypot answers with configurable TTL.
- Configured upstream pass-through for `pass` and `observe`, after local
  rewrites; explicit `forward` remains a distinct fail-closed action.
- Explicit fail-closed behavior when a forward rule has no upstream attached.
- Configured upstream forwarding through Proxima's `DnsClientUpstream`, using
  bounded UDP exchanges and DNS-over-TCP fallback when UDP sets `TC`; timeout
  is bounded to 60 seconds, at most eight attempts per exchange, and the
  outstanding-query limit is bounded.
- Configurable Proxima upstream transport: `udp` (with TCP fallback), `tcp`,
  `tls` for DNS-over-TLS, or `doh` for DNS-over-HTTPS stream-only exchanges;
  encrypted modes require an explicit server name and use Proxima's GitHub
  HTTP/TLS pipe adapters. An opt-in `doq` feature uses Proxima's GitHub QUIC
  stream adapter with the DoQ ALPN and a bounded reusable connection pool;
  stale connections are replaced; the default Prime build remains QUIC-free.
- Bounded positive and negative response caching with a configured maximum
  protocol TTL, a bounded stale-serving window for upstream outages, plus
  Proxima-native hit/miss/stale/eviction counters and effective positive/
  negative TTL histograms.
- A bounded upstream circuit breaker with configurable failure threshold and
  cooldown; open circuits fail closed unless a stale cached answer is usable.
- Bounded admission controls that reject malformed/overlong owned queries,
  response/reserved DNS query flags, optionally reject `ANY`, cap emitted answer records and approximate wire
  size, cap response amplification relative to the query, and shed excess
  in-flight work with bounded global and per-client limits.
- A bounded per-client abuse breaker that temporarily sheds clients which
  repeatedly exceed the configured query-rate or encoded-response-byte budget,
  without affecting unidentified callers.
- A bounded network abuse breaker that temporarily sheds the configured IPv4
  or IPv6 client network after repeated aggregate violations, without affecting
  unrelated networks or unidentified callers.
- A bounded global queries-per-second ceiling that sheds excess traffic,
  including unidentified callers, as a DDoS stopgap.
- A bounded per-client encoded-response-byte budget that sheds identified
  clients after their configured one-second egress budget is exhausted,
  without applying a shared identity to unidentified callers.
- Upstream rebinding protection for private, local, link-local, unspecified,
  multicast, and IPv6 unique-local A/AAAA answers, with fail-closed SERVFAIL.
- Optional country deny and observe-only (“snitch”) policy from a bounded,
  operator-supplied country-to-CIDR map; longest-prefix entries win and the
  classification is not treated as exact identity. An optional freshness bound
  fails closed when the map file is stale or its timestamp is unavailable.
- A committed libFuzzer target for the borrowed DNS query boundary, with a
  privacy-safe corpus location for minimized wire samples.
- Proxima-native action counters, failure-cause counters, and request-latency
  histograms that preserve the complete action identity.
- An optional Proxima recording-sink hook emits only bounded decision metadata
  (`action`, `qtype`, and `qclass`); DNS names, client identity, credentials,
  and wire payloads are excluded from recording events. The convenience API
  wraps a supplied backend in Proxima's bounded queue.
- Atomic in-process rule-table reloads over Proxima's immutable `Live` snapshot
  primitive, with failed reloads retaining the last valid generation and
  successful policy reloads invalidating cached forwarding answers.
- Atomic operator-triggered blocklist reloads rebuild the explicit rules plus
  current bounded files and retain the last good snapshot on failure.
- Optional Proxima HTTP admin control plane with bearer authentication, a
  read-only health, bounded rule metadata, and non-sensitive status endpoints, authenticated blocklist
  and country-map reloads, bounded complete domain and regex rule-table
  reloads from JSON, and an atomic bounded domain-rule append operation.
- The authenticated control plane can also remove domain rules by stable ID;
  unknown IDs fail without changing the published snapshot.
- The authenticated admin control plane includes a bounded status UI for
  status, rule metadata, and privacy-log inspection/clearing; it contains no
  packet payloads and uses the existing Proxima HTTP pipe.
- Authenticated bounded `GET /profiles` and `GET /client-groups` routes expose
  configured service-profile and client-network metadata without exposing
  runtime client identity.
- Authenticated bounded `POST /reload/profiles` atomically replaces service
  profiles and client groups, preserves explicit domain rules, and rejects
  invalid expansions without publishing them.
- Authenticated bounded `POST /reload/policy-bundle` validates and replaces
  domain, regex, profile, client-group, local-rewrite, and country-policy
  tables as one snapshot while retaining the loaded blocklist snapshot.
- Authenticated cache deletion clears all bounded positive and negative DNS
  answers and reports only the number of entries removed.
- Optional bounded privacy-safe query-decision logs use Proxima's recording
  event shape, retain only timestamp/action/qtype/qclass metadata, enforce
  entry and age limits, cap the authenticated inspection projection, and
  support authenticated deletion; logging is disabled by default.
- A tested policy/FSM/snapshot core that does not require privileged capture
  APIs.
- Shared capture-controller orchestration with exact ownership journaling,
  rollback on journal failure, corruption-safe restart recovery, and cleanup
  refusal for ownership mismatches.
- Explicit opt-in capture configuration wires the shared controller to the
  native platform backend, recovers ownership before install, and cleans up
  after orderly shutdown.
- A hardened Linux systemd deployment unit runs the resolver as a dedicated
  service user with bounded state access and only low-port bind capability;
  firewall capture remains a separate opt-in operation.
- Linux builds expose an explicit `nft` command capability; macOS builds
  expose the corresponding `pfctl` capability without including either
  privileged backend in the policy core.
- Proxima consumed from its GitHub source, with Prime as the default runtime
  path and an opt-in `tokio-compat` feature that compiles the same core with
  Proxima's Tokio capability available.
