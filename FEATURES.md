# Blackhole features

This is the current product surface. It records what is implemented and
verified today; planned capabilities belong in [ROADMAP.md](ROADMAP.md).

## Implemented

- DNS service over UDP and TCP through Proxima, sharing one configured bind.
- Optional bounded DHCPv4 service with DISCOVER/OFFER and REQUEST/ACK handling,
  deterministic lease allocation, broadcast delivery, and loopback-tested UDP
  adapter shutdown.
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
- Atomic operator control to temporarily disable all filtering while retaining
  the configured policy for a later re-enable; rewrites and forwarding remain
  available during the disabled interval.
- Client-scoped rules can match one exact address or a bounded list of IPv4
  and IPv6 CIDRs; the most specific matching network wins.
- Bounded client identity labels can be mapped from exact IPv4/IPv6 addresses
  or non-overlapping IPv4/IPv6 CIDR scopes to policy rules without retaining
  client identity in telemetry, logs, or payload records; exact addresses win
  over CIDR matches. Identity mappings can be disabled without deleting their
  configured address and network scope.
- Bounded Pi-hole/AdGuard-compatible blocklist ingestion from hosts/domain files
  with comments, normalization, deduplication, apex-and-subdomain blocking,
  `@@` exceptions, `$important` priority, order-independent `$badfilter`
  cancellation, bounded `$denyallow` exceptions, fail-closed startup reloads,
  and retained per-source enable/disable state; unknown or malformed filter
  modifiers are rejected.
- Bounded local A/AAAA/CNAME rewrites with exact and one-label wildcard
  matching, explicit policy precedence, and fail-closed validation for
  malformed, duplicate, mixed-record, or oversized configuration.
- Named service-blocking profiles compile into the authoritative rule table,
  with bounded domains, optional IPv4/IPv6 client-network scopes, stable
  generated IDs, independent qtype/qclass filters, optional adapter-owned
  client-identity targeting, and duplicate-name rejection. Identity and
  network scopes compose as an AND constraint; ambiguous group/direct-CIDR
  scopes fail closed. Profiles can be disabled without deleting their
  configuration, and disabled profiles generate no rules.
- Named client groups assign bounded exact IPv4/IPv6 client addresses and CIDR
  sets to service profiles; one profile may target multiple groups, with
  duplicate, unknown, or ambiguous scopes rejected before publication. Groups
  can be disabled without deleting their configured address and network scope.
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
- A bounded upstream circuit breaker using Proxima's `CircuitBreaker` state
  machine, with configurable failure threshold and cooldown; open circuits
  fail closed unless a stale cached answer is usable.
- Bounded admission controls that reject malformed/overlong owned queries,
  response/reserved DNS query flags, optionally reject `ANY`, cap emitted answer records and approximate wire
  size, reject zero-valued question type/class fields, cap response amplification relative to the query, and shed excess
  in-flight work with bounded global and per-client limits.
- A bounded per-client abuse breaker that temporarily sheds clients which
  repeatedly exceed the configured query-rate or encoded-response-byte budget,
  without affecting unidentified callers.
- Identified malformed-query failures feed the same bounded client/network
  abuse breaker using stable parser causes, without retaining malformed wire
  payloads.
- A bounded network abuse breaker that temporarily sheds the configured IPv4
  or IPv6 client network after repeated aggregate violations, without affecting
  unrelated networks or unidentified callers.
- A bounded global queries-per-second ceiling that sheds excess traffic,
  including unidentified callers, as a DDoS stopgap.
- An operator-configured bounded IPv4/IPv6 CIDR denylist, including exact
  addresses via `/32` or `/128`, that rejects clients before policy matching
  and is atomically reloadable without publishing invalid entries.
- Authenticated bounded denylist export, operator-managed additions, and
  revocations through the same atomic lock-free admission snapshot; updates
  are idempotent, bounded, and fail closed on invalid CIDRs.
- An opt-in lock-free global abuse breaker opens after repeated aggregate
  rate or response-budget violations and temporarily sheds all callers; zero
  disables it, and its window/cooldown are bounded and operator-configurable.
- Automatic temporary IP and network blacklisting after repeated per-client
  rate or encoded-response-budget violations; entries use bounded lock-free
  keyed state, expire after a configured cooldown, and fail closed while
  open. This is adaptive mitigation, not a permanent reputation database.
- Optional conflaguration-backed DDoS incident persistence records the
  threshold crossing through the existing bounded Proxima JSONL sink so the
  incident survives process death; the event includes a bounded expiry, and
  startup restores only active incidents to both the exact-client and
  configured-network breakers. DNS names and wire payloads remain absent.
- When incident persistence is enabled, authenticated operator denylist
  additions and revocations are appended to that same bounded Proxima JSONL
  sink and replayed in order during startup; a failed durable append rolls the
  live admission snapshot back.
- A bounded per-client encoded-response-byte budget that sheds identified
  clients after their configured one-second egress budget is exhausted,
  without applying a shared identity to unidentified callers.
- A bounded per-network encoded-response-byte budget that applies the same
  egress ceiling across each configured IPv4/IPv6 prefix.
- A bounded aggregate encoded-response-byte budget that sheds total DNS
  egress, including responses with no identified client, before transport
  write.
- Responses that reach the configured amplification ceiling emit a bounded
  failure cause and count toward the existing per-client and per-network
  temporary abuse breakers; repeated capped responses can therefore trigger
  the same expiring blacklist and optional durable incident path.
- Upstream rebinding protection for private, local, link-local, unspecified,
  multicast, and IPv6 unique-local A/AAAA answers, with fail-closed SERVFAIL.
- Optional country deny and observe-only (“snitch”) policy from a bounded,
  operator-supplied country/CIDR map with optional region and ASN labels;
  longest-prefix entries win and the classification is not treated as exact
  identity. Region and ASN selectors are explicit map-label policy, not a
  bundled or inferred GeoIP identity. An optional freshness bound fails closed
  when the map file is stale or its timestamp is unavailable.
- An optional bounded background country-map reload uses Proxima's interval
  and lifecycle primitives, publishes only changed valid maps, and preserves
  the last good snapshot after a failed refresh.
- Authenticated bounded `POST /reload/country/replace` atomically replaces the
  country/CIDR map configuration and selectors, retaining the previous live
  map and selectors when validation or loading fails.
- Country-policy request reads use Proxima's lock-free `Live` snapshot;
  validated reloads replace one complete immutable generation.
- A committed libFuzzer target for the borrowed DNS query boundary, with a
  privacy-safe corpus location for minimized wire samples.
- Proxima-native action counters, bounded failure-cause counters, and
  request-latency histograms that preserve the complete action identity;
  listener parser failures retain stable causes for wire-short, malformed-wire,
  response, flags, unsupported-name, question-count, and oversized inputs.
- Authenticated privacy-safe aggregate decision statistics at `GET /stats`,
  retaining counts for every action identity without DNS names, client
  metadata, or packet payloads; the same projection is shown in the admin UI.
- An optional Proxima recording-sink hook emits only bounded decision metadata
  (`action`, `qtype`, and `qclass`); DNS names, client identity, credentials,
  and wire payloads are excluded from recording events. The convenience API
  wraps a supplied backend in Proxima's bounded queue, and the executable can
  append the same events to an operator-selected Proxima JSONL destination
  with a hard encoded-byte ceiling.
- Bounded `--replay recording.jsonl` tooling consumes the existing Proxima
  JSONL source and deterministically reports event, full-action, and DDoS
  incident counts; it accepts only Blackhole metadata events, caps the input
  at 64 MiB, and never reconstructs or retains DNS names or wire payloads.
- Explicit local `--delete-recording recording.jsonl` management removes only
  the durable recording and its bounded `.1` through `.16` rotations after a
  regular-file preflight, then verifies every exact target is absent.
- The in-process query-decision log uses Proxima's lock-free live snapshot
  publication for concurrent append/read paths while retaining bounded count
  and age limits.
- Atomic in-process rule-table reloads over Proxima's immutable `Live` snapshot
  primitive, with failed reloads retaining the last valid generation and
  successful policy reloads invalidating cached forwarding answers.
- Optional bounded background reloads of the policy-bearing configuration file
  use Proxima's cancellable interval lifecycle; startup-only listener,
  transport, capture, storage, and process-capacity changes fail closed.
- Atomic operator-triggered blocklist reloads rebuild the explicit rules plus
  current bounded files and retain the last good snapshot on failure.
- Optional bounded background blocklist reloads use Proxima's cancellable
  interval source, publish only changed rule sets, and drain during shutdown;
  malformed or unreadable replacements retain the last good snapshot.
- Optional Proxima HTTP admin control plane with bearer authentication, a
  read-only health, bounded rule metadata, and non-sensitive status endpoints, authenticated blocklist
  and country-map reloads, bounded complete domain and regex rule-table
  reloads from JSON, and an atomic bounded domain-rule append operation.
- Authenticated bounded `POST /reload/blocklists/replace` atomically replaces
  the blocklist source path set and retains the prior sources and rules when
  any replacement fails validation or loading.
- Authenticated bounded `POST /reload/blocklists/add` and `/reload/blocklists/remove`
  atomically add or remove exact source paths while retaining the prior live
  snapshot when validation or loading fails.
- Authenticated bounded blocklist source enable/disable routes atomically
  rebuild the active rule snapshot while retaining configured source paths and
  their operator state.
- Authenticated bounded `GET /blocklists` inspects the configured source paths,
  loaded rule count, source count, reload interval, and policy generation
  without returning source contents; each source also reports bounded file
  status, parser load status, contributed rule count, size, and modification
  age.
- Bounded authenticated `GET /policy/status` exposes effective rule, rewrite,
  blocklist-source, profile, group, and country-entry counts without source
  paths, query names, credentials, client identities, or packet payloads; its
  monotonic policy generation advances once per successful publication.
- The same policy status projection reports the live legacy-domain count,
  legacy mode, and default action without exposing legacy domain names.
- The authenticated control plane can also remove domain rules by stable ID;
  unknown IDs fail without changing the published snapshot.
- The authenticated control plane can atomically upsert domain rules by stable
  ID, preserving unspecified rules and rejecting duplicate update IDs without
  publication.
- The authenticated control plane can atomically upsert and remove regex rules
  by stable ID, preserving unspecified rules and rejecting invalid or unknown
  updates without publication.
- The authenticated control plane can atomically upsert and remove local DNS
  rewrites by normalized name, preserving the prior table after invalid or
  unknown updates.
- The authenticated control plane can also replace the complete rewrite table
  atomically through a bounded JSON route.
- The bounded authenticated status UI also displays configured rewrite metadata
  through the existing Proxima HTTP pipe.
- The bounded authenticated status UI can enable or disable retained service
  profiles, client groups, and client identities through their validated
  atomic upsert routes.
- The authenticated admin control plane includes a bounded status UI for
  status, admission limits, adaptive-abuse status and clearing, privacy
  status, rule metadata, and privacy-log inspection/clearing; it loads the
  live policy bundle and provides authenticated blocklist reload and complete
  full-configuration publication controls, contains no packet payloads, and uses
  the existing Proxima HTTP pipe.
- `deploy/package/build.sh` creates a bounded release archive from an explicit
  executable and output directory, including configuration, service assets,
  source/toolchain/lock provenance, and a SHA-256 manifest. Native package
  manager artifacts and host upgrade automation remain outside this artifact.
- `deploy/package/build-deb.sh` creates a native Debian package from an explicit
  executable and output directory, with bounded metadata and systemd payloads;
  host installation and upgrade smoke verification remain separate.
- Authenticated bounded `GET /admission/status` exposes configured query,
  response, amplification, and abuse limits without exposing counters, client
  identities, credentials, or payloads.
- Authenticated bounded `POST /reload/admission` atomically publishes live
  admission, rate, response-budget, and abuse-breaker limits; the startup-sized
  global in-flight atomic permit pool is immutable and capacity changes fail
  closed.
- Authenticated bounded `POST /reload/admission/denylist` atomically replaces
  only the configured client CIDRs while preserving every other live admission
  limit and rejecting invalid input without publication.
- Authenticated bounded `POST /reload/config` publishes the validated policy
  bundle and live admission snapshot together, preserving the same startup-only
  capacity boundary as the separate admission route.
- Per-client query-rate buckets use Proxima's bounded lock-free keyed table;
  full tagged IPv4/IPv6 bytes are retained as keys and eviction remains bounded.
- Authenticated bounded `GET /country/status` exposes country-policy deny/
  observe controls, entry count, freshness, and reload interval without
  exposing source paths or client addresses.
- Authenticated bounded `GET /privacy/status` exposes recording enablement and
  retention ceilings without exposing recording paths, query names, clients,
  credentials, or payloads.
- Authenticated bounded `GET /profiles` and `GET /client-groups` routes expose
  configured service-profile and client-network metadata without exposing
  runtime client identity.
- Authenticated bounded `POST /reload/client-groups/upsert` atomically replaces
  existing named CIDR groups or adds new groups while preserving profiles and
  rejecting invalid expansions without publication.
- Authenticated bounded `POST /reload/client-groups/remove` removes unused
  named groups and rejects removal when a configured profile still references
  the group.
- Authenticated bounded `POST /reload/profiles` atomically replaces service
  profiles and client groups, preserves explicit domain rules, and rejects
  invalid expansions without publishing them.
- Authenticated bounded `POST /reload/profiles/upsert` replaces or adds service
  profiles by stable ID while preserving unspecified profiles; duplicate IDs
  and invalid expansions fail without publication.
- Authenticated bounded `POST /reload/profiles/remove` removes service profiles
  by stable ID and rejects unknown IDs without changing the live snapshot.
- Authenticated bounded `POST /reload/policy-bundle` validates and replaces
  domain, regex, profile, client-group, client-identity, local-rewrite, and country-policy
  tables as one snapshot while retaining the loaded blocklist snapshot; an
  optional blocklist-path array replaces sources only after all files validate,
  with bounded source count, path length, per-file size, and aggregate bytes.
- The policy-bundle reload can also atomically replace the legacy fallback mode,
  legacy domain set, and default action; invalid legacy domains fail before any
  table or fallback setting is published.
- The policy-bundle editor round-trips bounded client-identity address and CIDR
  mappings; identity publication uses Proxima's lock-free `Live` snapshot and
  rejects invalid or overlapping replacements before changing the mapping.
- Authenticated client-identity upsert and removal routes publish copy-on-write
  snapshots, preserve unspecified identities, and reject unknown or invalid
  updates without changing the live mapping.
- Authenticated cache deletion clears all bounded positive and negative DNS
  answers and reports only the number of entries removed.
- Optional bounded privacy-safe query-decision logs use Proxima's recording
  event shape, retain only timestamp/action/qtype/qclass metadata, enforce
  entry and age limits, cap the authenticated inspection projection, and
  support authenticated deletion; logging is disabled by default.
- Optional durable Proxima JSONL decision recording can rotate the active file
  at startup with a bounded number of retained generations and verifies oldest
  generation deletion before continuing.
- A tested policy/FSM/snapshot core that does not require privileged capture
  APIs.
- A pure `blackhole::edge` parse-and-policy entry point that preserves the
  existing rule/action identity and compiles in the no-std WASM edge tier;
  a target-gated exported probe and Node benchmark exercise the same
  parse/match path without the owned runtime.
- Shared capture-controller orchestration with exact ownership journaling,
  rollback on journal failure, corruption-safe restart recovery, and cleanup
  refusal for ownership mismatches.
- Explicit opt-in capture configuration wires the shared controller to the
  native platform backend, recovers ownership before install, and cleans up
  after orderly shutdown.
- A hardened Linux systemd deployment unit runs the resolver as a dedicated
  service user with bounded state access and only low-port bind capability;
  a macOS launchd service runs directly as a dedicated unprivileged account
  with bounded process resources and leaves PF capture separately authorized;
  firewall capture remains a separate opt-in operation.
- Transactional Linux systemd and macOS launchd installers validate release
  inputs, preserve ownership, and roll back installed service files when an
  upgrade fails; launchd service state is restored when applicable.
- Linux builds expose an explicit `nft` command capability; macOS builds
  expose the corresponding `pfctl` capability without including either
  privileged backend in the policy core.
- Proxima consumed from its GitHub source, with Prime as the default runtime
  path and an opt-in `tokio-compat` feature that compiles the same core with
  Proxima's Tokio capability available.
