# Blackhole feature list

Blackhole is a privacy-first, policy-driven DNS interceptor for operators who
need the familiar capabilities of Pi-hole and AdGuard Home plus explicit
traffic interception, forwarding, and honeypot controls.

This is the product feature list, not an implementation plan. A feature listed
here is a target capability and is not a claim that the current prototype
already provides it. Implementation work and evidence belong in `TODO.md`.

## Incumbent parity

The baseline is the feature surface users reasonably expect from a modern
network DNS blocker. Pi-hole documents allowlists, denylists, regex filters,
groups, query logging, statistics, and an API. AdGuard Home additionally
documents encrypted upstreams, per-client settings, access controls, DNS
rewrites, built-in DHCP, query logging, statistics, parental controls, safe
search, and safe browsing.

| Capability | Pi-hole | AdGuard Home | Blackhole target |
| --- | --- | --- | --- |
| DNS service over UDP and TCP | yes | yes | yes |
| Allowlist and denylist | yes | yes | yes |
| Wildcard and suffix rules | yes | yes | yes |
| Regex/domain-pattern rules | yes | yes | yes, bounded and explicit |
| Per-client policy | groups | clients/groups | client and network scopes |
| Rule precedence and explanations | database precedence | filter/rewrite precedence | deterministic priority, specificity, and decision explanation |
| Upstream DNS resolution | yes | yes | yes, explicit and loop-safe |
| Encrypted upstream DNS | optional integrations | DoH, DoT, DNSCrypt, DoQ | target: reuse a Proxima-supported transport |
| DNS caching | yes | yes | bounded positive, negative, and stale cache |
| Local DNS rewrites | custom records | rewrites | target: typed A, AAAA, CNAME, and policy responses |
| Query log | yes | yes | target: bounded, redactable, access-controlled |
| Statistics and latency reporting | yes | yes | target: action, error, and latency telemetry |
| DNS abuse protection | rate limiting and blocking `ANY` | rate limiting and blocking `ANY` | bounded global/per-client limits, `ANY` policy, amplification controls |
| Upstream failure protection | resolver failure handling | resolver failure handling | target: bounded concurrency, timeout budget, and upstream circuit breaker |
| Service blocking | blocklists/groups | blocked services | target: named service profiles |
| Built-in DHCP | yes | yes | explicit non-goal for the DNS core; adapter may follow |
| Admin API | yes | yes | target: small authenticated control API |
| Admin web UI | yes | yes | target: separate product surface, not required by the core |
| Client access control | network/group policy | allowlist/denylist clients | target: fail-closed access policy |
| Geographic access policy | no core feature | no core feature | optional country/region/ASN allow, deny, or observe-only policy |
| DoH/DoT/DoQ server endpoints | no native parity | yes | target only after the UDP/TCP core is proven |
| Cross-platform operation | Linux-first | cross-platform | Linux and macOS native adapters |
| Runs without broad root privileges | limited by deployment | yes | target: unprivileged DNS core; privilege isolated to capture adapters |
| Privacy controls | local operation and query-log controls | local operation and retention controls | no payload retention by default; explicit redaction, retention, access, deletion |

## Blackhole-specific capabilities

- Explicit actions: pass, reject, drop, NXDOMAIN, sink, honeypot, forward, and
  observe, with transport behavior defined independently from policy.
- Deterministic matching by priority, exact/deep wildcard specificity,
  qclass, qtype, client/network scope, and stable rule identity.
- Optional geographic access policy: classify the adapter-owned client IP by
  country, region, or ASN and apply allow, deny, or observe-only (“snitch”)
  rules. GeoIP database version, lookup result, and uncertainty are explicit
  telemetry fields; location is never inferred from DNS names.
- DNS interception as a first-class deployment mode, with original-destination
  and client metadata kept in the capture adapter.
- Bounded transparent forwarding with QR/question validation, transaction
  matching, timeout/failure policy, loop prevention, and cache safety.
- DNS abuse resistance: global and per-client/subnet admission limits, bounded
  outstanding work, optional refusal of `ANY`, response-size limits, and an
  upstream circuit breaker. This protects the resolver process; it is not a
  substitute for upstream network DDoS mitigation.
- A controlled honeypot terminal as a separate capability from synthetic DNS
  sink answers; no credential or payload collection by default.
- Prime-native operation with Tokio compatibility where the Proxima runtime
  provides it.
- A sans-IO parser and decision core that can be tested independently of
  sockets, executors, filesystem state, and privileged operating-system APIs.

## Explicit non-goals

- Browser-content or URL filtering after DNS resolution.
- TLS interception or decryption.
- Silent forwarding of unknown protocols.
- An open resolver by default.
- Unbounded query, payload, cache, log, or honeypot retention.
- Treating GeoIP classification as exact identity, attribution, or a substitute
  for authentication and network-level DDoS protection.
- Calling the prototype zero-copy, production-grade, or high-performance
  without end-to-end measurements.

## Reference sources

- Pi-hole overview and feature documentation: <https://docs.pi-hole.net/>
- Pi-hole group management: <https://docs.pi-hole.net/group_management/>
- Pi-hole regex blocking: <https://docs.pi-hole.net/regex/>
- Pi-hole API: <https://docs.pi-hole.net/api/>
- AdGuard Home feature comparison: <https://github.com/AdguardTeam/AdGuardHome>
- AdGuard Home configuration and client capabilities: <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration>
