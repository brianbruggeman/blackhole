# Blackhole roadmap

Blackhole is a privacy-first, policy-driven DNS interceptor for operators who
need the familiar capabilities of Pi-hole and AdGuard Home plus explicit
traffic interception, forwarding, and honeypot controls.

This roadmap describes the product surface Blackhole is intended to deliver.
It is organized by capability area. It is not a claim about the current
prototype or a substitute for engineering verification.
Every item is a target capability; implementation details and verification
evidence stay in the engineering workflow rather than this product roadmap.

The current baseline is documented in [FEATURES.md](FEATURES.md). The items
below are future capabilities, grouped by the dependency layer they extend.

## Resolver completion

- Make the borrowed sans-IO query/decision path the executable listener path.
- Complete DNS QR-bit, question/name, ID, response, and truncation validation.
- Define transport semantics for every policy action, including pass, reject,
  drop, NXDOMAIN, sink, honeypot, forward, and observe.
- Add bounded forwarding with matching-question checks, transaction checks,
  timeout behavior, TCP fallback, loop prevention, and fail-closed errors.
- Add bounded positive, negative, and stale caching.

## Policy and operator controls

- Ingest Pi-hole-compatible blocklists with bounded parsing, normalization,
  deduplication, and safe reload.
- Add per-client and network scopes, local rewrites, service profiles, and
  authenticated administration.
- Add global/per-client admission limits, amplification controls, `ANY`
  handling, bounded outstanding work, and an upstream circuit breaker.
- Add optional country/region/ASN access policy with allow, deny, and
  observe-only (“snitch”) modes; keep GeoIP uncertainty and database lifecycle
  explicit.
- Add reloadable snapshots with bounded retirement and concurrent-reader
  guarantees.

## Interception and deployment

- Complete Linux nftables and macOS packet-filter capture adapters with
  ownership, rollback, crash recovery, and platform smoke evidence.
- Keep client and original-destination metadata adapter-owned.
- Support unprivileged DNS operation with privilege isolated to capture setup.
- Add cross-platform native deployment adapters.

## Incumbent parity and extensions

- Add encrypted upstreams and optional DoH, DoT, and DoQ server endpoints.
- Add bounded query logs, statistics, action/error/latency histograms, and
  privacy controls for retention, redaction, access, and deletion.
- Add an authenticated admin API, optional web UI, and optional DHCP adapter.
- Add named service-blocking profiles and the remaining Pi-hole/AdGuard Home
  policy features.
- Add a separately isolated honeypot terminal with explicit retention and
  access controls.
- Add a measured policy/codec WASM edge experiment while retaining scalar
  fallback.

## Reference sources

- Pi-hole overview and feature documentation: <https://docs.pi-hole.net/>
- Pi-hole group management: <https://docs.pi-hole.net/group_management/>
- Pi-hole regex blocking: <https://docs.pi-hole.net/regex/>
- Pi-hole API: <https://docs.pi-hole.net/api/>
- AdGuard Home feature comparison: <https://github.com/AdguardTeam/AdGuardHome>
- AdGuard Home configuration and client capabilities: <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration>
