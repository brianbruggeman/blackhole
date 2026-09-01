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

- Isolate the synthetic honeypot answer from any future payload-collection
  terminal and preserve its bounded DNS-only contract.

## Policy and operator controls

- Extend the authenticated blocklist and policy administration with
  incremental background reload and richer management operations beyond the
  current bounded atomic domain-rule append, read-only status, and
  complete-snapshot reload routes.
- Extend named client groups with richer per-client identity and network
  policy controls and authenticated administration.
- Extend adaptive amplification controls for repeated abusive patterns beyond
  the current per-query response-ratio cap, per-client admission limits, and
  bounded rate/response-budget abuse breaker.
- Add managed GeoIP/region/ASN data lifecycle and richer country policy beyond
  the current explicit country-to-CIDR map; keep uncertainty and database
  freshness explicit.
- Add authenticated configuration reload and incremental background updates on
  top of the current in-process atomic rule-table reload API.

## Interception and deployment

- Add privileged Linux nftables and macOS packet-filter smoke evidence for the
  opt-in capture configuration and complete original-destination integration.
- Keep client and original-destination metadata adapter-owned.
- Support unprivileged DNS operation with privilege isolated to capture setup.
- Add cross-platform native deployment adapters.

## Incumbent parity and extensions

- Add optional DoQ upstream/server endpoints; DNS-over-TLS and DNS-over-HTTPS
  upstream transports are implemented in the current baseline.
- Add bounded query logs and privacy controls for retention, redaction, access,
  and deletion.
- Extend the authenticated admin API with an optional web UI and optional DHCP
  adapter.
- Add the remaining Pi-hole/AdGuard Home policy features, including richer
  per-client identity and group-management controls.
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
