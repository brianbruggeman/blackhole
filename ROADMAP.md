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

- Extend the authenticated blocklist and policy administration with richer
  management operations beyond the current bounded background blocklist
  reload/source replacement, atomic domain/regex-rule append/upsert/removal,
  read-only status, and complete-snapshot reload routes.
- Extend the authenticated profile and client-group metadata views with richer
  per-client identity and network policy controls beyond the current atomic
  profile replacement/upsert/removal and client-group upsert/removal
  operations.
- Extend adaptive amplification controls for repeated abusive patterns beyond
  the current per-query response-ratio cap, aggregate/per-client admission
  limits, and bounded rate/response-budget abuse breaker.
- Add managed GeoIP/region/ASN data lifecycle and richer country policy beyond
  the current explicit country-to-CIDR map and bounded background refresh;
  uncertainty must remain explicit.
- Add authenticated full-configuration reload and incremental background
  updates beyond the current in-process atomic policy-bundle reload API.

## Interception and deployment

- Add privileged Linux nftables and macOS packet-filter smoke evidence for the
  opt-in capture configuration and complete original-destination integration.
- Keep client and original-destination metadata adapter-owned.
- Support unprivileged DNS operation with privilege isolated to capture setup.
- Extend the current systemd and launchd service definitions with native
  packaging and host-installed upgrade/rollback verification.

## Incumbent parity and extensions

- Extend the bounded privacy-safe query-decision log with operator-selected
  redaction, rotation, and deletion-verification backends beyond the current
  metadata-only, byte-bounded Proxima JSONL destination.
- Extend the current bounded authenticated status UI into a full optional web
  UI and add an optional DHCP adapter.
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
