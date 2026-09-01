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

## Policy and operator controls

- Extend the authenticated blocklist and policy administration with richer
  policy management beyond the current bounded source inspection and health,
  background reload, source replacement, atomic domain/regex-rule
  append/upsert/removal, per-source activation, read-only status, and
  complete-snapshot reload routes.
- Extend the authenticated profile and client-group metadata views with
  additional policy controls beyond atomic enabled/disabled profile,
  identity, and network scope replacement/upsert/removal operations, including
  retained enable/disable state for profiles, groups, and identity mappings.
- Extend the current bounded operator-managed CIDR denylist and expiring DDoS
  breakers into the remaining explainable reputation lifecycle: incident
  review, durable approval, bounded import/export, and safe recovery after
  restart. Exact-client and network revocation is now durable and replayed in
  order. It must remain separate from authentication and must never become an
  unbounded permanent blacklist.
- Add managed GeoIP/region/ASN data lifecycle and richer country policy beyond
  the current explicit country/CIDR/region/ASN map labels and bounded background
  refresh; uncertainty must remain explicit.
- Add incremental background updates for deployment-managed configuration
  sources beyond the bounded TOML policy-file reload; changes to startup-only
  listener, transport, capture, storage, and service settings still require a
  controlled restart.

## Interception and deployment

- Complete original-destination integration for the opt-in capture
  configuration by consuming a supported Proxima listener context/raw-socket
  capability; until that upstream seam exists, keep original-destination and
  reply-routing metadata inside the platform adapter and do not synthesize it
  in policy, telemetry, or recordings.

## Incumbent parity and extensions

- Extend the bounded privacy-safe query-decision log with operator-selected
  redaction and deletion-verification backends beyond the current metadata-only,
  byte-bounded Proxima JSONL destination and bounded startup rotation.
- Extend the current bounded authenticated status UI into a full optional web
  UI beyond the current bounded status, aggregate decision statistics,
  policy-bundle, and blocklist source activation controls.
- Add the remaining Pi-hole/AdGuard Home policy features, including richer
  per-client identity and group-management controls.
- Add a separately isolated honeypot terminal with explicit retention and
  access controls.
- Extend the measured policy/codec WASM edge experiment with additional
  runtimes and workload cells while retaining scalar fallback.

## Reference sources

- Pi-hole overview and feature documentation: <https://docs.pi-hole.net/>
- Pi-hole group management: <https://docs.pi-hole.net/group_management/>
- Pi-hole regex blocking: <https://docs.pi-hole.net/regex/>
- Pi-hole API: <https://docs.pi-hole.net/api/>
- AdGuard Home feature comparison: <https://github.com/AdguardTeam/AdGuardHome>
- AdGuard Home configuration and client capabilities: <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration>
