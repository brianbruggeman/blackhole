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

- Extend the authenticated policy administration with richer query rules and
  client/group workflows beyond the bounded source, rule, profile, identity,
  and network-scope operations in the current baseline.
- Add a managed GeoIP/region/ASN data lifecycle and richer country policy
  beyond the explicit operator-supplied map labels, fingerprint-pinned
  bounded refresh, and last-good snapshot in the current baseline; uncertainty
  must remain explicit.
- Add incremental background updates for deployment-managed configuration
  sources beyond the bounded TOML policy-file reload. Listener, transport,
  capture, storage, and service changes still require a controlled restart.

## Interception and deployment

- Complete original-destination integration for the opt-in capture
  configuration by consuming a supported Proxima listener context/raw-socket
  capability; until that upstream seam exists, keep original-destination and
  reply-routing metadata inside the platform adapter and do not synthesize it
  in policy, telemetry, or recordings.

## Incumbent parity and extensions

- Extend the bounded privacy-safe query-decision log with operator-selected
  deletion-verification backends beyond the current exact-file deletion,
  byte-bounded Proxima JSONL destination, and bounded startup rotation. The
  current `metadata` and `action_only` redaction modes are part of the baseline.
- Extend the current bounded authenticated status UI into a full optional web
  UI with richer policy editing, client/group workflows, and operational
  diagnostics while preserving the existing authentication and response
  bounds.
- Add the remaining Pi-hole/AdGuard Home policy features that fit Blackhole's
  explicit-action model, including richer per-client identity and
  group-management controls.
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
