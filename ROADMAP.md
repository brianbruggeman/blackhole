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

- Add a managed GeoIP/region/ASN data lifecycle and richer country policy
  beyond the explicit operator-supplied map labels, SHA-256-pinned
  bounded refresh, and last-good snapshot in the current baseline; uncertainty
  must remain explicit.

## Interception and deployment

- Complete original-destination integration for the opt-in capture
  configuration by consuming a supported Proxima listener context/raw-socket
  capability; until that upstream seam exists, keep original-destination and
  reply-routing metadata inside the platform adapter and do not synthesize it
  in policy, telemetry, or recordings. The pinned Proxima revision and the
  current upstream `main` audit expose no such listener seam yet.

## Incumbent parity and extensions

- Add the remaining Pi-hole/AdGuard Home policy features that fit Blackhole's
  explicit-action model, including additional client-specific service settings
  beyond the current identity, filtering, query-log, statistics, cache, fallback,
  named-upstream, profile, global rate-limit-whitelist, per-identity query-rate,
  per-identity response-budget, and per-identity concurrency controls.
- Add a separately isolated honeypot terminal with explicit retention and
  access controls.
- Run the measured policy/codec WASM edge experiment under additional runtimes
  beyond Node.js while retaining the existing bounded workload cells and
  scalar fallback.

## Reference sources

- Pi-hole overview and feature documentation: <https://docs.pi-hole.net/>
- Pi-hole group management: <https://docs.pi-hole.net/group_management/>
- Pi-hole regex blocking: <https://docs.pi-hole.net/regex/>
- Pi-hole API: <https://docs.pi-hole.net/api/>
- AdGuard Home feature comparison: <https://github.com/AdguardTeam/AdGuardHome>
- AdGuard Home configuration and client capabilities: <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration>
