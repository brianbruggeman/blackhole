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

- Extend the capture adapter to populate the request metadata envelope from
  live kernel original-destination/control data where the platform exposes it;
  keep the envelope inside the existing universal-listener pipe and preserve
  adapter-owned reply-routing metadata. The current configured destination
  envelope is the safe baseline for the single-target capture plan.

## Incumbent parity and extensions

- Close the remaining Pi-hole/AdGuard Home parity gaps that fit Blackhole's
  explicit-action model: client-specific ordered upstream failover, and any
  additional client/service controls confirmed by the incumbent comparison.
  The current baseline already covers identity filtering, query logs,
  statistics, cache, fallback action, named upstream, scoped profiles and
  allowlists, global rate-limit-whitelist, per-identity query rate, response
  budgets, and concurrency controls.
- Add durable honeypot payload storage only after field-level redaction,
  authenticated role-scoped access, crash-safe deletion verification, and
  bounded credential retention are implemented.

## Reference sources

- Pi-hole overview and feature documentation: <https://docs.pi-hole.net/>
- Pi-hole group management: <https://docs.pi-hole.net/group_management/>
- Pi-hole regex blocking: <https://docs.pi-hole.net/regex/>
- Pi-hole API: <https://docs.pi-hole.net/api/>
- AdGuard Home feature comparison: <https://github.com/AdguardTeam/AdGuardHome>
- AdGuard Home configuration and client capabilities: <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration>
