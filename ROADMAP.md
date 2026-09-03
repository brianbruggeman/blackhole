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

- Add a managed GeoIP/region/ASN database lifecycle beyond the current
  operator-supplied map and locally supplied MaxMind database: bounded,
  authenticated provider downloads, license/source metadata, SHA-256-pinned
  publication, last-good recovery, and explicit uncertainty when the provider
  data is unavailable.

## Interception and deployment

- Extend the capture adapter to populate the request metadata envelope from
  live kernel original-destination/control data where the platform exposes it;
  keep the envelope inside the existing universal-listener pipe and preserve
  adapter-owned reply-routing metadata. The current configured destination
  envelope is the safe baseline for the single-target capture plan.

## Incumbent parity and extensions

- Close additional Pi-hole/AdGuard Home parity gaps confirmed by the
  incumbent comparison, while preserving Blackhole's explicit action model
  and bounded fail-closed behavior. The current baseline already covers
  identity filtering, query logs, statistics, cache, ordered upstream
  failover, named upstreams, scoped profiles, allowlists, rate limits,
  response budgets, and concurrency controls.
- Complete durable honeypot payload storage by extending the current opt-in
  canonical redaction, bounds, Proxima recording path, restart recovery,
  deletion verification, and separate honeypot role token with a durable
  deletion audit and explicit credential-retention policy. The durable store
  must continue to reuse Proxima recording primitives and remain opt-in.

## Reference sources

- Pi-hole overview and feature documentation: <https://docs.pi-hole.net/>
- Pi-hole group management: <https://docs.pi-hole.net/group_management/>
- Pi-hole regex blocking: <https://docs.pi-hole.net/regex/>
- Pi-hole API: <https://docs.pi-hole.net/api/>
- AdGuard Home feature comparison: <https://github.com/AdguardTeam/AdGuardHome>
- AdGuard Home configuration and client capabilities: <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration>
