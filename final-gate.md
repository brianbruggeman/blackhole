# Blackhole final gate

This is an evidence ledger, not a completion claim. A gate is marked proven
only for the exact command and scope that ran. Missing evidence remains open.

## Proven

| Gate | Evidence |
| --- | --- |
| Formatting | `cargo fmt --all -- --check` passed on the current Blackhole changes. |
| Compilation | `cargo check --offline --all-targets` passed with Proxima from GitHub revision `0652a0c0`. |
| Unit and integration tests | `cargo test --offline --all-targets` passed: 80 library tests, 1 real HTTP admin fixture, 3 real loopback UDP/TCP resolver fixture tests, and 8 fake-upstream tests against GitHub Proxima revision `0652a0c0`; verified at Blackhole policy-admin changes with Rust `1.98.0` and Cargo `1.98.0`. |
| Cache failure behavior | `fake_upstream_servfail_is_not_cached` passed at `3e463c8`; SERVFAIL caused two upstream exchanges. |
| Nextest | `cargo nextest run --offline --workspace` passed: 84 tests, 84 passed, 0 skipped, against GitHub Proxima revision `0652a0c0`. |
| Doctests | `cargo test --doc --offline` passed: 1 doctest. |
| No-std and WASM | `cargo check --offline --no-default-features` passed for `thumbv7m-none-eabi` and `wasm32-unknown-unknown` after the response-size work. |
| Dependency audit | `cargo audit --no-fetch` passed with one allowed warning: unmaintained `paste` (`RUSTSEC-2024-0436`). The fuzz lockfile audit also passed. |
| Fuzz smoke | The `query_view` nightly fuzz target ran 1,000 iterations without a crash; the bounded corpus contains 50 inputs. |
| Resolver fixture | The actual loopback UDP/TCP listener fixture passed. |
| Configuration validation | `cargo run --offline -- --check blackhole.example.toml` and `cargo run --offline -- --check` both exited successfully before listener startup; enabled capture plans are validated through the platform planner without installation. |
| Authenticated admin control plane | Focused and real-listener tests prove Proxima HTTP health routing, bearer rejection/admission, bounded 404/405 routes, authenticated blocklist and JSON policy reload behavior, bounded policy bodies, and loopback-only binding while the control plane is plaintext HTTP. |
| Live forwarding FSM path | The real loopback resolver fixture exercises the listener's `Matched(Forward)`, `Forward`, `Forwarded`, and response-send transitions while forwarding through Proxima's GitHub-pinned `DnsClientUpstream`. |
| Capture lifecycle | Planner, rollback, ownership, recovery, and cleanup tests pass. Capture is explicitly opt-in, wired through the shared controller, and native Linux cleanup targets only the exact journal-owned chain rather than deleting the shared table. |
| Per-client admission | The configured per-client concurrent-request cap rejects a second in-flight request at the limit, releases on completion, and passes the focused unit test. |
| Response amplification cap | The configured response-ratio cap is validated and applied below the absolute response ceiling; the focused cap test is included in the current 77-test library suite. |
| Per-client rate limiting | The configured per-second client rate cap sheds the third request in a deterministic focused test, while unidentified callers remain unkeyed and the rate-state table is bounded. |
| Atomic blocklist reload | A replacement blocklist publishes as one snapshot and an invalid replacement leaves the previous generation active; the focused reload test is included in the current 77-test library suite. |
| Cache outcome telemetry | Proxima-native counters record fresh hits, misses, stale serves, and capacity evictions; the deterministic bounded-eviction test passes. |
| Cache TTL telemetry | The focused `cache_ttl_telemetry_reports_effective_positive_and_negative_ttls` test proves the histogram reports the configured post-clamp positive TTL and negative TTL through Proxima's telemetry interface. |
| Local DNS rewrites | Bounded A/AAAA rewrites answer pass/observe queries, explicit policy actions override them, and malformed or oversized configuration fails closed. |
| Per-client abuse breaker | Full all-target suite passed with a focused test covering repeated rate-limit violations opening a temporary bounded breaker while unidentified callers remain unaffected. |
| Per-client response-byte budget | Focused tests prove encoded-response budget accumulation sheds a client at the configured one-second ceiling, unidentified callers remain unkeyed, and zero-value configuration fails closed. |
| Named service profiles | Focused tests prove profile domains compile into authoritative rules and duplicate profile names or invalid domains fail closed. |
| Listener rewrite path | Full all-target suite includes a real loopback UDP test proving a local rewrite is encoded and returned through the Proxima listener adapter. |
| Listener profile path | Full all-target suite includes a real loopback UDP test proving a configured service profile is enforced by the listener's actual policy path. |
| Cache TTL bound | Full all-target suite includes tests proving positive and negative cache entries remain bounded, protocol TTLs above the configured ceiling are clamped, and a zero ceiling fails configuration validation. |
| Cache invalidation | Rule-table reload tests prove successful policy publication clears cached forwarding answers while failed reloads retain the previous snapshot. |

## Evidence still required

| Gate | Current state |
| --- | --- |
| Privileged capture smoke | Not produced here. The process has no effective capabilities (`CapEff: 0`); non-mutating `nft --check` returned netlink `EPERM`. |
| macOS build and PF smoke | CI workflow exists, but no local macOS execution evidence is recorded here. |
| TCP upstream fallback | Open. GitHub-pinned Proxima `0652a0c0` exposes only UDP `DnsClientUpstream` and discards `TC` and response-question metadata. |
| Proxima metadata change publication | Local Proxima commits `e41c8ac8` and `49146ea3` are not on GitHub; push was rejected for `slot-0` access. Blackhole remains on the published GitHub revision. |
| Performance gate | `cargo run --release --features perf-instrument --example performance_gate` ran three times on Linux x86_64. Allocator data and policy/owned boundaries are measured; listener TCP/encode/transport boundaries are instrumented but were not exercised by this example. No zero-copy or production-performance claim is supported. |
| Privacy and honeypot terminal | The retention contract is documented in `PRIVACY.md`; retention, redaction, access control, and deletion verification controls are not implemented. |
| Managed GeoIP/region/ASN policy | Open. The current implementation supports only an explicit operator-supplied country-to-CIDR map; managed database lifecycle and region/ASN sources are not implemented. |
| Incumbent parity | Pi-hole/AdGuard parity is incomplete: encrypted upstreams, admin/API/UI, DHCP, and richer policy controls remain open; named service profiles are implemented and tested. |

The open rows must be resolved and rerun with fresh evidence before this file
can support a release or a completion claim.
