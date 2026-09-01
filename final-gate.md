# Blackhole final gate

This is an evidence ledger, not a completion claim. A gate is marked proven
only for the exact command and scope that ran. Missing evidence remains open.

## Proven

| Gate | Evidence |
| --- | --- |
| Formatting | `cargo fmt --all -- --check` passed at Blackhole `ce3b7d1` with Rust `1.98.0`. |
| Compilation | `cargo check --offline --all-targets` passed at Blackhole `ce3b7d1` with GitHub Proxima revision `d8cf174e`, Rust `1.98.0`, and Cargo `1.98.0`. |
| Unit and integration tests | `cargo test --offline --all-targets` passed at Blackhole `bddb401` with 110 tests, 110 passed, including install-failure capture rollback, the privacy-safe recording proof, scoped regex policy proof, the real HTTP admin fixture, 4 real loopback UDP/TCP resolver fixtures (including `listener_retries_a_truncated_upstream_reply_over_tcp`), and 10 fake-upstream tests against GitHub Proxima revision `d8cf174e`. |
| Cache failure behavior | `fake_upstream_servfail_is_not_cached` passes in the current 103-test run at Blackhole `c23c1ac`; SERVFAIL causes a second upstream exchange rather than a reusable negative cache entry. |
| Nextest | `cargo nextest run --offline --workspace` passed at Blackhole `ce3b7d1`: 109 tests, 109 passed, 0 skipped, against GitHub Proxima revision `d8cf174e`; the real admin and resolver fixtures use OS-assigned loopback ports and pass under the parallel runner. |
| Doctests | `cargo test --doc --offline` passed at Blackhole `ce3b7d1`: 1 doctest. |
| No-std and WASM | `cargo build --offline --no-default-features --target thumbv7m-none-eabi` and the equivalent `wasm32-unknown-unknown` command passed at Blackhole `ce3b7d1` with GitHub Proxima revision `d8cf174e`; both completed without warnings. |
| Tokio compatibility build | `cargo check --offline --features tokio-compat --all-targets` passed at Blackhole `ce3b7d1` with GitHub Proxima revision `d8cf174e`; the lane compiles Tokio capability support while the default executable remains Prime-backed. |
| Dependency audit | Root `cargo audit --no-fetch` and `cargo audit --no-fetch --file fuzz/Cargo.lock` passed at Blackhole `ad4fd5b`; the root graph reports one allowed warning for unmaintained `paste` (`RUSTSEC-2024-0436`), while the fuzz lockfile reports no findings. |
| Fuzz smoke | The installed nightly `query_view` target ran 1,000 iterations over the 56 tracked corpus inputs without a crash at Blackhole `ad4fd5b`; generated corpus files were discarded after the smoke run. |
| Resolver fixture | The actual loopback UDP/TCP listener fixture passed. |
| Configuration validation | At Blackhole `1455ec5`, `cargo run --offline -- --check blackhole.example.toml` exited successfully before listener startup; enabled capture plans are validated through the platform planner without installation. |
| Authenticated admin control plane | Focused and real-listener tests prove Proxima HTTP health routing, bearer rejection/admission, bounded 404/405 routes, authenticated blocklist, country-map, domain-rule, and regex-rule reload behavior, bounded policy bodies, live bounded `/rules` inspection, and loopback-only binding while the control plane is plaintext HTTP. |
| Live forwarding FSM path | The real loopback resolver fixtures exercise the listener's `Matched(Forward)`, `Forward`, `Forwarded`, and response-send transitions while forwarding through Proxima's GitHub-pinned `DnsClientUpstream`; the TCP fallback fixture also proves the actual UDP-TC-to-TCP path. |
| TCP upstream fallback | `DnsClientUpstream` retains the echoed question and TC bit, validates `QR=1`/`OPCODE=0`, retries TC-marked UDP answers through the injected existing `StreamUpstream`, and exchanges bounded two-byte-length DNS-over-TCP frames under the same configured deadline. Proxima's deterministic fallback test and Blackhole's real listener fixture pass against GitHub Proxima `d8cf174e`. |
| Capture lifecycle | Planner, install-failure rollback, verification-failure rollback, ownership, recovery, and cleanup tests pass at Blackhole `bddb401`. Capture is explicitly opt-in, wired through the shared controller, and native Linux cleanup targets only the exact journal-owned chain rather than deleting the shared table. |
| Linux deployment artifact | `deploy/systemd/blackhole.service`, its tmpfiles definition, and the root-checked `deploy/systemd/install.sh` are present and diff-validated; the unit restricts the service to a dedicated user, low-port bind capability, and `/var/lib/blackhole` state. The installer’s non-root guard exits before mutation. Host installation smoke is not claimed because the service binary and `blackhole` account are not installed in this workspace. |
| Disposable-root systemd verification | A disposable root containing the built `blackhole` executable (`0755`), the declared `blackhole` user/group, the service unit, and the state directory passed `systemd-analyze verify --root=...` with status 0. This validates the deployment-shaped unit without mutating the host. |
| Per-client admission | The configured per-client concurrent-request cap rejects a second in-flight request at the limit, releases on completion, and passes the focused unit test. |
| Response amplification cap | The configured response-ratio cap is validated and applied below the absolute response ceiling; the focused cap test passes in the current 81-test library suite. |
| Per-client rate limiting | The configured per-second client rate cap sheds the third request in a deterministic focused test, while unidentified callers remain unkeyed and the rate-state table is bounded. |
| Atomic blocklist reload | A replacement blocklist publishes as one snapshot and an invalid replacement leaves the previous generation active; the focused reload test passes in the current 89-test library suite. |
| Cache outcome telemetry | Proxima-native counters record fresh hits, misses, stale serves, and capacity evictions; the deterministic bounded-eviction test passes. |
| Cache TTL telemetry | The focused `cache_ttl_telemetry_reports_effective_positive_and_negative_ttls` test proves the histogram reports the configured post-clamp positive TTL and negative TTL through Proxima's telemetry interface. |
| Reload latency telemetry | `telemetry_records_reload_latency_by_reload_kind` proves Proxima's histogram surface receives successful rules and regex reload durations labeled by reload kind at Blackhole `3bd1062`. |
| Local DNS rewrites | Bounded A/AAAA rewrites answer pass/observe queries, explicit policy actions override them, and malformed or oversized configuration fails closed. |
| Per-client abuse breaker | Full all-target suite passed with a focused test covering repeated rate-limit violations opening a temporary bounded breaker while unidentified callers remain unaffected. |
| Network abuse breaker | Focused coverage proves repeated violations from clients in one configured IPv4/IPv6 network open a bounded network breaker while another network and unidentified callers remain unaffected. |
| Per-client response-byte budget | Focused tests prove encoded-response budget accumulation sheds a client at the configured one-second ceiling, unidentified callers remain unkeyed, and zero-value configuration fails closed. |
| Adaptive response-budget abuse breaker | The actual listener now records identified-client response-budget violations in the existing bounded abuse state; repeated violations trigger its configured cooldown breaker, while unidentified callers remain unaffected. Focused coverage passes. |
| Named service profiles | Focused tests prove profile domains compile into authoritative rules, optional client CIDR scopes apply only to matching clients, and duplicate profile names or invalid domains fail closed. |
| Listener rewrite path | Full all-target suite includes a real loopback UDP test proving a local rewrite is encoded and returned through the Proxima listener adapter. |
| Listener profile path | Full all-target suite includes a real loopback UDP test proving a configured service profile is enforced by the listener's actual policy path. |
| Cache TTL bound | Full all-target suite includes tests proving positive and negative cache entries remain bounded, protocol TTLs above the configured ceiling are clamped, and a zero ceiling fails configuration validation. |
| Cache invalidation | Rule-table reload tests prove successful policy publication clears cached forwarding answers while failed reloads retain the previous snapshot. |
| Concurrent snapshot readers | `concurrent_readers_observe_only_complete_generations` runs four readers across 63 reloads and proves each read sees a complete generation, not a mixed rule table, at Blackhole `dcee4fd`. |
| Bounded upstream exchange | Current tree validates `query_timeout_ms` to 1–60,000 ms, `max_attempts` to 1–8, and `max_outstanding` to 1–4096 before listener construction; UDP and TCP upstream operations share the configured exchange deadline, and upstream answers reject impossible RCODE values above DNS’s 4-bit range. Focused validation and the full all-target suite pass against GitHub Proxima `d8cf174e`. |
| Upstream CNAME validation | Upstream CNAME targets are parsed through Proxima’s DNS name parser and rejected on pointer loops, trailing bytes, or invalid names; valid targets pass. Focused and full all-target tests pass. |
| Upstream loop prevention | Upstream configuration rejects exact listener endpoints and same-family unspecified listener binds that overlap the upstream address and port; IPv4 and IPv6 proofs pass. |
| Bounded upstream records | Upstream answers exceeding the configured `max_response_records` are rejected before validation can reach cache insertion; focused and full all-target suites pass. |
| Upstream pass-through | `pass` and `observe` actions use the configured upstream after local rewrites, while explicit `forward` remains distinct and fail-closed without an upstream; deterministic fake-upstream proofs pass. |
| DNS query flag validation | The shared borrowed query boundary and UDP/TCP probes reject AA, TC, RA, Z, and nonzero RCODE bits before policy evaluation; focused and full all-target suites pass. |
| Blocklist exceptions and subdomains | Bounded blocklist ingestion generates apex and subdomain rules, honors basic AdGuard `@@||domain^` exceptions, and proves normalization/deduplication and fail-closed parsing in the full suite. |
| Authenticated status endpoint | The existing Proxima bearer-authenticated admin handler exposes bounded non-sensitive status fields; unit and real HTTP listener proofs pass. |
| Authenticated rule inspection | The bearer-authenticated `GET /rules` route returns policy metadata without query payloads and caps serialized output at 64 KiB; focused tests prove non-empty output, truncation, and wrong-method rejection, while `admin_http_listener_enforces_bearer_auth` proves the route through a live Proxima HTTP listener at Blackhole `e9e4f3e`. |
| Privacy-safe decision recording | The optional Proxima `RecordingSink` hook emits only action, qtype, and qclass metadata; `recording_sink_receives_only_dns_decision_metadata` proves names and wire data are excluded at Blackhole `a5cde62`. |
| Bounded regex policy rules | Regex expressions compile with count, pattern, and program-size bounds; invalid expressions fail closed, filter specificity is deterministic, explicit domain rules win, and focused policy proofs pass. |
| Regex client-network scopes | Regex rules accept bounded IPv4/IPv6 CIDR scopes, reject invalid or conflicting scopes, rank the most-specific matching network, expose metadata through `/rules`, and pass deterministic matching tests at Blackhole `a5cde62`. |
| Multi-network client scopes | Existing rule configuration accepts one bounded `client_cidrs` list of IPv4/IPv6 networks, rejects ambiguous or oversized scopes, and selects the longest matching prefix; focused policy proofs pass. |

## Evidence still required

| Gate | Current state |
| --- | --- |
| Privileged capture smoke | Not produced here. The process has no effective capabilities (`CapEff: 0`); non-mutating `nft --check` returned netlink `EPERM`. |
| Host-installed systemd smoke | Not produced here. `systemd-analyze verify` reaches the unit but reports the expected missing `/usr/local/bin/blackhole` installation path. |
| macOS build and PF smoke | CI workflow exists, but no local macOS execution evidence is recorded here. |
| Performance gate | The expanded scalar harness ran three times on Linux x86_64 at Blackhole `c506caf`, Rust `1.98.0`, and GitHub Proxima `d8cf174e`, with N=25 samples per workload. Across runs, build p50 was 46.513–53.079 ms, match p50 41.120–42.096 µs, parse-short 50–51 ns, parse-long 233–238 ns, parse-adversarial 80–81 ns, parse-mixed 80–90 ns, and owned 118–121 ns; all values are MEASURED and each run records allocations, allocation bytes, p95/p99, min/max, CoV, RSS, and load. The actual listener forwarding fixture separately recorded policy canonicalization 28 B, borrowed-to-owned 28 B, TCP frame buffer 31 B, encode output 120 B, and transport write 120 B. Short/mixed/owned variance remains high, so this is measurement evidence only; no zero-copy or production-performance claim is supported. |
| Privacy and honeypot terminal | The retention contract is documented in `PRIVACY.md`; retention, redaction, access control, and deletion verification controls are not implemented. |
| Managed GeoIP/region/ASN policy | Open. The current implementation supports only an explicit operator-supplied country-to-CIDR map; managed database lifecycle and region/ASN sources are not implemented. |
| Incumbent parity | Pi-hole/AdGuard parity is incomplete: encrypted upstreams, admin/API/UI, DHCP, and richer policy controls remain open; named service profiles are implemented and tested. |

The open rows must be resolved and rerun with fresh evidence before this file
can support a release or a completion claim.
