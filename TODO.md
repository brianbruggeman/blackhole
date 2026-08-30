# blackhole implementation status

This file is the current work list. End-user documentation lives in
`README.md`, `blackhole.example.toml`, and `examples/`. Internal design logs,
source maps, threat models, and gate reports are intentionally not shipped.

## Completed and evidenced

- [x] DNS interception surface is UDP and TCP on one explicit listener bind.
  See `src/main.rs` and `src/lib.rs`.
- [x] Proxima dependencies use the GitHub repository rather than local paths.
  See `Cargo.toml` and the Git sources recorded in `Cargo.lock`.
- [x] Borrowed DNS query narrowing reuses Proxima's parser and enforces the
  4096-byte bound, one question, and compression-loop rejection. See
  `src/query.rs`.
- [x] Reference policy matching is deterministic and validates rule count,
  domain length, wildcard shape, and duplicate IDs. See `src/policy.rs`.
- [x] Policy precedence includes priority, exact/deep wildcard specificity,
  client scope, independent qclass/qtype selectors, and rule ID.
- [x] A configured rule table is authoritative; legacy `mode`/`domains` are
  used only when the table is empty. See the authority test in `src/lib.rs`.
- [x] The sans-IO FSM has explicit borrowed states and transitions for parse,
  partial input, forwarding, response, sent, next message, drop, and close.
  See `src/fsm.rs`.
- [x] Immutable snapshot publication and failed-reload preservation use
  Proxima's `Live<T>`. See `src/snapshot.rs`.
- [x] Linux nftables and macOS PF plans are pure, bounded, owned plans with
  shared transactional install/verify/rollback/cleanup orchestration. See
  `src/linux_capture.rs` and `src/pf_capture.rs`.
- [x] Telemetry action labels preserve the selected policy action. See
  `src/lib.rs`.
- [x] The GitHub-sourced all-target test gate currently passes 36 tests:
  `RUSTC_WRAPPER= CARGO_TARGET_DIR=/tmp/blackhole-github-target CARGO_BUILD_JOBS=1 cargo test --all-targets --locked --offline`.

## P0 — semantics and executable listener path

- [ ] Make the borrowed `QueryView`/`DecisionState` path the actual listener
  execution path. Add an integration test that sends real UDP and TCP queries
  through the listener and observes the FSM transitions.
- [ ] Replace the owned facade's temporary status mapping with a typed
  transport outcome where Proxima permits it. Preserve distinct meanings for
  `Pass`, `Reject`, `Drop`, `Nxdomain`, `Sink`, `Honeypot`, `Forward`, and
  `Observe`; do not turn `Drop` into NODATA.
- [ ] Define and test QR-bit, question-count, question-name, qtype, qclass,
  and unsupported-IDNA validation at the policy/listener boundary.

## P0 — forwarding

- [ ] Add upstream configuration to `Config` and `main`, using only
  `proxima_dns::DnsClientUpstream`.
- [ ] Define bounded timeout, retries, response size, and outstanding-request
  behavior; prevent forwarded traffic from looping back into Blackhole. Add
  global/per-client admission limits and an upstream circuit breaker.
- [ ] Add deterministic fake-upstream tests for success, timeout, malformed
  reply, oversized reply, spoofed sender, ID mismatch, cache hit, stale entry,
  negative caching, and fail-closed behavior.
- [ ] Add a loopback resolver fixture covering UDP success and TCP/TC fallback.

## P1 — capture lifecycle

- [ ] Add platform-specific privileged backends behind platform modules only.
- [ ] Make nftables rendering and inbound-port capture pass a real privileged
  or loopback smoke test.
- [ ] Persist ownership/recovery state so crash and reboot cleanup removes only
  Blackhole-owned rules.
- [ ] Add Linux and macOS compile lanes and record capability failures as
  explicit results.

## P1 — snapshots and telemetry

- [ ] Add concurrent-reader tests during repeated reload and measure reload
  latency plus retained old-snapshot memory bounds.
- [ ] Emit parser, FSM, adapter, and upstream failure causes through Proxima's
  existing logging/telemetry primitives.
- [ ] Add latency histograms and use Proxima recording primitives for any
  deterministic replay; do not add a parallel replay abstraction.

## P1 — security and privacy

- [ ] Add rebinding, amplification, malformed-name, wildcard-bypass, and
  client-metadata spoofing tests.
- [ ] Add optional GeoIP country/region/ASN policy with an observe-only mode;
  define database provenance, update/expiry behavior, unknown-location
  handling, privacy controls, and tests for proxy/VPN/unknown classifications.
- [ ] Add DNS abuse-resistance tests for rate limits, `ANY` refusal,
  amplification bounds, concurrent outstanding work, and circuit recovery.
- [ ] Either implement IDNA/confusable-name policy or explicitly reject
  unsupported IDNA with a typed error.
- [ ] Define credential and payload retention, redaction, access control, and
  deletion verification before adding a honeypot terminal.
- [ ] Add fuzz targets/corpus and run dependency audits.

## P2 — performance evidence

- [ ] Instrument allocations and copies at parse, canonicalization, match,
  encode, and transport boundaries.
- [ ] Measure scalar, chunked/memchr, and SIMD arms on small, long,
  adversarial, mixed, and end-to-end workloads. Record p50/p95/p99, CoV,
  allocations, copies, RSS, and throughput.
- [ ] Evaluate the pure policy/codec WASM edge experiment only after native
  measurements; retain scalar fallback unless end-to-end evidence wins.
- [ ] Do not describe the implementation as zero-copy, production-grade, or
  fast without the corresponding evidence.

## P2 — release gate

- [ ] Run fmt/check/tests/nextest/doctests against the GitHub dependency.
- [ ] Run examples and a real UDP/TCP resolver fixture.
- [ ] Run no-std, Prime Linux/macOS, and Tokio compatibility builds.
- [ ] Run fuzz, dependency, and privileged capture audits.
- [ ] Attach commit, source revision, toolchain, corpus, machine, and command
  metadata to every published artifact.

## Working rules

- Keep end-user docs in `README.md`, `blackhole.example.toml`, and `examples/`.
- Keep source-of-truth behavior in code and tests; do not recreate deleted
  internal docs as release evidence.
- Reuse Proxima pipes, parser, telemetry, recording, and snapshot primitives.
- Keep client/original-destination metadata in adapters; do not infer it from
  DNS payloads.
- Every completed item needs a source location, test, command, or artifact.
