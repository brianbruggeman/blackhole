# Blackhole decisions

## B0-001 — keep the existing DNS facade and isolate future sans-IO policy

- Problem: the listener currently accepts an owned asynchronous `SendPipe`,
  while policy matching must be deterministic and independent of I/O.
- Decision: retain Proxima's DNS facade at the edge and introduce any borrowed
  query/disposition seam below it in later packets.
- Evidence: `../../proxima/proxima-dns/src/pipes.rs:23-39,94-151` and
  `../../proxima/proxima-primitives/src/pipe/primitives.rs:104-124`.
- Risk: the adapter currently allocates owned query/answer values and cannot
  represent silent drop as a typed outcome.
- Follow-up gate: B4 and B7 must add tests before the current convention is
  removed.

## B0-002 — safe startup defaults

- Decision: default to `127.0.0.1:5353`; an explicitly named missing or invalid
  config fails before listener construction.
- Rationale: a local interception tool must not become an accidentally exposed
  resolver, and configuration errors must not occur after bind.
- Evidence: `src/main.rs` constructs the listener only after config parsing and
  bind parsing; `src/lib.rs` owns the default listen value.
- Test: `cargo test -p blackhole` covers the default address; `cargo check
  --all-targets -p blackhole` covers the startup compilation path.

## B4-001 — reuse Proxima's borrowed DNS message and name walk

- Problem: policy needs query metadata without copying the wire name.
- Decision: `query::QueryView::parse` delegates complete-message validation to
  `proxima_protocols::dns::parse_message` and stores its borrowed `Name` view.
- Evidence: `../../proxima/proxima-protocols/src/dns/codec_trait.rs:159-190` and
  `../../proxima/proxima-protocols/src/dns/mod.rs:142-175` provide validated lazy
  section/name traversal; `blackhole/src/query.rs` narrows that contract.
- Resource bound: no name materialization or allocation is performed by the
  view constructor; the caller owns the packet lifetime.
- Risk: complete-message parsing is atomic and cannot report TCP `NeedMore`;
  the B5 framing FSM must wrap the reusable `DnsTcpCodec` before live use.
- Test: `query::tests` covers valid, truncated, multi-question, root, and
  pointer-loop inputs.

## B6-001 — retain a linear reference matcher as the semantic oracle

- Problem: the existing global mode plus domain vector cannot express
  deterministic per-rule actions or query-context filters.
- Decision: `policy::ReferencePolicy` stores validated immutable rules and scans
  them linearly for correctness. It chooses by priority, exactness, client
  specificity, query specificity, and explicit rule ID.
- Evidence: `blackhole/src/policy.rs`; the fixed five-query proof remains in
  `blackhole/src/lib.rs` and `blackhole/docs/policy-proof.md`.
- Compatibility: legacy `mode`/`domains` remain available when no rule table
  is configured. A configured rule table is selected first.
- Risk: linear lookup is an oracle, not a production performance claim; B8
  must benchmark it against candidate indexes before replacing it.
- Tests: exact/wildcard boundaries, case/root normalization, qtype/client
  filters, precedence, duplicate IDs, and invalid wildcard rejection.

## B7-001 — pipe output carries the policy reply/drop distinction

- Decision: `Policy::evaluate` returns `Option<DnsAnswer>` as its output:
  `Some` emits a DNS reply and `None` emits no DNS message. This reuses the
  existing pipe-shaped output convention instead of adding an outcome wrapper.
- Compatibility: `SendPipe::call` still maps Drop to the Proxima facade's
  existing status `204` sentinel because that facade currently accepts only an
  owned `DnsPipeReply`. The sentinel is confined to this adapter method and is
  not part of policy semantics.
- Evidence: `blackhole/src/lib.rs`; Proxima's response type is documented at
  `../../proxima/proxima-dns/src/pipes.rs:56-98`.
- Tests: `typed_drop_maps_to_no_udp_datagram_and_no_tcp_message` asserts the
  output and no-output mapping.
- Open risk: B7's remaining adapter integration must replace the compatibility
  sentinel if the shared listener contract gains a typed silent outcome.

## B8-001 — benchmark harness is Rust-only; index selection remains open

- Decision: keep the benchmark in `examples/index_benchmark.rs`; it generates
  the corpus, measures build/hit/miss paths, and writes its artifact directly.
  No shell script is part of the implementation.
- Evidence: `artifacts/index/reference-linear.txt` contains completed 100-rule
  and 10,000-rule rows. The benchmark now uses the enforced `MAX_RULES`
  security ceiling (100,000), not a corpus that policy construction must reject.
- Status: no production index is selected from the partial artifact. A future
  large-corpus comparison must either raise the reviewed policy limit or use a
  separately bounded index-build fixture.
- Next gate: produce a complete maximum-bound result with memory and
  process-exit data, then compare a candidate index against this reference.

## B8-002 — canonicalize the query once per reference lookup

- Observation: the initial Rust benchmark caused the reference matcher to
  canonicalize the same query once per candidate rule.
- Change: `ReferencePolicy::decide` now canonicalizes once and passes the
  canonical name to each rule predicate.
- Evidence: `blackhole/src/policy.rs`; the regenerated artifact records
  `100` rules at `hit_ns=1930` and `miss_ns=1778`, and `10,000` rules at
  `hit_ns=162216` and `miss_ns=112694` in the debug Rust run.
- Status: correctness validated; performance values are environment-specific
  debug measurements and are not a production-index selection.

## B8-003 — reverse-label bucket candidate

- Decision: add `IndexedPolicy` as a candidate that buckets rules by their
  canonical suffix and reuses the reference rule predicate and precedence
  comparator.
- Evidence: `blackhole/src/policy.rs` and
  `indexed_candidate_matches_reference_for_fixed_proof`.
- Status: semantic parity is tested only on the fixed proof. Build cost,
  memory, adversarial suffixes, and large-corpus latency remain unmeasured;
  this candidate is not yet the production index.

## B9-001 — use Proxima `Live<T>` for policy publication

- Decision: `snapshot::PolicyStore` pairs `Live<ReferencePolicy>` with its
  `LiveControl` half. Reload validates a complete new reference policy before
  one wholesale replacement.
- Evidence: `../../proxima/proxima-core/src/live.rs:45-80,92-108` documents
  lock-free reads and out-of-band replacement; `blackhole/src/snapshot.rs`
  implements the narrow policy-specific controller.
- Tests: failed reload preserves the prior valid snapshot; successful reload
  replaces it atomically from the reader's perspective.
- Risk: retirement memory and reload latency still need measurement once the
  production index is selected.

## B10-001 — observe decisions through the existing pipe boundary

- Decision: `Policy` accepts an optional Proxima `TelemetryHandle` and observes
  the existing `Option<DnsAnswer>` result inside `SendPipe::call`. No second
  data path, wrapper outcome type, or new pipe trait is introduced.
- Disabled path: the handle's `is_active()` gate runs before constructing
  `Labels`; an absent handle and Proxima's no-op handle therefore preserve the
  decision path without telemetry label work.
- Cardinality: the counter is `blackhole.decisions` with exactly one static
  label, `action={reply,drop}`. Query names, payloads, and other unbounded
  values are never emitted.
- Evidence: `blackhole/src/lib.rs`; the telemetry test verifies that the
  observed output remains `None` for a drop and that the label set is bounded.
- Scope: parser/FSM causal events and deterministic replay records remain
  deferred until those paths are connected to the listener and recording
  primitives; this change does not invent a parallel logging or replay type.

## B11-001 — reuse Proxima's DNS upstream pipe

- Decision: `Policy::with_upstream` stores the existing
  `proxima_dns::DnsClientUpstream`, configured with an injected
  `DatagramFactory` and `DnsResolverConfig`. A `Forward` rule routes through
  that pipe from the existing `SendPipe` implementation.
- Safety: forwarding is opt-in. A `Forward` rule without an upstream produces
  the existing no-output sentinel (`204`) rather than an empty-success DNS
  answer, so an unavailable upstream fails closed.
- Inherited bounds: Proxima's upstream retries according to
  `max_attempts`, uses a fixed 4096-byte UDP receive buffer, preserves the
  query ID, requires the configured resolver as the sender, sets RD, and
  rejects malformed or mismatched replies. Its fake datagram factory tests
  cover success, timeout/retry, malformed replies, overflow, and sender/ID
  mismatches without network access.
- Evidence: `blackhole/src/lib.rs`; upstream implementation and deterministic
  transport tests are in `../../proxima/proxima-dns/src/client/pipe.rs`.
- Open boundary: caching, stale-entry policy, and loop prevention across a
  multi-hop forwarding graph require a configured upstream topology and are
  deferred until the forwarding path has an actual upstream pool. No cache or
  loop type is added to the policy pipe prematurely.

## B12-001 — pure Linux capture planner with injected privileged capability

- Decision: keep Linux capture planning and transaction state in the portable
  `linux_capture` module. `NftRulePlan::render` is the stable dry-run surface;
  `RuleBackend` is the only installation capability.
- Ownership: `CaptureContext` carries original destination, client address,
  bounded interface, mark, and reply route from the adapter. Policy never
  reconstructs these values from packet payloads.
- Safety: installation verifies after adding rules and removes only the plan
  on verification failure. Cleanup is idempotent, and no shell command or
  script is used.
- Evidence: `blackhole/src/linux_capture.rs` and
  `blackhole/docs/linux-capture.md`; mocked tests cover stable rendering,
  bounds, rollback, install, verify, and cleanup.
- Open boundary: the actual root-required nftables backend and privileged
  smoke lane remain intentionally separate from the shared crate. This keeps
  normal builds and tests free of Linux API dependencies.

## B13-001 — PF/rdr anchor with typed unsupported capabilities

- Decision: macOS uses a pure `PfRulePlan` for an explicitly owned PF anchor.
  Installation, verification, rollback, and cleanup use the shared generic
  capture orchestration FSM and injected `RuleBackend`; rule generation is
  separate from command execution.
- Reuse: macOS shares Linux's `CaptureContext`, `ReplyRoute`, and lifecycle
  state types, so policy semantics do not fork by operating system.
- Safety: plans are bounded and tagged with a `blackhole-owned` marker;
  verification failure removes only the planned anchor. Unsupported
  original-destination/reply-routing contexts return `PfError` instead of
  silently degrading.
- Evidence: `blackhole/src/pf_capture.rs` and
  `blackhole/docs/macos-capture.md`; deterministic tests cover rendering,
  cleanup rollback, and typed capability rejection.
- Open boundary: actual `pfctl` installation and a manually verified loopback
  smoke require macOS privileges and remain outside normal Linux CI.

## B14-001 — retain scalar path; reject unsupported performance claims

- Decision: keep the current scalar Rust matcher and borrowed query parser as
  the production baseline. Do not add SIMD, memchr/chunked, or WASM arms until
  an end-to-end workload demonstrates a buyer-relevant improvement with the
  same semantics and portability requirements.
- Measurement: `examples/performance_gate.rs` is an embedded Rust gate that
  records allocator calls/bytes separately for index build, matching, and
  parsing. It records copy count as not instrumented, so zero-copy is not
  claimed.
- Evidence: `blackhole/docs/performance-gate.md`; existing B8 artifacts cover
  scalar build/hit/miss timing, while this gate adds allocation visibility.
- Status: no optimization is approved. A future arm must add CPU feature
  detection and scalar fallback, measure small/long/adversarial/mixed names,
  startup separately, and include coefficient of variation before selection.

## B15-001 — fail closed at untrusted boundaries

- Decision: enforce explicit bounds before parser/config/index work: 4096-byte
  queries, 253-byte names, 100,000 rules, and 1 MiB configuration files.
- Security shape: use existing parser, policy, pipe, and adapter FSMs. No
  parallel security or logging layer is introduced. Adapter metadata remains
  caller-owned context and unsupported capability is a typed rejection.
- Privacy: honeypot replies are synthetic bounded A/AAAA records; telemetry
  contains only static reply/drop labels; credentials, full names, and payloads
  are not retained or logged by default.
- Evidence: `blackhole/docs/security-threat-model.md`, the parser/policy
  tests, the fail-closed forwarding test, and adapter rollback tests.
- Release status: fuzz execution, dependency audit, signed threat-model
  artifact, and privileged smoke lanes are explicitly release-lane work rather
  than being represented as completed here.

## B16-001 — final handoff is evidence-backed and scoped

- Decision: publish the executed Rust gate commands and results in
  `blackhole/docs/final-gate.md`; publish the complete bounded index baseline
  in `artifacts/index/reference-linear.txt`.
- Evidence: formatting, all-targets check, 30 unit tests, one doctest,
  30-test nextest run, and both embedded examples passed. The index benchmark
  now respects the 100,000-rule security ceiling.
- Scope: live resolver integration, non-host platform builds, fuzz/dependency
  audit, signed threat-model artifact, and privileged capture smoke remain
  explicit release-lane work because this host cannot provide those proofs.
