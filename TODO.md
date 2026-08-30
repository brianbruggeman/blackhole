# blackhole implementation plan

This is the working plan for a Proxima-native interception system: a policy
engine plus protocol/capture adapters, not a monolith.

## 0. product boundary

- [x] Define the first shipped surface as DNS interception over UDP and TCP.
- [ ] Write the threat model: accidental outage, resolver fail-open/fail-closed,
  spoofed source, malformed packets, reflection/amplification, privacy, and
  honeypot data retention.
- [ ] Specify action semantics independently of transport:
  `Pass`, `Drop`, `Reject`, `Nxdomain`, `Sink`, `Honeypot`, `Forward`, and
  `Observe`; define whether each action emits bytes, metadata, or nothing.
- [ ] Define policy precedence, default action, domain canonicalization,
  wildcard/suffix rules, qtype/qclass rules, client/network scopes, and an
  explicit rule for unknown protocols.
- [ ] Define the operator contract: safe local default, explicit bind scope,
  privileged-port handling, graceful drain, config errors before bind, and
  fail-closed behavior when a policy cannot be loaded.
- [ ] Make production defaults loopback-only and unprivileged. Missing config
  must not silently bind `0.0.0.0` or create an open resolver; an explicitly
  requested missing file must fail before any socket is bound.
- [ ] State non-goals for v1: TLS decryption, payload inspection, arbitrary
  packet rewriting, credential collection, and silently forwarding unknown
  traffic.

## 1. Proxima shape and RISC review

- [ ] Read the current source of truth before adding a type; first attempt each
  behavior as a composition of existing `Pipe`, `SendPipe`, filter, fan-out,
  observe, and listener primitives.
- [ ] Keep `proxima-dns` types at the wire facade only. Do not make the policy
  engine depend on sockets, an executor, Tokio, or a global configuration.
- [ ] Make the core contract one pipe-shaped operation, for example:
  `PacketView -> Result<Decision, PolicyError>` or
  `QueryView -> Result<Action, PolicyError>`; prove whether existing Proxima
  request/response pipes can express it before introducing a new trait.
- [ ] Add only types that carry a real capability: borrowed views, discriminated
  FSM states, bounded rule storage, or an OS adapter. Record the call-site proof
  for every new public type.
- [ ] Keep capture, protocol, policy, action, forwarding, and telemetry as
  replaceable pipes. The listener owns I/O; pipes own meaning.
- [ ] Preserve config/builder parity: one typed config schema drives TOML,
  environment settings, CLI validation, and the control plane.

## 2. sans-IO protocol and capture FSMs

- [ ] Create a standalone protocol crate/module with no sockets, executor,
  filesystem, or OS dependencies in its lowest tier.
- [ ] Model each connection/datagram parser as an exhaustive enum FSM, not
  booleans plus a mutable state bag. Minimum states:
  `NeedHeader`, `NeedBody`, `Classified`, `Policy`, `Emit`, `Dropped`, `Closed`.
- [ ] Define explicit events and transition errors for truncation, oversized
  frames, invalid lengths, unsupported protocol, timeout, and peer close.
- [ ] Use borrowed frame/query views (`parse(&[u8]) -> ...`) and caller-owned
  output buffers (`encode(&mut [u8]) -> ...`) in the sans-IO tier.
- [ ] Make ownership conversion a named edge operation. The core must not clone
  packet payloads merely to pass them between classifier and policy pipes.
- [ ] Bound every parser buffer, queue, rule expansion, and honeypot response;
  reject hostile sizes before allocation.
- [ ] Add model/property tests for every FSM transition, including malformed,
  partial, repeated, close, and recovery sequences. Add fuzz targets before
  enabling live capture.
- [ ] Keep the Proxima DNS listener adapter as a compatibility facade while the
  lower borrowed codec/FSM matures. Replace the temporary `204` no-reply
  convention with a typed transport outcome if the shared listener contract
  can support it without duplicating the DNS stack.

## 3. policy/index design

- [ ] Start with a correctness reference policy using sorted canonical rules;
  include exact, suffix, wildcard, qtype, client, and priority cases.
- [ ] Choose the production index from measurements: reverse-label trie,
  compact FST, minimal perfect hash, or another bounded representation. Do not
  use a linear `Vec` scan for the production hot path.
- [ ] Make read-side policy snapshots immutable and lock-free. Reload builds a
  complete new snapshot off-path, validates it, then swaps one pointer.
- [ ] Make canonicalization explicit and allocation-free in the query path:
  case folding, root-dot handling, label boundaries, IDNA policy, and malformed
  names must have exact tests.
- [ ] Keep rule storage mmap/compact where useful; document the tier and memory
  budget. No heap allocation in parse, classify, match, or score after warmup.
- [ ] Treat SIMD as an opt-sweep candidate, not a design premise. Benchmark
  scalar, memchr/chunked, and SIMD implementations on realistic small DNS
  names, long names, adversarial names, and mixed batches; retain SIMD only if
  the end-to-end result wins.
- [ ] If a scoring/ranking action is added, complete a paper-derived worked
  example before implementation and lock it as an exact test.

## 4. action and pipe graph

- [ ] Implement action selection as a pure, deterministic pipe over a borrowed
  query/context view.
- [ ] Compose independent concerns as pipes: normalize → classify → policy
  lookup → action → observe → encode/forward.
- [ ] Make `Drop`/`Ignore` a first-class outcome rather than an overloaded DNS
  status. Every transport adapter must map it to its own correct no-output or
  close behavior.
- [ ] Make unmatched DNS forwarding the explicit normal path once an upstream
  exists. Never represent “allowed” as empty-success NODATA; that breaks normal
  resolver operation and makes the daemon an accidental sinkhole.
- [ ] Make honeypot replies protocol-valid, bounded, non-reflective, and clearly
  synthetic. Never echo secrets or attacker-controlled payloads by default.
- [ ] Make forwarding explicit and bounded: upstream selection, timeout,
  retry/failover, cache behavior, recursion flags, loop prevention, and what
  happens when upstream is unavailable.
- [ ] Add replayable decision traces at the observe pipe without adding work to
  disabled telemetry and without retaining payloads by default.

## 5. native capture adapters

- [ ] Linux: specify supported deployment modes separately—local DNS bind,
  nftables redirect/TProxy, transparent TCP/UDP, and optional eBPF/XDP. Each
  mode gets an adapter FSM and capability/error contract; no privileged setup
  is hidden inside the policy crate.
- [ ] macOS: specify PF/rdr or divert/TUN integration separately from the DNS
  listener. Document required rules, cleanup, permissions, and recovery after
  crash.
- [ ] Make both adapters runtime-agnostic at the boundary; drive them with
  Prime first and retain a Tokio compatibility path where Proxima already
  provides one.
- [ ] Keep platform code behind feature flags and compile-test both platforms
  in CI. No Linux-only headers or macOS-only APIs in shared modules.
- [ ] Add an install/uninstall/status command only after the rule lifecycle is
  transactional, inspectable, and recoverable.
- [ ] Do not add WASM to native capture. Evaluate WASM only for a measured edge
  policy/codec deployment where its host ABI and latency budget are proven.

## 6. performance and disciplined-component gates

- [ ] Create `scripts/component-gate.sh`, a versioned discipline log, and a
  default-off feature for each new performance-sensitive primitive.
- [ ] Establish incumbents before optimization: a simple reference matcher,
  the current Proxima DNS path, and an appropriate system resolver/capture
  baseline. Include incumbent-favored workloads; do not benchmark only the
  design's home turf.
- [ ] Benchmark query sizes, rule counts, hit/miss ratios, suffix depth,
  malformed traffic, burst/concurrency, cold/warm snapshots, and reloads.
- [ ] Record throughput, p50/p95/p99 latency, allocations, bytes copied, RSS,
  CPU, drop/error counts, coefficient of variation, and platform/toolchain.
- [ ] Gate targets such as 55 MB/s sustained, sub-1 ms p99, and a 500 MB
  resident-memory ceiling only with artifacts; no prose claim is evidence.
- [ ] Run optimization in this order: representation, ownership, algorithm,
  batching, branch/layout, memchr, then SIMD. Every change gets a before/after
  result and is reverted when the realistic end-to-end score loses.
- [ ] Add Prime-vs-Tokio comparisons without changing policy semantics; explain
  any win as capability or measured performance, never assumption.

## 7. correctness, security, and operations

- [ ] Differential-test DNS wire behavior against a reference resolver for
  valid, truncated, compressed, multi-question, EDNS, TCP-framed, and malformed
  inputs.
- [ ] Add deterministic integration tests for UDP and TCP, no sleeps, with
  real-world fixtures and explicit packet ownership assertions.
- [ ] Add fuzzing for every parser/FSM and configuration loader; enforce caps
  under fuzz and live operation.
- [ ] Add security review for spoofing, amplification, cache poisoning, policy
  bypass via encoding/IDNA, privilege boundaries, rule installation, logs, and
  honeypot data handling.
- [ ] Use Proxima telemetry only: sparse causal info/error events, debug state
  transitions, counters/histograms for decisions, and bounded export sinks.
- [ ] Add health/readiness, config validation, graceful shutdown, reload status,
  and an explainable decision path without exposing query payloads by default.
- [ ] Add macOS and Linux CI, debug/all-targets checks, docs tests, examples,
  fuzz smoke tests, and a privileged integration lane for capture adapters.

## 8. delivery order and exit gates

- [ ] **Phase A — contract:** threat model, action semantics, RISC review,
  config schema, and paper examples approved.
- [ ] **Phase B — core:** borrowed sans-IO DNS/query FSM, deterministic policy
  pipe, typed action outcome, reference matcher, unit/property/fuzz tests.
- [ ] **Phase C — facade:** Proxima UDP/TCP adapter, Prime/Tokio drive paths,
  config parity, telemetry, replay, and end-to-end resolver tests.
- [ ] **Phase D — production index:** immutable snapshot/index implementation,
  reload FSM, allocation/copy instrumentation, incumbent comparison, and
  disciplined-component gate.
- [ ] **Phase E — forwarding:** bounded upstream pipe, cache/loop semantics,
  failure tests, and resolver differential tests.
- [ ] **Phase F — OS capture:** Linux adapter, then macOS adapter, each with
  transactional lifecycle and privileged CI proof.
- [ ] **Phase G — hardening:** security sign-off, resource budgets, packaging,
  uninstall/recovery, operator docs, and release artifact verification.
- [ ] **Final gate:** `cargo check --all-targets`, `cargo test --doc` with a
  nonzero matched-test assertion, nextest when available, examples actually
  run, fuzz smoke, both platform builds, and published benchmark artifacts.

## Sol review corrections to preserve during execution

Sol’s independent review establishes these implementation constraints:

- The current global mode plus flat domain vector is not production policy.
  Rules need deterministic priority/specificity, explicit allow rules,
  qtype/class, client scope, profiles, and an upstream pool. Keep the slow
  matcher as the semantic oracle.
- The current `Policy` is asynchronous only because it implements the owned
  `DnsPipe` facade. The decision algorithm itself must be synchronous,
  borrowed, deterministic, and sans-IO; async belongs around forwarding,
  capture, telemetry, and bounded terminal work.
- “Honeypot” is not synonymous with “return a documentation address.” A DNS
  sink target and connection honeypot are separate capabilities; the latter
  needs original-destination routing, a bounded terminal, egress isolation,
  profile selection, and a retention policy.
- The first native milestone is explicit DNS interception. Transparent L4
  interception is a privileged, optional capability layer. It must not be
  smuggled into the DNS policy crate or made a dependency of normal users.
- Existing Proxima packet paths and the current Blackhole owned pipe have not
  demonstrated zero-copy, zero-allocation, or lock-free behavior. Treat those
  as hypotheses until allocation/copy/lock instrumentation and incumbent
  comparisons produce artifacts. Do not use “fast” in user-facing claims before
  that evidence exists.
- Reuse the existing Proxima DNS parser, borrowed name/label iteration, listener
  facade, pipe combinators, live immutable snapshot primitive, recording pipes,
  telemetry, and `proxima-intercept` facilities where their source contracts
  fit. A parallel DNS parser, runtime, telemetry system, or generic pipe layer
  is a RISC failure.
- Prime is the native default and Tokio is compatibility. Neither runtime’s
  types may leak into the policy contract. Linux and macOS adapters must expose
  capability errors and transactional rollback rather than silently degrading.
- WASM is not a native hot-path escape hatch. Sol’s ruling is to evaluate it
  only as an edge policy experiment after measuring host-call and linear-memory
  copies against the scalar native implementation on the same corpus.

The first four implementation commits therefore have a fixed order: (1) write
the contract and baselines, (2) add a typed borrowed DNS disposition seam and
remove the status sentinel, (3) build the compiled immutable policy snapshot
with forwarding as the unmatched path, and (4) add resolver/cache behavior.
Do not start PF, nftables, XDP, TCP honeypot terminals, SIMD, or WASM before
those four commits have passed their gates.

## execution protocol for a Luna implementer

Each unchecked item below is an executable work packet. Work top to bottom
unless marked parallel; the boundaries are review and rollback units.

For every packet:

1. Read the referenced Proxima source before choosing an API. Cite the exact
   file and line in the design note or PR description.
2. Write the smallest test or worked example that proves the intended
   behavior, including one sad path.
3. Implement the behavior behind the narrowest feature that can compile.
4. Run the packet's acceptance commands and save their output under
   `artifacts/<packet>/` when the packet produces a measurement.
5. Update this file only by checking the item after its acceptance gate passes.
6. Record open risks and deviations in `docs/decisions.md`; never hide an
   unresolved design choice in an implementation detail.

Do not add a dependency, public trait, lock, heap allocation, SIMD
implementation, or OS privilege operation without its decision and test task.
A compile success is not a performance or security result.

## task cards

### B0 — source map, contract, and crate graph

- Read `slot-0/AGENTS.md`, the guiding-principles and disciplined-component
  skills, Proxima’s pipe primitives, DNS facade, listener, and Prime features.
- Create `docs/source-map.md` and `docs/contract.md`: cite reusable primitives,
  action-to-wire outcomes, unmatched behavior, precedence, canonicalization,
  scope, decision-record fields, and all non-goals before changing behavior.
- Define lowest-tier `std`/`alloc`/DNS surfaces and native Prime plus Tokio
  compatibility features. Keep OS imports out of the core and keep experimental
  indexes default-off.
- Acceptance: every API claim has a source citation, contract examples parse,
  every action has positive/negative examples, and `cargo check --all-targets`
  plus the lowest-tier and dependency-tree checks pass.

### B3 — derive the policy algorithm on paper

- Use the following fixed example as the first proof. Rules, in precedence
  order, are `ads.example -> Nxdomain`, `*.telemetry.example -> Ignore`, and
  `telemetry.example -> Honeypot(A=192.0.2.1)`. Queries are
  `ads.example. A`, `x.ads.example. A`, `telemetry.example. A`,
  `x.telemetry.example. A`, and `notexample. A`.
- Derive the exact match and action for every query by hand, including the
  apex-versus-descendant distinction and the tie between wildcard and apex.
- Write pseudocode with named inputs, lookup order, boundary tests, output, and
  error behavior. Walk the same five queries through the pseudocode.
- Encode the paper result as a test before optimizing. If the algorithm cannot
  be tested without the live listener, split it until it can.
- Acceptance: paper inputs and expected outputs are in `docs/policy-proof.md`,
  and the exact test passes. Any later index must reproduce these outputs.

### B4 — build the borrowed DNS/query surface

- Implement or reuse a borrowed query view at the lowest supported tier. It
  must expose id, flags needed for policy, qname labels, qtype, qclass, and
  bounded extension metadata without allocating.
- Keep wire parsing and encoding in a sans-IO FSM. The caller supplies input
  bytes and output storage; the FSM reports `NeedMore`, `Ready`, `Drop`, or a
  typed protocol error rather than blocking or reading a socket.
- Preserve DNS compression safety: pointers must be bounded, forward-progress
  must be proven, loops must be rejected, and the parser must never index past
  the caller's slice.
- Add vectors for root name, maximum legal labels, compressed names, EDNS,
  truncated UDP, TCP length prefixes, multi-question input, and invalid pointer
  loops. Use actual captured/public resolver packets where licensing permits.
- Acceptance: lowest-tier tests run without Prime, Tokio, filesystem, or network
  initialization; fuzzing can call parse/encode directly.

### B5 — implement the decision FSM

- Define an enum whose variants own only the data valid in that state. The
  initial proposed states are `Received`, `Parsing`, `Parsed`, `Matched`,
  `Forwarding`, `Responding`, `Dropped`, and `Closed`; revise only with a
  written state invariant.
- Transitions consume the current state and return the next state plus an
  event. Illegal transitions must be unrepresentable or return a named error.
- The FSM must accept one datagram at a time and must never retain a borrowed
  slice beyond the caller-controlled step. TCP framing may retain only a
  bounded partial frame in its explicit state.
- Add transition tests for partial input, retrying with more bytes, malformed
  input, policy error, drop, response buffer too small, peer close, and a second
  message on a healthy TCP connection.
- Acceptance: a state-transition table in `docs/fsm.md` matches the enum and
  tests cover every enum variant and error branch.

### B6 — implement reference policy as a pipe

- Implement the simplest correct matcher first, even if it linearly scans
  rules. The purpose is an oracle for later compact indexes, not a claimed
  production implementation.
- Make rule inputs immutable for calls. Use explicit rule ids and precedence;
  never depend on insertion order unless the contract says insertion order is
  the precedence.
- Avoid a global singleton and avoid a mutex around reads. The call must be
  deterministic for the same snapshot and query context.
- Add tests for exact/suffix/wildcard boundaries, case normalization, root dot,
  qtype mismatch, client scope, precedence, duplicate rule rejection, and an
  empty policy.
- Acceptance: `cargo test` passes, the paper proof passes, and the reference
  matcher is used as the oracle in the first benchmark rather than discarded.

### B7 — formalize action outcomes at the transport edge

- Replace status-code conventions in the policy contract with a typed outcome
  if the existing Proxima listener can be extended without breaking consumers.
  If it cannot, document the adapter-only mapping and keep the lowest tier
  independent of it.
- Define the mapping table for UDP, TCP, and future transparent streams. A
  `Drop` must not accidentally become NODATA; a `Reject` must not become a
  reflection amplifier; a `Forward` must not loop back into Blackhole.
- Add tests that assert both the decision and the exact emitted-byte/no-byte
  result at the adapter boundary.
- Acceptance: no action's meaning depends on an undocumented HTTP-like status
  field; existing Proxima DNS tests and Blackhole integration tests remain
  green.

### B8 — choose and build the production rule index

- Capture a rule corpus fixture with small (100), medium (10k), and large
  (1m+) rule sets, including adversarial shared suffixes and long labels.
- Benchmark reference sorted scan, reverse-label trie, compact FST, and perfect
  hash only where their semantics fit. Measure build time and memory as well
  as lookup. Include misses, apex hits, deep suffix hits, wildcard hits, and
  malformed names.
- Select one representation with a decision record that names the workload it
  optimizes, memory bound, reload cost, and feature/tier availability. Keep the
  reference implementation for differential tests.
- Acceptance: `artifacts/index/` contains source version, machine/toolchain,
  corpus checksum, allocation counts, p50/p95/p99, throughput, RSS, and a
  signed-off incumbent-favored result. No “zero-copy” or “O(1)” label appears
  without the measurement that supports it.

### B9 — make snapshots reloadable

- Define a reload FSM: `Unloaded`, `Loading`, `Validated`, `Published`,
  `Rejected`, and `Retired`. Loading and validation occur off the request path.
- Publish an immutable snapshot with an atomic pointer swap or existing Proxima
  lock-free snapshot primitive. Readers must see either old-valid or
  new-valid, never a partially built index.
- Enforce rule-count, file-size, nesting, and memory limits before publication.
  Keep the previous snapshot on failure and emit one causal error event.
- Add deterministic tests for concurrent readers conceptually through the
  chosen snapshot primitive, failed reload, repeated reload, and retirement.
- Acceptance: a reload benchmark shows lookup latency before/during/after
  publication, with zero request-path blocking and bounded old-snapshot memory.

### B10 — add observability as a pipe

- Build an observe pipe around decisions, not a second side-channel data path.
  It must be removable with no semantic change and near-zero disabled cost
  shown by benchmark.
- Use Proxima telemetry macros and instruments only. Emit sparse info/error
  causes, debug FSM transitions, and bounded counters/histograms for action and
  parser outcomes. Never log full payloads or secrets by default.
- Add optional deterministic replay records containing enough metadata to
  reproduce a decision while redacting or hashing names according to config.
- Acceptance: telemetry tests prove labels are bounded, a failed adapter is
  explainable from info/error, and disabled instrumentation does not change
  action output or allocation measurements.

### B11 — add forwarding only after sink behavior is stable

- Model upstream resolution as a separate pipe. Define timeout, retry, max
  response size, cache TTL, negative caching, recursion-bit handling, and loop
  prevention before coding.
- Add an in-process fake upstream for deterministic tests and one real-resolver
  differential lane. Never make network access necessary for unit tests.
- Ensure forwarded packets cannot be mistaken for fresh inbound traffic by the
  capture adapter. Preserve transaction ids safely and bound outstanding work.
- Acceptance: tests cover upstream success, timeout, malformed upstream reply,
  overflow, loop prevention, cache hit, stale entry, and fail-closed policy.

### B12 — Linux capture adapter

- Start with a documented nftables redirect/TProxy mode and a dry-run rule
  planner. The planner is pure data; installation is a privileged facade.
- Define ownership of original destination, client address, interface, mark,
  and reply routing. Preserve these in a bounded adapter context passed to the
  policy pipe; do not infer them from payload bytes.
- Implement transactional install, verify, rollback, status, and cleanup. A
  crash or failed partial install must leave a recoverable state and never flush
  unrelated user rules.
- Add a packet/socket FSM for accepted, parsed, policy-decided, forwarded,
  replied, dropped, timeout, and closed. Add a root-required integration lane;
  normal CI runs planner and mocked adapter tests.
- Acceptance: dry-run output is stable, rollback is tested, Linux compile and
  privileged smoke pass, and no shared crate imports Linux APIs.

### B13 — macOS capture adapter

- Choose PF/rdr, divert, or TUN only after documenting the capability needed
  for original-destination and reply routing. Keep rule generation separate
  from command execution.
- Implement install/verify/rollback/cleanup with ownership markers that cannot
  delete unrelated administrator rules. Handle reboot and crash recovery.
- Reuse the same capture context and policy pipe as Linux. Differences belong
  in the adapter and its capability report, not in policy semantics.
- Acceptance: macOS compile, planner tests, cleanup tests, and a manually
  verified loopback smoke are recorded. Unsupported capabilities return typed
  errors rather than silently degrading.

### B14 — SIMD, zero-copy, and edge/WASM decision gate

- Instrument allocation and copy counts at parse, canonicalization, match,
  encode, and transport boundaries before optimizing.
- Run scalar versus memchr/chunked versus SIMD arms on realistic small names,
  long names, adversarial names, mixed hit/miss batches, and full end-to-end
  requests. Include startup/index-build cost separately.
- Only retain SIMD if it improves the buyer-relevant end-to-end workload and
  does not violate target portability. Document CPU feature detection and the
  scalar fallback.
- Compile the pure policy/codec for WASM only as an edge experiment. Measure
  ABI crossing, linear-memory copies, cold start, and sustained latency. Do not
  call it performant because the inner loop alone is fast.
- Acceptance: a discipline log records every arm, coefficient of variation,
  allocation/copy count, and decision. “Zero-copy” means an instrumented fact,
  not a type signature or comment.

### B15 — security and privacy review

- Review parser bounds, compression loops, DNS rebinding, IDNA confusion,
  wildcard bypass, spoofed client metadata, reflection/amplification, cache
  poisoning, privilege escalation, rule lifecycle, and denial-of-service.
- Define honeypot data policy: no credential collection, no payload retention by
  default, bounded retention when explicitly enabled, redaction, access control,
  and deletion verification.
- Add adversarial fixtures and a security checklist to CI. Treat every parser
  fuzz finding as a release blocker until reproduced and fixed.
- Acceptance: a signed threat-model document, fuzz corpus, dependency audit,
  and explicit fail-open/fail-closed decision for every adapter failure.

### B16 — final Luna handoff gate

- Run `cargo fmt --check`, `cargo check --all-targets`, unit/property tests,
  `cargo test --doc` with a nonzero matched-test assertion, and nextest when
  installed.
- Run each example against loopback without sleeps, then the UDP/TCP resolver
  integration fixture. Record exact commands and outputs.
- Build the lowest tier without std, native Prime on Linux and macOS, and the
  Tokio compatibility feature. Build each platform adapter even if the current
  host cannot execute it.
- Publish benchmark and fuzz artifacts with commit hash, corpus checksum,
  machine, OS, compiler, feature set, and result interpretation.
- Acceptance: every checked item in this document points to an artifact,
  passing test, or reviewed decision. Remaining unchecked items are explicitly
  outside the release scope, never silently omitted.
