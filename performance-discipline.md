# Blackhole performance discipline

Numbers in this file carry provenance. `MEASURED` values come from a running
counter or timer; `DERIVED` values are calculations; `ASSUMED` values are
specification choices. No row authorizes an optimization by itself.

## Row 0 — current scalar reference

`MEASURED` on 2026-08-31, Linux `x86_64`, rustc 1.98.0, release build, source
commit reported as `working-tree`:

```text
gate=b14 implementation=scalar-reference rules=10000 samples=100
build_ns=46935015 allocs=20002 alloc_bytes=2288890
match_ns=43143 allocs=100 alloc_bytes=2300
parse_ns=207 result=Err(NotSingleQuestion) allocs=0 alloc_bytes=0
copy_count=not-instrumented decision=do-not-claim-zero-copy
arms=scalar-retained memchr-not-added simd-not-added wasm-not-built
```

This row is a baseline only. It predates boundary instrumentation.

## Row 3 — pure edge-path WASM build

`MEASURED` on 2026-09-01, `wasm32-unknown-unknown`, default features disabled,
source commit `df0a437`. `cargo build --locked --no-default-features
--target wasm32-unknown-unknown --lib` completed successfully. The compiler
reported `/home/bix/.cache/cargo/wasm32-unknown-unknown/debug/libblackhole.rlib`.
The edge correctness test also passed on the host. No WASM runtime is installed
in this environment, so runtime latency, throughput, allocations, and RSS are
not measured and no WASM performance win is claimed.

## Row 1 — scalar reference with boundary counters

`MEASURED` on 2026-08-31, Linux `x86_64`, rustc 1.98.0, release build, with
the default-off `perf-instrument` feature. Three consecutive runs produced:

```text
build_ns=49691549, 50173645, 47407523
match_ns=43806, 43839, 44259
parse_ns=415, 285, 279
owned_ns=935, 824, 914
allocs=20002 alloc_bytes=2288890 (build); allocs=100 alloc_bytes=2300 (match)
policy_canonicalize=2400 borrowed_to_owned=12
tcp_frame_buffer=0 encode_output=0 transport_write=0
```

The counters measure bytes crossing named application boundaries, not every
dependency-internal memcpy. The policy and owned-conversion counters were
exercised by this example. The TCP buffering, encoding, and transport counters
remain zero because this example does not run the listener; listener coverage
must be measured through the resolver fixture before those values are used.
No optimization decision is justified by this row.

## Row 4 — current scalar reference with full sample distribution

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `c824c38`, GitHub Proxima revision `afca73c`, and load average
`1.02`. The running harness used `N=25` samples per workload:

```text
build p50_ns=47019616 p95_ns=48097121 p99_ns=50590651 cov=0.016225 allocs=250025 alloc_bytes=27722250
match p50_ns=41540 p95_ns=42618 p99_ns=43008 cov=0.012390 allocs=2500 alloc_bytes=57500
parse_short p50_ns=47 p95_ns=69 p99_ns=491 cov=1.315419 allocs=0 alloc_bytes=0
parse_long p50_ns=228 p95_ns=271 p99_ns=279 cov=0.057121 allocs=0 alloc_bytes=0
parse_adversarial p50_ns=79 p95_ns=87 p99_ns=123 cov=0.107679 allocs=0 alloc_bytes=0
parse_mixed p50_ns=80 p95_ns=243 p99_ns=253 cov=0.639077 allocs=0 alloc_bytes=0
owned p50_ns=119 p95_ns=149 p99_ns=471 cov=0.506894 allocs=50 alloc_bytes=400
encode_response p50_ns=99 p95_ns=272 p99_ns=503 cov=0.691849 allocs=50 alloc_bytes=1450
boundary_bytes=MEASURED policy_canonicalize=60000 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0 rss_kib=5436
arms=scalar-retained memchr-not-added simd-not-added wasm-edge-compile-only wasm-runtime-not-installed
```

Throughput values printed by the harness are `DERIVED` from the measured
durations and operation counts. The zero transport counters are a property of
this pure harness; the listener fixture remains the authority for transport
boundaries. No optimization or zero-copy claim follows from this row.

The actual listener fixture was then run with the same feature and
`--nocapture`. `MEASURED` boundary totals were:

```text
listener_boundary_bytes=Snapshot {
    policy_canonicalize: 28,
    borrowed_to_owned: 28,
    tcp_frame_buffer: 31,
    encode_output: 120,
    transport_write: 120,
}
```

The fixture asserts every total is nonzero while exercising both UDP and TCP.

## Row 2 — distribution-reporting harness

`MEASURED` on 2026-08-31, Linux `x86_64`, rustc 1.98.0, release build, with
the default-off `perf-instrument` feature. Three consecutive runs used
Proxima GitHub revision `0652a0c0a9c4d10e745f5428b251a98648b4f64e`, source
commit `74ea46a`, and a clean `/tmp` target directory. Each run contains five
samples per operation; match contains 100 decisions per sample. Values below
are the observed ranges across the three process runs:

```text
build p50_ns=43220726..48438116 p95_ns=43417209..48628037 cov=0.002084..0.010909 n=5 allocs=50005 alloc_bytes=5144450
match p50_ns=39007..39528 p95_ns=40069..41331 cov=0.012266..0.024760 n=5 allocs=500 alloc_bytes=11500
parse p50_ns=36..48 p95_ns=214..260 cov=0.898773..1.013908 n=5 allocs=0 alloc_bytes=0
owned p50_ns=164..269 p95_ns=769..1076 cov=0.807043..0.983855 n=5 allocs=10 alloc_bytes=80
rss_kib=5040..5104 loadavg=3.62..4.19
boundary_bytes=MEASURED policy_canonicalize=12000 borrowed_to_owned=60 tcp_frame_buffer=0 encode_output=0 transport_write=0
```

Throughput is printed by the executable as `DERIVED` from the measured sample
durations and operation count. The wide small-sample parse and owned tails are
reported rather than hidden. This row improves observability; it does not
authorize an optimization or a zero-copy claim.

## Row 5 — reusable edge parse-to-match workload

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `0baa84a`, GitHub Proxima revision `afca73c`, and load average
`1.10`. The running harness used `N=25` samples and measured the reusable
`EdgePolicy` over one real DNS packet per sample:

```text
edge_parse_match p50_ns=44074 p95_ns=56511 p99_ns=72481 cov=0.129911 allocs=100 alloc_bytes=1375
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300
arms=scalar-retained memchr-not-added simd-not-added wasm-edge-compile-only wasm-runtime-not-installed
```

This measures the pure parse-to-match path; it does not establish a
production-performance or zero-copy claim.
