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
