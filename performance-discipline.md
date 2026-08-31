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
