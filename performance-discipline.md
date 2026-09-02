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

## Row 3 — pure edge-path WASM build and runtime probe

`MEASURED` on 2026-09-01, `wasm32-unknown-unknown`, default features disabled,
source commit `f8ebc00`. `cargo build --locked --no-default-features
--target wasm32-unknown-unknown --lib` completed successfully and produced a
5,565,632-byte `blackhole.wasm` artifact. The Node harness then ran three fresh
100,000-call probes with 2,162,688 bytes of linear memory:

```text
valid_result=0 short_result=-1 ns_per_call=2018.50412
valid_result=0 short_result=-1 ns_per_call=1958.42081
valid_result=0 short_result=-1 ns_per_call=1987.62586
```

This is runtime evidence for the bounded pure edge probe only. It does not
measure allocations or establish a production-performance or zero-copy claim;
the scalar production path remains unchanged.

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

## Row 6 — wire-name scan arm comparison

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `cfabb0a`, GitHub Proxima revision `afca73c`, and load average
`1.23..1.37`. Three consecutive process runs used `N=25` samples over the
same long valid DNS name. All arms performed zero allocations:

```text
name_scan_scalar p50_ns=42..43 p95_ns=59..60 p99_ns=78 cov=0.168791..0.180800
name_scan_chunked p50_ns=80..90 p95_ns=113..121 p99_ns=153..170 cov=0.146700..0.218168
name_scan_memchr p50_ns=20 p95_ns=48..53 p99_ns=1097..1238 cov=3.248039..3.400667
rss_kib=6556..6604
```

The memchr median is lower but its tail and variance are materially worse;
the chunked arm is slower than scalar on this workload. These are benchmark
arms only, not replacements for Proxima's validated parser. Scalar remains
the production arm; no SIMD or zero-copy claim is made. The separate WASM
runtime probe is recorded in Row 3.

## Row 7 — current provenance-corrected scalar reference

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `02c4d65`, GitHub Proxima revision `afca73c`, and load average
`2.35`. The running harness used `N=25` samples per workload:

```text
build p50_ns=50203365 p95_ns=51205942 p99_ns=51986069 cov=0.009429 allocs=250025 alloc_bytes=27722250
match p50_ns=43392 p95_ns=44067 p99_ns=44589 cov=0.008253 allocs=2500 alloc_bytes=57500
edge_parse_match p50_ns=45601 p95_ns=55986 p99_ns=70251 cov=0.111887 allocs=100 alloc_bytes=1375
parse_short p50_ns=52 p95_ns=63 p99_ns=165 cov=0.387821 allocs=0 alloc_bytes=0
parse_long p50_ns=236 p95_ns=284 p99_ns=321 cov=0.079670 allocs=0 alloc_bytes=0
parse_adversarial p50_ns=83 p95_ns=97 p99_ns=114 cov=0.083831 allocs=0 alloc_bytes=0
parse_mixed p50_ns=84 p95_ns=256 p99_ns=280 cov=0.643827 allocs=0 alloc_bytes=0
name_scan_scalar p50_ns=44 p95_ns=61 p99_ns=84 cov=0.186295 allocs=0 alloc_bytes=0
name_scan_chunked p50_ns=86 p95_ns=102 p99_ns=175 cov=0.196117 allocs=0 alloc_bytes=0
name_scan_memchr p50_ns=21 p95_ns=44 p99_ns=1402 cov=3.522717 allocs=0 alloc_bytes=0
owned p50_ns=110 p95_ns=125 p99_ns=242 cov=0.222498 allocs=50 alloc_bytes=400
encode_response p50_ns=110 p95_ns=264 p99_ns=447 cov=0.525206 allocs=50 alloc_bytes=1450
rss_kib=6592
arms=scalar-production name-scan-chunked-measured name-scan-memchr-measured simd-not-added wasm-edge-runtime-measured-separately
```

Throughput is `DERIVED` from the measured durations and operation counts.
The borrowed parser and scan arms performed zero allocations in this run;
the owned and response-encoding arms allocated as shown. Scalar remains the
production arm because chunked scanning is slower and memchr has materially
higher tail latency and variance. This row does not establish zero-copy or
production-performance claims.

## Row 8 — lock-free admission provenance run

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, debug build,
source commit `3116019`, GitHub Proxima revision `97c34da8`, and load average
`2.27`. The running harness used `N=25` samples per workload:

```text
build_ns=p50 175651034 p95 177221128 p99 177925491 cov=0.005185 allocs=250025 alloc_bytes=33722250
match_ns=p50 179422 p95 180179 p99 180699 cov=0.002741 allocs=2500 alloc_bytes=57500
edge_parse_match_ns=p50 162885 p95 189523 p99 190733 cov=0.048497 allocs=100 alloc_bytes=1375
parse_short_ns=p50 525 p95 539 p99 988 cov=0.166493 allocs=0 alloc_bytes=0
parse_long_ns=p50 2925 p95 2984 p99 3029 cov=0.009829 allocs=0 alloc_bytes=0
parse_adversarial_ns=p50 751 p95 818 p99 1117 cov=0.094252 allocs=0 alloc_bytes=0
parse_mixed_ns=p50 749 p95 2992 p99 3012 cov=0.764209 allocs=0 alloc_bytes=0
name_scan_scalar_ns=p50 152 p95 164 p99 185 cov=0.045127
name_scan_chunked_ns=p50 751 p95 787 p99 1156 cov=0.103381
name_scan_memchr_ns=p50 332 p95 373 p99 3047 cov=1.199414
owned_ns=p50 834 p95 911 p99 1939 cov=0.245690 allocs=50 alloc_bytes=400
encode_response_ns=p50 1175 p95 1350 p99 2121 cov=0.153498 allocs=50 alloc_bytes=1450
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0 rss_kib=7488
```

The borrowed parser still measured zero allocations. Scalar remained the
production arm for this workload; chunked scanning was slower and memchr had
materially worse tail latency and variance. This is a debug-profile
provenance row only and does not establish a release performance, zero-copy,
or production-grade claim.

## Row 9 — current release reference after deployment verification

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `1102d35`, GitHub Proxima revision `03ea2c7d`, and load average
`1.59`. The running harness used `N=25` samples per workload:

```text
build p50_ns=55645841 p95_ns=56474926 p99_ns=56481819 cov=0.007439 allocs=250025 alloc_bytes=33722250
match p50_ns=45558 p95_ns=47514 p99_ns=49138 cov=0.021283 allocs=2500 alloc_bytes=57500
edge_parse_match p50_ns=46479 p95_ns=70463 p99_ns=91623 cov=0.200058 allocs=100 alloc_bytes=1375
parse_short p50_ns=49 p95_ns=70 p99_ns=158 cov=0.394200 allocs=0 alloc_bytes=0
parse_long p50_ns=227 p95_ns=264 p99_ns=291 cov=0.063032 allocs=0 alloc_bytes=0
parse_adversarial p50_ns=83 p95_ns=85 p99_ns=117 cov=0.080319 allocs=0 alloc_bytes=0
parse_mixed p50_ns=81 p95_ns=239 p99_ns=243 cov=0.631035 allocs=0 alloc_bytes=0
name_scan_scalar p50_ns=42 p95_ns=60 p99_ns=77 cov=0.170613 allocs=0 alloc_bytes=0
name_scan_chunked p50_ns=84 p95_ns=103 p99_ns=156 cov=0.169822 allocs=0 alloc_bytes=0
name_scan_memchr p50_ns=20 p95_ns=45 p99_ns=1296 cov=3.438450 allocs=0 alloc_bytes=0
owned p50_ns=120 p95_ns=144 p99_ns=321 cov=0.301765 allocs=50 alloc_bytes=400
encode_response p50_ns=108 p95_ns=276 p99_ns=331 cov=0.427794 allocs=50 alloc_bytes=1450
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0 rss_kib=7264
```

Throughput is `DERIVED` from the measured durations and operation counts.
The borrowed parser and scan arms measured zero allocations. Scalar remains
the production arm: chunked scanning is slower, and memchr has materially
higher tail variance. The edge path has `cov=0.200058`, so this row is an
observed reference rather than a performance verdict; no zero-copy or
production-grade claim is made.

## Row 11 — current release reference after profile and DDoS controls

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `a938749`, GitHub Proxima revision `03ea2c7d`, and load average
`1.25`. The running harness used `N=25` samples per workload:

```text
build p50_ns=48727373 p95_ns=50482756 p99_ns=50490788 cov=0.011726 allocs=250025 alloc_bytes=33722250
match p50_ns=44757 p95_ns=47206 p99_ns=48929 cov=0.023493 allocs=2500 alloc_bytes=57500
edge_parse_match p50_ns=46937 p95_ns=88182 p99_ns=110810 cov=0.306948 allocs=100 alloc_bytes=1375
parse_short p50_ns=48 p95_ns=69 p99_ns=139 cov=0.337150 allocs=0 alloc_bytes=0
parse_long p50_ns=232 p95_ns=246 p99_ns=307 cov=0.064010 allocs=0 alloc_bytes=0
parse_adversarial p50_ns=80 p95_ns=82 p99_ns=121 cov=0.099022 allocs=0 alloc_bytes=0
parse_mixed p50_ns=81 p95_ns=238 p99_ns=238 cov=0.629793 allocs=0 alloc_bytes=0
name_scan_scalar p50_ns=42 p95_ns=60 p99_ns=73 cov=0.171311 allocs=0 alloc_bytes=0
name_scan_chunked p50_ns=80 p95_ns=100 p99_ns=135 cov=0.137180 allocs=0 alloc_bytes=0
name_scan_memchr p50_ns=20 p95_ns=44 p99_ns=1452 cov=3.569132 allocs=0 alloc_bytes=0
owned p50_ns=126 p95_ns=353 p99_ns=29891 cov=4.398529 allocs=50 alloc_bytes=400
encode_response p50_ns=110 p95_ns=268 p99_ns=488 cov=0.577802 allocs=50 alloc_bytes=1450
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0 rss_kib=7264
```

Throughput is `DERIVED` from measured durations and operation counts. The
borrowed parser and scan arms measured zero allocations. Scalar remains the
production arm; memchr retains high tail variance, and the owned arm had a
single high-tail observation in this small run. This is an observed reference
only; no zero-copy or production-grade claim is made.

## Row 10 — current release reference after roadmap documentation cleanup

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `dc1d8b9`, GitHub Proxima revision `03ea2c7d`, and load average
`0.84`. The running harness used `N=25` samples per workload:

```text
build p50_ns=55243815 p95_ns=55750253 p99_ns=55838527 cov=0.007710 allocs=250025 alloc_bytes=33722250
match p50_ns=48531 p95_ns=49909 p99_ns=51081 cov=0.012692 allocs=2500 alloc_bytes=57500
edge_parse_match p50_ns=49185 p95_ns=62100 p99_ns=82814 cov=0.135783 allocs=100 alloc_bytes=1375
parse_short p50_ns=51 p95_ns=62 p99_ns=140 cov=0.317302 allocs=0 alloc_bytes=0
parse_long p50_ns=238 p95_ns=285 p99_ns=312 cov=0.070676 allocs=0 alloc_bytes=0
parse_adversarial p50_ns=80 p95_ns=84 p99_ns=125 cov=0.106251 allocs=0 alloc_bytes=0
parse_mixed p50_ns=82 p95_ns=254 p99_ns=264 cov=0.647334 allocs=0 alloc_bytes=0
name_scan_scalar p50_ns=43 p95_ns=58 p99_ns=78 cov=0.165294 allocs=0 alloc_bytes=0
name_scan_chunked p50_ns=86 p95_ns=98 p99_ns=122 cov=0.096716 allocs=0 alloc_bytes=0
name_scan_memchr p50_ns=20 p95_ns=58 p99_ns=1698 cov=3.665237 allocs=0 alloc_bytes=0
owned p50_ns=121 p95_ns=167 p99_ns=309 cov=0.285290 allocs=50 alloc_bytes=400
encode_response p50_ns=107 p95_ns=275 p99_ns=329 cov=0.421902 allocs=50 alloc_bytes=1450
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0 rss_kib=7324
```

Throughput is `DERIVED` from the measured durations and operation counts.
The borrowed parser and scan arms measured zero allocations. Scalar remains
the production arm: chunked scanning is slower, and memchr has materially
higher tail variance. This is an observed reference only; no zero-copy or
production-grade claim is made.

## Row 12 — current three-run release reference

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `ab492fe`, GitHub Proxima revision
`03596bc908be7ae76179464f85ad867b311e2a65`, and load averages `2.69`,
`2.43`, and `2.48`. Three fresh processes used `N=25` samples per workload.
The observed p50/p95/p99 ranges were:

```text
build_ns=48684938..55468491 / 50486410..56507277 / 51036126..58251598 cov=0.010377..0.012550 allocs=250025 alloc_bytes=33722250
match_ns=44551..45045 / 46296..47160 / 46786..48268 cov=0.015165..0.017504 allocs=2500 alloc_bytes=57500
edge_parse_match_ns=45983..46125 / 61055..63750 / 77820..85011 cov=0.146625..0.169315 allocs=100 alloc_bytes=1375
parse_long_ns=228 / 262..281 / 279..300 cov=0.051067..0.075071 allocs=0 alloc_bytes=0
name_scan_scalar_ns=42..43 / 57..59 / 78..121 cov=0.165373..0.337318 allocs=0 alloc_bytes=0
name_scan_chunked_ns=85 / 94..99 / 137..153 cov=0.124484..0.156948 allocs=0 alloc_bytes=0
name_scan_memchr_ns=21 / 41..52 / 1131..1226 cov=3.269259..3.351425 allocs=0 alloc_bytes=0
owned_ns=117..119 / 150..169 / 289..320 cov=0.268092..0.310736 allocs=50 alloc_bytes=400
encode_response_ns=107..110 / 266..291 / 303..422 cov=0.395957..0.510889 allocs=50 alloc_bytes=1450
rss_kib=7304..7328
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0
```

Throughput is `DERIVED` by the executable from measured durations and
operation counts. The pure harness has no real-client single-request
latency, server CPU percentage, or error-rate workload, so those axes remain
`UNMEASURED`; this row is not an end-to-end production gate. The scalar scan
remains the production arm: chunked scanning is slower and memchr retains a
large tail and high CoV. No zero-copy or production-grade claim follows.

## Row 13 — real UDP listener/client boundary

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `8f6eac3`, GitHub Proxima revision
`03596bc908be7ae76179464f85ad867b311e2a65`, and load average `1.31`. The
`listener_performance` example sent `N=100` sequential requests from a real
Prime UDP client through the Proxima listener and Blackhole UDP adapter after
10 warmups:

```text
listener_udp samples=100 errors=0 first_error=None single_request_ns=80420
listener_latency_ns p50=26041 p95=31105 p99=67502 min=22840 max=67502 cov=0.164629 n=100
listener_throughput_ops_s=DERIVED 35610.67
cpu_percent=MEASURED 0.0 cpu_clock_ticks_s=MEASURED 100 rss_kib=MEASURED 8988 loadavg=MEASURED 1.31
```

The listener workload measured zero errors and a single-request latency of
80.4 microseconds. CPU time is sampled from process accounting at a 100 Hz
clock and rounded to zero for this short run; it is therefore not evidence of
idle CPU. This supplies the real-client latency, throughput, RSS, and error
axes for the local UDP boundary. TCP, sustained offered-load CPU utilization,
and cross-process client/server measurements remain outside this row.

## Row 15 — instrumented real listener transport boundaries

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build with
`perf-instrument`, source commit `27f3b01`, and GitHub Proxima revision
`03596bc908be7ae76179464f85ad867b311e2a65`. The real-client listener example
sent 100 sequential UDP and 100 sequential TCP requests; both transports
returned zero errors:

```text
listener_udp single_request_ns=64791 p50_ns=26280 p95_ns=33335 p99_ns=98199 cov=0.390924 throughput_ops_s=DERIVED 33795.75
listener_tcp single_request_ns=79611 p50_ns=31387 p95_ns=65948 p99_ns=84585 cov=0.317411 throughput_ops_s=DERIVED 28907.02
listener_boundary_bytes=MEASURED policy_canonicalize=0 borrowed_to_owned=3798 tcp_frame_buffer=3700 encode_output=14348 transport_write=14348
rss_kib=MEASURED 9060 cpu_percent=MEASURED 0.0 cpu_clock_ticks_s=MEASURED 100 loadavg=MEASURED 1.76
```

The counters cover the actual listener exercise, including TCP framing,
response encoding, and transport writes. CPU remains quantized by the short
100 Hz process-accounting window and is not interpreted as a utilization
verdict; sustained cross-process load remains required for that claim.

## Row 14 — real UDP and TCP listener/client boundary

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `7ca7cc8`, GitHub Proxima revision
`03596bc908be7ae76179464f85ad867b311e2a65`, and load average `2.47`. The
`listener_performance` example sent `N=100` sequential requests from real
Prime clients through the Proxima listener and Blackhole adapters after 10
UDP warmups:

```text
listener_udp samples=100 errors=0 single_request_ns=35351
listener_latency_ns p50=26124 p95=28120 p99=34825 min=25203 max=34825 cov=0.052817 n=100
listener_throughput_ops_s=DERIVED 37299.63
listener_tcp samples=100 errors=0 single_request_ns=86515
listener_tcp_latency_ns p50=32017 p95=78289 p99=86515 min=31073 max=86515 cov=0.329542 n=100
listener_tcp_throughput_ops_s=DERIVED 28195.34 errors=MEASURED 0
rss_kib=MEASURED 9164 cpu_percent=MEASURED 372.99626406941906 cpu_clock_ticks_s=MEASURED 100
```

Both listener transports completed with zero measured errors. CPU time is
sampled from process accounting at a 100 Hz clock over the short UDP window;
the reported value is process-wide and is not a cross-process server CPU
measurement. TCP has higher tail variance in this run; no production
performance claim follows without sustained offered-load and separated
client/server CPU measurements.

## Row 16 — sustained real listener workload

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build with
`perf-instrument`, source commit `79201ea`, GitHub Proxima revision
`03596bc908be7ae76179464f85ad867b311e2a65`, and load average `1.74`. The
listener benchmark used `N=1,000` sequential requests per transport after 10
UDP warmups:

```text
listener_udp samples=1000 errors=0 single_request_ns=80544 p50_ns=25985 p95_ns=30830 p99_ns=67962 min=21929 max=81544 cov=0.246334 throughput_ops_s=DERIVED 36198.97
listener_tcp samples=1000 errors=0 single_request_ns=64452 p50_ns=32199 p95_ns=39782 p99_ns=86686 min=30357 max=492508 cov=0.502453 throughput_ops_s=DERIVED 28690.17
listener_boundary_bytes=MEASURED policy_canonicalize=0 borrowed_to_owned=36198 tcp_frame_buffer=37000 encode_output=136748 transport_write=136748
cpu_percent=MEASURED 108.59690375023841 cpu_clock_ticks_s=MEASURED 100 rss_kib=MEASURED 9156
```

Both transports completed without measured errors. The longer run made
process CPU accounting measurable, but it remains process-wide rather than a
separated server measurement; TCP tail variance is high in this sample and is
retained as observed evidence rather than a performance claim.

## Row 17 — current scalar policy and codec reference

`MEASURED` on 2026-09-02, Linux `x86_64`, rustc `1.98.0`, release build with
`perf-instrument`, source commit `c56e2c8`, and GitHub Proxima revision
`03ea2c7d`. The executable used `N=25` samples per workload and was run with
load average `3.72`:

```text
build_ns p50=60965459 p95=62313845 p99=63305051 cov=0.010783 allocs=250025 alloc_bytes=33722250
match_ns p50=45584 p95=47525 p99=51151 cov=0.028272 allocs=2500 alloc_bytes=57500
edge_parse_match_ns p50=47223 p95=69836 p99=79330 cov=0.174242 allocs=100 alloc_bytes=1375
parse_short_ns p50=52 p95=56 p99=145 cov=0.324357 allocs=0 alloc_bytes=0
parse_long_ns p50=229 p95=270 p99=305 cov=0.071489 allocs=0 alloc_bytes=0
parse_adversarial_ns p50=81 p95=95 p99=132 cov=0.121392 allocs=0 alloc_bytes=0
parse_mixed_ns p50=82 p95=236 p99=247 cov=0.603831 allocs=0 alloc_bytes=0
name_scan_scalar_ns p50=43 p95=58 p99=74 cov=0.161139 allocs=0 alloc_bytes=0
name_scan_chunked_ns p50=85 p95=94 p99=155 cov=0.162070 allocs=0 alloc_bytes=0
name_scan_memchr_ns p50=20 p95=34 p99=1142 cov=3.298557 allocs=0 alloc_bytes=0
owned_ns p50=121 p95=143 p99=283 cov=0.247238 allocs=50 alloc_bytes=400
encode_response_ns p50=108 p95=298 p99=321 cov=0.432492 allocs=50 alloc_bytes=1450
boundary_bytes=MEASURED policy_canonicalize=60600 borrowed_to_owned=300 tcp_frame_buffer=0 encode_output=0 transport_write=0 rss_kib=7332
```

Throughput is `DERIVED` from measured duration and operation counts. The
borrowed parser and scan arms measured zero allocations; owned conversion and
response encoding allocated as shown. Scalar remains the production arm:
chunked scanning is slower and memchr retains a materially higher tail and
coefficient of variation. This is a current reference row, not a
zero-copy, high-performance, or production-grade claim.

## Row 18 — lock-free snapshot publication and retirement

`MEASURED` on 2026-09-01, Linux `x86_64`, rustc `1.98.0`, release build,
source commit `3b8a8eb`, and GitHub Proxima revision `03ea2c7d`. The bounded
`snapshot_gate` example published 256 complete immutable generations through
`PolicyStore` and measured the process before and after the run:

```text
snapshot_samples=256 rss_before_kib=Some(2428) rss_after_kib=Some(2500)
snapshot_reload_ns p50=241 p95=254 p99=437
snapshot_rss_delta_kib=MEASURED 72 provenance=process-wide-rss
```

The reload timings are a single local run and are not a throughput claim. RSS
is process-wide and includes allocator retention and unrelated runtime state;
the 72 KiB delta is an observed bound for this workload, not a universal
memory bound. The concurrent-reader and repeated-retirement proof tests remain
the correctness evidence for complete generations.
