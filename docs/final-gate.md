# B16 final handoff gate

Executed from `/home/bix/repos/slot-0` with Cargo's target redirected to
`/tmp/blackhole-target` and wrappers disabled because the default cache is
read-only in this environment.

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path blackhole/Cargo.toml -- --check` | pass |
| `cargo check --manifest-path blackhole/Cargo.toml --all-targets --locked --offline` | pass |
| `RUSTC_WRAPPER= CARGO_TARGET_DIR=/tmp/blackhole-target CARGO_BUILD_JOBS=1 cargo test --all-targets --offline` | 36 passed |
| `cargo run --manifest-path blackhole/Cargo.toml --example performance_gate --locked --offline` | pass; output recorded in B14 gate docs |
| `cargo run --manifest-path blackhole/Cargo.toml --example index_benchmark --locked --offline -- /tmp/blackhole-index-final.txt` | pass; published in `artifacts/index/reference-linear.txt` |

The examples are Rust programs and require no scripts. The index benchmark
uses the 100,000-rule security ceiling. The final gate does not claim a live
UDP/TCP resolver fixture, macOS compilation, fuzz execution, signed artifact,
or privileged PF/nftables smoke because those require unavailable external
platform/privilege lanes. Those omissions are explicit release-scope items,
not silently treated as passing.
