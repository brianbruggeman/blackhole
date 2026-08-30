# B14 performance gate

The gate is embedded in `examples/performance_gate.rs` and uses Rust's global
allocator hooks. Run it with:

```text
cargo run --example performance_gate --release --offline
```

The measurement separates 10,000-rule index build, scalar reference matching,
and borrowed query parsing. It reports allocator calls and bytes for each
section. The parser result is intentionally a malformed packet, proving the
measurement reaches the parser boundary without requiring network traffic.

The current gate records `copy_count=not-instrumented`; therefore the project
does not claim zero-copy. SIMD, memchr/chunked matching, and WASM are not
retained or described as faster: there is no buyer-relevant end-to-end result
showing a win, and the current policy path still allocates during canonical
matching. The scalar implementation remains the portability fallback.
