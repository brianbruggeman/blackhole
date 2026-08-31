# blackhole

A DNS sinkhole/honeypot for Linux and macOS. The policy engine is pure
Rust and the wire/runtime edge uses Proxima from
[`brianbruggeman/proxima`](https://github.com/brianbruggeman/proxima); the
default Prime path has no Tokio dependency. DNS over UDP and TCP share one
bind.

See [FEATURES.md](FEATURES.md) for the current prototype surface and
[ROADMAP.md](ROADMAP.md) for the intended product scope and parity targets with
Pi-hole and AdGuard Home.
See [contract.md](contract.md) for the wire meaning of each policy action.
See [PRIVACY.md](PRIVACY.md) for the retention and honeypot-terminal contract.

This first slice intercepts DNS, the portable boundary used by Pi-hole and
AdGuard. It does not claim to transparently capture all IP traffic: that needs
OS firewall/TProxy setup and is deliberately a separate adapter boundary.

```sh
cargo run --release -- blackhole.example.toml
dig @127.0.0.1 -p 5353 ads.example A
```

Use port 53 only with the platform's normal low-port capability mechanism.
The default configuration binds only to loopback. An explicitly supplied
configuration path must exist and parse successfully before the listener is
created. `ignore` is represented as a silent response by the current Proxima
DNS edge. When `policy.rules` is configured, it is authoritative and legacy
`mode`/`domains` are ignored; unmatched queries use `policy.default_action`.
Explicit forwarding uses the opt-in Proxima upstream pipe and fails closed
when no upstream is attached. Forwarded positive and negative answers are
cached within configured bounds; an upstream circuit breaker limits repeated
failures and permits stale answers only during its configured stale window.
Repeated per-client rate-limit violations open a bounded temporary abuse
breaker; unidentified callers are not assigned a shared abuse identity.
Local A/AAAA rewrites are bounded and apply to `pass`/`observe` queries;
explicit policy actions take precedence. The `[capture]` section is disabled
by default; when enabled, it installs and recovers only the platform-native,
journal-owned DNS redirect rules.
