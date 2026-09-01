# blackhole

A DNS sinkhole/honeypot for Linux and macOS. The policy engine is pure
Rust and the wire/runtime edge uses Proxima from
[`brianbruggeman/proxima`](https://github.com/brianbruggeman/proxima); the
default runtime path is Prime-backed, with the full Tokio capability set
available through the opt-in compatibility feature. DNS over UDP and TCP share
one bind.

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

Validate a configuration without opening the DNS listener or installing the
optional capture rules:

```sh
cargo run --release -- --check blackhole.example.toml
```

Use port 53 only with the platform's normal low-port capability mechanism.
The default configuration binds only to loopback. An explicitly supplied
configuration path must exist and parse successfully before the listener is
created. `ignore` is represented as a silent response by the current Proxima
DNS edge. When `policy.rules` is configured, it is authoritative and legacy
`mode`/`domains` are ignored; unmatched queries use `policy.default_action`.
Pass and observe queries use the configured Proxima upstream after local
rewrites; explicit forward rules use the same bounded upstream path and fail
closed when it is not configured. Forwarded positive and negative answers are
cached within configured bounds; timeout is bounded to 60 seconds and retries
to eight attempts per exchange, while an upstream circuit breaker limits
repeated failures and permits stale answers only during its configured stale
window.
Repeated per-client rate-limit violations open a bounded temporary abuse
breaker; unidentified callers are not assigned a shared abuse identity.
Encoded responses also consume a bounded per-client byte budget per second;
when it is exhausted, the listener sheds that client's response rather than
amplifying the traffic pattern.
The network-scoped breaker aggregates those violations across configurable
IPv4/IPv6 prefixes (defaults `/24` and `/64`) and sheds only the offending
network during its cooldown.
Blocklist files accept hosts/domain entries and basic AdGuard `||domain^`
filters; `@@||domain^` exceptions override the generated apex and subdomain
blocks. Local A/AAAA rewrites are bounded and apply to `pass`/`observe` queries;
explicit policy actions take precedence. The `[capture]` section is disabled
by default; when enabled, it installs and recovers only the platform-native,
journal-owned DNS redirect rules.
Named service profiles are also compiled into the authoritative rule table;
each profile supplies a bounded domain set and action.
Rules may use `client_cidrs` for a bounded set of IPv4/IPv6 networks; the
most-specific matching network wins while `client_cidr` remains supported.
Bounded regular-expression rules are available through `policy.regex_rules`;
invalid or oversized expressions fail configuration validation, and explicit
domain rules take precedence when both match. Regex rules may also use the
same bounded `client_cidrs` network scope as domain rules.

Proxima is consumed from GitHub. Prime is the default runtime and executable
path. Proxima's HTTP listener currently brings a small Tokio dependency into
the default graph for its UDS support; use the opt-in `tokio-compat` feature
to compile the full Proxima Tokio capability set as well.

An optional authenticated control plane can be enabled with `[admin]`:

```toml
[admin]
listen = "127.0.0.1:8081"
token = "a-long-random-secret"
```

It provides `GET /health`, authenticated `GET /status` and bounded `GET /rules`, `POST /reload/blocklists`, bounded
`POST /reload/country`, bounded `POST /reload/policy` (a JSON array of complete rule objects), and bounded
`POST /reload/regex` (a JSON array of regex rule objects). Send the token
as a Bearer credential; `/rules` returns only bounded policy metadata and no
query payloads; keep the configuration file readable only by the service user.

For a hardened Linux local-network deployment, install the example unit at
`deploy/systemd/blackhole.service`, create the `blackhole` service account,
install `deploy/systemd/blackhole.conf` under `/etc/tmpfiles.d/`, place
configuration at `/etc/blackhole/blackhole.toml`, and grant only
`CAP_NET_BIND_SERVICE` when listening on port 53. Capture remains disabled in
this unit and must be installed through the separately authorized platform
capture step. After building the release binary, the checked-in installer can
perform those service-account, ownership, unit, tmpfiles, and systemd steps:

```sh
cargo build --release --features std --bin blackhole
sudo BLACKHOLE_BINARY="$PWD/target/release/blackhole" \
  BLACKHOLE_CONFIG="$PWD/blackhole.example.toml" \
  ./deploy/systemd/install.sh
```

The installer requires root and starts the service, but it does not install
firewall capture rules.
