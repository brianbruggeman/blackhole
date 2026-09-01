# blackhole

A DNS sinkhole/honeypot for Linux and macOS. The policy engine is pure
Rust and the wire/runtime edge uses Proxima from
[`brianbruggeman/proxima`](https://github.com/brianbruggeman/proxima); the
default runtime path is Prime-backed, with the full Tokio capability set
available through the opt-in compatibility feature. DNS over UDP and TCP share
one bind.

See [FEATURES.md](FEATURES.md) for the current implemented surface and
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
cached within configured bounds. A truncated UDP answer is retried over the
same upstream's bounded DNS-over-TCP path after validating its response ID,
question, QR bit, and opcode. Timeout is bounded to 60 seconds and retries to
eight attempts per exchange, while an upstream circuit breaker limits repeated
failures and permits stale answers only during its configured stale window.
Repeated per-client rate-limit violations open a bounded temporary abuse
breaker; unidentified callers are not assigned a shared abuse identity.
Encoded responses also consume a bounded per-client byte budget per second;
when it is exhausted, the listener sheds that client's response rather than
amplifying the traffic pattern.
The aggregate `admission.max_response_bytes_per_second` budget also caps all
encoded DNS egress, including unidentified callers, before transport write;
its default is 16 MiB per second.
The network-scoped breaker aggregates those violations across configurable
IPv4/IPv6 prefixes (defaults `/24` and `/64`) and sheds only the offending
network during its cooldown. A separate bounded global queries-per-second
ceiling also applies to unidentified callers as a DDoS stopgap.
Blocklist files accept hosts/domain entries and basic AdGuard `||domain^`
filters; `@@||domain^` exceptions override the generated apex and subdomain
blocks. Local A/AAAA rewrites are bounded and apply to `pass`/`observe` queries;
explicit policy actions take precedence. The `[capture]` section is disabled
by default; when enabled, it installs and recovers only the platform-native,
journal-owned DNS redirect rules.
Configured blocklists may be refreshed by Proxima's cancellable background
interval with `policy.blocklist_reload_interval_secs`; zero disables polling,
the interval is bounded to one day, unchanged content does not create a new
policy generation, and failed reloads retain the last good snapshot.
Named service profiles are also compiled into the authoritative rule table;
each profile supplies a bounded domain set and action.
The optional country policy accepts an operator-supplied `COUNTRY CIDR` map;
`country_policy.reload_interval_secs` enables bounded background refresh, where
unchanged content is not republished and failed refreshes retain the last good
map. Classification remains an explicit policy signal, not authentication.
Profiles may name bounded client groups with `groups = ["family", "guest"]`;
each group supplies IPv4/IPv6 CIDRs and a profile may target multiple groups.
Direct `client_cidrs` and named groups are mutually exclusive.
Rules may use `client_cidrs` for a bounded set of IPv4/IPv6 networks; the
most-specific matching network wins while `client_cidr` remains supported.
Bounded regular-expression rules are available through `policy.regex_rules`;
invalid or oversized expressions fail configuration validation, and explicit
domain rules take precedence when both match. Regex rules may also use the
same bounded `client_cidrs` network scope as domain rules.

The upstream transport is selected in `[upstream]`: `transport = "udp"` keeps
UDP with bounded TCP fallback, `transport = "tcp"` uses DNS-over-TCP for every
exchange, `transport = "tls"` uses DNS-over-TLS for every exchange, and
`transport = "doh"` uses DNS-over-HTTPS for every exchange. Encrypted modes
require `tls_server_name` and validate the server certificate through
Proxima's GitHub HTTP/TLS pipe adapters. `transport = "doq"` uses
DNS-over-QUIC through Proxima's existing QUIC stream adapter and requires the
opt-in `doq` feature; the default Prime build remains QUIC-free.

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

It provides an authenticated bounded status UI at `GET /` that links the
status, privacy status, rule metadata, and privacy-log views, with a button for
reloading configured blocklists. The same routes are available as
authenticated `GET /health`, `GET /status`, bounded `GET /policy/status`,
`GET /rules`, `GET /logs`,
and `POST /logs/clear`, `POST /cache/clear`, `POST /reload/blocklists`, bounded
`POST /reload/country`, bounded `POST /reload/policy` (a JSON array of complete rule objects), bounded
`POST /reload/policy/add` (a non-empty JSON array appended atomically to the current domain rules), bounded
`POST /reload/policy/upsert` (a non-empty JSON array that replaces or adds rules by stable ID while preserving unspecified rules), and bounded
`POST /reload/policy/remove` (a JSON array of stable rule IDs removed atomically), and bounded
`POST /reload/regex` (a JSON array of regex rule objects), bounded `GET /profiles`
and `GET /client-groups` metadata views, plus bounded privacy-safe
query-decision inspection at `GET /logs` and deletion at `POST /logs/clear` when
enabled. `POST /reload/profiles` atomically replaces the profile and client-group
tables from a bounded JSON object with `profiles` and `client_groups` arrays.
`POST /reload/profiles/upsert` replaces or adds profiles by stable ID while
preserving unspecified profiles; duplicate IDs and invalid expansions fail
without publication. `POST /reload/profiles/remove` removes profiles by stable
ID and rejects unknown IDs without changing the live snapshot.
`POST /reload/client-groups/upsert` replaces or adds named client CIDR groups
while preserving profiles and validates the resulting profile expansion before
publication.
`POST /reload/client-groups/remove` removes named groups only when no profile
references them; dependent removals fail without changing the live snapshot.
`POST /reload/policy-bundle` replaces the domain, regex, profile, client-group,
local-rewrite, and country-policy tables as one validated snapshot while
retaining loaded blocklists. Its optional `mode`, `domains`, and
`default_action` fields also replace the legacy fallback settings atomically;
its optional `blocklists` array can replace the
blocklist source paths in the same validated publication; omitted or `null`
retains the current blocklist snapshot. Reloads bound source count, path
length, each file, and aggregate file bytes before touching the live snapshot.
`POST /reload/blocklists/replace` atomically replaces the blocklist source path
set and preserves the previous sources and rules if a replacement fails.
`GET /privacy/status` exposes only privacy-recording enablement and configured
limits; it does not expose recording paths, names, clients, or payloads.
`GET /policy/status` includes a monotonic `policy_generation` that advances
once for each successful publication and does not advance on rejected input.
Send the token
as a Bearer credential; `/rules` returns only bounded policy metadata and no
query payloads. Query logs are disabled by default and retain only timestamp,
action, qtype, and qclass metadata; keep the configuration file readable only
by the service user.

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
