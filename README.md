# blackhole

A DNS sinkhole/honeypot for Linux and macOS. The policy engine is pure
Rust and the wire/runtime edge uses Proxima from
[`brianbruggeman/proxima`](https://github.com/brianbruggeman/proxima); the
default runtime path is Prime-backed, with the full Tokio capability set
available through the opt-in compatibility feature. DNS over UDP and TCP share
one bind.
An optional bounded DHCPv4 adapter serves a configured LAN pool; it is
disabled by default and requires an explicitly authorized bind on UDP port 67.

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

The sans-IO edge also builds without the runtime tier. Because no-std targets
cannot unwind panics, include the abort strategy explicitly:

```sh
RUSTFLAGS='-C panic=abort' cargo check --locked --no-default-features
```

Enable DHCP only on a dedicated LAN-facing address after reviewing the pool:

```toml
[dhcp]
enabled = true
listen = "192.0.2.1:67"
server = "192.0.2.1"
subnet_mask = "255.255.255.0"
pool_start = "192.0.2.100"
pool_end = "192.0.2.199"
lease_secs = 3600
max_leases = 256
```

Use port 53 only with the platform's normal low-port capability mechanism.
The default configuration binds only to loopback. An explicitly supplied
configuration path must exist and parse successfully before the listener is
created. `ignore` is represented as a silent response by the current Proxima
DNS edge. When `policy.rules` is configured, it is authoritative and legacy
`mode`/`domains` are ignored; unmatched queries use `policy.default_action`.
Set `policy.filtering_enabled = false` for an atomic temporary filtering
pause; the policy remains loaded and can be re-enabled through the full
configuration reload without losing rules, rewrites, or forwarding settings.
Pass and observe queries use the configured Proxima upstream after local
rewrites; explicit forward rules use the same bounded upstream path and fail
closed when it is not configured. Forwarded positive and negative answers are
cached within configured bounds. A truncated UDP answer is retried over the
same upstream's bounded DNS-over-TCP path after validating its response ID,
question, QR bit, and opcode. Timeout is bounded to 60 seconds and retries to
eight attempts per exchange, while an upstream circuit breaker limits repeated
failures through Proxima's `CircuitBreaker` state machine and permits stale
answers only during its configured stale window.
Repeated per-client rate-limit violations open a bounded temporary abuse
breaker; unidentified callers are not assigned a shared abuse identity.
Identified malformed-query floods also feed that same bounded client/network
breaker using parser failure causes only; malformed wire payloads are never
retained.
Operators can also set `[admission].deny_client_cidrs` to a bounded list of
IPv4/IPv6 CIDRs (use `/32` or `/128` for one address); those clients receive
REFUSED before policy matching, rate accounting, or forwarding. The denylist
is live-reloadable and invalid replacements are rejected without publication.
Set `[admission.ddos].persist_incidents = true` to persist temporary-blacklist
events through the bounded Proxima recording sink; active markers are restored
after restart until their configured expiry and expired markers are ignored.
The equivalent environment override is
`BLACKHOLE_DDOS_PERSIST_INCIDENTS=true`.
Encoded responses also consume a bounded per-client byte budget per second;
when it is exhausted, the listener sheds that client's response rather than
amplifying the traffic pattern.
An additional bounded response-byte budget applies across each identified
IPv4/IPv6 network prefix, so distributing requests across clients cannot evade
the per-network ceiling.
The aggregate `admission.max_response_bytes_per_second` budget also caps all
encoded DNS egress, including unidentified callers, before transport write;
its default is 16 MiB per second.
The network-scoped breaker aggregates those violations across configurable
IPv4/IPv6 prefixes (defaults `/24` and `/64`) and sheds only the offending
network during its cooldown. A separate bounded global queries-per-second
ceiling also applies to unidentified callers as a DDoS stopgap.
Responses that reach the configured amplification ceiling are also counted as
abuse violations for identified TCP clients and their configured networks;
repeated violations open the same bounded, expiring blacklist and can be
persisted when DDoS incident persistence is enabled.
Blocklist files accept hosts/domain entries and bounded AdGuard filters;
`@@||domain^` exceptions override the generated apex and subdomain blocks,
`$important` raises a block's priority, `$badfilter` cancels that domain's
block regardless of source order, and `$denyallow=domain|domain` permits
listed domains and their subdomains for that blocking filter. Unknown or
malformed filter modifiers fail closed. Local
A/AAAA/CNAME rewrites are bounded and apply to `pass`/`observe` queries;
explicit policy actions take precedence. A rewrite contains exactly one
record family: `ipv4`, `ipv6`, or `cname`. The `[capture]` section is disabled
by default; when enabled, it installs and recovers only the platform-native,
journal-owned DNS redirect rules.
Configured blocklists may be refreshed by Proxima's cancellable background
interval with `policy.blocklist_reload_interval_secs`; zero disables polling,
the interval is bounded to one day, unchanged content does not create a new
policy generation, and failed reloads retain the last good snapshot.
Individual sources can be retained but disabled with
`policy.disabled_blocklists`; the authenticated admin API also exposes
`POST /reload/blocklists/disable` and `/reload/blocklists/enable` for atomic
runtime changes. `GET /blocklists` includes each source's bounded filesystem
status, parser load status, and contributed rule count without returning its
contents.
Set the top-level `reload_interval_secs` to enable bounded polling of the
policy-bearing portions of the same configuration file; listener, transport,
capture, storage, and process-capacity changes fail closed until restart.
Named service profiles are also compiled into the authoritative rule table;
each profile supplies a bounded domain set and action.
The optional country policy accepts an operator-supplied `COUNTRY CIDR [REGION]
[ASN]` map;
`country_policy.reload_interval_secs` enables bounded background refresh, where
unchanged content is not republished and failed refreshes retain the last good
map. Region and ASN selectors are explicit operator policy over those map
labels; no GeoIP database or inferred identity is provided. Classification
remains an explicit policy signal, not authentication.
Profiles may name bounded client groups with `groups = ["family", "guest"]`;
each group supplies exact IPv4/IPv6 client addresses and/or CIDRs, and a
profile may target multiple groups.
For direct identity-scoped rules, map bounded adapter-owned client addresses
to an opaque label:

```toml
[[policy.client_identities]]
name = "family-router"
clients = ["192.0.2.10"]
client_cidrs = ["192.0.2.0/24"]
```

Rules using `client_identity = "family-router"` match that transient label;
exact addresses take precedence over CIDR scopes, overlapping scopes across
identities are rejected, and names and client identities are excluded from
telemetry and recording.
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

The control plane includes `GET /stats`, a privacy-safe aggregate view of
decision counts for every action identity. It contains no DNS names, client
metadata, or packet payloads.

```toml
[admin]
listen = "127.0.0.1:8081"
token = "a-long-random-secret"
```

It provides an authenticated bounded status UI at `GET /` that links the
status, admission-limit, country-policy, privacy status, rule metadata, and
privacy-log views, loads the current policy bundle into an editable bounded
JSON form, and provides buttons for reloading configured blocklists or
publishing the complete bundle. The same routes are available as
authenticated `GET /health`, `GET /status`, bounded `GET /admission/status`,
`GET /country/status`,
`GET /policy/status`,
`GET /policy-bundle`,
`GET /rules`, `GET /logs`,
and `POST /logs/clear`, `POST /cache/clear`, `POST /reload/blocklists`, bounded
`POST /reload/blocklists/replace`, `/reload/blocklists/add`, and
`/reload/blocklists/remove`, `/reload/blocklists/enable`, and
`/reload/blocklists/disable` (atomic exact source-path management), bounded
`POST /reload/admission` (a bounded JSON admission configuration; the global
in-flight capacity remains startup-only), bounded
`POST /reload/admission/denylist` (an atomic JSON array replacement for only
the configured client CIDRs), bounded
`POST /reload/country`, bounded `POST /reload/policy` (a JSON array of complete rule objects), bounded
`POST /reload/country/replace` (an atomic country/CIDR selector and map
configuration replacement), bounded
`POST /reload/policy/add` (a non-empty JSON array appended atomically to the current domain rules), bounded
`POST /reload/policy/upsert` (a non-empty JSON array that replaces or adds rules by stable ID while preserving unspecified rules), and bounded
`POST /reload/policy/remove` (a JSON array of stable rule IDs removed atomically), and bounded
`POST /reload/regex` (a JSON array of regex rule objects),
`POST /reload/regex/upsert` (a JSON array that replaces or adds regex rules by
stable ID), and `POST /reload/regex/remove` (a JSON array of regex rule IDs).
It also provides bounded `GET /profiles`, `GET /client-groups`, and
`GET /rewrites` metadata views, plus bounded privacy-safe
query-decision inspection at `GET /logs` and deletion at `POST /logs/clear` when
enabled. `POST /reload/profiles` atomically replaces the profile and client-group
tables from a bounded JSON object with `profiles` and `client_groups` arrays.
`POST /reload/profiles/upsert` replaces or adds profiles by stable ID while
preserving unspecified profiles; duplicate IDs and invalid expansions fail
without publication. `POST /reload/profiles/remove` removes profiles by stable
ID and rejects unknown IDs without changing the live snapshot.
`POST /reload/client-groups/upsert` replaces or adds named client CIDR groups
while preserving profiles and validates the resulting profile expansion before
publication; each group may be disabled atomically while retaining its address
and CIDR metadata.
`POST /reload/client-groups/remove` removes named groups only when no profile
references them; dependent removals fail without changing the live snapshot.
`POST /reload/client-identities` replaces all exact/CIDR client-identity mappings,
while `POST /reload/client-identities/upsert` and
`POST /reload/client-identities/remove` update them by exact name without
publishing partial state; each mapping can be disabled while retaining its
metadata, and invalid or unknown updates fail closed.
`POST /reload/rewrites/upsert` replaces or adds local A/AAAA/CNAME rewrites by
normalized DNS name, while `POST /reload/rewrites/remove` removes named
rewrites atomically; `POST /reload/rewrites` replaces the complete rewrite
table. Invalid and unknown updates fail without publication.
`POST /reload/policy-bundle` replaces the domain, regex, profile, client-group,
client-identity,
local-rewrite, and country-policy tables as one validated snapshot while
retaining loaded blocklists. Its optional `mode`, `domains`, `default_action`,
and `filtering_enabled` fields also replace the legacy fallback settings
atomically;
its optional `blocklists` array can replace the
blocklist source paths in the same validated publication, while
`disabled_blocklists` retains configured paths without loading their rules;
omitted or `null` retains the current blocklist snapshot. Reloads bound source count, path
length, each file, and aggregate file bytes before touching the live snapshot.
`POST /reload/config` accepts the same policy shape plus a required `admission`
object and publishes policy tables and live admission limits together;
startup-only capacity changes are rejected before either snapshot changes.
`POST /reload/blocklists/replace` atomically replaces the blocklist source path
set and preserves the previous sources and rules if a replacement fails.
`POST /reload/blocklists/add` and `/reload/blocklists/remove` atomically manage
individual source paths, preserving the last good snapshot on failure.
`GET /privacy/status` exposes only privacy-recording enablement and configured
limits; it does not expose recording paths, names, clients, or payloads. When
`privacy.query_recording_rotation_enabled = true`, startup rotates an oversized
Proxima JSONL decision log into a bounded number of numbered generations and
verifies deletion of the exact oldest generation before opening the active file.
For deterministic offline inspection, run `blackhole --replay recording.jsonl`.
To remove a durable decision recording, run `blackhole --delete-recording
recording.jsonl`; this deletes only the exact file and its bounded `.1` through
`.16` rotations, then verifies that each target is absent.
This consumes the existing Proxima JSONL recording source, accepts only
Blackhole metadata events, caps input at 64 MiB, and prints stable counts for
events, complete action identities, and persisted DDoS incidents. It does not
replay DNS names or wire payloads.
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

For an unprivileged macOS deployment, install
`deploy/launchd/com.brianbruggeman.blackhole.plist` as
`/Library/LaunchDaemons/com.brianbruggeman.blackhole.plist`. The launch daemon
runs directly as the dedicated `_blackhole` user and reads
`/usr/local/etc/blackhole/blackhole.toml`; create
`/usr/local/var/lib/blackhole` owned by that account before loading it. Keep the
example high-port listener unless a separately authorized PF redirect is
installed: macOS does not provide Linux-style per-binary low-port capabilities.
Validate the installed configuration with
`blackhole --check /usr/local/etc/blackhole/blackhole.toml` before running
`launchctl bootstrap system` on the plist. The launch daemon neither installs
nor removes PF rules.

After building the release binary, the checked-in launchd installer can create
the `_blackhole` account, install the binary/configuration/plist with bounded
ownership, validate the configuration and plist, and roll back an interrupted
upgrade:

```sh
cargo build --release --features std --bin blackhole
sudo BLACKHOLE_BINARY="$PWD/target/release/blackhole" \
  BLACKHOLE_CONFIG="$PWD/blackhole.example.toml" \
  ./deploy/launchd/install.sh
```

For a reproducible release bundle, build the binary and run the checked-in
packager with explicit paths:

```sh
cargo build --release --features std --bin blackhole
deploy/package/build.sh target/release/blackhole dist
```

The resulting archive contains the binary, example configuration, systemd and
launchd assets, `PROVENANCE.txt`, and `SHA256SUMS`. Native package-manager
artifacts and host upgrade automation are not implied by this bundle.
