# blackhole

A DNS sinkhole/honeypot for Linux and macOS. The policy engine is pure
Rust and the wire/runtime edge uses Proxima from
[`brianbruggeman/proxima`](https://github.com/brianbruggeman/proxima); the
default runtime path is Prime-backed, with the full Tokio capability set
available through the opt-in compatibility feature. DNS over UDP datagrams and
TCP share one bind and the same bounded policy/FSM path. Client-scoped rules,
admission limits, action semantics, and telemetry apply consistently to both
transports; TCP additionally uses bounded length-prefixed framing and UDP
rejects oversized datagrams before parsing.
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

For a LAN resolver starting point, copy
`blackhole.lan.example.toml`, replace `192.168.50.1` with the host's LAN
address, and set the upstream and blocklist paths for that network. Keep
`capture.enabled = false` until the platform-specific firewall adapter has
been reviewed and authorized; the file binds only the selected LAN address.

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
Authenticated operators can also toggle that live gate directly with
`POST /reload/filtering` and `{"enabled":false}` (or `true`); repeated values
return `unchanged` without rebuilding the policy snapshot.
Pass and observe queries use the configured Proxima upstream after local
rewrites; explicit forward rules use the same bounded upstream path and fail
closed when it is not configured. Forwarded positive and negative answers are
cached within configured bounds. A truncated UDP answer is retried over the
same upstream's bounded DNS-over-TCP path after validating its response ID,
question, QR bit, and opcode. Timeout is bounded to 60 seconds and retries to
eight attempts per exchange, while an upstream circuit breaker limits repeated
failures through Proxima's `CircuitBreaker` state machine and permits stale
answers only during its configured stale window.
Upstream failures preserve bounded cause labels for timeout, wire, response-ID,
I/O, and configuration errors in the existing Proxima telemetry stream before
the failure is returned to the listener.
Private/local upstream answers are rejected by default. For split-DNS deployments,
`[security].allowed_upstream_cidrs` provides a bounded explicit CIDR exception
without disabling rebinding protection for other private addresses.
DNSSEC response records (DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, CDS, and
CDNSKEY) are bounded
and passed through with validated owner/class metadata; cryptographic DNSSEC
validation remains the upstream resolver's responsibility.
Validated upstream CNAME targets are inspected against the same policy before
the response is cached or returned, so a blocked target cannot bypass domain,
regex, qtype, qclass, or client-scope rules.
Client identities may set an optional bounded `max_queries_per_second` ceiling;
identities without an override use the configured admission default.
They may also set `max_response_bytes_per_second` to cap encoded DNS egress for
that identity independently of the default per-client budget.
They may set `max_inflight_requests` to lower the concurrent request ceiling
for that identity; absent overrides use the admission default.
Repeated per-client rate-limit violations open a bounded temporary abuse
breaker; unidentified callers are not assigned a shared abuse identity.
Identified malformed-query floods also feed that same bounded client/network
breaker using parser failure causes only; malformed wire payloads are never
retained.
Operators can also set `[admission].deny_client_cidrs` to a bounded list of
IPv4/IPv6 CIDRs (use `/32` or `/128` for one address); those clients receive
REFUSED before policy matching, rate accounting, or forwarding. The denylist
is live-reloadable and invalid replacements are rejected without publication.
Set `[admission].allow_client_cidrs` to make admission default-deny: only
identified clients in the listed IPv4/IPv6 CIDRs are served, and unidentified
clients are refused before the denylist and DNS policy are evaluated. The
allowlist is bounded, live-reloadable with the rest of admission, and invalid
replacements are rejected without publication.
`[admission].global_rate_limit_whitelist_cidrs` can exempt bounded IPv4/IPv6
CIDRs from only the global query-rate ceiling; per-client, network, response,
and abuse limits still apply.
Authenticated operators can export it at `GET /abuse/denylist`, add bounded
entries with `POST /abuse/denylist/add`, and revoke entries with
`POST /abuse/denylist/remove`; these operations publish through the same
atomic admission snapshot and are safe to retry.
The global rate-limit whitelist is visible at authenticated
`GET /abuse/rate-limit-whitelist` and is similarly manageable through
authenticated `POST /abuse/rate-limit-whitelist/add` and
`/abuse/rate-limit-whitelist/remove`

The first-class domain allowlist is available at authenticated `GET /allowlist`
and can be atomically replaced with a bounded JSON array using
`POST /reload/allowlist`. Configured client identities can use
`POST /reload/allowlist/identity` with
`{"identity":"family-router","domains":["safe.example"]}`; an empty
domain array removes that scoped entry. Invalid domains or unknown identities
leave the active allowlists unchanged.
Client-group blocklist assignments are similarly available at authenticated
`GET /blocklist-groups` and can be atomically replaced with a bounded JSON
object using `POST /reload/blocklist-groups`; invalid assignments leave the
active snapshot unchanged.
For configuration-driven per-device policy, use
`policy.blocklists_by_identity = { family-router = ["/etc/blackhole/family.txt"] }`.
The named identity must be enabled, each source must also appear in
`policy.blocklists`, and assigned sources are removed from the global snapshot;
only requests carrying that adapter-owned identity receive those rules.
The same bounded assignment map is inspectable at authenticated
`GET /blocklists-by-identity` and replaceable with
`POST /reload/blocklists-by-identity`.
with bounded JSON CIDR arrays; it changes only the global ceiling exemption
and is safe to retry.
Set `[admission.ddos].persist_incidents = true` to persist temporary-blacklist
events through the bounded Proxima recording sink; client, network, and global
breaker markers are restored after restart until their configured expiry, and
expired markers are ignored. Global markers contain no client key.
Authenticated operators can revoke temporary blocks with bounded
`POST /abuse/revoke` using an array of exact client IPs; when persistence is
enabled, the revocation is recorded before the live breaker state is cleared
and startup replays it in event order.
The global breaker has a separate `POST /abuse/global/revoke` control; when
persistence is enabled, its scope-only revocation is recorded and replayed so
an operator-cleared global incident does not return after restart.
When the bounded query log is enabled, `GET /abuse/incidents` provides a
redacted incident review containing causes, expiry timestamps, and active or
expired state without client addresses.
Authenticated operators can export the newest bounded durable incident and
revocation events at `GET /abuse/incidents/export`; this endpoint includes
client keys for recovery and must be protected as operator-sensitive data.
The same setting persists authenticated operator denylist additions and
revocations in order; startup replays those bounded mutations before serving,
and a failed durable mutation is rolled back.
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
malformed filter modifiers fail closed. A bounded `[policy].allowlist` is also
available for operator-owned domain exceptions; each entry covers its apex and
subdomains and takes precedence over ordinary generated blocklist rules.
Invalid or duplicate entries fail closed. Local
A/AAAA/CNAME/PTR/TXT rewrites are bounded and apply to `pass`/`observe` queries;
exact names win over one-label wildcard names, identity-scoped rewrites win over
global rewrites, and explicit policy actions take precedence. A rewrite contains
exactly one record family: `ipv4`, `ipv6`,
`cname`, `ptr`, or `txt`. The `[capture]` section is disabled
by default; when enabled, it installs and recovers only the platform-native,
journal-owned DNS redirect rules.
An optional `policy.hosts_path` reads a bounded standard hosts file at startup
and turns its IPv4/IPv6 entries into local A/AAAA rewrites. Comments and
multiple names per address are supported; explicit rewrites win for names
present in both sources. Set `policy.hosts_reload_interval_secs` to enable a
bounded Proxima interval reload; failed reads retain the last good snapshot.
The source path itself remains startup-only.
Configured blocklists may be refreshed by Proxima's cancellable background
interval with `policy.blocklist_reload_interval_secs`; zero disables polling,
the interval is bounded to one day, unchanged content does not create a new
policy generation, and failed reloads retain the last good snapshot.
Individual sources can be retained but disabled with
`policy.disabled_blocklists`; the authenticated admin API also exposes
`POST /reload/blocklists/disable` and `/reload/blocklists/enable` for atomic
runtime changes. `GET /blocklists` includes each source's bounded filesystem
status, parser load status, contributed rule count, and deterministic content
fingerprint without returning its contents.
Set the top-level `reload_interval_secs` to enable bounded polling of the
policy-bearing portions of the same configuration file; listener, transport,
capture, storage, and process-capacity changes fail closed until restart.
Named service profiles are also compiled into the authoritative rule table;
each profile supplies a bounded domain set and action.
The optional country policy accepts an operator-supplied local file or bounded
HTTP(S) `COUNTRY CIDR [REGION] [ASN]` map;
`country_policy.last_good_path` enables an optional local, atomically replaced
last-good map snapshot for recovery from a failed source refresh.
`country_policy.reload_interval_secs` enables bounded background refresh, where
unchanged content is not republished and failed refreshes retain the last good
map. Local files may use `max_age_secs`; that bound also applies when a
last-good snapshot is used after a failed refresh, so stale recovery fails
closed. Hosted refreshes use Proxima's bounded 30-second timeout for connection,
response headers, and the complete response body, and fail closed when that
deadline or the byte bound is exceeded. When `max_age_secs` is configured for a
hosted map, the response must provide a valid `Cache-Control: max-age` contract;
without it the refresh fails closed. Region and ASN selectors are explicit
operator policy over those map labels; no GeoIP database or inferred identity
is provided. Set `country_policy.unmapped_action` to `pass` (the default),
`observe`, or `deny` to make the treatment of clients absent from the map
explicit. Classification remains an explicit policy signal, not authentication.
Profiles may name bounded client groups with `groups = ["family", "guest"]`;
each group supplies exact IPv4/IPv6 client addresses and/or CIDRs, and a
profile may target multiple groups.
Conditional forwarding routes can send PTR queries, or all queries below an
explicit local suffix, for selected client CIDRs or enabled client identities
to named upstreams. Identity and CIDR selectors can be combined, in which case
both must match. The most-specific matching suffix, identity scope, and client
prefix win; routes use the existing
Proxima exchange, cache namespace, permits, and circuit breaker, and unknown
upstreams or invalid scopes fail configuration before startup.
For direct identity-scoped rules, map bounded adapter-owned client addresses
to an opaque label:

```toml
[[policy.client_identities]]
name = "family-router"
filtering_enabled = true
clients = ["192.0.2.10"]
client_cidrs = ["192.0.2.0/24"]
```

Rules using `client_identity = "family-router"` match that transient label;
exact addresses take precedence over CIDR scopes, overlapping scopes across
identities are rejected, and names and client identities are excluded from
telemetry and recording.
Set `filtering_enabled = false` on an identity to retain its mapping while
allowing that client's queries through without applying policy rules; the
global filtering switch remains independent.
Set `query_log_enabled = false` to exclude that client's decision metadata from
both query-recording destinations while retaining policy enforcement.
Set `statistics_enabled = false` to exclude that client's actions from aggregate
statistics while retaining policy enforcement, failure telemetry, and recording.
Set `cache_enabled = false` to bypass bounded positive, negative, and stale
response caching for that client while retaining upstream forwarding.
Set `max_response_bytes_per_network_per_second` on an identity to override the
encoded response-byte budget for its configured client network; absent values
inherit the admission default.
Set `max_response_bytes_per_network_per_second` on an identity to override the
encoded response-byte budget for its configured client network; absent values
inherit the admission default.
To assign an existing named service profile to an adapter-owned identity, add
`service_profiles_by_identity = { family-router = ["family-blocks"] }` under
`[policy]`. Assigned profiles apply only to those identities (while retaining
their bounded domains, action, query selectors, and existing network/group
scopes) and are validated as a startup-only configuration change.
Direct `client_cidrs` and named groups are mutually exclusive.
Rules may use `client_cidrs` for a bounded set of IPv4/IPv6 networks; the
most-specific matching network wins while `client_cidr` remains supported.
Domain and regex rules may select one `qtype`/`qclass` or bounded
`qtypes`/`qclasses` lists; selector sets are deduplicated, validated, and
ranked independently while the single-value fields remain compatible.
Bounded regular-expression rules are available through `policy.regex_rules`;
invalid or oversized expressions fail configuration validation, and explicit
domain rules take precedence when both match. Regex rules may also use the
same bounded `client_cidrs` network scope as domain rules, or an adapter-owned
`client_identity` scope.

The upstream transport is selected in `[upstream]`: `transport = "udp"` keeps
UDP with bounded TCP fallback, `transport = "tcp"` uses DNS-over-TCP for every
exchange, `transport = "tls"` uses DNS-over-TLS for every exchange, and
`transport = "doh"` uses DNS-over-HTTPS for every exchange. Encrypted modes
require `tls_server_name` and validate the server certificate through
Proxima's GitHub HTTP/TLS pipe adapters. `transport = "doq"` uses
DNS-over-QUIC through Proxima's existing QUIC stream adapter and requires the
opt-in `doq` feature; the default Prime build remains QUIC-free.

The default route may also set `upstream_fallbacks = ["name"]` to try an
ordered list of named upstreams after transport or wire failures. Valid DNS
error answers are not retried, and each fallback keeps its own bounded
outstanding-query pool and circuit breaker.

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
JSON form, and provides buttons for replacing, adding, removing, enabling,
disabling, and reloading configured blocklists or
publishing the complete bundle. The same routes are available as
authenticated `GET /health`, `GET /status`, bounded `GET /admission/status`,
`GET /country/status`,
`POST /country/preview` (an authenticated, non-retaining country/region/ASN
classification preview for an operator-supplied client address),
`GET /policy/status`,
`POST /policy/preview` (an authenticated dry-run for a name, qtype, qclass,
and optional client address),
`GET /abuse/denylist`,
`GET /policy-bundle`,
`GET /rules`, `GET /logs`,
and `POST /logs/clear`, `POST /logs/clear-durable`, `POST /logs/verify-durable`, `POST /cache/clear`, `POST /reload/blocklists`, bounded
`POST /reload/blocklists/replace`, `/reload/blocklists/add`, and
`/reload/blocklists/remove`, `/reload/blocklists/enable`, and
`/reload/blocklists/disable` (atomic exact source-path management), bounded
`POST /reload/admission` (a bounded JSON admission configuration; the global
in-flight capacity remains startup-only), bounded
`POST /reload/admission/denylist` (an atomic JSON array replacement for only
the configured client CIDRs), bounded
`POST /abuse/denylist/add` and `/abuse/denylist/remove` (atomic bounded
operator-managed additions and revocations), bounded
`POST /abuse/rate-limit-whitelist/add` and `/abuse/rate-limit-whitelist/remove`
(atomic bounded global-ceiling exemptions), bounded
`POST /abuse/revoke` (atomic bounded temporary-incident revocation), bounded
`POST /abuse/global/revoke` (durable global-breaker revocation), bounded
`POST /abuse/incidents/approve` (atomic exact-client incident approval into the
managed denylist), bounded
`GET /abuse/incidents` (redacted bounded incident review), bounded
`GET /abuse/incidents/export` (bounded durable incident export), bounded
`POST /reload/country` (returns `reloaded` or `unchanged`), bounded
`POST /reload/hosts` (manually reloads the configured hosts source and retains
the last valid rewrite snapshot on failure), bounded
`POST /reload/policy` (a JSON array of complete rule objects; each rule may
set `enabled` to retain it without matching), bounded
`POST /reload/country/replace` (an atomic country/CIDR selector and map
configuration replacement), bounded
`POST /reload/policy/add` (a non-empty JSON array appended atomically to the current domain rules), bounded
`POST /reload/policy/upsert` (a non-empty JSON array that replaces or adds rules by stable ID while preserving unspecified rules), and bounded
`POST /reload/policy/remove` (a JSON array of stable rule IDs removed atomically), and bounded
`POST /validate/policy` (a JSON array validated against the current profile-generated rules without publishing), and bounded
`POST /validate/policy-bundle` (a complete bundle validated across profiles,
identities, rewrites, country policy, blocklists, legacy fields, admission,
and rule IDs without publishing), and bounded
`POST /reload/regex` (a JSON array of regex rule objects; each rule may set
`enabled` to retain it without matching),
`POST /validate/regex` (a JSON array validated against the current domain rule IDs without publishing),
`POST /reload/regex/upsert` (a JSON array that replaces or adds regex rules by
stable ID), and `POST /reload/regex/remove` (a JSON array of regex rule IDs).
It also provides bounded `GET /profiles`, `GET /client-groups`, and
`GET /rewrites` metadata views, plus bounded privacy-safe
query-decision inspection at `GET /logs` and deletion at `POST /logs/clear` when
enabled. `POST /logs/clear-durable` deletes the configured durable recording and
bounded rotations only after regular-file preflight and post-delete verification.
`POST /logs/verify-durable` reports bounded file and byte totals for the exact
recording target and rotations without reading payload contents or deleting
anything. Set `privacy.query_recording_verification = "directory_scan"` to
also detect unexpected recording generations in the destination directory.
`POST /reload/privacy/redaction` atomically selects `"metadata"` or
`"action_only"` for future decision events without restarting the resolver.
`POST /reload/profiles` atomically replaces the profile and client-group
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
metadata, may select a default action for unmatched queries, and invalid or
unknown updates fail closed.
`POST /reload/rewrites/upsert` replaces or adds local A/AAAA/CNAME/PTR/TXT rewrites by
identity and normalized DNS name, while `POST /reload/rewrites/remove` removes all
identity variants of named rewrites atomically. `POST /reload/rewrites/remove-scoped`
accepts selectors such as `[{"name":"router.example","client_identity":"family-router"}]`
to remove only the selected variant; `POST /reload/rewrites` replaces the complete
rewrite table. Invalid and unknown updates fail without publication.
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
Blocklist sources may also be absolute `http://` or `https://` URLs; hosted
lists are fetched through Proxima with the same per-source and aggregate byte
limits, and failed fetches do not replace the last good snapshot.
Sources can be scoped to a named client group with `[policy.blocklist_groups]`;
assigned sources are not applied globally. Group assignments are validated at
startup and participate in bounded blocklist refreshes; changing assignments
requires restart so a live refresh cannot publish a partially scoped table.
`GET /privacy/status` exposes only privacy-recording enablement and configured
limits; it does not expose recording paths, names, clients, or payloads. When
`privacy.query_recording_rotation_enabled = true`, startup rotates an oversized
Proxima JSONL decision log into a bounded number of numbered generations and
verifies deletion of the exact oldest generation before opening the active file.
`GET /country/status` exposes bounded map lifecycle metadata: source kind and
state, source age for local files, freshness validity under `max_age_secs`,
entry count, and content fingerprints. It never exposes the configured path,
map rows, or client addresses; a missing or unreadable local source is reported
without replacing the last good published snapshot.
`GET /abuse/status` reports bounded live breaker occupancy together with the
configured client, network, and global violation thresholds, windows,
cooldowns, and incident-persistence flag; it never exposes breaker keys.
`GET /status` also reports the bounded upstream circuit-breaker state
(`closed`, `open`, or `half_open`) so operators can distinguish an idle
resolver from one fail-closed by upstream health.
Named upstreams are configured under `[upstreams.<name>]`; an enabled client
identity may set `upstream = "<name>"` to use that route. Named routes are
startup-only, independently bounded, and use the same Proxima DNS exchange,
transport validation, cache isolation, and circuit-breaker behavior as the
default upstream.
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
firewall capture rules. Linux nftables capture requires a kernel with NAT-table
and redirect support; unsupported kernels fail closed with an actionable
capability error and roll back any partial installation.

For an unprivileged macOS deployment, install
`deploy/launchd/com.brianbruggeman.blackhole.plist` as
`/Library/LaunchDaemons/com.brianbruggeman.blackhole.plist`. The launch daemon
runs directly as the dedicated `_blackhole` user and reads
`/usr/local/etc/blackhole/blackhole.toml`; the checked-in installer creates the
account and state directory with bounded ownership. Keep the
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
launchd assets, the launchd host install/upgrade smoke harness,
`PROVENANCE.txt`, and `SHA256SUMS`. Native package-manager artifacts are not
implied by this archive; the Debian builder and its disposable install/upgrade
smoke are separate checked-in paths.
Country-map status reports whether an operator SHA-256 content pin is active;
the existing last-good snapshot is retained when a refresh does not match it.
