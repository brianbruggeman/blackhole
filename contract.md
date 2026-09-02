# Blackhole policy contract

Policy actions have one transport meaning at the DNS boundary:

| Action | Result |
| --- | --- |
| `pass` | Use a local rewrite when configured; otherwise pass through the configured upstream, or return empty `NOERROR` when no upstream is attached. |
| `observe` | Same pass-through behavior as `pass`, while preserving the observation identity. |
| `ignore` | Send no DNS response. |
| `drop` | Send no DNS response and record a policy drop. |
| `reject` | Return `REFUSED` (RCODE 5). |
| `nxdomain` | Return `NXDOMAIN` (RCODE 3). |
| `sink` | Return empty `NOERROR` (NODATA). |
| `honeypot` | Return the configured synthetic A/AAAA address when the type supports it. |
| `forward` | Query the configured Proxima upstream, subject to bounds and fail-closed errors. |

Local rewrites are configured as bounded A/AAAA/CNAME/PTR/TXT answers. They are used only
when the selected action is `pass` or `observe`; an explicit matching rule for
any other action takes precedence over the rewrite.

Named service profiles are configuration shorthand for bounded sets of policy
rules. Their generated rules participate in the same domain, client, qtype,
qclass, priority, and action precedence contract as explicit rules.
Explicit domain and regex rules may use bounded `qtypes` and `qclasses` sets;
the legacy singular fields are equivalent one-value sets. A singular field
must be included in its corresponding set when both forms are supplied.

Client groups are named, bounded sets of IPv4/IPv6 CIDRs. A service profile
may name one or more groups; the compiler expands the profile into one
authoritative rule set per group. Direct `client_cidrs` and named `groups`
cannot be combined, and an unknown or empty group fails configuration before
publication.

Conditional forwarding routes are bounded client-CIDR routes to named
upstreams. A route without `domain` handles only PTR queries; a route with a
domain handles that exact suffix and its subdomains for every query type.
Overlapping routes select the longest matching domain, then the longest client
network prefix. Named upstream validation applies before startup, and each
route reuses that upstream's Proxima exchange, permits, breaker, and cache
namespace. Routes are startup configuration; a live configuration reload
rejects changes rather than silently leaving the old route active.

Blocklist sources named by `[policy.blocklist_groups]` are removed from the
unscoped blocklist set and apply only to the referenced enabled client group.
Each source is validated against the configured source list, and its generated
rules inherit the group's exact-address and CIDR scopes. Group assignments are
startup configuration and are reused by bounded background source refreshes.

`[policy].allowlist` is a bounded list of normalized ASCII domains. Each entry
publishes an exact apex pass rule and a deep-subdomain pass rule. These rules
take precedence over ordinary generated blocklist rules, while invalid or
duplicate entries fail closed; every policy publication retains the configured
allowlist.

Regular-expression rules are evaluated only when no explicit domain rule
matches. They use the normalized DNS name without its trailing root dot and
are bounded at startup by expression count, pattern bytes, and compiled
program size. Among matching expressions, priority, qclass/qtype/client filter
specificity, and rule ID determine the winner.

Client scope accepts either one `client_cidr` or a bounded `client_cidrs` list,
but not both. A rule matches when the query client belongs to any listed
network; the longest matching network prefix wins client-scope precedence.

Malformed, response-shaped, flag-invalid, non-single-question, oversized, and
non-ASCII IDNA names are rejected before policy evaluation. A forward cache is bounded
by entry count, honors positive record TTLs, applies the configured negative
TTL to empty negative answers, and may serve stale data only within the
configured stale window during an upstream failure. The upstream circuit
breaker limits repeated failures; an open circuit has no network side effect.

Decision recording is opt-in. The authenticated `/logs` surface reads the bounded
in-memory metadata log; `privacy.query_recording_path` additionally appends the same
metadata-only events through Proxima's JSONL recording sink. An authenticated
`POST /logs/clear-durable`
 deletes only the configured recording basename and its bounded `.1` through
 `.16` rotations after regular-file preflight, then verifies every exact target
 is absent. When startup rotation is explicitly enabled,
Blackhole rotates only oversized files within the configured bounded generation
count and verifies deletion of the exact oldest generation. Its encoded size is bounded by
`privacy.query_recording_max_bytes`; operators must configure rotation and deletion
before enabling it.
The authenticated `POST /logs/verify-durable` operation checks the same exact
regular-file targets and reports bounded file and byte totals without reading
record payloads, deleting files, or retaining new metadata.

The authenticated `POST /policy/preview` control-plane route is a dry-run of
the live policy matcher. It accepts an ASCII DNS name, non-zero qtype and
qclass, and an optional client address, and returns the selected action and
matched rule ID. It does not execute rewrites or forwarding, increment
decision counters, emit recording events, or retain the supplied address.

An enabled client identity may set `filtering_enabled = false`. In that case
the identity remains configured and visible to control-plane projections, but
its queries bypass policy matching and continue through the normal pass,
rewrite, and upstream path; the global filtering switch is independent.

An enabled client identity may also set `query_log_enabled = false`. Decisions
for that mapped client are omitted from both the bounded in-memory query log
and the optional durable Proxima recording sink; telemetry action counts and
failure causes remain unaffected.

An enabled client identity may set `statistics_enabled = false` independently.
Its action is omitted from aggregate decision counts, while policy matching,
failure causes, and optional query-decision recording remain active.

An enabled client identity may set `cache_enabled = false` independently. Its
requests bypass fresh, negative, and stale response-cache reads and writes;
upstream forwarding, bounded exchange admission, and fail-closed behavior
remain active.

The authenticated `POST /country/preview` route performs the same kind of
non-retaining dry-run for a client address against the live country map. It
reports the matched country, region, ASN, and deny/observe results; it does
not classify the address as identity, persist it, or emit an observation.

Upstream transport failures are observed before they are returned through the
existing Proxima telemetry stream. Their bounded causes distinguish timeout,
wire decoding, response-ID mismatch, I/O, and configuration failures; an
unknown future Proxima error remains `upstream_error`.

When `admission.ddos.persist_incidents` is enabled, the same Proxima JSONL
destination records client, network, and global breaker openings without
retaining client keys for global events, and startup restores active incidents
until their bounded expiry. It also records authenticated operator denylist
mutations. The
bounded `add` and `remove` events replay in file order during startup; an
unavailable recording sink rejects the live mutation and leaves the prior
admission snapshot active.
