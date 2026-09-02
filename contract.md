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

Local rewrites are configured as bounded A/AAAA answers. They are used only
when the selected action is `pass` or `observe`; an explicit matching rule for
any other action takes precedence over the rewrite.

Named service profiles are configuration shorthand for bounded sets of policy
rules. Their generated rules participate in the same domain, client, qtype,
qclass, priority, and action precedence contract as explicit rules.

Client groups are named, bounded sets of IPv4/IPv6 CIDRs. A service profile
may name one or more groups; the compiler expands the profile into one
authoritative rule set per group. Direct `client_cidrs` and named `groups`
cannot be combined, and an unknown or empty group fails configuration before
publication.

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

Upstream transport failures are observed before they are returned through the
existing Proxima telemetry stream. Their bounded causes distinguish timeout,
wire decoding, response-ID mismatch, I/O, and configuration failures; an
unknown future Proxima error remains `upstream_error`.

When `admission.ddos.persist_incidents` is enabled, the same Proxima JSONL
destination also records authenticated operator denylist mutations. The
bounded `add` and `remove` events replay in file order during startup; an
unavailable recording sink rejects the live mutation and leaves the prior
admission snapshot active.
