# Blackhole policy contract

Policy actions have one transport meaning at the DNS boundary:

| Action | Result |
| --- | --- |
| `pass` | Return `NOERROR` with no synthetic records. |
| `observe` | Same wire result as `pass`, while preserving the observation identity. |
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

Malformed, response-shaped, non-single-question, oversized, and non-ASCII
IDNA names are rejected before policy evaluation. A forward cache is bounded
by entry count, honors positive record TTLs, applies the configured negative
TTL to empty negative answers, and may serve stale data only within the
configured stale window during an upstream failure. The upstream circuit
breaker limits repeated failures; an open circuit has no network side effect.
