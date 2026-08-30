# Policy proof: exact, wildcard, and apex precedence

This is the B3 paper example. It deliberately uses exact rules and descendant
wildcards so an apex rule does not silently expand to every descendant.

## Inputs

Rules are evaluated in listed precedence order:

1. `ads.example` → `Nxdomain`
2. `*.telemetry.example` → `Ignore`
3. `telemetry.example` → `Honeypot(A=192.0.2.1)`

Queries are normalized by removing one or more terminal root dots and folding
ASCII letters to lowercase. A plain pattern matches only its apex. A `*.`
pattern matches one or more labels below its suffix and requires a dot boundary.

| Query | Matching rule | Result |
| --- | --- | --- |
| `ads.example. A` | `ads.example` | `Nxdomain` |
| `x.ads.example. A` | none | `Pass` |
| `telemetry.example. A` | `telemetry.example` | `Honeypot(A=192.0.2.1)` |
| `x.telemetry.example. A` | `*.telemetry.example` | `Ignore` |
| `notexample. A` | none | `Pass` |

The wildcard does not match the apex because the query must be longer than the
wildcard suffix. `notexample` does not match any suffix because it has no label
boundary. The wildcard wins for `x.telemetry.example` because the apex rule is
exact-only and therefore is not a candidate; no insertion-order tie is used.

## Pseudocode

```text
decide(query, rules):
    name = canonicalize(query.qname)
    if canonicalization fails:
        return PolicyError(MalformedName)

    for rule in rules ordered by priority, specificity, rule_id:
        if qclass/qtype/client scope does not match query:
            continue
        if rule.pattern is exact and name == rule.name:
            return rule.action
        if rule.pattern is wildcard:
            suffix = rule.name after "*."
            if name is longer than suffix and the preceding byte is '.':
                return rule.action

    return Pass
```

The proof test is `policy_proof_preserves_apex_and_wildcard_boundaries` in
`src/lib.rs`. It runs without the listener, sockets, runtime, filesystem, or
network. The matcher is intentionally a small semantic oracle; B6 will replace
the test-local rule representation with the reference policy pipe while
preserving these outputs.
