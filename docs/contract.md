# Blackhole contract (B0)

This is the first contract for DNS interception over UDP and TCP. It is a
design boundary, not a claim that every action is implemented by the current
facade.

## Operator contract

- With no argument, the process uses an in-memory default and binds
  `127.0.0.1:5353`.
- With an argument, that path is explicit. It must be readable and valid TOML;
  failure occurs before listener construction and therefore before socket bind.
- Binding is explicit configuration. There is no implicit `0.0.0.0` bind and no
  open-resolver default.
- Invalid bind addresses are configuration errors before listener construction.
- A policy-load failure is fail-closed: do not start the listener.
- v1 does not decrypt TLS, inspect arbitrary payloads, rewrite arbitrary
  packets, collect credentials, or forward unknown protocols.

## Policy input and precedence

The future decision seam receives a borrowed query view and bounded client
context. It evaluates rules in this order:

1. highest explicit priority;
2. most specific name: exact names, then the deepest matching wildcard suffix;
3. client scope;
4. qclass scope;
5. qtype scope;
6. stable rule id as the final deterministic tie-breaker.

When `policy.rules` is non-empty it is the complete policy. An unmatched query
uses the normal pass-through path and legacy `mode`/`domains` are ignored.
Legacy mode/domain behavior is used only when the rule table is empty.

Names are compared case-insensitively, with one optional root dot removed.
Suffix matches require a label boundary. Malformed names, unsupported classes,
and unknown protocols produce a typed policy/protocol error; they are never
silently treated as an allow.

## Actions and transport outcomes

The semantic action is independent of transport:

| Action | Decision meaning | UDP/TCP wire result in v1 |
| --- | --- | --- |
| `Pass` | permit normal resolution | forward when an upstream exists; otherwise typed unavailable outcome |
| `Drop` | intentionally emit nothing | UDP: no datagram; TCP: close without a DNS answer |
| `Reject` | actively refuse without synthesizing data | typed refusal outcome; never an echoed/reflection response |
| `Nxdomain` | name does not exist | DNS response with RCODE 3 |
| `Sink` | return a bounded synthetic sink answer | only requested supported RR data, bounded TTL and size |
| `Honeypot` | route to a separately controlled synthetic terminal | not a DNS address alias; unavailable until its adapter contract exists |
| `Forward` | send to an explicitly selected upstream | bounded upstream request/response, with loop prevention |
| `Observe` | record decision metadata and preserve semantics | no wire change |

The current Proxima facade can encode `Nxdomain` and sink answers through
`DnsAnswer`; it cannot express `Drop` without the existing adapter convention.
That gap is recorded for B7. Until then, no integer status field is part of
the policy contract.

## Positive and negative examples

| Input | Expected contract result |
| --- | --- |
| exact `ads.example.` / IN / A matching an `Nxdomain` rule | DNS NXDOMAIN |
| `notads.example.` | no match; normal path, not NODATA-as-allow |
| `x.ads.example.` with an apex-only rule | no match |
| `x.ads.example.` with a suffix rule | match |
| `X.Example.` and `x.example` | equivalent canonical name |
| malformed compression or unsupported protocol | typed error, then adapter drop/close |
| missing explicit config file | startup configuration error, no bind |

## Decision record fields

Each later design decision must state: problem, alternatives considered,
reused Proxima source, semantic effect, resource bounds, tier/feature impact,
security/privacy impact, tests, acceptance command, artifact path, and open
risk. Unmeasured performance properties remain unclaimed.
