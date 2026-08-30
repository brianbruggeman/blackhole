# Blackhole security and privacy review

## Scope and trust boundary

Blackhole trusts the local operator configuration and the injected Proxima
transport/runtime. DNS payloads, client addresses, original destinations,
firewall marks, interfaces, and upstream replies are untrusted. Adapter
metadata comes from the capture facility, never from payload bytes.

## Decisions

| Threat | Control | Failure decision |
| --- | --- | --- |
| malformed, compressed, or oversized DNS input | Proxima parser, compression-loop rejection, one-question requirement, 4096-byte query cap | drop |
| policy/resource denial of service | 100,000-rule cap, 253-byte domain cap, 1 MiB config cap, bounded honeypot records | reject config or drop |
| wildcard/case bypass | canonical lowercase/root-dot handling, label-boundary matching, invalid wildcard rejection | reject config or no match |
| spoofed client/original destination | metadata is supplied only by the adapter context; policy has no payload-derived client path | reject unsupported context |
| upstream spoofing/cache poisoning | Proxima upstream validates resolver sender and transaction ID; no cache is enabled | fail closed on transport/wire error |
| reflection/amplification | bounded A/AAAA synthetic replies; no attacker payload echo; forwarding is opt-in | drop when unavailable |
| privilege escalation/rule damage | privileged backend is injected; owned plans and transactional rollback never flush global rules | abort and rollback |
| credential or payload retention | no credentials, payload logging, or replay records by default; telemetry uses static action labels | omit data |

## Honeypot data policy

The current honeypot emits only configured synthetic A/AAAA records. It does
not collect credentials, retain payloads, or route connections to a terminal.
Any future terminal must have an explicit bounded retention duration,
redaction/hash policy, access control, and deletion verification before it is
connected to this policy pipe.

## Release evidence

Adversarial unit fixtures cover truncation, multi-question messages,
compression-pointer loops, oversized input, wildcard boundaries, invalid
rules, fail-closed forwarding, and adapter rollback. Fuzzing and a signed
operator threat-model artifact remain release-lane work; this document is the
review source, not a claim that those lanes have run.
