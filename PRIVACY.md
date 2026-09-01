# Blackhole privacy contract

This contract describes what Blackhole may retain. It applies to the current
DNS edge and is a prerequisite for any future honeypot terminal.

## Current DNS edge

- Raw query and response payloads are not persisted.
- Client and original-destination metadata remain adapter-owned and are not
  put into the borrowed policy view.
- Telemetry contains action identity, bounded failure causes, and latency
  histograms; it must not contain query names, record data, credentials, or
  packet bytes.
- The optional Proxima recording sink receives only action, qtype, and qclass
  metadata. Operators must attach Proxima's bounded recording sink and enforce
  its retention and storage limits before enabling it; Blackhole never supplies
  query names, client identity, credentials, or packet bytes to that sink.
- The bounded fuzz corpus contains only synthetic/minimized wire samples and
  must not contain client identity or production payloads.
- The capture ownership journal contains only the exact firewall plan needed
  for recovery; it is not a query log.
- An authenticated `POST /cache/clear` operation deletes all currently cached
  DNS answers and returns only the bounded number of entries removed. It does
  not expose names, client identity, or payloads.
- Country-policy classification uses adapter-owned client addresses against an
  operator-supplied CIDR map. It is an operational classification signal, not
  identity, attribution, authentication, or a substitute for network-level
  DDoS protection.

## Future terminal requirements

No honeypot terminal may be enabled until all of these are implemented and
verified:

1. A documented retention period and a hard upper bound for every stored
   record, byte buffer, credential, and derived artifact.
2. Field-level redaction before persistence, with secrets and client identity
   excluded by default.
3. Authenticated, role-scoped access with an audit trail that contains no
   sensitive payload copy.
4. Crash-safe deletion that covers primary data, indexes, caches, exports,
   backups, and temporary files, followed by machine-checkable deletion
   verification.
5. Explicit consent and operator configuration for collection, with startup
   failure when a required retention or access control is absent.
6. Tests proving that disabled collection retains no payload and that every
   configured limit is enforced under overflow and restart conditions.

Until those controls exist, `Honeypot` means only the bounded synthetic DNS
answer documented in [contract.md](contract.md); it does not open a payload
collection terminal.
