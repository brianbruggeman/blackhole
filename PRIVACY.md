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
  metadata. The executable may append the same events to the configured
  `privacy.query_recording_path`; operators must choose an appropriate
  retention bound before enabling it. Blackhole enforces the configured
  `privacy.query_recording_max_bytes` ceiling and never supplies
  query names, client identity, credentials, or packet bytes to that sink.
  Operators may set `privacy.query_recording_redaction = "action_only"` to
  remove qtype and qclass before the shared event reaches either recording
  destination or the in-memory query log.
- The bounded fuzz corpus contains only synthetic/minimized wire samples and
  must not contain client identity or production payloads.
- The capture ownership journal contains only the exact firewall plan needed
  for recovery; it is not a query log.
- An authenticated `POST /cache/clear` operation deletes all currently cached
  DNS answers and returns only the bounded number of entries removed. It does
  not expose names, client identity, or payloads.
- The optional query-decision log is disabled by default. When enabled, it is
  bounded by `privacy.query_log_max_entries` and
  `privacy.query_log_retention_secs`, stores only timestamp/action/qtype/qclass
  metadata through Proxima's recording event shape, and is readable or
  deletable only through the authenticated loopback admin surface (`GET
  /logs` and `POST /logs/clear`). The in-memory log is not a durable honeypot
  store and is cleared on process exit. An authenticated
  `POST /logs/clear-durable` applies the same bounded exact-target deletion and
  verification to operator-requested durable erasure.
- The optional JSONL recording destination is a durable decision audit, not a
  honeypot terminal. It contains no query names, client identity, credentials,
  or wire payloads. When explicitly enabled, bounded startup rotation retains
  at most the configured number of old files, deletes only the oldest exact
  path, and verifies that deletion before opening the active destination.
- When `admission.ddos.persist_incidents` is explicitly enabled, the same
  destination may retain the temporary blacklist key (client IP), cause,
  timestamp, and bounded expiry. Startup restores only unexpired markers to
  the exact-client and configured-network breakers; global markers contain no
  client key and restore only the global breaker. Names and wire payloads
  remain excluded. Durable incident deletion is operator-managed through the
  recording files, not the in-memory `/abuse/clear` operation.
- The explicit local `--delete-recording` command preflights the active
  recording and its bounded 16 rotated generations, removes only those exact
  regular-file paths, and verifies each target is absent afterward. It does
  not recursively delete directories or unrelated files.
- Country-policy classification uses adapter-owned client addresses against an
  operator-supplied CIDR map. It is an operational classification signal, not
  identity, attribution, authentication, or a substitute for network-level
  DDoS protection. Operators may configure `country_policy.max_age_secs`; a
  stale or timestamp-unreadable map fails closed before publication.
- The authenticated `/abuse/denylist` export and add/remove routes expose only
  operator-managed CIDR configuration to an authenticated administrator; this
  is control-plane metadata, not telemetry, query logging, or payload storage.

## Future terminal requirements

The opt-in honeypot terminal stores bounded, base64-encoded DNS query payloads
in the existing Proxima recording-event shape in a separate in-memory sink.
It never stores DNS names separately, client addresses, or credentials. It is
exposed through the authenticated loopback admin surface at `GET /honeypot`
and can be cleared with `POST /honeypot/clear`.

Before any future payload-collection terminal is enabled, all of these must
be implemented and verified:

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

The current payload terminal remains in-memory and intentionally has no
durable payload sink until the controls above are complete.
