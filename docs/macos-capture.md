# macOS capture boundary

Blackhole's macOS capture plan uses a PF/rdr anchor. The pure planner emits
an explicitly owned anchor containing TCP and UDP redirects to the local DNS
listener. A privileged facade must install and verify that anchor through the
shared `RuleBackend` capability; the shared crate does not invoke `pfctl` or
any macOS API.

The adapter reuses Linux's `CaptureContext` and `ReplyRoute` types. Original
destination, client address, interface, mark, and reply routing remain
adapter-owned metadata and are never inferred from DNS bytes. Contexts that
PF cannot support transparently are rejected with a typed `PfError`.

Install verification failure removes only the owned anchor. Cleanup is
idempotent, so reboot/crash recovery can safely reapply or remove the known
anchor without flushing administrator rules. Loopback smoke verification is a
manual privileged operation and is intentionally not run by normal tests.
