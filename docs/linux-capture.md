# Linux capture boundary

The first Linux capture slice is a pure nftables planner and transaction
controller in `src/linux_capture.rs`. It does not open sockets, invoke `nft`,
or import Linux APIs. A privileged deployment backend must implement the
`RuleBackend` capability and own only the rule plan it receives.

The dry-run plan creates an `inet blackhole` table and an owned `capture`
chain. TCP and UDP traffic for the configured listener port is marked and
redirected to that port. The plan is deliberately explicit and stable so a
privileged facade can print it before installation.

Each captured flow carries these values as adapter context:

- original destination, retained from the socket/capture facility;
- client address, retained from the capture facility;
- interface name, bounded to the Linux interface limit;
- firewall mark, used for reply routing; and
- reply route, either original destination or marked route.

The policy layer must not infer any of these from DNS payload bytes. Install
is transactional: verify failure removes only the plan passed to the backend.
The backend must implement the same ownership rule for crash recovery,
status, and cleanup. No command runner or shell script is part of this crate.
