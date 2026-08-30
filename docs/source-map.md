# Blackhole source map

This map records the existing contracts used by the B0 implementation packet.
Line references are to the current Proxima source tree.

## Reused primitives

| Need | Existing source | Contract used |
| --- | --- | --- |
| Policy composition boundary | `../../proxima/proxima/src/lib.rs:1-13` | Proxima models transforms, sources, sinks, and observers as one pipe-shaped operation; runtime and I/O stay at the edge. |
| Cross-core handler | `../../proxima/proxima-primitives/src/pipe/primitives.rs:104-124` | `SendPipe` requires `Send + Sync + 'static` and returns a `Send` future. |
| DNS request/response types | `../../proxima/proxima-dns/src/pipes.rs:23-39,56-98` | The current facade hands handlers an owned `DnsQuery` and expects an owned `DnsAnswer`. |
| DNS wire boundary | `../../proxima/proxima-dns/src/wire.rs:32-50,106-139` | Wire parsing is performed before the handler; response encoding is performed after it. |
| Borrowed query codec | `src/query.rs` and `../../proxima/proxima-protocols/src/dns/codec_trait.rs:38-65,159-190` | Blackhole narrows Proxima's validated borrowed `Message` to one `QueryView` without dotted-name or label allocation. |
| Listener registration | `../../proxima/proxima-dns/src/pipes.rs:127-151` and `../../proxima/proxima/src/listener/protocol.rs:710-724` | `into_dns_handle` erases a compatible pipe, and the listener mounts that handle for DNS. |
| Immutable reload candidate | `../../proxima/proxima-core/src/live.rs:45-80,92-108` | `live` supplies a lock-free read half and an out-of-band replacement half. Reload validation must finish before replacement. |

## Crate graph and tiers

The present binary is a native edge crate: `blackhole` depends on the Proxima
DNS listener and Prime serving feature in `Cargo.toml`. The policy contract is
kept independent of sockets and listener builders. Future sans-IO protocol and
policy modules must use only the lowest dependencies needed for their data
model; Prime/Tokio compatibility belongs to adapters.

The current facade is owned and asynchronous because that is what the existing
`SendPipe` listener accepts. The decision algorithm planned by B4-B6 is a
separate borrowed, synchronous operation; it must not inherit this async
requirement merely because the adapter does.

## Deliberate non-reuse

The current `DnsAnswer` has an empty `NOERROR` representation for NODATA
(`../../proxima/proxima-dns/src/pipes.rs:56-60`). That is a valid DNS answer but
cannot represent silent drop. B7 therefore needs a typed transport disposition
at the adapter edge; the policy layer must not use an HTTP-like status integer
to distinguish those meanings.
