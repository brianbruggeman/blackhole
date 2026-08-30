# Blackhole decision FSM

The B5 FSM is `fsm::DecisionState`. Each transition consumes the current state
and returns a new state or a named `TransitionError`; it does not access a
socket, executor, or global policy.

| State | Valid events | Next state |
| --- | --- | --- |
| `Received` | `BeginParse`, `PeerClosed` | `Parsing`, `Closed` |
| `Parsing` | `Parsed`, `NeedMore`, `Drop`, `PeerClosed` | `Parsed`, `Parsing`, `Dropped`, `Closed` |
| `Parsed` | `Matched`, `Drop` | `Matched`, `Dropped` |
| `Matched(Forward)` | `Forward` | `Forwarding` |
| `Matched` | `Respond`, `Drop` | `Responding`, `Dropped` |
| `Forwarding` | `Forwarded`, `Drop`, `PeerClosed` | `Responding`, `Dropped`, `Closed` |
| `Responding` | `Sent`, `PeerClosed` | `Sent`, `Closed` |
| `Sent` | `NextMessage`, `PeerClosed` | `Received`, `Closed` |
| `Dropped` | `PeerClosed` | `Closed` |
| `Closed` | none | `TransitionError::Illegal` |

`NeedMore` is the retry edge for a caller-owned partial frame. `Sent` records
that the current response has been emitted; `NextMessage` is the separate
healthy TCP edge to the next caller-owned frame. Empty response storage is rejected as
`OutputTooSmall`; malformed input and policy failure are represented by
`DropReason`, not by a successful DNS answer.

The transition tests in `src/fsm.rs` cover every state, valid retry/forward/
close path, malformed and policy drops, the empty-output error, and illegal
transitions.
