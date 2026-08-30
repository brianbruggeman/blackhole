//! Explicit sans-IO decision state machine for one DNS message at a time.

use crate::policy::Action;
use crate::query::QueryView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    PolicyFailure,
    OutputTooSmall,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Peer,
    Protocol,
}

/// One event supplied by the caller to advance the FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'packet> {
    BeginParse,
    Parsed(QueryView<'packet>),
    NeedMore(&'packet [u8]),
    Matched(Action),
    Forward,
    Forwarded(&'packet [u8]),
    Respond(&'packet [u8]),
    Sent,
    NextMessage(&'packet [u8]),
    Drop(DropReason),
    PeerClosed,
}

/// State data is limited to what is valid in that state. No state retains a
/// borrowed slice after the caller consumes the next transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionState<'packet> {
    Received {
        packet: &'packet [u8],
    },
    Parsing {
        packet: &'packet [u8],
    },
    Parsed {
        query: QueryView<'packet>,
    },
    Matched {
        query: QueryView<'packet>,
        disposition: Action,
    },
    Forwarding {
        query: QueryView<'packet>,
    },
    Responding {
        query: QueryView<'packet>,
        output: &'packet [u8],
    },
    Sent {
        query: QueryView<'packet>,
    },
    Dropped {
        reason: DropReason,
    },
    Closed {
        reason: CloseReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    Illegal {
        state: &'static str,
        event: &'static str,
    },
    OutputTooSmall,
}

impl core::fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Illegal { state, event } => {
                write!(formatter, "illegal FSM transition: {state} + {event}")
            }
            Self::OutputTooSmall => formatter.write_str("response output buffer is too small"),
        }
    }
}

impl core::error::Error for TransitionError {}

impl<'packet> DecisionState<'packet> {
    #[must_use]
    pub const fn received(packet: &'packet [u8]) -> Self {
        Self::Received { packet }
    }

    /// Consume one state and apply one caller-supplied event.
    pub fn transition(self, event: Event<'packet>) -> Result<Self, TransitionError> {
        match (self, event) {
            (Self::Received { packet }, Event::BeginParse) => Ok(Self::Parsing { packet }),
            (Self::Received { .. }, Event::PeerClosed) => Ok(Self::Closed {
                reason: CloseReason::Peer,
            }),
            (Self::Parsing { .. }, Event::Parsed(query)) => Ok(Self::Parsed { query }),
            (Self::Parsing { .. }, Event::NeedMore(packet)) => Ok(Self::Parsing { packet }),
            (Self::Parsing { .. }, Event::Drop(reason)) => Ok(Self::Dropped { reason }),
            (Self::Parsing { .. }, Event::PeerClosed) => Ok(Self::Closed {
                reason: CloseReason::Peer,
            }),
            (Self::Parsed { query }, Event::Matched(disposition)) => {
                Ok(Self::Matched { query, disposition })
            }
            (Self::Parsed { .. }, Event::Drop(reason)) => Ok(Self::Dropped { reason }),
            (
                Self::Matched {
                    query,
                    disposition: Action::Forward,
                },
                Event::Forward,
            ) => Ok(Self::Forwarding { query }),
            (Self::Matched { query, .. }, Event::Respond(output)) => {
                if output.is_empty() {
                    return Err(TransitionError::OutputTooSmall);
                }
                Ok(Self::Responding { query, output })
            }
            (Self::Matched { .. }, Event::Drop(reason)) => Ok(Self::Dropped { reason }),
            (Self::Forwarding { query }, Event::Forwarded(output)) => {
                if output.is_empty() {
                    return Err(TransitionError::OutputTooSmall);
                }
                Ok(Self::Responding { query, output })
            }
            (Self::Forwarding { .. }, Event::Drop(reason)) => Ok(Self::Dropped { reason }),
            (Self::Forwarding { .. }, Event::PeerClosed) => Ok(Self::Closed {
                reason: CloseReason::Peer,
            }),
            (Self::Responding { query, .. }, Event::Sent) => Ok(Self::Sent { query }),
            (Self::Responding { .. }, Event::PeerClosed) => Ok(Self::Closed {
                reason: CloseReason::Peer,
            }),
            (Self::Dropped { .. }, Event::PeerClosed) => Ok(Self::Closed {
                reason: CloseReason::Peer,
            }),
            (Self::Sent { .. }, Event::NextMessage(packet)) => Ok(Self::Received { packet }),
            (Self::Sent { .. }, Event::PeerClosed) => Ok(Self::Closed {
                reason: CloseReason::Peer,
            }),
            (state, event) => Err(TransitionError::Illegal {
                state: state.name(),
                event: event.name(),
            }),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Received { .. } => "Received",
            Self::Parsing { .. } => "Parsing",
            Self::Parsed { .. } => "Parsed",
            Self::Matched { .. } => "Matched",
            Self::Forwarding { .. } => "Forwarding",
            Self::Responding { .. } => "Responding",
            Self::Sent { .. } => "Sent",
            Self::Dropped { .. } => "Dropped",
            Self::Closed { .. } => "Closed",
        }
    }
}

impl Event<'_> {
    const fn name(self) -> &'static str {
        match self {
            Self::BeginParse => "BeginParse",
            Self::Parsed(_) => "Parsed",
            Self::NeedMore(_) => "NeedMore",
            Self::Matched(_) => "Matched",
            Self::Forward => "Forward",
            Self::Forwarded(_) => "Forwarded",
            Self::Respond(_) => "Respond",
            Self::Sent => "Sent",
            Self::NextMessage(_) => "NextMessage",
            Self::Drop(_) => "Drop",
            Self::PeerClosed => "PeerClosed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> QueryView<'static> {
        QueryView::parse(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1])
            .expect("root query")
    }

    #[test]
    fn valid_udp_path_reaches_response() {
        let state = DecisionState::received(b"partial")
            .transition(Event::BeginParse)
            .expect("begin")
            .transition(Event::Parsed(query()))
            .expect("parse")
            .transition(Event::Matched(Action::Nxdomain))
            .expect("match")
            .transition(Event::Respond(b"dns response"))
            .expect("response");
        assert!(matches!(state, DecisionState::Responding { .. }));
    }

    #[test]
    fn partial_input_retries_and_tcp_accepts_next_message() {
        let state = DecisionState::received(b"one")
            .transition(Event::BeginParse)
            .expect("begin")
            .transition(Event::NeedMore(b"one plus more"))
            .expect("retry");
        assert!(matches!(state, DecisionState::Parsing { .. }));
        let next = DecisionState::Responding {
            query: query(),
            output: b"reply",
        }
        .transition(Event::Sent)
        .expect("response sent")
        .transition(Event::NextMessage(b"second message"))
        .expect("next message");
        assert!(matches!(next, DecisionState::Received { .. }));
    }

    #[test]
    fn sent_is_distinct_from_waiting_for_the_next_message() {
        let sent = DecisionState::Responding {
            query: query(),
            output: b"reply",
        }
        .transition(Event::Sent)
        .expect("response sent");
        assert!(matches!(sent, DecisionState::Sent { .. }));
        assert!(matches!(
            sent.transition(Event::Sent),
            Err(TransitionError::Illegal { .. })
        ));
    }

    #[test]
    fn malformed_policy_drop_and_peer_close_are_explicit() {
        let dropped = DecisionState::received(b"bad")
            .transition(Event::BeginParse)
            .expect("begin")
            .transition(Event::Drop(DropReason::Malformed))
            .expect("drop");
        let closed = dropped
            .transition(Event::PeerClosed)
            .expect("close after drop");
        assert_eq!(
            closed,
            DecisionState::Closed {
                reason: CloseReason::Peer
            }
        );

        let policy_drop = DecisionState::Parsed { query: query() }
            .transition(Event::Drop(DropReason::PolicyFailure))
            .expect("policy drop");
        assert!(matches!(policy_drop, DecisionState::Dropped { .. }));
    }

    #[test]
    fn forwarding_and_empty_response_error_are_covered() {
        let state = DecisionState::Parsed { query: query() }
            .transition(Event::Matched(Action::Forward))
            .expect("match")
            .transition(Event::Forward)
            .expect("forward")
            .transition(Event::Forwarded(b"upstream reply"))
            .expect("upstream");
        assert!(matches!(state, DecisionState::Responding { .. }));
        assert_eq!(
            DecisionState::Matched {
                query: query(),
                disposition: Action::Sink,
            }
            .transition(Event::Respond(b"")),
            Err(TransitionError::OutputTooSmall)
        );
    }

    #[test]
    fn illegal_transition_is_named_and_closed_is_terminal() {
        let error = DecisionState::received(b"input").transition(Event::Respond(b"reply"));
        assert_eq!(
            error,
            Err(TransitionError::Illegal {
                state: "Received",
                event: "Respond",
            })
        );
        let closed = DecisionState::Closed {
            reason: CloseReason::Protocol,
        };
        assert!(matches!(
            closed.transition(Event::BeginParse),
            Err(TransitionError::Illegal {
                state: "Closed",
                ..
            })
        ));
    }
}
