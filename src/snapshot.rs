//! Immutable policy publication over Proxima's lock-free `Live<T>` primitive.
//!
//! `Live<T>` is a publication cell, not a Proxima `Pipe`: it has no `In`, `Out`,
//! `Err`, or async `call`. The resolver samples the read half; authenticated
//! reload code validates and swaps through the control half. Actual request
//! dataflow remains in the Proxima pipe/listener path.

use crate::policy::{PolicyError, ReferencePolicy, RuleConfig};
use proxima_core::live::{Live, LiveControl, live};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadState {
    Published,
    Unchanged,
}

/// Read/control halves for immutable policy snapshots.
///
/// This is shared state publication, not a pipe or a second dataflow model.
pub struct PolicyStore {
    current: Live<ReferencePolicy>,
    control: LiveControl<ReferencePolicy>,
}

impl PolicyStore {
    pub fn new(rules: &[RuleConfig]) -> Result<Self, PolicyError> {
        let snapshot = ReferencePolicy::new(rules)?;
        let (current, control) = live(snapshot);
        Ok(Self { current, control })
    }

    /// Read one complete immutable snapshot without taking a lock.
    pub fn read<R>(&self, with: impl FnOnce(&ReferencePolicy) -> R) -> R {
        self.current.read(with)
    }

    /// Return the IDs in the currently published snapshot for cross-table
    /// validation performed by the runtime's regex table.
    pub fn rule_ids(&self) -> BTreeSet<u32> {
        self.current.read(ReferencePolicy::rule_ids)
    }

    /// Validate off the request path, then publish one whole snapshot.
    pub fn reload(&self, rules: &[RuleConfig]) -> Result<ReloadState, PolicyError> {
        let next = ReferencePolicy::new(rules)?;
        if self.current.read(|current| current == &next) {
            return Ok(ReloadState::Unchanged);
        }
        self.control.replace(next);
        Ok(ReloadState::Published)
    }
}

impl Clone for PolicyStore {
    fn clone(&self) -> Self {
        Self {
            current: self.current.clone(),
            control: self.control.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, QueryContext};

    fn rule(id: u32, domain: &str, action: Action) -> RuleConfig {
        RuleConfig {
            id,
            domain: domain.into(),
            action,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
            client_identity: None,
        }
    }

    #[test]
    fn failed_reload_keeps_the_last_valid_snapshot() {
        let store = PolicyStore::new(&[rule(1, "old.example", Action::Drop)]).expect("initial");
        let invalid = [
            rule(1, "new.example", Action::Pass),
            rule(1, "other.example", Action::Drop),
        ];
        assert_eq!(
            store.reload(&invalid),
            Err(PolicyError::DuplicateRule { id: 1 })
        );
        assert!(store.read(|policy| {
            policy
                .decide(QueryContext {
                    name: "old.example",
                    qtype: 1,
                    qclass: 1,
                    client: None,
                    client_identity: None,
                })
                .is_some()
        }));
        assert!(store.read(|policy| {
            policy
                .decide(QueryContext {
                    name: "new.example",
                    qtype: 1,
                    qclass: 1,
                    client: None,
                    client_identity: None,
                })
                .is_none()
        }));
    }

    #[test]
    fn valid_reload_publishes_atomically() {
        let store = PolicyStore::new(&[rule(1, "old.example", Action::Drop)]).expect("initial");
        assert_eq!(
            store.reload(&[rule(2, "new.example", Action::Reject)]),
            Ok(ReloadState::Published)
        );
        assert!(store.read(|policy| {
            policy
                .decide(QueryContext {
                    name: "new.example",
                    qtype: 1,
                    qclass: 1,
                    client: None,
                    client_identity: None,
                })
                .is_some()
        }));
        assert!(store.read(|policy| {
            policy
                .decide(QueryContext {
                    name: "old.example",
                    qtype: 1,
                    qclass: 1,
                    client: None,
                    client_identity: None,
                })
                .is_none()
        }));
    }

    #[test]
    fn identical_reload_is_reported_without_republication() {
        let rules = [rule(1, "same.example", Action::Reject)];
        let store = PolicyStore::new(&rules).expect("initial");
        assert_eq!(store.reload(&rules), Ok(ReloadState::Unchanged));
    }

    #[test]
    fn repeated_reload_retires_old_snapshots_without_mixed_reads() {
        let store = PolicyStore::new(&[rule(0, "generation-0.example", Action::Drop)]).unwrap();
        for generation in 1..32 {
            let domain = format!("generation-{generation}.example");
            assert_eq!(
                store.reload(&[rule(generation, &domain, Action::Reject)]),
                Ok(ReloadState::Published)
            );
            assert!(store.read(|policy| {
                policy
                    .decide(QueryContext {
                        name: &domain,
                        qtype: 1,
                        qclass: 1,
                        client: None,
                        client_identity: None,
                    })
                    .is_some()
            }));
        }
    }

    #[test]
    fn concurrent_readers_observe_only_complete_generations() {
        use std::sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
        };
        use std::thread;

        let store = Arc::new(
            PolicyStore::new(&[
                rule(0, "generation-0-a.example", Action::Drop),
                rule(1, "generation-0-b.example", Action::Reject),
            ])
            .unwrap(),
        );
        let inconsistent = Arc::new(AtomicBool::new(false));
        let start = Arc::new(Barrier::new(5));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let store = Arc::clone(&store);
            let inconsistent = Arc::clone(&inconsistent);
            let start = Arc::clone(&start);
            readers.push(thread::spawn(move || {
                start.wait();
                for _ in 0..1_000 {
                    let ids = store.read(|snapshot| snapshot.rule_ids());
                    if ids.len() != 2 {
                        inconsistent.store(true, Ordering::Relaxed);
                        continue;
                    }
                    let mut ids = ids.into_iter();
                    let first = ids.next().unwrap_or_default();
                    let second = ids.next().unwrap_or_default();
                    if second != first + 1 {
                        inconsistent.store(true, Ordering::Relaxed);
                    }
                }
            }));
        }

        start.wait();
        for generation in 1..64 {
            let first = generation * 2;
            let rules = [
                rule(
                    first,
                    &format!("generation-{generation}-a.example"),
                    Action::Drop,
                ),
                rule(
                    first + 1,
                    &format!("generation-{generation}-b.example"),
                    Action::Reject,
                ),
            ];
            assert_eq!(store.reload(&rules), Ok(ReloadState::Published));
        }
        for reader in readers {
            reader.join().expect("reader thread");
        }
        assert!(!inconsistent.load(Ordering::Relaxed));
    }
}
