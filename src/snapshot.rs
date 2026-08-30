//! Immutable policy publication over Proxima's lock-free `Live<T>` primitive.

use crate::policy::{PolicyError, ReferencePolicy, RuleConfig};
use proxima_core::live::{Live, LiveControl, live};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadState {
    Published,
}

/// Read/control halves for immutable policy snapshots.
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

    /// Validate off the request path, then publish one whole snapshot.
    pub fn reload(&self, rules: &[RuleConfig]) -> Result<ReloadState, PolicyError> {
        let next = ReferencePolicy::new(rules)?;
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
                })
                .is_none()
        }));
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
                    })
                    .is_some()
            }));
        }
    }
}
