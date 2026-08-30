//! Pure planning and lifecycle state for Linux nftables capture.
//!
//! This module intentionally contains no Linux or nftables bindings. The
//! privileged backend is an injected capability at the edge; the planner and
//! transaction controller are portable and deterministic.

use std::fmt;
use std::net::SocketAddr;

const MAX_INTERFACE_BYTES: usize = 15;
const MAX_CHAIN_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureContext {
    pub original_destination: SocketAddr,
    pub client: SocketAddr,
    pub interface: String,
    pub mark: u32,
    pub reply_route: ReplyRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyRoute {
    OriginalDestination,
    MarkedRoute,
}

impl CaptureContext {
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.interface.is_empty() || self.interface.len() > MAX_INTERFACE_BYTES {
            return Err(CaptureError::Bound("interface"));
        }
        if !self.interface.is_ascii() {
            return Err(CaptureError::Bound("interface"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRulePlan {
    pub table: String,
    pub chain: String,
    pub listen_port: u16,
    pub mark: u32,
}

impl NftRulePlan {
    pub fn new(
        chain: impl Into<String>,
        listen_port: u16,
        mark: u32,
    ) -> Result<Self, CaptureError> {
        let plan = Self {
            table: "blackhole".into(),
            chain: chain.into(),
            listen_port,
            mark,
        };
        if plan.chain.is_empty() || plan.chain.len() > MAX_CHAIN_BYTES || !plan.chain.is_ascii() {
            return Err(CaptureError::Bound("chain"));
        }
        if plan.listen_port == 0 || plan.mark == 0 {
            return Err(CaptureError::InvalidPlan);
        }
        Ok(plan)
    }

    /// Stable dry-run representation. The ownership comment is part of the
    /// plan so operators can audit exactly what a privileged backend may add.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "table inet {} {{\n  chain {} {{\n    type filter hook prerouting priority -150; policy accept;\n    tcp dport {} meta mark set {} redirect to :{}\n    udp dport {} meta mark set {} redirect to :{}\n  }}\n}}\n",
            self.table,
            self.chain,
            self.listen_port,
            self.mark,
            self.listen_port,
            self.listen_port,
            self.mark,
            self.listen_port,
        )
    }
}

pub trait CapturePlan {
    fn render(&self) -> String;
}

pub trait RuleBackend {
    type Plan: CapturePlan;

    fn install(&mut self, plan: &Self::Plan) -> Result<(), String>;
    fn verify(&mut self, plan: &Self::Plan) -> Result<(), String>;
    fn remove(&mut self, plan: &Self::Plan) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallState {
    Uninstalled,
    Installing,
    Installed,
    Failed,
}

pub struct CaptureController<B> {
    backend: B,
    state: InstallState,
}

impl<B: RuleBackend> CaptureController<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: InstallState::Uninstalled,
        }
    }

    pub fn install(&mut self, plan: &B::Plan) -> Result<(), CaptureError> {
        if self.state == InstallState::Installed {
            return Ok(());
        }
        self.state = InstallState::Installing;
        if let Err(error) = self.backend.install(plan) {
            self.state = InstallState::Failed;
            return Err(CaptureError::Backend(error));
        }
        if let Err(error) = self.backend.verify(plan) {
            let rollback = self.backend.remove(plan);
            self.state = InstallState::Failed;
            return Err(CaptureError::Transaction { error, rollback });
        }
        self.state = InstallState::Installed;
        Ok(())
    }

    pub fn cleanup(&mut self, plan: &B::Plan) -> Result<(), CaptureError> {
        if self.state == InstallState::Uninstalled {
            return Ok(());
        }
        self.backend.remove(plan).map_err(CaptureError::Backend)?;
        self.state = InstallState::Uninstalled;
        Ok(())
    }

    #[must_use]
    pub fn status(&self) -> InstallState {
        self.state
    }

    #[cfg(test)]
    pub(crate) fn backend(&self) -> &B {
        &self.backend
    }
}

impl CapturePlan for NftRulePlan {
    fn render(&self) -> String {
        self.render()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    Bound(&'static str),
    InvalidPlan,
    Backend(String),
    Transaction {
        error: String,
        rollback: Result<(), String>,
    },
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound(field) => write!(formatter, "{field} exceeds its bounded capture limit"),
            Self::InvalidPlan => formatter.write_str("capture plan has a zero port or mark"),
            Self::Backend(error) => write!(formatter, "capture backend: {error}"),
            Self::Transaction { error, rollback } => {
                write!(
                    formatter,
                    "capture verification failed: {error}; rollback: {rollback:?}"
                )
            }
        }
    }
}

impl std::error::Error for CaptureError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        calls: Vec<&'static str>,
        fail_verify: bool,
    }

    impl RuleBackend for FakeBackend {
        type Plan = NftRulePlan;

        fn install(&mut self, _plan: &Self::Plan) -> Result<(), String> {
            self.calls.push("install");
            Ok(())
        }
        fn verify(&mut self, _plan: &Self::Plan) -> Result<(), String> {
            self.calls.push("verify");
            if self.fail_verify {
                Err("not present".into())
            } else {
                Ok(())
            }
        }
        fn remove(&mut self, _plan: &Self::Plan) -> Result<(), String> {
            self.calls.push("remove");
            Ok(())
        }
    }

    #[test]
    fn dry_run_is_stable_and_owned() {
        let plan = NftRulePlan::new("capture", 5353, 42).unwrap();
        assert_eq!(
            plan.render(),
            "table inet blackhole {\n  chain capture {\n    type filter hook prerouting priority -150; policy accept;\n    tcp dport 5353 meta mark set 42 redirect to :5353\n    udp dport 5353 meta mark set 42 redirect to :5353\n  }\n}\n"
        );
    }

    #[test]
    fn context_rejects_unbounded_interface_names() {
        let context = CaptureContext {
            original_destination: "192.0.2.1:443".parse().unwrap(),
            client: "198.51.100.1:1234".parse().unwrap(),
            interface: "this-interface-is-too-long".into(),
            mark: 42,
            reply_route: ReplyRoute::MarkedRoute,
        };
        assert_eq!(context.validate(), Err(CaptureError::Bound("interface")));
    }

    #[test]
    fn verification_failure_rolls_back_only_the_planned_rules() {
        let plan = NftRulePlan::new("capture", 5353, 42).unwrap();
        let backend = FakeBackend {
            fail_verify: true,
            ..Default::default()
        };
        let mut controller = CaptureController::new(backend);
        assert!(matches!(
            controller.install(&plan),
            Err(CaptureError::Transaction { .. })
        ));
        assert_eq!(controller.status(), InstallState::Failed);
        assert_eq!(
            controller.backend.calls,
            vec!["install", "verify", "remove"]
        );
    }

    #[test]
    fn successful_install_and_cleanup_are_idempotent_at_the_boundary() {
        let plan = NftRulePlan::new("capture", 5353, 42).unwrap();
        let mut controller = CaptureController::new(FakeBackend::default());
        controller.install(&plan).unwrap();
        controller.install(&plan).unwrap();
        assert_eq!(controller.status(), InstallState::Installed);
        controller.cleanup(&plan).unwrap();
        controller.cleanup(&plan).unwrap();
        assert_eq!(controller.status(), InstallState::Uninstalled);
    }
}
