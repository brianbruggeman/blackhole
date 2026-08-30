//! Pure macOS PF/rdr planning and lifecycle state.
//!
//! The module is portable by design. A privileged macOS facade supplies the
//! shared `RuleBackend` capability; no `pfctl` process, shell script, or
//! macOS API is used here.

use std::fmt;
use std::net::SocketAddr;

use crate::linux_capture::{CaptureContext, CapturePlan};

const MAX_ANCHOR_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfRulePlan {
    pub anchor: String,
    pub original_destination: SocketAddr,
    pub redirect_port: u16,
}

impl PfRulePlan {
    pub fn new(
        anchor: impl Into<String>,
        original_destination: SocketAddr,
        redirect_port: u16,
    ) -> Result<Self, PfError> {
        let plan = Self {
            anchor: anchor.into(),
            original_destination,
            redirect_port,
        };
        if plan.anchor.is_empty() || plan.anchor.len() > MAX_ANCHOR_BYTES || !plan.anchor.is_ascii()
        {
            return Err(PfError::Bound("anchor"));
        }
        if plan.redirect_port == 0 {
            return Err(PfError::InvalidPlan);
        }
        Ok(plan)
    }

    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "# blackhole-owned anchor: {}\nrdr pass inet proto tcp to {} -> 127.0.0.1 port {}\nrdr pass inet proto udp to {} -> 127.0.0.1 port {}\n",
            self.anchor,
            self.original_destination,
            self.redirect_port,
            self.original_destination,
            self.redirect_port,
        )
    }
}

impl CapturePlan for PfRulePlan {
    fn render(&self) -> String {
        self.render()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfError {
    Bound(&'static str),
    InvalidPlan,
    Unsupported(&'static str),
}

impl fmt::Display for PfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound(field) => write!(formatter, "{field} exceeds its PF limit"),
            Self::InvalidPlan => formatter.write_str("PF plan has a zero redirect port"),
            Self::Unsupported(capability) => {
                write!(formatter, "unsupported PF capability: {capability}")
            }
        }
    }
}

impl std::error::Error for PfError {}

/// PF rdr does not provide transparent original-destination and reply-route
/// semantics for every UDP deployment. Reject unsupported contexts instead of
/// silently degrading to a policy path with invented metadata.
pub fn validate_context(context: &CaptureContext) -> Result<(), PfError> {
    context
        .validate()
        .map_err(|_| PfError::Unsupported("capture context"))?;
    if context.original_destination.ip().is_unspecified() {
        return Err(PfError::Unsupported("unspecified original destination"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_capture::{CaptureController, CaptureError, InstallState, RuleBackend};

    #[derive(Default)]
    struct FakePf {
        calls: Vec<&'static str>,
        fail_verify: bool,
    }

    impl RuleBackend for FakePf {
        type Plan = PfRulePlan;

        fn install(&mut self, _: &PfRulePlan) -> Result<(), String> {
            self.calls.push("install");
            Ok(())
        }
        fn verify(&mut self, _: &PfRulePlan) -> Result<(), String> {
            self.calls.push("verify");
            if self.fail_verify {
                Err("anchor missing".into())
            } else {
                Ok(())
            }
        }
        fn remove(&mut self, _: &PfRulePlan) -> Result<(), String> {
            self.calls.push("remove");
            Ok(())
        }
    }

    #[test]
    fn pf_dry_run_is_stable_and_owned() {
        let plan =
            PfRulePlan::new("blackhole/capture", "192.0.2.10:443".parse().unwrap(), 5353).unwrap();
        assert_eq!(
            plan.render(),
            "# blackhole-owned anchor: blackhole/capture\nrdr pass inet proto tcp to 192.0.2.10:443 -> 127.0.0.1 port 5353\nrdr pass inet proto udp to 192.0.2.10:443 -> 127.0.0.1 port 5353\n"
        );
    }

    #[test]
    fn verification_failure_removes_only_the_owned_anchor() {
        let plan =
            PfRulePlan::new("blackhole/capture", "192.0.2.10:443".parse().unwrap(), 5353).unwrap();
        let mut controller = CaptureController::new(FakePf {
            fail_verify: true,
            ..Default::default()
        });
        assert!(matches!(
            controller.install(&plan),
            Err(CaptureError::Transaction { .. })
        ));
        assert_eq!(controller.status(), InstallState::Failed);
        assert_eq!(
            controller.backend().calls,
            vec!["install", "verify", "remove"]
        );
    }

    #[test]
    fn unsupported_context_is_typed() {
        let context = CaptureContext {
            original_destination: "0.0.0.0:443".parse().unwrap(),
            client: "198.51.100.1:1234".parse().unwrap(),
            interface: "lo0".into(),
            mark: 1,
            reply_route: crate::linux_capture::ReplyRoute::OriginalDestination,
        };
        assert_eq!(
            validate_context(&context),
            Err(PfError::Unsupported("unspecified original destination"))
        );
    }
}
