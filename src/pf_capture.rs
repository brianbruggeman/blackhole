//! Pure macOS PF/rdr planning and lifecycle state.
//!
//! The module is portable by design. A privileged macOS facade supplies the
//! shared `RuleBackend` capability; no `pfctl` process, shell script, or
//! macOS API is used here.

use std::fmt;
use std::net::SocketAddr;

use crate::linux_capture::{CaptureContext, CaptureError, CaptureOwnership, CapturePlan};

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
        if original_destination.ip().is_unspecified() || original_destination.port() == 0 {
            return Err(PfError::InvalidPlan);
        }
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
        let family = if self.original_destination.is_ipv4() {
            "inet"
        } else {
            "inet6"
        };
        let destination = self.original_destination.ip();
        let destination_port = self.original_destination.port();
        format!(
            "# blackhole-owned anchor: {}\nrdr pass {} proto tcp to {} port {} -> 127.0.0.1 port {}\nrdr pass {} proto udp to {} port {} -> 127.0.0.1 port {}\n",
            self.anchor,
            family,
            destination,
            destination_port,
            self.redirect_port,
            family,
            destination,
            destination_port,
            self.redirect_port,
        )
    }
}

impl CapturePlan for PfRulePlan {
    fn render(&self) -> String {
        self.render()
    }

    fn ownership(&self) -> CaptureOwnership {
        CaptureOwnership {
            table: "pf".into(),
            chain: self.anchor.clone(),
            inbound_port: self.original_destination.port(),
            redirect_port: self.redirect_port,
            mark: 0,
            original_destination: Some(self.original_destination),
        }
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

#[cfg(target_os = "macos")]
pub mod native {
    use super::PfRulePlan;
    use crate::linux_capture::{CapturePlan, RuleBackend};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    /// Privileged pfctl capability. It is compiled only for macOS and does
    /// not run until a caller explicitly uses the capture controller.
    #[derive(Debug, Clone)]
    pub struct PfctlCommandBackend {
        program: PathBuf,
    }

    impl Default for PfctlCommandBackend {
        fn default() -> Self {
            Self {
                program: PathBuf::from("pfctl"),
            }
        }
    }

    impl PfctlCommandBackend {
        #[must_use]
        pub fn new(program: impl Into<PathBuf>) -> Self {
            Self {
                program: program.into(),
            }
        }

        fn apply(&self, args: &[&str], input: Option<&str>) -> Result<(), String> {
            let mut command = Command::new(&self.program);
            command.args(args);
            if input.is_some() {
                command.stdin(Stdio::piped());
            }
            let mut child = command.spawn().map_err(|error| error.to_string())?;
            if let Some(input) = input {
                child
                    .stdin
                    .take()
                    .ok_or_else(|| "pfctl stdin was unavailable".to_owned())?
                    .write_all(input.as_bytes())
                    .map_err(|error| error.to_string())?;
            }
            let output = child
                .wait_with_output()
                .map_err(|error| error.to_string())?;
            if output.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
            }
        }
    }

    impl RuleBackend for PfctlCommandBackend {
        type Plan = PfRulePlan;

        fn install(&mut self, plan: &Self::Plan) -> Result<(), String> {
            self.apply(&["-a", &plan.anchor, "-f", "-"], Some(&plan.render()))
        }

        fn verify(&mut self, plan: &Self::Plan) -> Result<(), String> {
            self.apply(&["-a", &plan.anchor, "-sr"], None)
        }

        fn remove(&mut self, plan: &Self::Plan) -> Result<(), String> {
            self.apply(&["-a", &plan.anchor, "-F", "all"], None)
        }
    }
}

/// PF rdr does not provide transparent original-destination and reply-route
/// semantics for every UDP deployment. Reject unsupported contexts instead of
/// silently degrading to a policy path with invented metadata.
pub fn validate_context(context: &CaptureContext) -> Result<(), PfError> {
    if let Err(error) = context.validate() {
        return match error {
            CaptureError::InvalidContext("original destination") => {
                Err(PfError::Unsupported("unspecified original destination"))
            }
            _ => Err(PfError::Unsupported("capture context")),
        };
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
            "# blackhole-owned anchor: blackhole/capture\nrdr pass inet proto tcp to 192.0.2.10 port 443 -> 127.0.0.1 port 5353\nrdr pass inet proto udp to 192.0.2.10 port 443 -> 127.0.0.1 port 5353\n"
        );
    }

    #[test]
    fn pf_render_selects_inet6_for_ipv6_destinations() {
        let plan = PfRulePlan::new(
            "blackhole_capture",
            "[2001:db8::10]:443".parse().unwrap(),
            5353,
        )
        .unwrap();
        let rendered = plan.render();
        assert!(rendered.contains("rdr pass inet6 proto tcp to 2001:db8::10 port 443"));
        assert!(rendered.contains("rdr pass inet6 proto udp to 2001:db8::10 port 443"));
        assert!(!rendered.contains("2001:db8::10:443"));
    }

    #[test]
    fn pf_rejects_unspecified_or_zero_port_destinations() {
        for destination in ["0.0.0.0:53", "192.0.2.53:0"] {
            assert_eq!(
                PfRulePlan::new("blackhole_capture", destination.parse().unwrap(), 5353),
                Err(PfError::InvalidPlan)
            );
        }
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
