//! Pure planning and lifecycle state for Linux nftables capture.
//!
//! This module intentionally contains no Linux or nftables bindings. The
//! privileged backend is an injected capability at the edge; the planner and
//! transaction controller are portable and deterministic.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const MAX_INTERFACE_BYTES: usize = 15;
const MAX_CHAIN_BYTES: usize = 32;

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CHAIN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

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
    pub inbound_port: u16,
    pub redirect_port: u16,
    pub mark: u32,
}

impl NftRulePlan {
    pub fn new(
        chain: impl Into<String>,
        listen_port: u16,
        mark: u32,
    ) -> Result<Self, CaptureError> {
        Self::for_ports(chain, listen_port, listen_port, mark)
    }

    pub fn for_table(
        table: impl Into<String>,
        chain: impl Into<String>,
        inbound_port: u16,
        redirect_port: u16,
        mark: u32,
    ) -> Result<Self, CaptureError> {
        let plan = Self {
            table: table.into(),
            chain: chain.into(),
            inbound_port,
            redirect_port,
            mark,
        };
        if !valid_identifier(&plan.table) {
            return Err(CaptureError::Bound("table"));
        }
        if !valid_identifier(&plan.chain) {
            return Err(CaptureError::Bound("chain"));
        }
        if plan.inbound_port == 0 || plan.redirect_port == 0 || plan.mark == 0 {
            return Err(CaptureError::InvalidPlan);
        }
        Ok(plan)
    }

    pub fn for_ports(
        chain: impl Into<String>,
        inbound_port: u16,
        redirect_port: u16,
        mark: u32,
    ) -> Result<Self, CaptureError> {
        Self::for_table("blackhole", chain, inbound_port, redirect_port, mark)
    }

    /// Stable dry-run representation. The ownership comment is part of the
    /// plan so operators can audit exactly what a privileged backend may add.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "table inet {} {{\n  chain {} {{\n    type nat hook prerouting priority dstnat; policy accept;\n    tcp dport {} meta mark set {} redirect to :{}\n    udp dport {} meta mark set {} redirect to :{}\n  }}\n}}\n",
            self.table,
            self.chain,
            self.inbound_port,
            self.mark,
            self.redirect_port,
            self.inbound_port,
            self.mark,
            self.redirect_port,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureOwnership {
    pub table: String,
    pub chain: String,
    pub inbound_port: u16,
    pub redirect_port: u16,
    pub mark: u32,
}

impl CaptureOwnership {
    fn is_valid(&self) -> bool {
        valid_identifier(&self.table)
            && valid_identifier(&self.chain)
            && self.inbound_port != 0
            && self.redirect_port != 0
    }
}

pub trait CapturePlan {
    fn render(&self) -> String;
    fn ownership(&self) -> CaptureOwnership;
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

pub trait OwnershipStore {
    fn load(&self) -> Result<Option<CaptureOwnership>, String>;
    fn save(&mut self, ownership: &CaptureOwnership) -> Result<(), String>;
    fn clear(&mut self) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct MemoryOwnershipStore {
    ownership: Option<CaptureOwnership>,
}

impl OwnershipStore for MemoryOwnershipStore {
    fn load(&self) -> Result<Option<CaptureOwnership>, String> {
        Ok(self.ownership.clone())
    }

    fn save(&mut self, ownership: &CaptureOwnership) -> Result<(), String> {
        self.ownership = Some(ownership.clone());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), String> {
        self.ownership = None;
        Ok(())
    }
}

/// A small line-oriented journal. The file is replaced atomically enough for
/// restart recovery: an incomplete record is treated as absent, never as
/// permission to delete unrelated firewall state.
#[derive(Debug, Clone)]
pub struct FileOwnershipStore {
    path: PathBuf,
}

impl FileOwnershipStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn encode(ownership: &CaptureOwnership) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n",
            ownership.table,
            ownership.chain,
            ownership.inbound_port,
            ownership.redirect_port,
            ownership.mark
        )
    }

    fn decode(value: &str) -> Option<CaptureOwnership> {
        let mut lines = value.lines();
        let ownership = CaptureOwnership {
            table: lines.next()?.to_owned(),
            chain: lines.next()?.to_owned(),
            inbound_port: lines.next()?.parse().ok()?,
            redirect_port: lines.next()?.parse().ok()?,
            mark: lines.next()?.parse().ok()?,
        };
        if lines.next().is_some() || !ownership.is_valid() {
            return None;
        }
        Some(ownership)
    }

    fn validate_path(path: &Path) -> Result<(), String> {
        if path.as_os_str().is_empty() {
            Err("ownership journal path is empty".into())
        } else {
            Ok(())
        }
    }
}

impl OwnershipStore for FileOwnershipStore {
    fn load(&self) -> Result<Option<CaptureOwnership>, String> {
        Self::validate_path(&self.path)?;
        match std::fs::read_to_string(&self.path) {
            Ok(value) => Ok(Self::decode(&value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn save(&mut self, ownership: &CaptureOwnership) -> Result<(), String> {
        Self::validate_path(&self.path)?;
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, Self::encode(ownership)).map_err(|error| error.to_string())?;
        std::fs::File::open(&temporary)
            .map_err(|error| error.to_string())?
            .sync_all()
            .map_err(|error| error.to_string())?;
        std::fs::rename(&temporary, &self.path).map_err(|error| error.to_string())?;
        if let Some(parent) = self.path.parent() {
            std::fs::File::open(parent)
                .map_err(|error| error.to_string())?
                .sync_all()
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), String> {
        Self::validate_path(&self.path)?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

pub struct CaptureController<B, S = MemoryOwnershipStore> {
    backend: B,
    store: S,
    state: InstallState,
}

impl<B: RuleBackend> CaptureController<B, MemoryOwnershipStore> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self::with_store(backend, MemoryOwnershipStore::default())
    }
}

impl<B: RuleBackend, S: OwnershipStore> CaptureController<B, S> {
    #[must_use]
    pub fn with_store(backend: B, store: S) -> Self {
        Self {
            backend,
            store,
            state: InstallState::Uninstalled,
        }
    }

    pub fn install(&mut self, plan: &B::Plan) -> Result<(), CaptureError> {
        if self.state == InstallState::Installed {
            return Ok(());
        }
        self.state = InstallState::Installing;
        if let Err(error) = self.backend.install(plan) {
            let rollback = self.backend.remove(plan);
            self.state = InstallState::Failed;
            return Err(CaptureError::Transaction { error, rollback });
        }
        if let Err(error) = self.backend.verify(plan) {
            let rollback = self.backend.remove(plan);
            self.state = InstallState::Failed;
            return Err(CaptureError::Transaction { error, rollback });
        }
        if let Err(error) = self.store.save(&plan.ownership()) {
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
        match self.store.load().map_err(CaptureError::Backend)? {
            Some(ownership) if ownership == plan.ownership() => {}
            _ => return Err(CaptureError::OwnershipMismatch),
        }
        self.backend.remove(plan).map_err(CaptureError::Backend)?;
        self.store.clear().map_err(CaptureError::Backend)?;
        self.state = InstallState::Uninstalled;
        Ok(())
    }

    /// Reconcile after a process crash or reboot. Only an exact ownership
    /// record can cause a backend verification; unrelated rules are ignored.
    pub fn recover(&mut self, plan: &B::Plan) -> Result<InstallState, CaptureError> {
        let Some(ownership) = self.store.load().map_err(CaptureError::Backend)? else {
            return Ok(self.state);
        };
        if ownership != plan.ownership() {
            return Ok(self.state);
        }
        if self.backend.verify(plan).is_ok() {
            self.state = InstallState::Installed;
        } else {
            self.store.clear().map_err(CaptureError::Backend)?;
            self.state = InstallState::Uninstalled;
        }
        Ok(self.state)
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

    fn ownership(&self) -> CaptureOwnership {
        CaptureOwnership {
            table: self.table.clone(),
            chain: self.chain.clone(),
            inbound_port: self.inbound_port,
            redirect_port: self.redirect_port,
            mark: self.mark,
        }
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
    OwnershipMismatch,
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
            Self::OwnershipMismatch => {
                formatter.write_str("capture ownership record does not match the plan")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

#[cfg(target_os = "linux")]
pub mod native {
    use super::{NftRulePlan, RuleBackend};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    /// Privileged nftables capability. Construction is harmless; commands run
    /// only when the caller explicitly installs or removes a capture plan.
    #[derive(Debug, Clone)]
    pub struct NftCommandBackend {
        program: PathBuf,
    }

    impl Default for NftCommandBackend {
        fn default() -> Self {
            Self {
                program: PathBuf::from("nft"),
            }
        }
    }

    impl NftCommandBackend {
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
                    .ok_or_else(|| "nft stdin was unavailable".to_owned())?
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

    impl RuleBackend for NftCommandBackend {
        type Plan = NftRulePlan;

        fn install(&mut self, plan: &Self::Plan) -> Result<(), String> {
            self.apply(&["-f", "-"], Some(&plan.render()))
        }

        fn verify(&mut self, plan: &Self::Plan) -> Result<(), String> {
            self.apply(&["list", "table", "inet", &plan.table], None)
        }

        fn remove(&mut self, plan: &Self::Plan) -> Result<(), String> {
            // Delete only the chain recorded in the ownership journal. The
            // table name is shared namespace; removing the whole table could
            // destroy unrelated operator-managed chains.
            self.apply(&["delete", "chain", "inet", &plan.table, &plan.chain], None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        calls: Vec<&'static str>,
        fail_install: bool,
        fail_verify: bool,
    }

    impl RuleBackend for FakeBackend {
        type Plan = NftRulePlan;

        fn install(&mut self, _plan: &Self::Plan) -> Result<(), String> {
            self.calls.push("install");
            if self.fail_install {
                return Err("partial install".into());
            }
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
            "table inet blackhole {\n  chain capture {\n    type nat hook prerouting priority dstnat; policy accept;\n    tcp dport 5353 meta mark set 42 redirect to :5353\n    udp dport 5353 meta mark set 42 redirect to :5353\n  }\n}\n"
        );
    }

    #[test]
    fn dns_capture_can_match_port_53_and_redirect_to_the_listener() {
        let plan = NftRulePlan::for_ports("capture", 53, 5353, 42).unwrap();
        let rendered = plan.render();
        assert!(rendered.contains("type nat hook prerouting priority dstnat"));
        assert!(rendered.contains("tcp dport 53"));
        assert!(rendered.contains("udp dport 53"));
        assert!(rendered.contains("redirect to :5353"));
    }

    #[test]
    fn capture_plan_can_use_an_isolated_table_for_smoke_tests() {
        let plan = NftRulePlan::for_table("blackhole_ci", "capture_ci", 53, 5353, 42).unwrap();
        assert!(plan.render().starts_with("table inet blackhole_ci {"));
        assert_eq!(plan.ownership().table, "blackhole_ci");
    }

    #[test]
    fn capture_plan_rejects_unquoted_nft_identifiers() {
        for (table, chain) in [("blackhole-ci", "capture"), ("blackhole", "capture/ci")] {
            assert_eq!(
                NftRulePlan::for_table(table, chain, 53, 5353, 42),
                Err(CaptureError::Bound(if table.contains('-') {
                    "table"
                } else {
                    "chain"
                }))
            );
        }
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
    fn install_failure_attempts_rollback_of_partial_rules() {
        let plan = NftRulePlan::new("capture", 5353, 42).unwrap();
        let backend = FakeBackend {
            fail_install: true,
            ..Default::default()
        };
        let mut controller = CaptureController::new(backend);
        assert!(matches!(
            controller.install(&plan),
            Err(CaptureError::Transaction { .. })
        ));
        assert_eq!(controller.status(), InstallState::Failed);
        assert_eq!(controller.backend.calls, vec!["install", "remove"]);
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

    #[test]
    fn file_ownership_store_round_trips_and_ignores_corruption() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-capture-ownership-{}.state",
            std::process::id()
        ));
        let mut store = FileOwnershipStore::new(&path);
        let ownership = NftRulePlan::new("capture", 5353, 42).unwrap().ownership();
        store.save(&ownership).expect("journal save");
        assert_eq!(store.load().expect("journal load"), Some(ownership.clone()));
        std::fs::write(&path, "partial\nrecord\n").expect("corrupt journal");
        assert_eq!(store.load().expect("corrupt journal is safe"), None);
        store.clear().expect("journal cleanup");
    }

    #[test]
    fn file_ownership_store_rejects_unusable_records() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-capture-invalid-ownership-{}.state",
            std::process::id()
        ));
        let store = FileOwnershipStore::new(&path);
        for record in [
            "blackhole\ncapture\n0\n5353\n42\n",
            "blackhole\ncapture\n53\n0\n42\n",
            "blackhole\nthis-chain-name-is-way-too-long-for-recovery\n53\n5353\n42\n",
            "blackhole\ncapture\n53\n5353\n42\ntrailing\n",
        ] {
            std::fs::write(&path, record).expect("write invalid journal");
            assert_eq!(store.load().expect("invalid journal is safe"), None);
        }
        std::fs::remove_file(path).expect("remove invalid journal");
    }

    #[test]
    fn recovery_verifies_only_an_exact_owned_plan() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-capture-recovery-{}.state",
            std::process::id()
        ));
        let plan = NftRulePlan::new("capture", 53, 5353).unwrap();
        let mut first =
            CaptureController::with_store(FakeBackend::default(), FileOwnershipStore::new(&path));
        first.install(&plan).expect("install");

        let mut recovered =
            CaptureController::with_store(FakeBackend::default(), FileOwnershipStore::new(&path));
        assert_eq!(recovered.recover(&plan).unwrap(), InstallState::Installed);
        recovered.cleanup(&plan).expect("owned cleanup");
        assert_eq!(recovered.status(), InstallState::Uninstalled);
        assert!(!path.exists());
    }
}
