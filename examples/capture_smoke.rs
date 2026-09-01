//! Install and remove one uniquely owned capture plan.
//!
//! This example is intentionally run only by a privileged CI smoke step. It
//! never uses the production `blackhole` table or capture anchor.

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use blackhole::linux_capture::{
        CaptureController, FileOwnershipStore, NftRulePlan, native::NftCommandBackend,
    };

    let suffix = std::process::id();
    let table = format!("blackhole_ci_{suffix}");
    let chain = format!("capture_ci_{suffix}");
    let plan = NftRulePlan::for_table(table.clone(), chain, 53, 5353, 42)?;
    let journal = std::env::temp_dir().join(format!("blackhole-capture-smoke-{suffix}.state"));
    let mut controller = CaptureController::with_store(
        NftCommandBackend::default(),
        FileOwnershipStore::new(&journal),
    );

    let operation = controller
        .install(&plan)
        .and_then(|()| controller.cleanup(&plan));
    let table_cleanup = Command::new("nft")
        .args(["delete", "table", "inet", &table])
        .status()?;
    if !table_cleanup.success() {
        return Err(format!("nft table cleanup failed for {table}").into());
    }
    operation?;
    if journal.exists() {
        return Err("capture smoke left an ownership journal".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use blackhole::linux_capture::{CaptureController, FileOwnershipStore};
    use blackhole::pf_capture::{PfRulePlan, native::PfctlCommandBackend};

    let suffix = std::process::id();
    let anchor = format!("blackhole_ci_{suffix}");
    let plan = PfRulePlan::new(anchor, "127.0.0.1:53".parse()?, 5353)?;
    let journal = std::env::temp_dir().join(format!("blackhole-capture-smoke-{suffix}.state"));
    let mut controller = CaptureController::with_store(
        PfctlCommandBackend::default(),
        FileOwnershipStore::new(&journal),
    );
    controller.install(&plan)?;
    controller.cleanup(&plan)?;
    if journal.exists() {
        return Err("capture smoke left an ownership journal".into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("capture smoke is supported only on Linux and macOS");
    std::process::exit(2);
}
