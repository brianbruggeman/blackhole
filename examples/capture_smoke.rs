//! Install and remove one uniquely owned capture plan.
//!
//! This example is intentionally run only by a privileged CI smoke step. It
//! never uses the production `blackhole` table or capture anchor.

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("Install and remove an isolated nftables capture plan (requires root).");
        return Ok(());
    }
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
        .output()?;
    if let Err(error) = operation {
        return Err(error.into());
    }
    if !table_cleanup.status.success() {
        return Err(format!(
            "nft table cleanup failed for {table}: {}",
            String::from_utf8_lossy(&table_cleanup.stderr).trim()
        )
        .into());
    }
    if journal.exists() {
        return Err("capture smoke left an ownership journal".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("Install and remove an isolated PF capture plan (requires root).");
        return Ok(());
    }
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
