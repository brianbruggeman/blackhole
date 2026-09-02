use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const LAUNCHD_PLIST: &str = "deploy/launchd/com.brianbruggeman.blackhole.plist";
const SYSTEMD_UNIT: &str = "deploy/systemd/blackhole.service";
const SYSTEMD_TMPFILES: &str = "deploy/systemd/blackhole.conf";
const SYSTEMD_INSTALLER: &str = "deploy/systemd/install.sh";
const SYSTEMD_SMOKE: &str = "deploy/systemd/smoke.sh";
const LAUNCHD_INSTALLER: &str = "deploy/launchd/install.sh";
const LAUNCHD_SMOKE: &str = "deploy/launchd/smoke.sh";
const PACKAGE_BUILDER: &str = "deploy/package/build.sh";
const DEB_BUILDER: &str = "deploy/package/build-deb.sh";
const DEB_SMOKE: &str = "deploy/package/smoke-deb.sh";
const ARCHIVE_SMOKE: &str = "deploy/package/smoke-archive.sh";
const VERIFY_WORKFLOW: &str = ".github/workflows/verify.yml";
const WASM_BENCH: &str = "scripts/wasm_edge_bench.mjs";

#[test]
fn wasm_edge_benchmark_covers_bounded_workload_cells() {
    let bench = fs::read_to_string(WASM_BENCH).expect("read WASM edge benchmark");
    for required in [
        "validPacket",
        "shortPacket",
        "longPacket",
        "adversarialPacket",
        "mixed_p50_ns=",
        "boundedFailureWorkloads",
        "[\"null\",",
        "[\"oversized\",",
        "p95_ns=",
        "p99_ns=",
        "_cov=",
        "typeof globalThis.Deno",
        "monotonicNanoseconds",
    ] {
        assert!(
            bench.contains(required),
            "missing WASM workload evidence: {required}"
        );
    }
}

#[test]
fn wasm_workflow_runs_node_and_deno_measurements() {
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    let wasm = workflow.find("  wasm:").expect("WASM verification job");
    let fuzz = workflow[wasm..]
        .find("  fuzz:")
        .map_or(workflow.len(), |offset| wasm + offset);
    let section = &workflow[wasm..fuzz];
    assert!(section.contains("node scripts/wasm_edge_bench.mjs"));
    assert!(section.contains("denoland/setup-deno@v2"));
    assert!(section.contains("deno run --allow-read scripts/wasm_edge_bench.mjs"));
    assert!(section.contains("| tee wasm-node.txt"));
    assert!(section.contains("| tee wasm-deno.txt"));
    assert!(section.contains("wasm-node.txt"));
    assert!(section.contains("wasm-deno.txt"));
}

#[test]
fn measurement_workflows_record_source_and_corpus_identity() {
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    for section in [
        "name: record WASM provenance",
        "name: record fuzz provenance",
        "name: record performance provenance",
    ] {
        let start = workflow.find(section).expect("provenance section");
        let end = workflow[start..]
            .find("- uses: actions/upload-artifact@v4")
            .map_or(workflow.len(), |offset| start + offset);
        let provenance = &workflow[start..end];
        for required in [
            "source_tree_sha256",
            "fuzz_corpus_files",
            "fuzz_corpus_sha256",
        ] {
            assert!(provenance.contains(required), "{section} lacks {required}");
        }
    }
}

#[test]
fn launchd_service_is_unprivileged_and_direct() {
    let plist = fs::read_to_string(LAUNCHD_PLIST).expect("read launchd service definition");

    assert!(plist.contains("<string>/usr/local/bin/blackhole</string>"));
    assert!(plist.contains("<string>/usr/local/etc/blackhole/blackhole.toml</string>"));
    assert_eq!(plist.matches("<string>_blackhole</string>").count(), 2);
    assert!(plist.contains("<string>/usr/local/var/lib/blackhole</string>"));
    assert!(plist.contains("<key>HardResourceLimits</key>"));

    for forbidden in ["/bin/sh", "sudo", "<string>root</string>", "Program</key>"] {
        assert!(
            !plist.contains(forbidden),
            "forbidden launchd value: {forbidden}"
        );
    }
}

#[test]
fn launchd_service_restarts_only_after_failure() {
    let plist = fs::read_to_string(LAUNCHD_PLIST).expect("read launchd service definition");
    let keepalive = plist
        .split_once("<key>KeepAlive</key>")
        .expect("KeepAlive key")
        .1;

    assert!(keepalive.contains("<key>SuccessfulExit</key>\n    <false/>"));
    assert!(plist.contains("<key>ThrottleInterval</key>\n  <integer>2</integer>"));
}

#[test]
fn systemd_service_is_restricted_and_direct() {
    let unit = fs::read_to_string(SYSTEMD_UNIT).expect("read systemd service definition");

    for required in [
        "User=blackhole",
        "Group=blackhole",
        "ExecStart=/usr/local/bin/blackhole /etc/blackhole/blackhole.toml",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ReadWritePaths=/var/lib/blackhole",
        "MemoryDenyWriteExecute=yes",
        "UMask=0077",
    ] {
        assert!(
            unit.contains(required),
            "missing systemd hardening: {required}"
        );
    }
    for forbidden in ["ExecStart=/bin/sh", "ExecStart=/usr/bin/env", "User=root"] {
        assert!(
            !unit.contains(forbidden),
            "forbidden systemd setting: {forbidden}"
        );
    }
}

#[test]
fn systemd_state_and_installer_are_scoped() {
    let tmpfiles = fs::read_to_string(SYSTEMD_TMPFILES).expect("read systemd tmpfiles definition");
    assert!(tmpfiles.contains("d /var/lib/blackhole 0750 blackhole blackhole -"));

    let installer = fs::read_to_string(SYSTEMD_INSTALLER).expect("read systemd installer");
    for required in [
        "set -eu",
        "backup_file \"$binary_target\"",
        "restore_file \"$binary_target\"",
        "installation failed; restoring the previous service files",
        "trap cleanup EXIT HUP INT TERM",
        "service_was_active=0",
        "systemctl restart blackhole.service",
        "systemctl stop blackhole.service",
        "rollback_needed=0",
        "../../../../bin/blackhole",
        "../../../../etc/blackhole/blackhole.toml",
        "install -d -o \"$blackhole_uid\" -g \"$blackhole_gid\" -m 0750 \"$state_target\"",
        "systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf",
        "systemctl daemon-reload",
        "if [ -n \"$install_root\" ]; then",
        "BLACKHOLE_INSTALL_ROOT",
        "root_path()",
        "install -d -o 0 -g 0 -m 0755 \"$(root_path /usr/local/bin)\"",
        "install -d -o 0 -g 0 -m 0755 \"$(root_path /etc/systemd/system)\"",
        "systemd-analyze verify --root=\"$install_root\" blackhole.service",
        "blackhole installed into disposable root",
    ] {
        assert!(
            installer.contains(required),
            "missing installer step: {required}"
        );
    }
    assert!(installer.contains("if [ \"$(id -u)\" -ne 0 ]"));
}

#[test]
fn systemd_smoke_covers_install_and_rollback() {
    let smoke = fs::read_to_string(SYSTEMD_SMOKE).expect("read systemd smoke harness");
    for required in [
        "set -eu",
        "BLACKHOLE_INSTALL_ROOT",
        "install.sh",
        "BLACKHOLE_INSTALL_ROOT=",
        "rollback_root",
        "rollback fixture unexpectedly succeeded",
        "sha256sum",
        "systemd disposable install and rollback smoke passed",
    ] {
        assert!(smoke.contains(required), "missing smoke step: {required}");
    }
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    let systemd = workflow
        .find("name: run systemd install and rollback smoke")
        .expect("Linux systemd smoke step");
    let systemd_contract = &workflow[systemd..];
    assert!(systemd_contract.contains("BLACKHOLE_SMOKE_TRACE=1"));
    assert!(systemd_contract.contains("tee systemd-smoke.log"));
    assert!(systemd_contract.contains("name: blackhole-linux-smoke-"));
    assert!(systemd_contract.contains("report systemd smoke failure"));
}

#[test]
fn launchd_installer_is_transactional_and_platform_native() {
    let installer = fs::read_to_string(LAUNCHD_INSTALLER).expect("read launchd installer");
    for required in [
        "set -eu",
        "plutil -lint",
        "backup_file /usr/local/bin/blackhole",
        "restore_file /usr/local/bin/blackhole",
        "launchctl bootout",
        "launchctl bootstrap system",
        "installation failed; restoring the previous launchd files",
        "trap cleanup EXIT HUP INT TERM",
        "rollback_needed=0",
        "../../../../bin/blackhole",
        "../../../../etc/blackhole/blackhole.toml",
    ] {
        assert!(
            installer.contains(required),
            "missing launchd installer step: {required}"
        );
    }
    for forbidden in ["sudo", "pfctl"] {
        assert!(
            !installer.contains(forbidden),
            "launchd installer must not invoke {forbidden}"
        );
    }
}

#[test]
fn launchd_smoke_covers_host_install_and_upgrade() {
    let smoke = fs::read_to_string(LAUNCHD_SMOKE).expect("read launchd smoke harness");
    for required in [
        "set -eu",
        "uname -s",
        "launchctl print",
        "refusing to overwrite an existing Blackhole launchd service",
        "BLACKHOLE_PLIST",
        "old_binary=$(shasum -a 256",
        "second real install exercises the host upgrade path",
        "failed launchd upgrade unexpectedly succeeded",
        "launchd host install and upgrade smoke passed",
    ] {
        assert!(
            smoke.contains(required),
            "missing launchd smoke step: {required}"
        );
    }
    let plist = fs::read_to_string(LAUNCHD_PLIST).expect("read launchd service definition");
    assert!(plist.contains("StandardOutPath"));
    assert!(plist.contains("StandardErrorPath"));
}

#[test]
fn workflow_reports_platform_smoke_failures() {
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    assert!(workflow.contains("cancel-in-progress: true"));
    assert!(workflow.contains("report launchd smoke failure"));
    assert!(workflow.contains("tail -n 80 launchd-smoke.log"));
    assert!(workflow.contains("tail -n 80 systemd-smoke.log"));
    assert!(workflow.contains("nft_nat_redirect_check:"));
    assert!(workflow.contains("always() && steps.launchd-smoke.outcome == 'failure'"));
    assert!(workflow.contains("always() && steps.systemd-smoke.outcome == 'failure'"));
}

#[test]
fn linux_diagnostic_artifacts_include_job_provenance() {
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    let linux = workflow.find("  linux:").expect("Linux verification job");
    let macos = workflow.find("  macos:").expect("macOS verification job");
    let linux = &workflow[linux..macos];
    assert!(linux.contains("name: record Linux provenance"));
    for artifact in [
        "blackhole-linux-capabilities-",
        "blackhole-linux-smoke-",
        "blackhole-debian-smoke-",
    ] {
        let start = linux.find(artifact).expect("Linux diagnostic artifact");
        let end = linux[start..]
            .find("      -")
            .map_or(linux.len(), |offset| start + offset);
        assert!(
            linux[start..end].contains("linux-provenance.txt"),
            "{artifact} lacks provenance"
        );
    }
}

#[cfg(unix)]
#[test]
fn installers_are_executable() {
    for path in [
        SYSTEMD_INSTALLER,
        SYSTEMD_SMOKE,
        LAUNCHD_INSTALLER,
        LAUNCHD_SMOKE,
        PACKAGE_BUILDER,
        DEB_BUILDER,
    ] {
        let mode = fs::metadata(path)
            .unwrap_or_else(|error| panic!("read metadata for {path}: {error}"))
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "installer is not executable: {path}");
    }
}

#[test]
fn query_fuzz_corpus_is_bounded_and_content_addressed() {
    let corpus = Path::new("fuzz/corpus/query_view");
    let mut samples = 0usize;
    for entry in fs::read_dir(corpus).expect("read query fuzz corpus") {
        let entry = entry.expect("read query fuzz corpus entry");
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some("README.md") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).expect("read query fuzz sample metadata");
        assert!(
            metadata.file_type().is_file(),
            "fuzz sample is not a file: {path:?}"
        );
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fuzz sample name is UTF-8");
        assert_eq!(
            name.len(),
            40,
            "fuzz sample name is not a SHA-1 label: {name}"
        );
        assert!(
            name.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "fuzz sample name is not hexadecimal: {name}"
        );
        assert!(
            metadata.len() as usize <= blackhole::query::MAX_QUERY_BYTES,
            "fuzz sample exceeds the query bound: {path:?}"
        );
        samples += 1;
    }
    assert!(samples > 0, "query fuzz corpus must contain samples");
}

#[test]
fn macos_workflow_builds_and_bounds_launchd_smoke() {
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    assert!(workflow.contains("CARGO_TARGET_DIR: ${{ github.workspace }}/target"));
    let release_build = workflow
        .find("name: build launchd release binary")
        .expect("macOS release build step");
    let smoke = workflow
        .find("name: run launchd host install and upgrade smoke")
        .expect("macOS launchd smoke step");
    assert!(
        release_build < smoke,
        "launchd smoke must use the release binary"
    );
    let smoke_contract = &workflow[smoke..];
    assert!(smoke_contract.contains("timeout-minutes: 2"));
    assert!(smoke_contract.contains("BLACKHOLE_SMOKE_TRACE=1"));
    assert!(smoke_contract.contains("tee launchd-smoke.log"));
}

#[test]
fn package_builder_contains_provenance_and_bounded_inputs() {
    let builder = fs::read_to_string(PACKAGE_BUILDER).expect("read package builder");
    for required in [
        "set -eu",
        "usage: $0 BINARY OUTPUT_DIR",
        "mktemp -d",
        "PROVENANCE.txt",
        "source_tree_sha256",
        "fuzz_corpus_sha256",
        "SHA256SUMS",
        "blackhole.example.toml",
        "blackhole.service",
        "com.brianbruggeman.blackhole.plist",
        "deploy/systemd/install.sh",
        "deploy/launchd/install.sh",
        "tar -C",
    ] {
        assert!(
            builder.contains(required),
            "missing package step: {required}"
        );
    }
    assert!(!builder.contains("rm -rf /"));
}

#[test]
fn linux_workflow_selects_one_debian_package_for_inspection() {
    let workflow = fs::read_to_string(VERIFY_WORKFLOW).expect("read verification workflow");
    let packages = workflow
        .find("name: build release packages")
        .expect("Linux package build step");
    let smoke = workflow
        .find("name: run Debian package install smoke")
        .expect("Debian package smoke step");
    let package_contract = &workflow[packages..smoke];
    assert!(package_contract.contains("new_package=$(find dist -name"));
    assert!(package_contract.contains("ar t \"$new_package\""));
    assert!(package_contract.contains("ar p \"$new_package\" control.tar.gz"));
    assert!(package_contract.contains("ar p \"$new_package\" data.tar.gz"));
    let smoke_contract = &workflow[smoke..];
    assert!(workflow.contains("name: probe Debian package smoke capability"));
    assert!(smoke_contract.contains("if: steps.debian-capability.outputs.available == 'true'"));
    assert!(workflow.contains("test \"$(id -u)\" = 0"));
    assert!(smoke_contract.contains("package_version=$(sed -n"));
}

#[test]
fn deb_builder_contains_native_package_contract() {
    let builder = fs::read_to_string(DEB_BUILDER).expect("read Debian package builder");
    for required in [
        "usage: $0 BINARY OUTPUT_DIR",
        "command -v ar",
        "BLACKHOLE_DEB_VERSION",
        "Package: blackhole",
        "Version: $version",
        "Architecture: $architecture",
        "blackhole.service",
        "blackhole.conf",
        "cat > \"$staging/control/postinst\"",
        "cat > \"$staging/control/prerm\"",
        "cat > \"$staging/control/conffiles\"",
        "/etc/blackhole/blackhole.toml",
        "systemctl enable --now blackhole.service",
        "systemctl disable --now blackhole.service",
        "ps -p 1 -o comm=",
        "[ \"$init\" = systemd ]",
        "DPKG_ROOT",
        "PROVENANCE.txt",
        "source_tree_sha256",
        "fuzz_corpus_sha256",
        "root_path()",
        "has_group()",
        "has_user()",
        "blackhole_uid=",
        "blackhole_gid=",
        "awk -F:",
        "install -d -o \"$blackhole_uid\"",
        "groupadd --system",
        "useradd --system",
        "ar r",
        ".deb",
    ] {
        assert!(
            builder.contains(required),
            "missing Debian package step: {required}"
        );
    }
    assert!(!builder.contains("dpkg -i"));
}

#[test]
fn deb_smoke_exercises_a_disposable_root_transaction() {
    let script = fs::read_to_string(DEB_SMOKE).expect("read Debian package smoke script");
    assert!(script.starts_with("#!/bin/sh\nset -eu\n"));
    assert!(script.contains("usage: $0 DEB [UPGRADE_DEB]"));
    assert!(script.contains("upgrade_package=${2:-$package}"));
    assert!(script.contains("dpkg --root=\"$root\" --unpack"));
    assert!(script.contains("export DEBIAN_FRONTEND=noninteractive"));
    assert!(script.contains("dpkg --root=\"$root\" --force-confold --configure blackhole"));
    assert!(script.contains("dpkg-deb --field \"$package\" Version"));
    assert!(script.contains("dpkg --compare-versions \"$new_version\" gt \"$old_version\""));
    assert!(script.contains("--unpack \"$upgrade_package\""));
    assert!(script.contains("--force-confold --unpack"));
    assert!(script.contains("installed_version=$(dpkg-query"));
    assert!(script.contains("dpkg-query --root=\"$root\""));
    assert!(script.contains("/var/lib/blackhole"));
}

#[test]
fn archive_smoke_runs_the_shipped_installer_in_a_disposable_root() {
    let script = fs::read_to_string(ARCHIVE_SMOKE).expect("read archive smoke script");
    assert!(script.starts_with("#!/bin/sh\nset -eu\n"));
    assert!(script.contains("tar -xzf"));
    assert!(script.contains("share/blackhole/deploy/systemd/install.sh"));
    assert!(script.contains("BLACKHOLE_INSTALL_ROOT=\"$install_root\""));
    assert!(script.contains("etc/systemd/system/blackhole.service"));
    assert!(script.contains("/var/lib/blackhole"));
}
