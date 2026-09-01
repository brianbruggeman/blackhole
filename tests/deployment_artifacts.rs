use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const LAUNCHD_PLIST: &str = "deploy/launchd/com.brianbruggeman.blackhole.plist";
const SYSTEMD_UNIT: &str = "deploy/systemd/blackhole.service";
const SYSTEMD_TMPFILES: &str = "deploy/systemd/blackhole.conf";
const SYSTEMD_INSTALLER: &str = "deploy/systemd/install.sh";
const SYSTEMD_SMOKE: &str = "deploy/systemd/smoke.sh";
const LAUNCHD_INSTALLER: &str = "deploy/launchd/install.sh";
const PACKAGE_BUILDER: &str = "deploy/package/build.sh";
const DEB_BUILDER: &str = "deploy/package/build-deb.sh";
const DEB_SMOKE: &str = "deploy/package/smoke-deb.sh";

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

#[cfg(unix)]
#[test]
fn installers_are_executable() {
    for path in [
        SYSTEMD_INSTALLER,
        SYSTEMD_SMOKE,
        LAUNCHD_INSTALLER,
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
fn package_builder_contains_provenance_and_bounded_inputs() {
    let builder = fs::read_to_string(PACKAGE_BUILDER).expect("read package builder");
    for required in [
        "set -eu",
        "usage: $0 BINARY OUTPUT_DIR",
        "mktemp -d",
        "PROVENANCE.txt",
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
fn deb_builder_contains_native_package_contract() {
    let builder = fs::read_to_string(DEB_BUILDER).expect("read Debian package builder");
    for required in [
        "usage: $0 BINARY OUTPUT_DIR",
        "command -v ar",
        "Package: blackhole",
        "Version: $version",
        "Architecture: $architecture",
        "blackhole.service",
        "blackhole.conf",
        "cat > \"$staging/control/postinst\"",
        "cat > \"$staging/control/prerm\"",
        "systemctl enable --now blackhole.service",
        "systemctl disable --now blackhole.service",
        "ps -p 1 -o comm=",
        "[ \"$init\" = systemd ]",
        "DPKG_ROOT",
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
    assert!(script.contains("dpkg --root=\"$root\" --unpack"));
    assert!(script.matches("dpkg --root=\"$root\" --unpack").count() >= 2);
    assert!(script.contains("dpkg-query --root=\"$root\""));
    assert!(script.contains("/var/lib/blackhole"));
}
