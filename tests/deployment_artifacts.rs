use std::fs;

const LAUNCHD_PLIST: &str = "deploy/launchd/com.brianbruggeman.blackhole.plist";
const SYSTEMD_UNIT: &str = "deploy/systemd/blackhole.service";
const SYSTEMD_TMPFILES: &str = "deploy/systemd/blackhole.conf";
const SYSTEMD_INSTALLER: &str = "deploy/systemd/install.sh";

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
        "backup_file /usr/local/bin/blackhole",
        "restore_file /usr/local/bin/blackhole",
        "installation failed; restoring the previous service files",
        "trap cleanup EXIT HUP INT TERM",
        "service_was_active=0",
        "systemctl restart blackhole.service",
        "systemctl stop blackhole.service",
        "rollback_needed=0",
        "install -d -o blackhole -g blackhole -m 0750 /var/lib/blackhole",
        "systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf",
        "systemctl daemon-reload",
    ] {
        assert!(
            installer.contains(required),
            "missing installer step: {required}"
        );
    }
    assert!(installer.contains("if [ \"$(id -u)\" -ne 0 ]"));
}
