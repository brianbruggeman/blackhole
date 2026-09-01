use std::fs;

const LAUNCHD_PLIST: &str = "deploy/launchd/com.brianbruggeman.blackhole.plist";

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
