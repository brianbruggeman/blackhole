#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "launchd smoke.sh must run as root" >&2
    exit 1
fi
if [ "$(uname -s)" != Darwin ]; then
    echo "launchd smoke.sh requires macOS" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${BLACKHOLE_BINARY:-"$script_dir/../../target/release/blackhole"}
config=${BLACKHOLE_CONFIG:-"$script_dir/../../blackhole.example.toml"}
plist=${BLACKHOLE_PLIST:-"$script_dir/com.brianbruggeman.blackhole.plist"}
label=com.brianbruggeman.blackhole
binary_target=/usr/local/bin/blackhole
config_target=/usr/local/etc/blackhole/blackhole.toml
plist_target=/Library/LaunchDaemons/$label.plist
state_target=/usr/local/var/lib/blackhole
created_user=0

[ -x "$binary" ] || { echo "release binary is required: $binary" >&2; exit 1; }
[ -r "$config" ] || { echo "configuration is required: $config" >&2; exit 1; }
[ -r "$plist" ] || { echo "launchd plist is required: $plist" >&2; exit 1; }

if launchctl print "system/$label" >/dev/null 2>&1; then
    echo "refusing to overwrite an existing Blackhole launchd service" >&2
    exit 1
fi
if dscl . -read /Users/_blackhole >/dev/null 2>&1; then
    echo "refusing to overwrite an existing _blackhole account" >&2
    exit 1
fi

cleanup() {
    status=$?
    launchctl bootout "system/$label" >/dev/null 2>&1 || true
    rm -f "$binary_target" "$config_target" "$plist_target"
    if [ -n "${failed_plist:-}" ]; then
        rm -f "$failed_plist"
    fi
    rmdir "$state_target" /usr/local/var/lib /usr/local/etc/blackhole \
        /usr/local/etc /Library/LaunchDaemons 2>/dev/null || true
    if [ "$created_user" -eq 1 ]; then
        sysadminctl -deleteUser _blackhole >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

BLACKHOLE_BINARY="$binary" BLACKHOLE_CONFIG="$config" \
    BLACKHOLE_PLIST="$plist" "$script_dir/install.sh"
launchctl print "system/$label" >/dev/null
test -x "$binary_target"
test -f "$config_target"
test -f "$plist_target"
created_user=1

old_binary=$(shasum -a 256 "$binary_target")
old_config=$(shasum -a 256 "$config_target")
old_plist=$(shasum -a 256 "$plist_target")

# A second real install exercises the host upgrade path and must preserve the
# running service and all installed payloads.
BLACKHOLE_BINARY="$binary" BLACKHOLE_CONFIG="$config" \
    BLACKHOLE_PLIST="$plist" "$script_dir/install.sh"
launchctl print "system/$label" >/dev/null
test "$old_binary" = "$(shasum -a 256 "$binary_target")"
test "$old_config" = "$(shasum -a 256 "$config_target")"
test "$old_plist" = "$(shasum -a 256 "$plist_target")"

# A valid plist with no executable is accepted by plutil but rejected by
# launchd. The installer must restore the previous service and every payload
# after this failed upgrade transaction.
failed_plist=$(mktemp "${TMPDIR:-/tmp}/blackhole-launchd-failed.XXXXXX")
cp -p "$plist" "$failed_plist"
sed -i '' 's#<string>/usr/local/bin/blackhole</string>#<string></string>#' \
    "$failed_plist"
if BLACKHOLE_BINARY="$binary" BLACKHOLE_CONFIG="$config" \
    BLACKHOLE_PLIST="$failed_plist" "$script_dir/install.sh"; then
    echo "failed launchd upgrade unexpectedly succeeded" >&2
    exit 1
fi
launchctl print "system/$label" >/dev/null
test "$old_binary" = "$(shasum -a 256 "$binary_target")"
test "$old_config" = "$(shasum -a 256 "$config_target")"
test "$old_plist" = "$(shasum -a 256 "$plist_target")"
rm -f "$failed_plist"
printf '%s\n' 'launchd host install and upgrade smoke passed'
