#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${BLACKHOLE_BINARY+x}" ]; then
    binary=$BLACKHOLE_BINARY
elif [ -x "$script_dir/../../../../bin/blackhole" ]; then
    binary=$script_dir/../../../../bin/blackhole
else
    binary=$script_dir/../../target/release/blackhole
fi
if [ -n "${BLACKHOLE_CONFIG+x}" ]; then
    config=$BLACKHOLE_CONFIG
elif [ -r "$script_dir/../../../../etc/blackhole/blackhole.toml" ]; then
    config=$script_dir/../../../../etc/blackhole/blackhole.toml
else
    config=$script_dir/../../blackhole.example.toml
fi
plist=${BLACKHOLE_PLIST:-"$script_dir/com.brianbruggeman.blackhole.plist"}
label=com.brianbruggeman.blackhole

if [ ! -x "$binary" ]; then
    echo "executable not found or not executable: $binary" >&2
    exit 1
fi
if [ ! -r "$config" ]; then
    echo "configuration not readable: $config" >&2
    exit 1
fi
if [ ! -r "$plist" ]; then
    echo "launchd plist not readable: $plist" >&2
    exit 1
fi
if ! "$binary" --check "$config" >/dev/null; then
    echo "configuration validation failed: $config" >&2
    exit 1
fi
if ! plutil -lint "$plist" >/dev/null; then
    echo "launchd plist validation failed: $plist" >&2
    exit 1
fi

backup_dir=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-launchd-install.XXXXXX")
rollback_needed=1
service_was_loaded=0
if launchctl print "system/$label" >/dev/null 2>&1; then
    service_was_loaded=1
fi

backup_file() {
    target=$1
    backup=$2
    if [ -e "$target" ]; then
        cp -p -- "$target" "$backup"
    else
        : > "$backup.absent"
    fi
}

restore_file() {
    target=$1
    backup=$2
    if [ -e "$backup" ]; then
        cp -p -- "$backup" "$target"
    elif [ -e "$backup.absent" ]; then
        rm -f -- "$target"
    fi
}

cleanup() {
    status=$?
    if [ "$rollback_needed" -eq 1 ] && [ "$status" -ne 0 ]; then
        echo "installation failed; restoring the previous launchd files" >&2
        launchctl bootout "system/$label" >/dev/null 2>&1 || true
        restore_file /usr/local/bin/blackhole "$backup_dir/binary"
        restore_file /usr/local/etc/blackhole/blackhole.toml "$backup_dir/config"
        restore_file "/Library/LaunchDaemons/$label.plist" "$backup_dir/plist"
        if [ "$service_was_loaded" -eq 1 ]; then
            launchctl bootstrap system "/Library/LaunchDaemons/$label.plist" >/dev/null 2>&1 || true
        fi
    fi
    rm -r -- "$backup_dir"
    exit "$status"
}

trap cleanup EXIT HUP INT TERM

if ! dscl . -read /Users/_blackhole >/dev/null 2>&1; then
    sysadminctl -addUser _blackhole -shell /usr/bin/false -home /usr/local/var/lib/blackhole
fi

install -d -o root -g wheel -m 0755 /usr/local/etc/blackhole
install -d -o _blackhole -g _blackhole -m 0750 /usr/local/var/lib/blackhole
backup_file /usr/local/bin/blackhole "$backup_dir/binary"
backup_file /usr/local/etc/blackhole/blackhole.toml "$backup_dir/config"
backup_file "/Library/LaunchDaemons/$label.plist" "$backup_dir/plist"

install -o root -g wheel -m 0755 "$binary" /usr/local/bin/blackhole
install -o _blackhole -g _blackhole -m 0640 "$config" \
    /usr/local/etc/blackhole/blackhole.toml
install -o root -g wheel -m 0644 "$plist" "/Library/LaunchDaemons/$label.plist"

launchctl bootout "system/$label" >/dev/null 2>&1 || true
launchctl bootstrap system "/Library/LaunchDaemons/$label.plist"
rollback_needed=0
echo "blackhole installed and started"
