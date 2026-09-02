#!/bin/sh
set -eu

if [ "${BLACKHOLE_SMOKE_TRACE:-0}" = 1 ]; then
    set -x
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "smoke.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${BLACKHOLE_BINARY:-"$script_dir/../../target/release/blackhole"}
config=${BLACKHOLE_CONFIG:-"$script_dir/../../blackhole.example.toml"}
if [ ! -x "$binary" ] || [ ! -r "$config" ]; then
    echo "release binary and readable configuration are required" >&2
    exit 1
fi

make_root() {
    root=$1
    chown root:root "$root"
    mkdir -p "$root/etc" "$root/usr/lib/systemd/system"
    cp /etc/passwd /etc/group /etc/shadow "$root/etc/"
}

root_dir=$(mktemp -d /tmp/blackhole-systemd-smoke.XXXXXX)
rollback_root=$(mktemp -d /tmp/blackhole-systemd-rollback.XXXXXX)
cleanup() {
    rm -rf "$root_dir" "$rollback_root"
}
trap cleanup EXIT HUP INT TERM

make_root "$root_dir"
# Keep verification independent of the runner's systemd unit subset. The
# install itself remains rooted in this disposable directory; copying the
# unit definitions supplies dependency metadata without touching the host.
cp -a /usr/lib/systemd/system/. "$root_dir/usr/lib/systemd/system/"
BLACKHOLE_INSTALL_ROOT="$root_dir" BLACKHOLE_BINARY="$binary" \
    BLACKHOLE_CONFIG="$config" "$script_dir/install.sh"
test -x "$root_dir/usr/local/bin/blackhole"
test -f "$root_dir/etc/blackhole/blackhole.toml"
test -f "$root_dir/etc/systemd/system/blackhole.service"
test -d "$root_dir/var/lib/blackhole"

make_root "$rollback_root"
mkdir -p "$rollback_root/usr/local/bin" "$rollback_root/etc/blackhole" \
    "$rollback_root/etc/systemd/system" "$rollback_root/etc/tmpfiles.d"
cp /bin/true "$rollback_root/usr/local/bin/blackhole"
cp "$config" "$rollback_root/etc/blackhole/blackhole.toml"
cp "$script_dir/blackhole.service" "$rollback_root/etc/systemd/system/blackhole.service"
cp "$script_dir/blackhole.conf" "$rollback_root/etc/tmpfiles.d/blackhole.conf"
old_binary=$(sha256sum "$rollback_root/usr/local/bin/blackhole")
old_config=$(sha256sum "$rollback_root/etc/blackhole/blackhole.toml")
old_service=$(sha256sum "$rollback_root/etc/systemd/system/blackhole.service")
old_tmpfiles=$(sha256sum "$rollback_root/etc/tmpfiles.d/blackhole.conf")
if BLACKHOLE_INSTALL_ROOT="$rollback_root" BLACKHOLE_BINARY="$binary" \
    BLACKHOLE_CONFIG="$config" "$script_dir/install.sh"; then
    echo "rollback fixture unexpectedly succeeded" >&2
    exit 1
fi
test "$old_binary" = "$(sha256sum "$rollback_root/usr/local/bin/blackhole")"
test "$old_config" = "$(sha256sum "$rollback_root/etc/blackhole/blackhole.toml")"
test "$old_service" = "$(sha256sum "$rollback_root/etc/systemd/system/blackhole.service")"
test "$old_tmpfiles" = "$(sha256sum "$rollback_root/etc/tmpfiles.d/blackhole.conf")"
printf '%s\n' 'systemd disposable install and rollback smoke passed'
