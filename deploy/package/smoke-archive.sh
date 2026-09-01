#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ARCHIVE" >&2
    exit 2
fi
archive=$1
[ -f "$archive" ] || { echo "archive must be a regular file: $archive" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "archive smoke requires root" >&2; exit 1; }

extract_root=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-archive-smoke.XXXXXX")
install_root=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-archive-install.XXXXXX")
cleanup() {
    status=$?
    rm -r -- "$extract_root"
    find "$install_root" -depth -delete 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

tar -xzf "$archive" -C "$extract_root"
package_count=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d | wc -l)
[ "$package_count" -eq 1 ] || { echo "archive must contain one package directory" >&2; exit 1; }
package_root=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d -print -quit)
systemd_installer="$package_root/share/blackhole/deploy/systemd/install.sh"
[ -x "$systemd_installer" ] || { echo "archive systemd installer missing" >&2; exit 1; }

install -d -m 0755 "$install_root/etc/systemd/system"
cp /etc/passwd /etc/group /etc/shadow "$install_root/etc/"
cp /usr/lib/systemd/system/sysinit.target \
    /usr/lib/systemd/system/basic.target \
    /usr/lib/systemd/system/local-fs.target \
    "$install_root/etc/systemd/system/"

BLACKHOLE_INSTALL_ROOT="$install_root" "$systemd_installer"
test -x "$install_root/usr/local/bin/blackhole"
test -f "$install_root/etc/blackhole/blackhole.toml"
test -f "$install_root/etc/systemd/system/blackhole.service"
test -d "$install_root/var/lib/blackhole"
echo "archive installer disposable-root smoke passed"
