#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 DEB" >&2
    exit 2
fi

package=$1
[ -f "$package" ] || {
    echo "package must be a regular file: $package" >&2
    exit 1
}
command -v dpkg >/dev/null 2>&1 || {
    echo "dpkg is required for the Debian package smoke test" >&2
    exit 1
}
command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required for the Debian package smoke test" >&2
    exit 1
}
[ "$(id -u)" -eq 0 ] || {
    echo "the Debian package smoke test requires root for disposable ownership" >&2
    exit 1
}

root=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-deb-smoke.XXXXXX")
cleanup() { rm -rf "$root"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$root/etc" "$root/var/lib/dpkg" "$root/var/log"
printf 'Package: blackhole\nStatus: install ok installed\n' > "$root/var/lib/dpkg/status"
cp /etc/passwd /etc/group /etc/shadow "$root/etc/"

dpkg --root="$root" --unpack "$package"
dpkg --root="$root" --configure blackhole

# A second real transaction catches non-idempotent maintainer scripts and
# exercises the package reapplication path used by an upgrade.
dpkg --root="$root" --unpack "$package"
dpkg --root="$root" --configure blackhole

dpkg-query --root="$root" -W -f='${Status}\n' blackhole | grep -Fx \
    'install ok installed' >/dev/null
test -x "$root/usr/local/bin/blackhole"
test -f "$root/etc/blackhole/blackhole.toml"
test -f "$root/etc/systemd/system/blackhole.service"
test -f "$root/etc/tmpfiles.d/blackhole.conf"
test -d "$root/var/lib/blackhole"
test "$(awk -F: '$1 == "blackhole" { print $1 }' "$root/etc/passwd")" = blackhole
test "$(stat -c '%a' "$root/var/lib/blackhole")" = 750

echo "Debian package install and repeat-transaction smoke passed"
