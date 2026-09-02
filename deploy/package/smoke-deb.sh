#!/bin/sh
set -eu

export DEBIAN_FRONTEND=noninteractive

if [ "${BLACKHOLE_SMOKE_TRACE:-}" = 1 ]; then
    set -x
fi

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 DEB [UPGRADE_DEB]" >&2
    exit 2
fi

package=$1
upgrade_package=${2:-$package}
[ -f "$package" ] || {
    echo "package must be a regular file: $package" >&2
    exit 1
}
[ -f "$upgrade_package" ] || {
    echo "upgrade package must be a regular file: $upgrade_package" >&2
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

phase() { printf 'debian-smoke: %s\n' "$1"; }

mkdir -p "$root/etc" "$root/var/lib/dpkg" "$root/var/log"
printf 'Package: blackhole\nStatus: install ok installed\n' > "$root/var/lib/dpkg/status"
cp /etc/passwd /etc/group /etc/shadow "$root/etc/"

phase 'unpack initial package'
dpkg --root="$root" --unpack "$package"
phase 'configure initial package'
dpkg --root="$root" --force-confold --configure blackhole

old_version=$(dpkg-deb --field "$package" Version)
new_version=$(dpkg-deb --field "$upgrade_package" Version)
if [ "$package" != "$upgrade_package" ]; then
    dpkg --compare-versions "$new_version" gt "$old_version" || {
        echo "upgrade package must have a newer version: $old_version -> $new_version" >&2
        exit 1
    }
fi

# A local operator configuration is a Debian conffile and must survive an
# upgrade transaction that carries a newer packaged default.
printf 'operator-policy = "retain-me"\n' > "$root/etc/blackhole/blackhole.toml"

# A second real transaction catches non-idempotent maintainer scripts and,
# when supplied, exercises a real newer-package upgrade.
phase 'unpack upgrade package'
dpkg --root="$root" --force-confold --unpack "$upgrade_package"
phase 'configure upgrade package'
dpkg --root="$root" --force-confold --configure blackhole
phase 'verify installed package'
grep -Fx 'operator-policy = "retain-me"' "$root/etc/blackhole/blackhole.toml" >/dev/null

if [ "$package" != "$upgrade_package" ]; then
    installed_version=$(dpkg-query --root="$root" -W -f='${Version}' blackhole)
    test "$installed_version" = "$new_version"
fi

dpkg-query --root="$root" -W -f='${Status}\n' blackhole | grep -Fx \
    'install ok installed' >/dev/null
test -x "$root/usr/local/bin/blackhole"
test -f "$root/etc/blackhole/blackhole.toml"
test -f "$root/etc/systemd/system/blackhole.service"
test -f "$root/etc/tmpfiles.d/blackhole.conf"
test -d "$root/var/lib/blackhole"
test "$(awk -F: '$1 == "blackhole" { print $1 }' "$root/etc/passwd")" = blackhole
test "$(stat -c '%a' "$root/var/lib/blackhole")" = 750

echo "Debian package install and upgrade smoke passed"
