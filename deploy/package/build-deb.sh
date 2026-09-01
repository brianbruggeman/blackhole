#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 BINARY OUTPUT_DIR" >&2
    exit 2
fi

binary=$1
output_dir=$2
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    echo "binary must be an executable regular file: $binary" >&2
    exit 1
fi
command -v ar >/dev/null 2>&1 || {
    echo "ar is required to build a Debian package" >&2
    exit 1
}

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_dir/Cargo.toml" | head -n 1)
if [ -z "$version" ]; then
    echo "unable to read package version" >&2
    exit 1
fi
case "$version" in
    *[!A-Za-z0-9.+~:-]*)
        echo "unsupported Debian version: $version" >&2
        exit 1
        ;;
esac

if command -v dpkg >/dev/null 2>&1; then
    architecture=$(dpkg --print-architecture)
else
    case "$(uname -m)" in
        x86_64) architecture=amd64 ;;
        aarch64) architecture=arm64 ;;
        armv7l) architecture=armhf ;;
        *) architecture=unknown ;;
    esac
fi
if [ "$architecture" = unknown ]; then
    echo "unable to determine Debian architecture" >&2
    exit 1
fi

package_name="blackhole_${version}_${architecture}"
mkdir -p "$output_dir"
staging=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-deb.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM

mkdir -p "$staging/control" "$staging/data/usr/local/bin" \
    "$staging/data/etc/blackhole" "$staging/data/etc/systemd/system" \
    "$staging/data/etc/tmpfiles.d"
cp "$binary" "$staging/data/usr/local/bin/blackhole"
cp "$repo_dir/blackhole.example.toml" \
    "$staging/data/etc/blackhole/blackhole.toml"
cp "$repo_dir/deploy/systemd/blackhole.service" \
    "$staging/data/etc/systemd/system/blackhole.service"
cp "$repo_dir/deploy/systemd/blackhole.conf" \
    "$staging/data/etc/tmpfiles.d/blackhole.conf"
chmod 0755 "$staging/data/usr/local/bin/blackhole"
cat > "$staging/control/control" <<EOF
Package: blackhole
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Maintainer: Brian Bruggeman
Description: policy-driven DNS sinkhole and honeypot
 Blackhole is a privacy-first DNS resolver with bounded policy and forwarding.
EOF
cat > "$staging/control/postinst" <<'EOF'
#!/bin/sh
set -eu

if ! getent group blackhole >/dev/null 2>&1; then
    groupadd --system blackhole
fi
if ! getent passwd blackhole >/dev/null 2>&1; then
    useradd --system --gid blackhole --home-dir /var/lib/blackhole \
        --shell /usr/sbin/nologin blackhole
fi
install -d -o blackhole -g blackhole -m 0750 /var/lib/blackhole
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf
fi
init=$(ps -p 1 -o comm= 2>/dev/null || true)
if [ "$init" = systemd ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now blackhole.service
fi
EOF
cat > "$staging/control/prerm" <<'EOF'
#!/bin/sh
set -eu

init=$(ps -p 1 -o comm= 2>/dev/null || true)
if [ "${1:-}" = remove ] && [ "$init" = systemd ] \
    && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now blackhole.service || true
    systemctl daemon-reload || true
fi
EOF
chmod 0755 "$staging/control/postinst" "$staging/control/prerm"

tar -C "$staging/control" --sort=name --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner -czf "$staging/control.tar.gz" \
    control postinst prerm
tar -C "$staging/data" --sort=name --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner -czf "$staging/data.tar.gz" .
printf '2.0\n' > "$staging/debian-binary"
ar r "$output_dir/$package_name.deb" "$staging/debian-binary" \
    "$staging/control.tar.gz" "$staging/data.tar.gz" >/dev/null
printf '%s\n' "$output_dir/$package_name.deb"
