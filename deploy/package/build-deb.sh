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

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=${BLACKHOLE_DEB_VERSION:-$(sed -n 's/^version = "\([^\"]*\)"/\1/p' "$repo_dir/Cargo.toml" | head -n 1)}
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
    "$staging/data/etc/tmpfiles.d" "$staging/data/usr/share/doc/blackhole"
cp "$binary" "$staging/data/usr/local/bin/blackhole"
cp "$repo_dir/blackhole.example.toml" \
    "$staging/data/etc/blackhole/blackhole.toml"
cp "$repo_dir/deploy/systemd/blackhole.service" \
    "$staging/data/etc/systemd/system/blackhole.service"
cp "$repo_dir/deploy/systemd/blackhole.conf" \
    "$staging/data/etc/tmpfiles.d/blackhole.conf"
chmod 0755 "$staging/data/usr/local/bin/blackhole"
{
    printf 'package=%s\n' "$package_name"
    printf 'source_commit=%s\n' "$(git -C "$repo_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
    printf 'package_version=%s\n' "$version"
    printf 'target=%s\n' "$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
    rustc -vV | sed 's/^/rustc_/'
    cargo -vV | sed 's/^/cargo_/'
    printf 'cargo_lock_sha256=%s\n' "$(hash_file "$repo_dir/Cargo.lock" | awk '{print $1}')"
    printf 'source_tree_sha256=%s\n' "$(git -C "$repo_dir" ls-files -z | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
    printf 'fuzz_corpus_files=%s\n' "$(find "$repo_dir/fuzz/corpus/query_view" -type f | wc -l)"
    printf 'fuzz_corpus_sha256=%s\n' "$(find "$repo_dir/fuzz/corpus/query_view" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
} > "$staging/data/usr/share/doc/blackhole/PROVENANCE.txt"
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
cat > "$staging/control/conffiles" <<'EOF'
/etc/blackhole/blackhole.toml
EOF
cat > "$staging/control/postinst" <<'EOF'
#!/bin/sh
set -eu

root=${DPKG_ROOT:-}
root_path() { printf '%s%s' "$root" "$1"; }
has_group() {
    if [ -n "$root" ]; then
        grep -q '^blackhole:' "$(root_path /etc/group)" 2>/dev/null
    else
        getent group blackhole >/dev/null 2>&1
    fi
}
has_user() {
    if [ -n "$root" ]; then
        grep -q '^blackhole:' "$(root_path /etc/passwd)" 2>/dev/null
    else
        getent passwd blackhole >/dev/null 2>&1
    fi
}
if [ -n "$root" ]; then
    blackhole_uid=$(awk -F: '$1 == "blackhole" { print $3 }' "$(root_path /etc/passwd)")
    blackhole_gid=$(awk -F: '$1 == "blackhole" { print $3 }' "$(root_path /etc/group)")
else
    blackhole_uid=$(id -u blackhole 2>/dev/null || true)
    blackhole_gid=$(id -g blackhole 2>/dev/null || true)
fi
if ! has_group; then
    groupadd --system ${root:+--root "$root"} blackhole
fi
if ! has_user; then
    useradd --system ${root:+--root "$root"} --gid blackhole \
        --home-dir /var/lib/blackhole --shell /usr/sbin/nologin blackhole
fi
if [ -z "$blackhole_uid" ] || [ -z "$blackhole_gid" ]; then
    if [ -n "$root" ]; then
        blackhole_uid=$(awk -F: '$1 == "blackhole" { print $3 }' "$(root_path /etc/passwd)")
        blackhole_gid=$(awk -F: '$1 == "blackhole" { print $3 }' "$(root_path /etc/group)")
    fi
fi
install -d -o "$blackhole_uid" -g "$blackhole_gid" -m 0750 \
    "$(root_path /var/lib/blackhole)"
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    if [ -n "$root" ]; then
        systemd-tmpfiles --create --root="$root" /etc/tmpfiles.d/blackhole.conf
    else
        systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf
    fi
fi
init=$(ps -p 1 -o comm= 2>/dev/null || true)
if [ -z "$root" ] && [ "$init" = systemd ] \
    && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now blackhole.service
fi
EOF
cat > "$staging/control/prerm" <<'EOF'
#!/bin/sh
set -eu

root=${DPKG_ROOT:-}
init=$(ps -p 1 -o comm= 2>/dev/null || true)
if [ -z "$root" ] && [ "${1:-}" = remove ] && [ "$init" = systemd ] \
    && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now blackhole.service || true
    systemctl daemon-reload || true
fi
EOF
chmod 0755 "$staging/control/postinst" "$staging/control/prerm"

tar -C "$staging/control" --sort=name --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner -czf "$staging/control.tar.gz" \
    conffiles control postinst prerm
tar -C "$staging/data" --sort=name --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner -czf "$staging/data.tar.gz" .
printf '2.0\n' > "$staging/debian-binary"
ar r "$output_dir/$package_name.deb" "$staging/debian-binary" \
    "$staging/control.tar.gz" "$staging/data.tar.gz" >/dev/null
printf '%s\n' "$output_dir/$package_name.deb"
