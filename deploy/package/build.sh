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

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_dir/Cargo.toml" | head -n 1)
if [ -z "$version" ]; then
    echo "unable to read package version" >&2
    exit 1
fi

target=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
package_name="blackhole-${version}-${target}"
mkdir -p "$output_dir"
staging=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-package.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

mkdir -p "$staging/$package_name/bin" \
    "$staging/$package_name/etc/blackhole" \
    "$staging/$package_name/share/blackhole/examples" \
    "$staging/$package_name/share/blackhole/deploy/systemd" \
    "$staging/$package_name/share/blackhole/deploy/launchd"
cp "$binary" "$staging/$package_name/bin/blackhole"
cp "$repo_dir/blackhole.example.toml" \
    "$staging/$package_name/etc/blackhole/blackhole.toml"
cp "$repo_dir/blackhole.lan.example.toml" \
    "$staging/$package_name/share/blackhole/examples/blackhole.lan.example.toml"
cp "$repo_dir/deploy/systemd/blackhole.service" \
    "$repo_dir/deploy/systemd/blackhole.conf" \
    "$repo_dir/deploy/systemd/install.sh" \
    "$staging/$package_name/share/blackhole/deploy/systemd/"
cp "$repo_dir/deploy/launchd/com.brianbruggeman.blackhole.plist" \
    "$repo_dir/deploy/launchd/install.sh" \
    "$repo_dir/deploy/launchd/smoke.sh" \
    "$staging/$package_name/share/blackhole/deploy/launchd/"
chmod 0755 "$staging/$package_name/bin/blackhole" \
    "$staging/$package_name/share/blackhole/deploy/systemd/install.sh" \
    "$staging/$package_name/share/blackhole/deploy/launchd/install.sh" \
    "$staging/$package_name/share/blackhole/deploy/launchd/smoke.sh"

{
    printf 'package=%s\n' "$package_name"
    printf 'source_commit=%s\n' "$(git -C "$repo_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
    printf 'package_version=%s\n' "$version"
    printf 'target=%s\n' "$target"
    rustc -vV | sed 's/^/rustc_/'
    cargo -vV | sed 's/^/cargo_/'
    printf 'cargo_lock_sha256=%s\n' "$(hash_file "$repo_dir/Cargo.lock" | awk '{print $1}')"
    printf 'source_tree_sha256=%s\n' "$(git -C "$repo_dir" ls-files -z | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
    printf 'fuzz_corpus_files=%s\n' "$(find "$repo_dir/fuzz/corpus/query_view" -type f | wc -l)"
    printf 'fuzz_corpus_sha256=%s\n' "$(find "$repo_dir/fuzz/corpus/query_view" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
} > "$staging/$package_name/PROVENANCE.txt"

(cd "$staging" && find "$package_name" -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    hash_file "$file"
done) > "$staging/$package_name/SHA256SUMS"
tar -C "$staging" -czf "$output_dir/$package_name.tar.gz" "$package_name"
printf '%s\n' "$output_dir/$package_name.tar.gz"
