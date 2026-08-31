#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${BLACKHOLE_BINARY:-"$script_dir/../../target/release/blackhole"}
config=${BLACKHOLE_CONFIG:-"$script_dir/../../blackhole.example.toml"}

if [ ! -x "$binary" ]; then
    echo "executable not found or not executable: $binary" >&2
    exit 1
fi
if [ ! -r "$config" ]; then
    echo "configuration not readable: $config" >&2
    exit 1
fi
if ! "$binary" --check "$config" >/dev/null; then
    echo "configuration validation failed: $config" >&2
    exit 1
fi

if ! getent group blackhole >/dev/null; then
    groupadd --system blackhole
fi
if ! getent passwd blackhole >/dev/null; then
    useradd --system --gid blackhole --home-dir /var/lib/blackhole \
        --shell /usr/sbin/nologin blackhole
fi

install -d -o root -g root -m 0755 /etc/blackhole
install -d -o blackhole -g blackhole -m 0750 /var/lib/blackhole
install -o root -g root -m 0755 "$binary" /usr/local/bin/blackhole
install -o blackhole -g blackhole -m 0640 "$config" /etc/blackhole/blackhole.toml
install -o root -g root -m 0644 "$script_dir/blackhole.service" \
    /etc/systemd/system/blackhole.service
install -d -o root -g root -m 0755 /etc/tmpfiles.d
install -o root -g root -m 0644 "$script_dir/blackhole.conf" \
    /etc/tmpfiles.d/blackhole.conf

systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf
systemctl daemon-reload
systemctl enable --now blackhole.service

echo "blackhole installed and started"
