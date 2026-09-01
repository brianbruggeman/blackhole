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

backup_dir=$(mktemp -d "${TMPDIR:-/tmp}/blackhole-install.XXXXXX")
rollback_needed=1
service_was_active=0
if systemctl is-active --quiet blackhole.service; then
    service_was_active=1
fi

cleanup() {
    status=$?
    if [ "$rollback_needed" -eq 1 ] && [ "$status" -ne 0 ]; then
        echo "installation failed; restoring the previous service files" >&2
        restore_file /usr/local/bin/blackhole "$backup_dir/binary"
        restore_file /etc/blackhole/blackhole.toml "$backup_dir/config"
        restore_file /etc/systemd/system/blackhole.service "$backup_dir/service"
        restore_file /etc/tmpfiles.d/blackhole.conf "$backup_dir/tmpfiles"
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [ "$service_was_active" -eq 1 ]; then
            systemctl restart blackhole.service >/dev/null 2>&1 || true
        else
            systemctl stop blackhole.service >/dev/null 2>&1 || true
        fi
    fi
    rm -r -- "$backup_dir"
    exit "$status"
}

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

trap cleanup EXIT HUP INT TERM

if ! getent group blackhole >/dev/null; then
    groupadd --system blackhole
fi
if ! getent passwd blackhole >/dev/null; then
    useradd --system --gid blackhole --home-dir /var/lib/blackhole \
        --shell /usr/sbin/nologin blackhole
fi

install -d -o root -g root -m 0755 /etc/blackhole
install -d -o blackhole -g blackhole -m 0750 /var/lib/blackhole
backup_file /usr/local/bin/blackhole "$backup_dir/binary"
backup_file /etc/blackhole/blackhole.toml "$backup_dir/config"
backup_file /etc/systemd/system/blackhole.service "$backup_dir/service"
backup_file /etc/tmpfiles.d/blackhole.conf "$backup_dir/tmpfiles"
install -o root -g root -m 0755 "$binary" /usr/local/bin/blackhole
install -o blackhole -g blackhole -m 0640 "$config" /etc/blackhole/blackhole.toml
install -o root -g root -m 0644 "$script_dir/blackhole.service" \
    /etc/systemd/system/blackhole.service
install -d -o root -g root -m 0755 /etc/tmpfiles.d
install -o root -g root -m 0644 "$script_dir/blackhole.conf" \
    /etc/tmpfiles.d/blackhole.conf

systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf
systemctl daemon-reload
systemctl enable blackhole.service
if [ "$service_was_active" -eq 1 ]; then
    systemctl restart blackhole.service
else
    systemctl start blackhole.service
fi

rollback_needed=0
echo "blackhole installed and started"
