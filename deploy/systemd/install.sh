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
install_root=${BLACKHOLE_INSTALL_ROOT:-}
root_path() { printf '%s%s' "$install_root" "$1"; }

binary_target=$(root_path /usr/local/bin/blackhole)
config_target=$(root_path /etc/blackhole/blackhole.toml)
service_target=$(root_path /etc/systemd/system/blackhole.service)
tmpfiles_target=$(root_path /etc/tmpfiles.d/blackhole.conf)
state_target=$(root_path /var/lib/blackhole)

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
if [ -z "$install_root" ] && systemctl is-active --quiet blackhole.service; then
    service_was_active=1
fi

cleanup() {
    status=$?
    if [ "$rollback_needed" -eq 1 ] && [ "$status" -ne 0 ]; then
        echo "installation failed; restoring the previous service files" >&2
        restore_file "$binary_target" "$backup_dir/binary"
        restore_file "$config_target" "$backup_dir/config"
        restore_file "$service_target" "$backup_dir/service"
        restore_file "$tmpfiles_target" "$backup_dir/tmpfiles"
        if [ -z "$install_root" ]; then
            systemctl daemon-reload >/dev/null 2>&1 || true
            if [ "$service_was_active" -eq 1 ]; then
                systemctl restart blackhole.service >/dev/null 2>&1 || true
            else
                systemctl stop blackhole.service >/dev/null 2>&1 || true
            fi
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

if [ -n "$install_root" ]; then
    if ! grep -q '^blackhole:' "$(root_path /etc/group)" 2>/dev/null; then
        groupadd --system --root "$install_root" blackhole
    fi
    if ! grep -q '^blackhole:' "$(root_path /etc/passwd)" 2>/dev/null; then
        useradd --system --root "$install_root" --gid blackhole \
            --home-dir /var/lib/blackhole --shell /usr/sbin/nologin blackhole
    fi
    blackhole_uid=$(awk -F: '$1 == "blackhole" { print $3 }' "$(root_path /etc/passwd)")
    blackhole_gid=$(awk -F: '$1 == "blackhole" { print $3 }' "$(root_path /etc/group)")
else
    if ! getent group blackhole >/dev/null; then
        groupadd --system blackhole
    fi
    if ! getent passwd blackhole >/dev/null; then
        useradd --system --gid blackhole --home-dir /var/lib/blackhole \
            --shell /usr/sbin/nologin blackhole
    fi
    blackhole_uid=$(id -u blackhole)
    blackhole_gid=$(id -g blackhole)
fi

install -d -o 0 -g 0 -m 0755 "$(root_path /usr/local/bin)"
install -d -o 0 -g 0 -m 0755 "$(root_path /etc/blackhole)"
install -d -o 0 -g 0 -m 0755 "$(root_path /etc/systemd/system)"
install -d -o "$blackhole_uid" -g "$blackhole_gid" -m 0750 "$state_target"
backup_file "$binary_target" "$backup_dir/binary"
backup_file "$config_target" "$backup_dir/config"
backup_file "$service_target" "$backup_dir/service"
backup_file "$tmpfiles_target" "$backup_dir/tmpfiles"
install -o 0 -g 0 -m 0755 "$binary" "$binary_target"
install -o "$blackhole_uid" -g "$blackhole_gid" -m 0640 "$config" "$config_target"
install -d -o 0 -g 0 -m 0755 "$(root_path /etc/tmpfiles.d)"
install -o 0 -g 0 -m 0644 "$script_dir/blackhole.service" "$service_target"
install -o 0 -g 0 -m 0644 "$script_dir/blackhole.conf" "$tmpfiles_target"

if [ -n "$install_root" ]; then
    systemd-tmpfiles --create --root="$install_root" /etc/tmpfiles.d/blackhole.conf
    systemd-analyze verify --root="$install_root" blackhole.service
elif [ "$service_was_active" -eq 1 ]; then
    systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf
    systemctl daemon-reload
    systemctl enable blackhole.service
    systemctl restart blackhole.service
else
    systemd-tmpfiles --create /etc/tmpfiles.d/blackhole.conf
    systemctl daemon-reload
    systemctl enable blackhole.service
    systemctl start blackhole.service
fi

rollback_needed=0
if [ -n "$install_root" ]; then
    echo "blackhole installed into disposable root"
else
    echo "blackhole installed and started"
fi
