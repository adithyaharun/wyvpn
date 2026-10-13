#!/bin/sh
set -e

dropin_dir=/etc/systemd/system/wyvpnd.service.d
dropin=$dropin_dir/50-resolv-conf.conf

fresh=
case "$1" in
    configure) [ -n "$2" ] || fresh=1 ;;
    1) fresh=1 ;;
    [0-9]*) ;;
    *) exit 0 ;;
esac

resolved_active() {
    [ -d /run/systemd/resolve ] || return 1
    [ -x /usr/bin/resolvectl ] || return 1
    if [ -L /etc/resolv.conf ]; then
        readlink /etc/resolv.conf | grep -q systemd/resolve
    else
        grep -qs -e 127.0.0.53 -e systemd-resolved /etc/resolv.conf
    fi
}

join_hint() {
    echo "To use WyVPN without sudo, join the wyvpn group and log in again:"
    echo "    sudo usermod -aG wyvpn \"\$USER\""
}

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers wyvpn.conf || true
fi
if ! getent group wyvpn >/dev/null 2>&1; then
    groupadd -r wyvpn
fi

# the daemon replaces /etc/resolv.conf by rename, which needs /etc itself writable
if resolved_active; then
    rm -f "$dropin"
else
    mkdir -p "$dropin_dir"
    printf '[Service]\nReadWritePaths=/etc\n' > "$dropin"
fi

if command -v systemctl >/dev/null 2>&1; then
    was_enabled=$(systemctl is-enabled wyvpnd.service 2>/dev/null) || true
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
    fi
    case "$was_enabled" in
        masked*) ;;
        *) systemctl enable wyvpnd.service >/dev/null 2>&1 || echo "wyvpnd.service could not be enabled" >&2 ;;
    esac
    if [ -d /run/systemd/system ]; then
        case "$was_enabled" in
            masked*) ;;
            enabled) systemctl try-restart wyvpnd.service || true ;;
            *) systemctl start wyvpnd.service || echo "wyvpnd.service could not be started; see: journalctl -u wyvpnd" >&2 ;;
        esac
    fi
fi

[ -n "$fresh" ] || exit 0

user=
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    user=$SUDO_USER
elif [ -n "${PKEXEC_UID:-}" ] && [ "$PKEXEC_UID" != 0 ]; then
    user=$(getent passwd "$PKEXEC_UID" | cut -d: -f1)
fi

if [ -n "$user" ] && id "$user" >/dev/null 2>&1; then
    if id -nG "$user" | tr ' ' '\n' | grep -qx wyvpn; then
        :
    elif usermod -aG wyvpn "$user"; then
        echo "Added $user to the wyvpn group. Log out and back in before using WyVPN."
    else
        join_hint
    fi
else
    join_hint
fi

exit 0
