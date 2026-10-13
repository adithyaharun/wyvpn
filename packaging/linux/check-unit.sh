#!/bin/sh
set -e

here=$(cd "$(dirname "$0")" && pwd)
image=${IMAGE:-debian:12}

for script in postinst.sh prerm.sh postrm.sh; do
    sh -n "$here/$script"
done
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -s sh "$here/postinst.sh" "$here/prerm.sh" "$here/postrm.sh" "$here/check-unit.sh"
else
    echo "shellcheck not installed; skipped" >&2
fi

if ! docker info >/dev/null 2>&1; then
    echo "docker is not running; skipped systemd-analyze and script smoke test" >&2
    exit 0
fi

docker run --rm -v "$here:/src:ro" "$image" sh -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq systemd dash passwd >/dev/null
    for script in postinst prerm postrm; do dash -n /src/$script.sh; done

    install -m 0755 /dev/null /usr/bin/wyvpnd
    install -m 0644 /src/wyvpnd.service /usr/lib/systemd/system/wyvpnd.service
    install -D -m 0644 /src/wyvpn.sysusers /usr/lib/sysusers.d/wyvpn.conf
    systemd-analyze verify /usr/lib/systemd/system/wyvpnd.service
    systemd-analyze security --offline=true /usr/lib/systemd/system/wyvpnd.service

    state() { systemctl is-enabled wyvpnd.service 2>/dev/null || true; }
    expect() { [ "$(state)" = "$1" ] || { echo "expected $1, got $(state): $2" >&2; exit 1; }; }

    useradd -m tester
    SUDO_USER=tester dash /src/postinst.sh configure ""
    getent group wyvpn
    id -nG tester | grep -qw wyvpn
    test -f /etc/systemd/system/wyvpnd.service.d/50-resolv-conf.conf
    expect enabled "deb install"
    dash /src/postinst.sh configure 0.1.0
    expect enabled "deb upgrade"
    dash /src/prerm.sh upgrade 0.1.1
    expect enabled "deb prerm upgrade"
    dash /src/prerm.sh remove
    expect disabled "deb remove"
    mkdir -p /var/lib/wyvpn
    dash /src/postrm.sh remove
    test -d /var/lib/wyvpn
    test ! -e /etc/systemd/system/wyvpnd.service.d
    dash /src/postinst.sh configure 0.1.0
    expect enabled "deb reinstall after remove"
    test -f /etc/systemd/system/wyvpnd.service.d/50-resolv-conf.conf
    systemctl disable wyvpnd.service
    systemctl mask wyvpnd.service
    dash /src/postinst.sh configure 0.1.0
    expect masked "deb upgrade while masked"
    systemctl unmask wyvpnd.service
    dash /src/prerm.sh remove
    dash /src/postrm.sh remove
    dash /src/postrm.sh purge
    test ! -e /var/lib/wyvpn
    dash /src/postinst.sh 1
    expect enabled "rpm install"
    dash /src/postinst.sh 2
    expect enabled "rpm upgrade"
    dash /src/prerm.sh 1
    expect enabled "rpm preun upgrade"
    dash /src/prerm.sh 0
    expect disabled "rpm erase"
    mkdir -p /var/lib/wyvpn
    dash /src/postrm.sh 0
    test -d /var/lib/wyvpn
    dash /src/postinst.sh 1
    expect enabled "rpm reinstall"
    echo "smoke test passed"
'
