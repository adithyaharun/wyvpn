#!/bin/sh
set -e

dropin_dir=/etc/systemd/system/wyvpnd.service.d

case "$1" in
    purge)
        rm -rf /var/lib/wyvpn
        ;;
    remove)
        echo "Profiles and secrets were kept in /var/lib/wyvpn; purge the package to delete them."
        ;;
    0)
        echo "Profiles and secrets were kept in /var/lib/wyvpn; delete them with: sudo rm -rf /var/lib/wyvpn"
        ;;
    *)
        exit 0
        ;;
esac

rm -f "$dropin_dir/50-resolv-conf.conf" /run/wyvpn.sock
rmdir "$dropin_dir" 2>/dev/null || true

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

exit 0
