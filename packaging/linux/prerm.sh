#!/bin/sh
set -e

case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now wyvpnd.service || true
        elif command -v systemctl >/dev/null 2>&1; then
            systemctl disable wyvpnd.service >/dev/null 2>&1 || true
        fi
        ;;
esac

exit 0
