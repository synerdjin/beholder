#!/bin/bash
#
# Removes the Beholder daemon and everything install-daemon.sh put on the system.
#
# Your captured history is NOT deleted — it lives under your own Application Support
# directory and is yours. The last line prints where, so you can remove it yourself if
# you want to. Deleting a record of everywhere your machine has been is not a decision an
# uninstall script should make for you.

set -euo pipefail

LABEL="com.beholder.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
REAL_USER="${SUDO_USER:-root}"
DATA_DIR="/Users/${REAL_USER}/Library/Application Support/Beholder"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Removing a system daemon needs root:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

echo "Stopping the daemon..."
launchctl bootout "system/${LABEL}" 2>/dev/null || echo "  (was not running)"

for path in "${PLIST}" /usr/local/libexec/beholderd; do
    if [[ -e "${path}" ]]; then
        rm -f "${path}"
        echo "Removed ${path}"
    fi
done

if [[ -d /usr/local/share/beholder ]]; then
    rm -rf /usr/local/share/beholder
    echo "Removed /usr/local/share/beholder"
fi

rm -f /var/run/beholder.sock

echo
echo "Beholder is no longer running or starting at boot."
if [[ -d "${DATA_DIR}" ]]; then
    echo
    echo "Your captured history has been left alone, at:"
    echo "  ${DATA_DIR}"
    echo "Remove it yourself if you want it gone."
fi
