#!/bin/bash
#
# Installs Beholder as a launchd daemon so it captures continuously, including across
# reboots.
#
# This is the piece that makes history worth having. A database that only fills while you
# are watching answers the same questions the live view already does; one that filled
# while you were not is what answers "what did this app do on Tuesday".
#
# It is a real change to your system, which is why it is a separate opt-in script rather
# than something `make run` does quietly. Everything it touches is listed below and
# `uninstall-daemon.sh` removes all of it.
#
#   /usr/local/libexec/beholderd                     the binary
#   /Library/LaunchDaemons/com.beholder.daemon.plist the launchd job
#
# When a Developer ID is available, SMAppService replaces all of this and lets the app
# install and remove the daemon itself, with a proper entry in System Settings.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${BEHOLDER_CONFIG:-release}"
LABEL="com.beholder.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
INSTALLED_BINARY="/usr/local/libexec/beholderd"

if [[ "${EUID}" -ne 0 ]]; then
    echo "This installs a system daemon and needs root:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

# The user who ran sudo owns the data the daemon produces, exactly as in a foreground run.
REAL_USER="${SUDO_USER:-root}"
REAL_UID="$(id -u "${REAL_USER}")"
REAL_GID="$(id -g "${REAL_USER}")"
DATA_DIR="/Users/${REAL_USER}/Library/Application Support/Beholder"

echo "Building (${CONFIGURATION})..."
sudo -u "${REAL_USER}" swift build --package-path "${ROOT}" \
    --configuration "${CONFIGURATION}" --product beholderd

echo "Installing the binary..."
mkdir -p /usr/local/libexec
install -m 755 "${ROOT}/.build/${CONFIGURATION}/beholderd" "${INSTALLED_BINARY}"

# Optional databases live somewhere the daemon can read regardless of who started it.
mkdir -p /usr/local/share/beholder
for name in geoip.mmdb asn.mmdb; do
    if [[ -f "${ROOT}/Resources/geoip/${name}" ]]; then
        install -m 644 "${ROOT}/Resources/geoip/${name}" "/usr/local/share/beholder/${name}"
        echo "  installed ${name}"
    fi
done
if [[ -f "${ROOT}/Resources/trackers/trackers.json" ]]; then
    install -m 644 "${ROOT}/Resources/trackers/trackers.json" \
        /usr/local/share/beholder/trackers.json
    echo "  installed trackers.json"
fi

mkdir -p "${DATA_DIR}"
chown "${REAL_UID}:${REAL_GID}" "${DATA_DIR}"

echo "Writing ${PLIST}..."
cat > "${PLIST}" <<PLIST_END
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALLED_BINARY}</string>
        <string>--serve</string>
        <string>--loopback</string>
        <string>--no-log</string>
        <string>--history-db</string>
        <string>${DATA_DIR}/history.sqlite</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <!-- SUDO_USER is how the daemon knows whose data this is: it hands the socket, the
         history database and the name cache to that user rather than leaving them owned
         by root and unreadable to the person they are about. -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>SUDO_USER</key>
        <string>${REAL_USER}</string>
        <key>SUDO_UID</key>
        <string>${REAL_UID}</string>
        <key>SUDO_GID</key>
        <string>${REAL_GID}</string>
    </dict>
    <key>StandardErrorPath</key>
    <string>/var/log/beholderd.err</string>
    <!-- Capture is steady background work, not something to compete with the user. -->
    <key>ProcessType</key>
    <string>Background</string>
    <key>Nice</key>
    <integer>5</integer>
</dict>
</plist>
PLIST_END

chown root:wheel "${PLIST}"
chmod 644 "${PLIST}"

# Replace any previous instance rather than failing on a second install.
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "${PLIST}"
launchctl enable "system/${LABEL}"

sleep 1
if launchctl print "system/${LABEL}" > /dev/null 2>&1; then
    echo
    echo "Beholder is now capturing continuously and will start at boot."
    echo
    echo "  History:   ${DATA_DIR}/history.sqlite"
    echo "  Errors:    /var/log/beholderd.err"
    echo "  Stop it:   sudo ${ROOT}/Scripts/uninstall-daemon.sh"
    echo
    echo "Open the app any time to watch: make open-app"
else
    echo "The daemon did not start. Check /var/log/beholderd.err." >&2
    exit 1
fi
