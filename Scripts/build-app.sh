#!/bin/bash
#
# Assembles Beholder.app from the SwiftPM-built binary.
#
# There is no Xcode project because none is needed: a macOS app bundle is a directory
# with an Info.plist and a binary in it. SwiftPM produces the binary; this arranges it.
# When a Developer ID exists, add a codesign step at the end — nothing else changes.

set -euo pipefail

CONFIGURATION="${1:-debug}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/.build/$CONFIGURATION"
APP="$ROOT/.build/Beholder.app"

# Braces on every expansion, and plain ASCII in the messages. An unbraced "$APP…" makes
# bash read the leading byte of the multibyte ellipsis as part of the variable name,
# which under `set -u` aborts the script with a confusing "APP?: unbound variable".
echo "Building BeholderApp (${CONFIGURATION})..."
swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}" --product BeholderApp

echo "Assembling ${APP}..."
rm -rf "${APP}"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"
cp "${BUILD_DIR}/BeholderApp" "${APP}/Contents/MacOS/Beholder"

cat > "${APP}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Beholder</string>
    <key>CFBundleDisplayName</key>
    <string>Beholder</string>
    <key>CFBundleIdentifier</key>
    <string>com.beholder.app</string>
    <key>CFBundleExecutable</key>
    <string>Beholder</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <!-- Beholder only reads a local socket; it has no business appearing as a network
         client itself, and no server component. -->
    <key>NSSupportsAutomaticTermination</key>
    <false/>
</dict>
PLIST
echo "</plist>" >> "${APP}/Contents/Info.plist"

plutil -lint "${APP}/Contents/Info.plist" > /dev/null

# Ad-hoc signature. Enough for local execution since the app claims no entitlements;
# replace with a Developer ID when one exists.
codesign --force --sign - "${APP}" 2>/dev/null || echo "note: ad-hoc signing skipped"

echo
echo "Built ${APP}"
echo
echo "Run the daemon first (it needs root), then open the app:"
echo "  sudo ${ROOT}/.build/${CONFIGURATION}/beholderd --serve --loopback"
echo "  open ${APP}"
