#!/bin/bash
#
# Downloads the DB-IP City Lite geolocation database.
#
# DB-IP publishes this free, monthly, with no account or API key, under CC BY 4.0.
# MaxMind's GeoLite2 is the better-known equivalent but now requires signing up for a
# licence key, which is a poor fit for a tool someone should be able to build and run
# without registering anywhere.
#
# Attribution is a licence condition and is reproduced in the README and in the app.
#
# The database is around 100 MB and is deliberately NOT committed: it is large, it is
# separately licensed, and it goes stale monthly.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESTINATION="${1:-${ROOT}/Resources/geoip}"
TARGET="${DESTINATION}/geoip.mmdb"

mkdir -p "${DESTINATION}"

# DB-IP publishes on the first of the month. Early in a month the new file may not be up
# yet, so fall back to the previous one rather than failing.
try_month() {
    local stamp="$1"
    local url="https://download.db-ip.com/free/dbip-city-lite-${stamp}.mmdb.gz"
    echo "Trying ${url}"
    curl --fail --location --silent --show-error --output "${TARGET}.gz" "${url}"
}

THIS_MONTH="$(date +%Y-%m)"
LAST_MONTH="$(date -v-1m +%Y-%m 2>/dev/null || date -d '1 month ago' +%Y-%m)"

if ! try_month "${THIS_MONTH}"; then
    echo "Not published yet; falling back to ${LAST_MONTH}."
    try_month "${LAST_MONTH}"
fi

echo "Decompressing..."
gunzip --force "${TARGET}.gz"

SIZE="$(du -h "${TARGET}" | cut -f1)"
echo
echo "Installed ${TARGET} (${SIZE})"
echo
echo "This product includes GeoLite data created by DB-IP, available from"
echo "https://db-ip.com/ and licensed under CC BY 4.0."
