#!/bin/bash
#
# Removes the pf anchor Beholder blocks with, and stops any blocking in progress.
#
# The reverse of install-pf-anchor.sh, and the thing to reach for when a block has gone
# wrong and the reason is not obvious. It leaves the block list alone: that is something
# you wrote, and an uninstaller deleting it would be the same mistake as an uninstaller
# deleting your captured history.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PF_CONF="/etc/pf.conf"
ANCHOR_FILE="/etc/pf.anchors/com.beholder"
BACKUP="/etc/pf.conf.beholder-backup"
BLOCKLIST="/usr/local/etc/beholder/blocklist.conf"
# The markers come from the binary when one is available, exactly as the installer takes
# them, so the two cannot disagree about which block to remove. The literals below are the
# fallback for uninstalling with no build present, and `make check` pins them against Swift's
# output — but a pin the *test* satisfies is not one this script satisfies, so deriving is
# what actually keeps them together.
BEGIN_MARKER="# BEGIN Beholder - added by Scripts/install-pf-anchor.sh"
END_MARKER="# END Beholder"

for candidate in "${ROOT}/.build/debug/beholderd" "${ROOT}/.build/release/beholderd" \
    /usr/local/libexec/beholderd; do
    [[ -x "${candidate}" ]] || continue
    BLOCK="$("${candidate}" --print-pf-conf 2> /dev/null)" || continue
    [[ -n "${BLOCK}" ]] || continue
    BEGIN_MARKER="$(head -1 <<< "${BLOCK}")"
    END_MARKER="$(tail -1 <<< "${BLOCK}")"
    break
done

if [[ $EUID -ne 0 ]]; then
    echo "This needs root: it edits ${PF_CONF}." >&2
    echo "Run: sudo $0" >&2
    exit 1
fi

echo "Removing Beholder's pf anchor"
echo

# Empty the table first, so anything blocked right now stops being blocked even if a
# later step fails.
if /sbin/pfctl -a com.beholder -t beholder_blocked -T flush > /dev/null 2>&1; then
    echo "  emptied the block table"
fi
/sbin/pfctl -a com.beholder -F rules > /dev/null 2>&1 || true

if grep -qF "${BEGIN_MARKER}" "${PF_CONF}" 2> /dev/null; then
    # Between the markers, and nothing else. A sed matching the anchor line itself would
    # happily take Apple's with it.
    awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
        $0 == begin { skipping = 1; next }
        $0 == end   { skipping = 0; next }
        !skipping   { print }
    ' "${PF_CONF}" > "${PF_CONF}.new"

    CHECK_OUTPUT="$(mktemp)"
    if ! /sbin/pfctl -n -f "${PF_CONF}.new" > "${CHECK_OUTPUT}" 2>&1; then
        echo "  the edited ${PF_CONF} does not parse; leaving the original alone:" >&2
        sed 's/^/    /' < "${CHECK_OUTPUT}" >&2
        rm -f "${PF_CONF}.new" "${CHECK_OUTPUT}"
        exit 1
    fi
    rm -f "${CHECK_OUTPUT}"
    chown root:wheel "${PF_CONF}.new"
    chmod 644 "${PF_CONF}.new"
    mv "${PF_CONF}.new" "${PF_CONF}"
    echo "  removed the anchor from ${PF_CONF}"
    /sbin/pfctl -f "${PF_CONF}" 2>&1 | sed 's/^/  /' || true
else
    echo "  ${PF_CONF} does not name the anchor"
fi

if [[ -f "${ANCHOR_FILE}" ]]; then
    rm -f "${ANCHOR_FILE}"
    echo "  removed ${ANCHOR_FILE}"
fi

# pf itself is left exactly as it was found. Beholder took a reference with `pfctl -E` and
# gave it back with `-X` when it stopped; switching pf off here would switch it off for
# whatever else is holding a reference of its own.
echo
echo "Done. pf is left in whatever state other users of it have put it in."
if [[ -f "${BACKUP}" ]]; then
    echo "The pre-install copy of ${PF_CONF} is still at ${BACKUP}."
fi
if [[ -f "${BLOCKLIST}" ]]; then
    echo "Your block list is untouched at ${BLOCKLIST}."
fi
