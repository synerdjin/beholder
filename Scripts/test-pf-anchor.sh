#!/bin/bash
#
# Checks the parts of blocking that only exist in the binary.
#
# Three properties, none of which a unit test can reach because they are all about the
# executable rather than about BeholderCore:
#
#   1. --print-pf-anchor and --print-pf-conf put nothing on stdout but the rules.
#      install-pf-anchor.sh redirects that output straight into /etc/pf.anchors, so a
#      stray print() anywhere in the startup path does not produce a confusing message —
#      it writes a corrupt ruleset into a system file. This is the same failure the MCP
#      server's stdout rule exists to prevent, with a worse blast radius.
#
#   2. Blocking is off unless asked for, and asking for it without root refuses rather
#      than half-working.
#
#   3. A block list that cannot be used is refused whole, with the line number.
#
# Needs no root and blocks nothing. Run directly, or via `make check`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=Scripts/lib/test-helpers.sh
source "${ROOT}/Scripts/lib/test-helpers.sh"
CONFIGURATION="${BEHOLDER_CONFIG:-debug}"
DAEMON="${ROOT}/.build/${CONFIGURATION}/beholderd"

if [[ ! -x "${DAEMON}" ]]; then
    echo "Building beholderd (${CONFIGURATION})..."
    swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}" --product beholderd
fi

if [[ $EUID -eq 0 ]]; then
    echo "SKIP: this test checks what happens *without* root; do not run it under sudo." >&2
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/beholder-pf-XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT


echo "1. The printed rules are the only thing on stdout"

ANCHOR="$("${DAEMON}" --print-pf-anchor 2> /dev/null)"
contains "the rule is present" "${ANCHOR}" "block return out log quick from any to <beholder_blocked>"
contains "the table is declared" "${ANCHOR}" "table <beholder_blocked> persist"

# Every line is either a comment or one of the two rules. Anything else on stdout would
# end up in /etc/pf.anchors/com.beholder.
STRAY="$(grep -v '^#' <<< "${ANCHOR}" | grep -v '^$' | grep -vc 'beholder_blocked' || true)"
check "no line that is not a comment or a rule" "${STRAY}" "0"

CONF="$("${DAEMON}" --print-pf-conf 2> /dev/null)"
contains "the anchor is named" "${CONF}" 'anchor "com.beholder"'
contains "the anchor is loaded" "${CONF}" 'load anchor "com.beholder"'
# Pinned in full, not by prefix. The installer greps for the whole first line to decide
# whether it has already run, and uninstall-pf-anchor.sh matches both markers exactly to find
# the block it must remove. Reword either in Swift without updating uninstall-pf-anchor.sh and
# a re-install silently appends a second anchor block that nothing can then take out.
check "the block opens with the exact marker the scripts grep for" \
    "$(head -1 <<< "${CONF}")" \
    "# BEGIN Beholder - added by Scripts/install-pf-anchor.sh"
check "the block closes with the exact marker" "$(tail -1 <<< "${CONF}")" "# END Beholder"

echo
echo "1b. The block can be found again and removed"

# The uninstaller's whole job is to find the block it installed and take it out. It matches on
# the markers, so this exercises the round trip: build a pf.conf with the block in it, run the
# same awk the uninstaller runs against the same derived markers, and check that exactly the
# block disappears. Without this the failure mode is silent — `uninstall-pf-anchor.sh` reports
# success while leaving the anchor named in /etc/pf.conf, so blocking stays armed across
# reboots after the user has been told it was removed.
BEGIN_MARKER="$(head -1 <<< "${CONF}")"
END_MARKER="$(tail -1 <<< "${CONF}")"

{
    echo "scrub-anchor \"com.apple/*\""
    echo "${CONF}"
    echo "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\""
} > "${WORK}/pf.conf"

STRIPPED="$(awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
    $0 == begin { skipping = 1; next }
    $0 == end   { skipping = 0; next }
    !skipping   { print }
' "${WORK}/pf.conf")"

check "the block is gone" "$(grep -c "com.beholder" <<< "${STRIPPED}" || true)" "0"
check "and nothing else went with it" \
    "$(grep -c "com.apple" <<< "${STRIPPED}" || true)" "2"

echo
echo "2. Blocking is off unless asked for, and refuses rather than half-working"

SELFTEST="$("${DAEMON}" --self-test --no-log 2>&1)"
check "a plain run says nothing about blocking" \
    "$(grep -ci 'block' <<< "${SELFTEST}" || true)" "0"

set +e
BLOCK_OUTPUT="$("${DAEMON}" --self-test --no-log --block 2>&1)"
BLOCK_STATUS=$?
set -e
check "--block without root exits non-zero" "$([[ ${BLOCK_STATUS} -ne 0 ]] && echo yes)" "yes"
contains "--block without root says why" "${BLOCK_OUTPUT}" "--block needs root"

echo
echo "3. A block list is refused whole, not enforced in part"

cat > "${WORK}/good.conf" << 'LIST'
# a comment
93.184.216.34     # example.com
10.0.0.0/8        # the lab
LIST

set +e
GOOD="$("${DAEMON}" --check-blocklist --blocklist "${WORK}/good.conf" 2> /dev/null)"
GOOD_STATUS=$?
set -e
check "a usable list exits 0" "${GOOD_STATUS}" "0"
contains "it says what it would block" "${GOOD}" "Would block 2 destination(s)"
contains "the note survives" "${GOOD}" "example.com"

cat > "${WORK}/bad.conf" << 'LIST'
93.184.216.34
doubleclick.net
10.0.0.0/99
LIST

set +e
BAD="$("${DAEMON}" --check-blocklist --blocklist "${WORK}/bad.conf" 2> /dev/null)"
BAD_STATUS=$?
set -e
check "an unusable list exits non-zero" "$([[ ${BAD_STATUS} -ne 0 ]] && echo yes)" "yes"
contains "the line number is given" "${BAD}" "line 2"
contains "host names get their own explanation" "${BAD}" "host names cannot be blocked"
contains "and so does a bad prefix" "${BAD}" "line 3"

# The file decides what a root process adds to the firewall, so a list this account can
# write is one the daemon will refuse. The check says so rather than passing it silently.
GOOD_REPORT="$("${DAEMON}" --check-blocklist --blocklist "${WORK}/good.conf" 2> /dev/null)"
contains "a list the user owns is flagged" "${GOOD_REPORT}" "will refuse it until that is fixed"

# pf enforces the union of the hand-edited list and the one the app writes, so a preview
# that named only the first would under-report for anyone who has used the Blocking tab.
contains "both lists are named" "${GOOD_REPORT}" "blocklist.app.conf"
contains "and each entry says which list holds it" "${GOOD_REPORT}" "[list]"

report_results
