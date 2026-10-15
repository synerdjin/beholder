#!/bin/bash
#
# Diagnoses why the app cannot see the daemon.
#
# The ordering here is deliberate, and was learned the hard way. An installed daemon that
# crash-loops looks almost identical to one macOS has refused to start: no process, a
# socket that is missing or stale, and — because a killed process never flushes a
# block-buffered stdout — two empty log files. Reading "no process plus empty logs" as
# approval-pending sent a real crash loop to System Settings and left it running 4,000
# times. So evidence that the job HAS run is checked before any conclusion that it has not.
#
#   launchctl print's `last terminating signal` is the field that settles it, and it costs
#   nothing to read. If it is set, the job ran and died, full stop.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# One home for the judgement. What follows used to be a second copy of it in shell, which
# is how a shell diagnosis and the MCP server's come to disagree about the same machine.
# `beholderd --diagnose` decides the verdict (see DaemonDiagnosis); this script keeps only
# what needs root or opens a window, which Core must not do.
DAEMON_BIN="${ROOT}/.build/debug/beholderd"
[[ -x "${DAEMON_BIN}" ]] || DAEMON_BIN="${ROOT}/.build/release/beholderd"
[[ -x "${DAEMON_BIN}" ]] || DAEMON_BIN="/usr/local/libexec/beholderd"

if [[ ! -x "${DAEMON_BIN}" ]]; then
    echo "No beholderd is built or installed, so there is nothing to diagnose with."
    echo "  make build"
    exit 1
fi

REPORT="$("${DAEMON_BIN}" --diagnose --diagnose-source "${ROOT}" 2> /dev/null)"
STATUS=$?
echo "${REPORT}"
echo

# Asked of the daemon rather than answered here. "Does this build satisfy the pin" is a
# code-requirement question, and deciding it by string-comparing `codesign` output to the
# pin file is a different test that can disagree - for a Developer ID pin, the case
# install-control-pin.sh explicitly plans for. A diagnostic that can be wrong about the
# failure it exists to catch is worse than none.
if [[ -f /etc/pf.anchors/com.beholder ]]; then
    echo "Blocking:"
    "${DAEMON_BIN}" --check-control-pin "${ROOT}/.build/Beholder.app" 2> /dev/null | sed 's/^/  /'

    # Reading the live pf table needs root, which is why it is here and not in Core.
    if [[ $EUID -eq 0 ]]; then
        RULES="$(/sbin/pfctl -a com.beholder -s rules 2> /dev/null)"
        if grep -q beholder_blocked <<< "${RULES}"; then
            COUNT="$(/sbin/pfctl -a com.beholder -t beholder_blocked -T show 2> /dev/null | grep -c . || true)"
            echo "  anchor loaded, ${COUNT} destination(s) currently blocked"
        else
            echo "  anchor is not loaded into the running ruleset"
        fi
    else
        echo "  (run under sudo to see what is currently blocked)"
    fi
    echo
fi

# Opening a window is not something a library should do, so the one verdict that wants
# System Settings is acted on here — keyed off the report's machine-readable last line,
# never its prose, which is free to be reworded.
if grep -qx "verdict: awaitingApproval" <<< "${REPORT}"; then
    echo "Opening Login Items now..."
    open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2> /dev/null || true
fi

exit "${STATUS}"
