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

LABEL="com.beholder.daemon"
SOCKET="/var/run/beholder.sock"
INSTALLED_BINARY="/usr/local/libexec/beholderd"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

JOB="$(launchctl print "system/${LABEL}" 2> /dev/null)"

echo "Daemon process:"
ps -Ao pid,lstart,command | grep -E "(libexec/)?beholderd --serve" | grep -v grep \
    || echo "  not running"
echo

echo "launchd job:"
if [[ -n "${JOB}" ]]; then
    # Anchored to a single tab: launchctl repeats keys like `state` inside the nested
    # resource-coalition block, and matching any indentation drags those in as duplicates.
    echo "${JOB}" | grep -E "^	(state|pid|runs|last exit code|last terminating signal) "
else
    echo "  not installed"
fi
echo

# Blocking, when it has been installed at all. Reported before the socket because the
# failure it looks for is silent: pf.conf is a system file, and a macOS update can restore
# the stock copy, which removes the line naming Beholder's anchor. Everything else keeps
# working - the daemon starts, the app connects, the block list still lists what it always
# did - and nothing is blocked. beholderd --block refuses to start in that state, but a
# daemon installed without --block gives no sign at all.
if [[ -f /etc/pf.anchors/com.beholder ]]; then
    echo "Blocking:"
    if grep -qF "anchor \"com.beholder\"" /etc/pf.conf 2> /dev/null; then
        echo "  /etc/pf.conf names the anchor"
    else
        echo "  ANCHOR FILE PRESENT BUT /etc/pf.conf DOES NOT NAME IT."
        echo "  Nothing is being blocked, whatever the block list says."
        echo "  A macOS update restoring the stock /etc/pf.conf does exactly this."
        echo "  Fix: sudo ./Scripts/install-pf-anchor.sh"
    fi
    # Asked of the daemon rather than answered here. "Does this build satisfy the pin" is a
    # code-requirement question, and deciding it by string-comparing `codesign` output to the
    # pin file is a different test that can disagree — for a Developer ID pin, the case
    # install-control-pin.sh explicitly plans for. A diagnostic that can be wrong about the
    # failure it exists to catch is worse than none.
    DAEMON_BIN="${ROOT}/.build/debug/beholderd"
    [[ -x "${DAEMON_BIN}" ]] || DAEMON_BIN="${ROOT}/.build/release/beholderd"
    [[ -x "${DAEMON_BIN}" ]] || DAEMON_BIN="/usr/local/libexec/beholderd"

    if [[ -x "${DAEMON_BIN}" ]]; then
        "${DAEMON_BIN}" --check-control-pin "${ROOT}/.build/Beholder.app" 2> /dev/null | sed 's/^/  /'
    else
        echo "  no beholderd built; cannot check the pinned identity"
    fi

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

echo "Publishing socket:"
if [[ -S "${SOCKET}" ]]; then
    ls -la "${SOCKET}"
    if python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect('${SOCKET}')" 2> /dev/null; then
        echo "  accepting connections - healthy"
    else
        echo "  PRESENT BUT REFUSING CONNECTIONS - left behind by a daemon that is gone"
    fi
else
    echo "  no socket at ${SOCKET}"
fi
echo

echo "Recent daemon output:"
if [[ -s /var/log/beholderd.log ]]; then
    tail -5 /var/log/beholderd.log
fi
if [[ -s /var/log/beholderd.err ]]; then
    tail -5 /var/log/beholderd.err
fi
if [[ ! -s /var/log/beholderd.log && ! -s /var/log/beholderd.err ]]; then
    echo "  (both logs are empty)"
fi
echo

# ------------------------------------------------------------------------ conclusions

if [[ -z "${JOB}" ]]; then
    echo "No daemon is installed, so only a foreground 'make run' will feed the app."
    echo "To capture continuously and across reboots:  make install"
    exit 0
fi

SIGNAL_LINE="$(echo "${JOB}" | grep "last terminating signal" | sed 's/^[[:space:]]*//')"
RUNS="$(echo "${JOB}" | sed -n 's/^[[:space:]]*runs = \([0-9]*\)$/\1/p')"
RUNNING=0
pgrep -f "libexec/beholderd" > /dev/null 2>&1 && RUNNING=1

# A binary older than the source it was built from explains a bug that is already fixed
# here but still crashing there — the installed copy is a snapshot, not a link.
if [[ -f "${INSTALLED_BINARY}" ]]; then
    NEWER="$(find "${ROOT}/Sources" -type f -newer "${INSTALLED_BINARY}" -print -quit 2> /dev/null)"
    if [[ -n "${NEWER}" ]]; then
        echo "The installed binary is older than the source in this checkout."
        echo "Whatever it is doing, it is not doing what the current code says:"
        echo
        echo "  make install"
        echo
    fi
fi

if [[ "${RUNNING}" -eq 1 ]]; then
    echo "The daemon is running. If the app still shows nothing, the socket above is"
    echo "the next thing to look at."
    exit 0
fi

if [[ -n "${SIGNAL_LINE}" ]]; then
    echo "The job is NOT waiting for approval - it has been running and dying."
    echo "launchd recorded: ${SIGNAL_LINE}"
    [[ -n "${RUNS}" ]] && echo "It has been restarted ${RUNS} times."
    echo
    echo "Empty logs do not contradict this: a process killed by a signal never flushes"
    echo "buffered output, so a daemon that dies during startup leaves nothing behind."
    echo
    echo "Install the current build, which is the only thing that changes what it does:"
    echo "  make install"
    exit 1
fi

if [[ "${RUNS}" == "0" || -z "${RUNS}" ]]; then
    echo "The job is loaded but has never run: no process, no recorded exit, no output."
    echo "macOS registers daemons from unidentified developers and refuses to start"
    echo "them until you approve them:"
    echo
    echo "  System Settings > General > Login Items & Extensions"
    echo "  find Beholder and turn it on."
    echo
    echo "Opening that pane now..."
    open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2> /dev/null || true
    exit 1
fi

echo "The job has run ${RUNS} times but is not running now, and recorded no signal."
echo "Check the logs above, then:  make restart"
exit 1
