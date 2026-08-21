#!/bin/bash
#
# Rebuilds Beholder and restarts whatever was already running, so that what is running is
# what the source now says. This is the command to run after editing code.
#
# The trap it exists to remove: `make restart` kickstarts the launchd job, and the launchd
# job runs /usr/local/libexec/beholderd — a COPY taken at install time, not a link into
# .build. So after an edit, `make restart` faithfully restarts the old binary, and the bug
# you just fixed is still there. doctor.sh has a whole check for this state ("the installed
# binary is older than the source in this checkout") because it is easy to spend an hour
# inside it. Restarting is not the same operation as updating, and this does both.
#
# It changes nothing about what is installed. It will not install a daemon, download a
# database, or register anything — if a piece is not running, it stays not running and is
# named in the summary. Use `make wizard` to add or remove pieces.
#
# What it restarts, and why each is different:
#
#   the app         quit and reopened, because build-app.sh replaces the bundle wholesale
#   launchd daemon  binary reinstalled, then kickstarted (see above)
#   foreground run  reported, not touched: it belongs to another terminal, whose Ctrl-C
#                   trap also quits the app. Killing it from here would race that.
#   MCP server      binary reinstalled; nothing to restart, since your assistant spawns
#                   a fresh one per question
#
# Usage:  Scripts/reload.sh [--open]
#
#   --open              open the app even if it was not running. Without it, an app you
#                       had deliberately closed stays closed.
#   BEHOLDER_CONFIG     debug or release. Defaults to whatever matches what is installed.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="com.beholder.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
INSTALLED_DAEMON="/usr/local/libexec/beholderd"
INSTALLED_MCP="/usr/local/libexec/beholder-mcp"
SOCKET="/var/run/beholder.sock"
APP="${ROOT}/.build/Beholder.app"

# Left empty so it can be decided from what is actually installed, below. BEHOLDER_CONFIG
# rather than a flag, because that is the name install-daemon.sh has always taken this
# setting under, and a third spelling of one setting is a third thing to keep straight.
CONFIGURATION="${BEHOLDER_CONFIG:-}"
FORCE_OPEN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --open) FORCE_OPEN=1; shift ;;
        # The header comment above IS the documentation, so --help prints it rather than
        # a second, shorter description that would drift from it.
        -h|--help) awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -n "${CONFIGURATION}" && "${CONFIGURATION}" != "debug" && "${CONFIGURATION}" != "release" ]]; then
    echo "BEHOLDER_CONFIG takes 'debug' or 'release', not '${CONFIGURATION}'." >&2
    exit 2
fi

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this as yourself, not with sudo: building as root leaves .build owned by" >&2
    echo "root. It asks for your password only if there is an installed daemon to swap." >&2
    exit 1
fi

BOLD=""; DIM=""; RESET=""
if [[ -t 1 ]]; then BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'; fi

STARTED="$(date '+%Y-%m-%d %H:%M:%S %Z')"

# The app is quit below, before the daemon swap, so build-app.sh can safely replace its
# bundle. If anything after that point fails — a declined sudo password, kickstart itself
# failing — `set -e` ends the script there, and without this trap the app stays closed
# with no explanation: reload would have taken something away and said nothing about it.
# APP_REOPENED is set right before the deliberate `open` near the end, so this is a no-op
# on the success path and only fires on an early exit.
APP_REOPENED=0
reopen_app_on_failure() {
    local status=$?
    if [[ "${status}" -ne 0 && "${APP_WAS_UP:-0}" -eq 1 && "${APP_REOPENED}" -eq 0 && -d "${APP}" ]]; then
        echo >&2
        echo "Reload failed partway through — reopening the app it quit at the start." >&2
        open "${APP}" 2> /dev/null || true
    fi
}
trap reopen_app_on_failure EXIT

# The pid launchd currently has for the job, empty when it is not running. Anchored to a
# single tab for the same reason doctor.sh is: launchctl repeats keys like this inside the
# nested resource-coalition block, and looser indentation matching picks those up too.
job_pid() {
    launchctl print "system/${LABEL}" 2> /dev/null \
        | sed -n 's/^	pid = \([0-9]*\)$/\1/p' | head -1
}

# ------------------------------------------------------------------- what was running
#
# Sampled once, up front. Everything below restores this state rather than deciding for
# you: a reload that opened the app you had deliberately closed would be a surprise.

DAEMON_JOB=0;  launchctl print "system/${LABEL}" > /dev/null 2>&1 && DAEMON_JOB=1
APP_WAS_UP=0;  pgrep -x Beholder > /dev/null 2>&1 && APP_WAS_UP=1
MCP_INSTALLED=0; [[ -x "${INSTALLED_MCP}" ]] && MCP_INSTALLED=1

# A foreground `./beholder` run, which is a different daemon from the installed one.
# -d makes pgrep join several pids for printing; the empty-string test still works.
FOREGROUND_PIDS="$(pgrep -d ', ' -f "\.build/[a-z]*/beholderd --serve" 2> /dev/null || true)"

# The configuration follows what is installed rather than being fixed, because the two
# workflows genuinely differ: an installed daemon is a release build (install-daemon.sh
# says so), and pushing a debug binary into /usr/local/libexec would quietly swap the
# thing capturing your network for a slower one. With nothing installed this is a
# checkout being iterated on, where ./beholder uses debug and a release rebuild would
# cost minutes per edit for nothing. BEHOLDER_CONFIG overrides either way.
if [[ -z "${CONFIGURATION}" ]]; then
    if [[ "${DAEMON_JOB}" -eq 1 ]]; then CONFIGURATION=release; else CONFIGURATION=debug; fi
fi

echo "${BOLD}Beholder — reload (${CONFIGURATION})${RESET}"
echo "${STARTED}"
echo
echo "Running now:"
printf '  %-18s %s\n' "app" "$([[ "${APP_WAS_UP}" -eq 1 ]] && echo "up" || echo "not running")"
printf '  %-18s %s\n' "launchd daemon" "$([[ "${DAEMON_JOB}" -eq 1 ]] && echo "installed" || echo "not installed")"
printf '  %-18s %s\n' "foreground daemon" "$([[ -n "${FOREGROUND_PIDS}" ]] && echo "pid ${FOREGROUND_PIDS}" || echo "none")"
printf '  %-18s %s\n' "MCP server" "$([[ "${MCP_INSTALLED}" -eq 1 ]] && echo "installed" || echo "not installed")"

# ---------------------------------------------------------------------------- compile
#
# Before anything is stopped. A build that fails here leaves the running system exactly as
# it was, which is what you want at the moment you have just written code that does not
# compile.

echo
echo "${BOLD}Building...${RESET}"
if [[ "${CONFIGURATION}" == "release" ]]; then
    # Said out loud because the wait is otherwise inexplicable: someone who edited one
    # SwiftUI view and expected a two-second debug build has no way to know that having a
    # daemon installed is what made this an optimised build of the whole package.
    echo "${DIM}  Release, because an installed daemon must not be handed a debug binary."
    echo "  The first one after 'make clean' is a cold build and takes minutes.${RESET}"
fi
swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}"

# -------------------------------------------------------------------------------- app
#
# Quit before reassembling: build-app.sh does `rm -rf` on the bundle, and pulling a
# running app's bundle out from under it is a good way to produce a crash that has nothing
# to do with the change being tested.

if [[ "${APP_WAS_UP}" -eq 1 ]]; then
    echo "Quitting the app..."
    osascript -e 'quit app "Beholder"' > /dev/null 2>&1 || true
    for _ in $(seq 1 50); do
        pgrep -x Beholder > /dev/null 2>&1 || break
        sleep 0.1
    done
    # It did not go on its own — an app stuck in a modal or a hang. pkill rather than
    # kill, because pgrep can return several pids and `kill "$(pgrep …)"` would pass them
    # as one newline-joined argument.
    pkill -x Beholder 2> /dev/null || true
fi

# SKIP_BUILD because the `swift build` above already covered every product; without it
# this repeats the whole thing as a no-op, and does so while the app is closed.
BEHOLDER_SKIP_BUILD=1 "${ROOT}/Scripts/build-app.sh" "${CONFIGURATION}" > /dev/null
echo "Assembled ${APP}"

# Re-pin the app's code identity, because rebuilding changed it.
#
# The control socket admits the app on its cdhash, and a rebuilt binary has a different one
# by design - an identity that survived the code changing would not be one. Without this, the
# first thing a developer would see after every edit is the app unable to change blocking,
# with a refusal naming a hash they have no reason to connect to the rebuild they just did.
#
# Only when a pin already exists. This installs nothing new, exactly like the rest of reload.
CONTROL_PIN="/usr/local/etc/beholder/control-peer.requirement"
if [[ -f "${CONTROL_PIN}" ]]; then
    if sudo "${ROOT}/Scripts/install-control-pin.sh" "${APP}" > /dev/null 2>&1; then
        echo "Re-pinned the app's control identity"
    else
        echo "WARNING: could not re-pin the app; it will not be able to change blocking." >&2
        echo "         Fix with: sudo ./Scripts/install-control-pin.sh" >&2
    fi
fi

# ----------------------------------------------------------------------------- daemon

DAEMON_RESULT="left alone (none installed)"
if [[ "${DAEMON_JOB}" -eq 1 ]]; then
    echo
    echo "${BOLD}Swapping the installed daemon...${RESET}"
    echo "${DIM}  Needs your password: /usr/local/libexec is root-owned.${RESET}"
    # Why not just call install-daemon.sh, which already knows how to replace a running
    # job? Because it does it by bootout/bootstrap, and this daemon is unsigned: macOS
    # registers it and can decline to start it until it is approved under Login Items,
    # with no prompt. A re-bootstrap can land you back in that state — the one doctor.sh
    # exists to tell apart from a crash loop — for what is meant to be a routine step
    # after an edit. `kickstart -k` keeps the job registered and approved.
    #
    # The cost of staying light is that the plist is not rewritten, which is why the
    # staleness check below exists.
    #
    # install(1) unlinks the target before creating it, so replacing the binary of a
    # process that is currently executing it is safe — no ETXTBSY, and the running
    # process keeps the inode it started with until kickstart replaces it.
    sudo install -m 755 "${ROOT}/.build/${CONFIGURATION}/beholderd" "${INSTALLED_DAEMON}"
    # -k kills the job first. Without it, kickstart on a running job is a no-op and the
    # old process — still executing the previous inode — carries on with the old code.
    OLD_PID="$(job_pid)"
    sudo launchctl kickstart -k "system/${LABEL}"

    # Wait for the pid to CHANGE before looking at the socket, not just for a socket to
    # answer. kickstart returns as soon as launchd accepts the request, and the old daemon
    # is still listening for a moment after that — so a socket probe on its own can
    # connect to the process being replaced and report the new build as running when it
    # has not started yet. That is the one failure this whole script exists to prevent.
    NEW_PID=""
    for _ in $(seq 1 100); do
        NEW_PID="$(job_pid)"
        [[ -n "${NEW_PID}" && "${NEW_PID}" != "${OLD_PID}" ]] && break
        sleep 0.1
    done

    if [[ -z "${OLD_PID}" && -z "${NEW_PID}" ]]; then
        # An empty pid before AND after kickstart means the job has never actually run —
        # not that it is still running old code. This is the state doctor.sh distinguishes
        # from a crash loop: macOS registers an unsigned daemon and can decline to start it
        # until approved under Login Items, with no prompt. Saying "still running the old
        # binary" here would point at the wrong fix entirely.
        DAEMON_RESULT="never started — check Login Items, or run 'make doctor'"
        echo "  The job has no pid before or after kickstart: it has never run, not" >&2
        echo "  restarted with old code. 'make doctor' tells this apart from a crash loop." >&2
    elif [[ -z "${NEW_PID}" || "${NEW_PID}" == "${OLD_PID}" ]]; then
        # Reported as the failure it is rather than falling through to the socket check,
        # which the un-replaced daemon would pass — and passing it would say the new code
        # is running when the old process never even stopped.
        DAEMON_RESULT="NOT replaced: still pid ${OLD_PID} after 10s — run 'make doctor'"
        echo "  The job did not restart. It is still pid ${OLD_PID}, running the" >&2
        echo "  binary it started with." >&2
    else
        # Then wait for the socket, rather than declaring success on the new pid: a daemon
        # that dies during startup gets a fresh pid and no socket at all, and KeepAlive
        # gives it another pid a moment later, so a pid alone proves nothing.
        # One python3 with the deadline inside it, not one per attempt: a fresh
        # interpreter costs about 25 ms to start, so polling from the shell spent longer
        # spawning than waiting and made a "10s" timeout take thirteen.
        #
        # PermissionError exits 2 rather than being retried like any other OSError: the
        # socket is created mode 0600, owned by whoever's account started capture. A
        # second account on the same Mac reloading a daemon they do not own would
        # otherwise see every attempt fail the same way as a daemon that is not
        # publishing at all, and "make doctor" as advice for that is a dead end — doctor
        # would report the same EACCES.
        PROBE_STATUS=0
        python3 -c "
import socket, sys, time
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    try:
        s.connect('${SOCKET}')
    except PermissionError:
        sys.exit(2)
    except OSError:
        time.sleep(0.05)
        continue
    sys.exit(0)
sys.exit(1)
" > /dev/null 2>&1 || PROBE_STATUS=$?
        if [[ "${PROBE_STATUS}" -eq 0 ]]; then
            DAEMON_RESULT="restarted as pid ${NEW_PID}, publishing on ${SOCKET}"
            echo "  Restarted as pid ${NEW_PID}, publishing again on ${SOCKET}"
        elif [[ "${PROBE_STATUS}" -eq 2 ]]; then
            SOCKET_OWNER="$(stat -f '%Su' "${SOCKET}" 2> /dev/null || echo "unknown")"
            DAEMON_RESULT="restarted as pid ${NEW_PID}; socket owned by ${SOCKET_OWNER}, not you"
            echo "  ${SOCKET} exists and answered EACCES: it is owned by ${SOCKET_OWNER}," >&2
            echo "  not you. That is a permission mismatch, not evidence the daemon" >&2
            echo "  failed to start." >&2
        else
            DAEMON_RESULT="restarted as pid ${NEW_PID} but NOT publishing — run 'make doctor'"
            echo "  ${SOCKET} did not come back within 10s." >&2
        fi
    fi
elif [[ -f "${PLIST}" ]]; then
    DAEMON_RESULT="plist present but the job is not loaded — run 'make install'"
fi

if [[ -n "${FOREGROUND_PIDS}" ]]; then
    DAEMON_RESULT="${DAEMON_RESULT}; a foreground run is still on the old build"
fi

# The binary is swapped above; the plist is not. So a change to install-daemon.sh — a new
# flag in ProgramArguments, a different history-db path — gets the new binary invoked with
# the old arguments, and this script would report a clean restart over it. That is the
# same failure it was written to remove, one layer up, so it is checked for by the same
# means doctor.sh uses for the stale-binary case: compare mtimes and say so.
PLIST_STALE=""
if [[ -f "${PLIST}" ]]; then
    PLIST_STALE="$(find "${ROOT}/Scripts/install-daemon.sh" -newer "${PLIST}" -print -quit 2> /dev/null || true)"
fi

# -------------------------------------------------------------------------------- MCP

MCP_RESULT="left alone (not installed)"
if [[ "${MCP_INSTALLED}" -eq 1 ]]; then
    # Through install-mcp.sh so the destination and mode have one definition, quietly
    # because this is the tenth rebuild of the day, not a first install needing the
    # registration guidance. No restart: your assistant starts one per question, so the
    # next question gets the new binary; a session mid-flight holds its old process.
    sudo env "BEHOLDER_CONFIG=${CONFIGURATION}" BEHOLDER_SKIP_BUILD=1 \
        "${ROOT}/Scripts/install-mcp.sh" --quiet
    MCP_RESULT="binary replaced; the next question starts the new one"
fi

# --------------------------------------------------------------------- back to the app

APP_RESULT="left closed"
if [[ "${FORCE_OPEN}" -eq 1 || "${APP_WAS_UP}" -eq 1 ]]; then
    open "${APP}"
    APP_REOPENED=1
    APP_RESULT="reopened"
fi

# ---------------------------------------------------------------------------- summary

echo
echo "${BOLD}Reloaded${RESET}  ${STARTED} -> $(date '+%Y-%m-%d %H:%M:%S %Z')"
printf '  %-18s %s\n' "app" "${APP_RESULT}"
printf '  %-18s %s\n' "daemon" "${DAEMON_RESULT}"
printf '  %-18s %s\n' "MCP server" "${MCP_RESULT}"

if [[ -n "${PLIST_STALE}" ]]; then
    echo
    echo "install-daemon.sh has changed since ${PLIST} was written."
    echo "Only the binary was swapped, so the new one is being started with the arguments"
    echo "the old plist names. If that edit was to the plist:  make install"
fi

if [[ -n "${FOREGROUND_PIDS}" ]]; then
    echo
    echo "A foreground daemon (pid ${FOREGROUND_PIDS}) is still running the build it"
    echo "started with. It belongs to another terminal — press Ctrl-C there and run"
    echo "'make run' again. Stopping it from here would race that terminal's cleanup,"
    echo "which also quits the app."
fi

if [[ "${DAEMON_JOB}" -eq 0 && -z "${FOREGROUND_PIDS}" ]]; then
    echo
    echo "Nothing is capturing, so the app will have nothing to show:"
    echo "  make run       capture in the foreground, this terminal"
    echo "  make wizard    install it as a daemon, continuously and at boot"
fi
