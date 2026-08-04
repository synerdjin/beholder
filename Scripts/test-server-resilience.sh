#!/bin/bash
#
# Checks that the publishing socket cannot take the daemon down with it.
#
# This exists because it already happened. Writing to a socket whose reader has gone
# raises SIGPIPE, whose default disposition is to kill the process — so quitting the app
# could kill capture. The per-socket SO_NOSIGPIPE guard looked like it covered this, but
# setsockopt returns EINVAL when the peer closed before the connection was accepted,
# leaving the option unset on exactly the socket that needed it. The daemon died with
# status 141 seconds after a clean startup.
#
# A unit test cannot reach FlowServer: it lives in the beholderd executable target. So
# this drives the real binary the way a real reader does, which is the behaviour that
# actually matters.
#
# Run directly, or via `make check`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${BEHOLDER_CONFIG:-debug}"
DAEMON="${ROOT}/.build/${CONFIGURATION}/beholderd"
SOCKET="$(mktemp -u "${TMPDIR:-/tmp}/beholder-test-XXXXXX.sock")"

if ! command -v python3 > /dev/null 2>&1; then
    echo "SKIP: python3 is needed to drive the client side of this test." >&2
    exit 0
fi

if [[ ! -x "${DAEMON}" ]]; then
    echo "Building beholderd (${CONFIGURATION})..."
    swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}" --product beholderd
fi

cleanup() {
    [[ -n "${DAEMON_PID:-}" ]] && kill "${DAEMON_PID}" 2> /dev/null || true
    rm -f "${SOCKET}"
}
trap cleanup EXIT

# --self-test runs the publishing path with no interfaces, so this needs no root and no
# live traffic. It stops itself after three ticks and should exit 0.
"${DAEMON}" --serve --self-test --no-log --socket "${SOCKET}" > /dev/null 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do
    [[ -S "${SOCKET}" ]] && break
    if ! kill -0 "${DAEMON_PID}" 2> /dev/null; then
        echo "FAIL: the daemon exited before it published a socket." >&2
        exit 1
    fi
    sleep 0.1
done

if [[ ! -S "${SOCKET}" ]]; then
    echo "FAIL: the daemon never created ${SOCKET}." >&2
    exit 1
fi

# Three ways a reader can leave, all of which the daemon has to survive:
#   - closing the instant the connection is up, before the first snapshot is written
#   - closing after reading part of a snapshot, mid-write
#   - connecting and going away without reading anything at all
#
# Connections are paced: the listen backlog is 8, sized for the one or two readers this
# daemon really has, so an unpaced burst just fills it and is refused before it reaches
# the code under test. A refusal is not a failure here — it means the connection never
# landed — but it does not exercise anything, so they are counted and required to be few.
CONNECTION_REPORT="$(python3 - "${SOCKET}" <<'PY'
import socket, sys, time

path = sys.argv[1]
accepted = refused = 0

def connect():
    global accepted, refused
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(path)
    except ConnectionRefusedError:
        refused += 1
        client.close()
        return None
    accepted += 1
    return client

def close_immediately():
    client = connect()
    if client:
        client.close()

def close_mid_read():
    client = connect()
    if not client:
        return
    try:
        client.recv(16)
    except OSError:
        pass
    client.close()

for step in (close_immediately, close_mid_read):
    for _ in range(20):
        step()
        time.sleep(0.01)

lingering = [client for client in (connect() for _ in range(5)) if client]
time.sleep(0.3)
for client in lingering:
    client.close()

# Reported rather than judged here. A dead daemon refuses connections exactly as a full
# backlog does, so deciding on these counts alone would blame the backlog for a crash —
# the shell checks how the daemon actually exited first, which is the real answer.
print(f"{accepted} landed, {refused} refused")
PY
)"

# The daemon should now finish its self-test on its own and report success. Anything else
# means a departing reader took it with it.
STATUS=0
wait "${DAEMON_PID}" || STATUS=$?
DAEMON_PID=""

if [[ "${STATUS}" -ne 0 ]]; then
    if [[ "${STATUS}" -gt 128 ]]; then
        SIGNAL_NUMBER="$((STATUS - 128))"
        SIGNAL_NAME="$(kill -l "${SIGNAL_NUMBER}" 2> /dev/null || echo "${SIGNAL_NUMBER}")"
        echo "FAIL: disconnecting readers killed the daemon with SIG${SIGNAL_NAME}." >&2
    else
        echo "FAIL: the daemon exited with status ${STATUS} after readers disconnected." >&2
    fi
    echo "      ${CONNECTION_REPORT}" >&2
    exit 1
fi

# Judged only now the daemon is known to have exited cleanly. Before that, refusals are
# as likely to be the symptom of a crash as the cause of a thin test, and checking them
# first would blame the backlog for a dead daemon.
ACCEPTED="${CONNECTION_REPORT%% *}"
if [[ "${ACCEPTED}" -lt 30 ]]; then
    echo "FAIL: only ${CONNECTION_REPORT} — too few to have tested anything." >&2
    exit 1
fi

echo "PASS: the daemon survived ${ACCEPTED} readers disconnecting at every stage of a write."
