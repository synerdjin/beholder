#!/bin/bash
#
# Checks the two promises the publishing socket makes to a reader.
#
#   1. Every message arrives whole. Clients are non-blocking, so a snapshot larger than
#      the kernel's send buffer takes several writes. Abandoning the rest when the buffer
#      fills is not "skipping a snapshot" — the terminating newline never arrives, the
#      next snapshot is appended to a truncated one, and the reader can never
#      resynchronise. The daemon looks healthy from outside while no client can decode a
#      single message from it, which is exactly how it shipped: 65,536 bytes delivered
#      over five seconds containing zero complete messages.
#
#   2. A reader leaving cannot take the daemon with it. Writing to a socket whose peer has
#      gone raises SIGPIPE, and the default disposition kills the process — so quitting
#      the app could kill capture. SO_NOSIGPIPE is not enough on its own: setsockopt
#      returns EINVAL when the peer closed before the connection was accepted, leaving the
#      option unset on precisely the socket that needed it.
#
# Both are properties of the deployed binary, and FlowServer lives in an executable target
# where a unit test cannot reach it, so this drives the real thing.
#
# Run directly, or via `make check`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${BEHOLDER_CONFIG:-debug}"
DAEMON="${ROOT}/.build/${CONFIGURATION}/beholderd"

if ! command -v python3 > /dev/null 2>&1; then
    echo "SKIP: python3 is needed to drive the client side of this test." >&2
    exit 0
fi

if [[ ! -x "${DAEMON}" ]]; then
    echo "Building beholderd (${CONFIGURATION})..."
    swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}" --product beholderd
fi

SOCKET=""
DAEMON_PID=""

cleanup() {
    [[ -n "${DAEMON_PID}" ]] && kill "${DAEMON_PID}" 2> /dev/null || true
    [[ -n "${SOCKET}" ]] && rm -f "${SOCKET}"
    return 0
}
trap cleanup EXIT

# --self-test runs the publishing path with no interfaces, so this needs no root and no
# live traffic. It stops itself after three ticks and should exit 0. Each check gets its
# own instance: three ticks is not long enough to share.
start_daemon() {
    SOCKET="$(mktemp -u "${TMPDIR:-/tmp}/beholder-test-XXXXXX.sock")"
    BEHOLDER_TEST_SEND_BUFFER="${1:-}" \
        "${DAEMON}" --serve --self-test --no-log --socket "${SOCKET}" > /dev/null 2>&1 &
    DAEMON_PID=$!

    for _ in $(seq 1 50); do
        [[ -S "${SOCKET}" ]] && return 0
        if ! kill -0 "${DAEMON_PID}" 2> /dev/null; then
            echo "FAIL: the daemon exited before it published a socket." >&2
            exit 1
        fi
        sleep 0.1
    done
    echo "FAIL: the daemon never created ${SOCKET}." >&2
    exit 1
}

# Reports how the daemon ended. Anything other than a clean exit means the client-side
# behaviour just exercised was fatal to it.
require_clean_exit() {
    local status=0
    wait "${DAEMON_PID}" || status=$?
    DAEMON_PID=""
    rm -f "${SOCKET}"
    SOCKET=""

    [[ "${status}" -eq 0 ]] && return 0
    if [[ "${status}" -gt 128 ]]; then
        local number="$((status - 128))"
        local name
        name="$(kill -l "${number}" 2> /dev/null || echo "${number}")"
        echo "FAIL: $1 killed the daemon with SIG${name}." >&2
    else
        echo "FAIL: the daemon exited with status ${status} after $1." >&2
    fi
    exit 1
}

# --------------------------------------------- 1. whole messages under back-pressure

# A 512-byte send buffer against a ~650-byte snapshot guarantees the server cannot write
# the message in one call. Setting it on the reader's end does not work: Darwin reports
# back whatever SO_RCVBUF you ask for on an AF_UNIX socket and then ignores it, happily
# buffering 1292 bytes into one that claims 256. SO_SNDBUF on the sender is honoured
# exactly, so that is the lever.
#
# Reading in small pieces lets the buffer drain, so a correctly framed server finishes the
# message across several writes. One that gives up at the first EAGAIN never emits the
# newline, and the reader waits for a message that will never be completed.
start_daemon 512

if ! FRAMING="$(
    python3 - "${SOCKET}" <<'PY'
import json, socket, sys, time

client = socket.socket(socket.AF_UNIX)
client.settimeout(0.3)
client.connect(sys.argv[1])

buffer = b""
deadline = time.time() + 2.5
while time.time() < deadline and b"\n" not in buffer:
    try:
        chunk = client.recv(128)
    except socket.timeout:
        continue
    if not chunk:
        break
    buffer += chunk

if b"\n" not in buffer:
    sys.exit(
        f"no complete message in {len(buffer)} bytes - the newline never arrived, "
        "so the snapshot was abandoned mid-write"
    )

message = buffer.split(b"\n")[0]
try:
    snapshot = json.loads(message)
except json.JSONDecodeError as error:
    sys.exit(f"the {len(message)}-byte message is not valid JSON: {error}")

if "flows" not in snapshot:
    sys.exit(f"decoded, but it is not a snapshot: keys were {sorted(snapshot)}")

print(f"{len(message)} bytes, framed and parsed")
PY
)"; then
    echo "FAIL: a reader with a small buffer never received a whole snapshot." >&2
    exit 1
fi

require_clean_exit "a slow reader"
echo "PASS: snapshots arrive whole under back-pressure (${FRAMING})."

# ----------------------------------------------------- 2. readers leaving abruptly

start_daemon

# Connections are paced: the listen backlog is 8, sized for the one or two readers this
# daemon really has, so an unpaced burst just fills it and is refused before it reaches
# the code under test.
CONNECTIONS="$(
    python3 - "${SOCKET}" <<'PY'
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

require_clean_exit "readers disconnecting"

ACCEPTED="${CONNECTIONS%% *}"
if [[ "${ACCEPTED}" -lt 30 ]]; then
    echo "FAIL: only ${CONNECTIONS} — too few to have tested anything." >&2
    exit 1
fi

echo "PASS: ${ACCEPTED} readers disconnected at every stage of a write, daemon survived."
