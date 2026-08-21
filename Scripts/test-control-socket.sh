#!/bin/bash
#
# Checks the one channel into the daemon that changes something.
#
# The property under test is the whole reason the control socket could be added at all:
# **a connection is admitted on the peer's code identity, not on file permissions.** Both
# ends run as the same account, so mode 0600 cannot tell Beholder.app from anything else
# you happen to be running. The daemon therefore checks the peer's audit token against a
# pinned code requirement, and this drives the real binary to prove it both ways:
#
#   - a peer whose identity matches the pin is admitted
#   - a peer whose identity does not match is refused, and told why
#
# Both directions matter. A check that only ever refuses is indistinguishable from a broken
# socket, and one that only ever admits is not a check.
#
# python3 stands in for the app: it carries a code signature and therefore a cdhash,
# exactly as the app does, so pinning it exercises the real mechanism.
#
# The test discovers python3's identity from the daemon's own refusal rather than reading it
# off the interpreter's path, and that is not laziness. Homebrew's python3 re-execs into
# Python.framework/.../Python.app/Contents/MacOS/Python, so `codesign` on the binary you
# invoked reports a different cdhash from the one the process actually presents. Which is
# the entire argument for authenticating the *running* process instead of a file path, and
# it would be a strange thing for this test to get wrong.
#
# Needs no root and blocks nothing - the daemon runs with --control but without --block, so
# pf is never touched. Run directly, or via `make check`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=Scripts/lib/test-helpers.sh
source "${ROOT}/Scripts/lib/test-helpers.sh"
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

if [[ $EUID -eq 0 ]]; then
    echo "SKIP: this test pins the identity of python3, not of root's app." >&2
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/beholder-control-XXXXXX")"
SOCKET="${WORK}/control.sock"
DAEMON_PID=""

cleanup() {
    [[ -n "${DAEMON_PID}" ]] && kill "${DAEMON_PID}" 2> /dev/null || true
    rm -rf "${WORK}"
    return 0
}
trap cleanup EXIT


# Sends one request and prints the reply, as one line, which is what the protocol wants.
send_request() {
    python3 -c '
import socket, sys
path, request = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(path)
s.sendall(request.encode() + b"\n")
data = b""
while b"\n" not in data:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.decode(errors="replace").strip())
' "${SOCKET}" "$1"
}

start_daemon() {
    rm -f "${SOCKET}"
    "${DAEMON}" --self-test --no-log --control \
        --control-socket "${SOCKET}" --control-pin "$1" \
        > "${WORK}/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 50); do
        [[ -S "${SOCKET}" ]] && return 0
        sleep 0.1
    done
    echo "  the daemon never opened ${SOCKET}:" >&2
    sed 's/^/    /' < "${WORK}/daemon.log" >&2
    return 1
}

stop_daemon() {
    [[ -n "${DAEMON_PID}" ]] && kill "${DAEMON_PID}" 2> /dev/null || true
    wait "${DAEMON_PID}" 2> /dev/null || true
    DAEMON_PID=""
}

echo "1. A peer that does not match the pinned identity is refused"

# A syntactically valid requirement naming a hash that is nothing's.
printf 'cdhash H"0000000000000000000000000000000000000000"\n' > "${WORK}/wrong.requirement"
start_daemon "${WORK}/wrong.requirement"

REPLY="$(send_request '{"version":1,"action":"status"}')"
contains "the request is refused" "${REPLY}" '"ok":false'
contains "and says it was an identity failure" "${REPLY}" "not authorised"
contains "the refusal names the identity it saw" "${REPLY}" "the peer is cdhash"
contains "and says what to do about it" "${REPLY}" "install-control-pin.sh"
contains "the daemon logged the refusal" "$(cat "${WORK}/daemon.log")" "control connection refused"

# The identity the peer actually presented, taken from that refusal. See the note at the
# top: the interpreter's path is not the code that runs, so this is the only honest way to
# learn what to pin.
# The quote after H is backslash-escaped inside JSON, so skip any non-hex characters
# between the H and the digits rather than assuming how many there are.
PEER_CDHASH="$(sed -n 's/.*the peer is cdhash H[^0-9a-f]*\([0-9a-f]\{20,\}\).*/\1/p' <<< "${REPLY}")"
if [[ -z "${PEER_CDHASH}" ]]; then
    echo "  FAIL: could not read the peer's cdhash out of the refusal" >&2
    echo "        ${REPLY}" >&2
    exit 1
fi
echo "  ok: the peer identifies as cdhash ${PEER_CDHASH}"

stop_daemon

echo
echo "2. A peer matching the pinned identity is admitted"

printf '# pinned for the test\n%s\n' "cdhash H\"${PEER_CDHASH}\"" > "${WORK}/good.requirement"
start_daemon "${WORK}/good.requirement"

REPLY="$(send_request '{"version":1,"action":"status"}')"
contains "status is answered" "${REPLY}" '"ok":true'
# Running without --block: "nothing is enforcing anything" is a different answer from
# "nothing is blocked", and the app draws a different screen for each.
contains "it says blocking is not running" "${REPLY}" '"isBlocking":false'
contains "and says why" "${REPLY}" "without --block"

REPLY="$(send_request '{"version":1,"action":"block","destination":"93.184.216.34"}')"
contains "blocking is refused when nothing is enforcing" "${REPLY}" '"ok":false'

REPLY="$(send_request '{"version":9,"action":"status"}')"
contains "a version mismatch is named, not decoded around" "${REPLY}" "different builds"

REPLY="$(send_request 'not json at all')"
contains "a malformed request is answered rather than dropped" "${REPLY}" '"ok":false'

REPLY="$(send_request '{"version":1,"action":"status"}')"
contains "the connection before it did not poison the socket" "${REPLY}" '"ok":true'

contains "the daemon logged the acceptance" "$(cat "${WORK}/daemon.log")" "control connection accepted"

stop_daemon

echo
echo "3. Without a usable pin, no control socket is opened at all"

# Fails closed: with no way to tell the app from anything else, nothing is served. Capture
# and any blocking already configured are unaffected, which is why this is a warning in the
# daemon rather than a refusal to start.
rm -f "${SOCKET}"
"${DAEMON}" --self-test --no-log --control \
    --control-socket "${SOCKET}" --control-pin "${WORK}/absent.requirement" \
    > "${WORK}/nopin.log" 2>&1 || true

contains "the daemon says why" "$(cat "${WORK}/nopin.log")" "not opening the control socket"
contains "and points at the fix" "$(cat "${WORK}/nopin.log")" "install-control-pin.sh"
if [[ -S "${SOCKET}" ]]; then
    echo "  FAIL: a control socket was created without a pin" >&2
    failures=$((failures + 1))
else
    echo "  ok: no socket was created"
fi

report_results
