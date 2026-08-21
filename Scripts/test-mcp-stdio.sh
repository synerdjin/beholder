#!/bin/bash
#
# Checks the one promise the MCP server makes to its client: stdout carries nothing but
# protocol.
#
# The transport is newline-delimited JSON with no framing header, so there is nothing to
# resynchronise from. A single stray byte on stdout — a print() left in after debugging, a
# startup banner, a usage message on a bad flag — corrupts the stream permanently, and the
# only symptom the user gets is their assistant reporting a parse error with no clue where
# it came from. That failure mode is invisible to a unit test, because it is a property of
# the binary and its startup path rather than of the protocol code, which is why this
# drives the real executable rather than calling into BeholderCore.
#
# It also pins the things a stdio server has to get right or leak processes: exiting when
# stdin closes, surviving the client hanging up mid-write rather than dying by SIGPIPE, and
# treating a malformed line as one bad request rather than the end of the session.
#
# Data correctness is not checked here — that is unit-tested. This is about the pipe.
#
# Run directly, or via `make check`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${BEHOLDER_CONFIG:-debug}"
SERVER="${ROOT}/.build/${CONFIGURATION}/BeholderMCP"

if ! command -v python3 > /dev/null 2>&1; then
    echo "python3 is required to drive this test." >&2
    exit 1
fi

if [ ! -x "$SERVER" ]; then
    echo "Building the MCP server first..."
    (cd "$ROOT" && swift build --configuration "$CONFIGURATION" --product BeholderMCP)
fi

# A database path that cannot exist, so the test never depends on whether this machine has
# captured anything — and so it exercises the "no history" answer, which has to stay
# well-formed rather than becoming a crash or a bare error.
ABSENT_DB="/nonexistent/beholder-test/history.sqlite"
ABSENT_SOCKET="/nonexistent/beholder-test.sock"

export BEHOLDER_MCP_SERVER="$SERVER"
export BEHOLDER_MCP_DB="$ABSENT_DB"
export BEHOLDER_MCP_SOCKET="$ABSENT_SOCKET"

python3 - <<'PYTHON'
import json
import os
import subprocess
import sys
import time

SERVER = os.environ["BEHOLDER_MCP_SERVER"]
ARGS = [SERVER, "--history-db", os.environ["BEHOLDER_MCP_DB"],
        "--socket", os.environ["BEHOLDER_MCP_SOCKET"]]

failures = []


def check(condition, message):
    if condition:
        print(f"PASS: {message}")
    else:
        print(f"FAIL: {message}")
        failures.append(message)


def run(lines, timeout=25):
    """Feeds lines on stdin, returns (stdout, stderr, exit code)."""
    process = subprocess.Popen(
        ARGS, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = process.communicate(
        "".join(line + "\n" for line in lines).encode(), timeout=timeout
    )
    return out.decode(), err.decode(), process.returncode


# ---------------------------------------------------------------- stdout is clean

requests = [
    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"}}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "beholder_status", "arguments": {}}}),
]
out, err, code = run(requests)
lines = [line for line in out.split("\n") if line]

# The load-bearing assertion. Three requests in, three lines out, nothing else — this is
# what catches a stray print() anywhere in the startup path.
check(len(lines) == 3, f"three requests produce exactly three stdout lines (got {len(lines)})")

parsed = []
all_json = True
for line in lines:
    try:
        parsed.append(json.loads(line))
    except json.JSONDecodeError as error:
        all_json = False
        print(f"       unparseable line: {line[:120]!r} ({error})")
check(all_json, "every stdout line is valid JSON")

if len(parsed) == 3:
    check(parsed[0].get("id") == 1 and "result" in parsed[0],
          "the first line is the response to the first request, with nothing before it")
    check(parsed[0]["result"].get("protocolVersion") == "2025-06-18",
          "the client's requested protocol revision is echoed back")
    names = [tool["name"] for tool in parsed[1]["result"]["tools"]]
    check(names == ["network_history", "endpoint_lookup", "live_connections",
                    "beholder_status", "network_quality"],
          "the five tools are advertised under their documented names")

# stderr is explicitly allowed to carry logging, and clients are told not to read it as
# failure. The one-line privacy banner lives there.
check("beholder-mcp:" in err, "the startup notice goes to stderr, not stdout")
check(code == 0, f"the server exits 0 when stdin closes (got {code})")

# ------------------------------------------------- a missing database is still an answer

out, _, _ = run([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": "beholder_status", "arguments": {}}})])
try:
    result = json.loads(out.strip())["result"]
    text = result["content"][0]["text"]
    # A tool that cannot say which path it looked at is a tool that will be read as
    # "you had no network traffic".
    check(os.environ["BEHOLDER_MCP_DB"] in text,
          "a missing database is reported by name rather than as an empty result")
except Exception as error:  # noqa: BLE001
    check(False, f"a missing database still produces a well-formed result ({error})")

# ------------------------------------------------------------- malformed input recovers

out, _, code = run(["{not json", json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"})])
lines = [line for line in out.split("\n") if line]
check(len(lines) == 2, f"a malformed line does not end the session (got {len(lines)} replies)")
if len(lines) == 2:
    first = json.loads(lines[0])
    check(first.get("error", {}).get("code") == -32700,
          "a malformed line is answered with a parse error")
    check(first.get("id") is None,
          "a parse error is reported against a null id, since none can be read")
    check(json.loads(lines[1]).get("id") == 2,
          "the request after a malformed line is still served")

# ------------------------------------------------------- a departing client is survivable

# Closing the read end and then writing is what raises SIGPIPE. The daemon has been bitten
# by this before, which is why the publishing-socket test makes the same check: a process
# that dies by signal exits above 128, and that is the difference between "the client left"
# and "the server crashed".
process = subprocess.Popen(ARGS, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL)
process.stdout.close()
try:
    for index in range(20):
        request = json.dumps({"jsonrpc": "2.0", "id": index, "method": "tools/list"}) + "\n"
        process.stdin.write(request.encode())
        process.stdin.flush()
        time.sleep(0.01)
except BrokenPipeError:
    pass
try:
    process.stdin.close()
except BrokenPipeError:
    pass

deadline = time.time() + 5
while process.poll() is None and time.time() < deadline:
    time.sleep(0.05)
if process.poll() is None:
    process.kill()
    check(False, "the server exits after its client goes away")
else:
    check(process.returncode is not None and process.returncode <= 128,
          f"the server exits rather than dying by SIGPIPE (status {process.returncode})")

# -------------------------------------------------------------------------- shutdown

# A server that lingers after stdin closes leaks one process per client restart, which
# surfaces weeks later as unexplained CPU.
started = time.time()
_, _, code = run([json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})])
elapsed = time.time() - started
check(elapsed < 5, f"the server exits promptly on end of input ({elapsed:.2f}s)")

print()
if failures:
    print(f"{len(failures)} check(s) failed.")
    sys.exit(1)
print("The MCP server's stdout carries nothing but protocol.")
PYTHON
