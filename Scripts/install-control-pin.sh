#!/bin/bash
#
# Pins the code identity of the program allowed to change what Beholder blocks.
#
# The control socket is the only channel into the daemon that changes anything, and file
# permissions cannot guard it: both ends run as you, so mode 0600 keeps out other accounts
# and keeps out nothing else. What distinguishes Beholder.app from everything else running
# as you is its code signature - and it does not need to be an Apple-issued one. An ad-hoc
# signature, which build-app.sh already applies, produces a stable cdhash, and that is all
# the identity this needs.
#
# This records the app's designated requirement in a root-owned file. beholderd loads it at
# startup and admits a control connection only from a process that satisfies it.
#
#   /usr/local/etc/beholder/control-peer.requirement
#
# Re-run it after every rebuild of the app. The cdhash changes when the binary changes, by
# design - that is what makes it an identity rather than a name - so a rebuilt app is a
# different program until it is pinned again. `make reload` does this for you.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_DIR="/usr/local/etc/beholder"
PIN="${PIN_DIR}/control-peer.requirement"

if [[ $EUID -ne 0 ]]; then
    echo "This needs root: it writes ${PIN}, which decides who may change the firewall." >&2
    echo "Run: sudo $0 [path/to/Beholder.app]" >&2
    exit 1
fi

APP="${1:-}"
if [[ -z "${APP}" ]]; then
    for candidate in "${ROOT}/.build/Beholder.app" "/Applications/Beholder.app"; do
        if [[ -d "${candidate}" ]]; then
            APP="${candidate}"
            break
        fi
    done
fi

if [[ -z "${APP}" || ! -d "${APP}" ]]; then
    echo "No Beholder.app found. Build one first:  make app" >&2
    echo "Or name it:  sudo $0 /path/to/Beholder.app" >&2
    exit 1
fi

echo "Pinning the control peer"
echo "  app: ${APP}"

# The designated requirement, as codesign computes it. For an ad-hoc signature that is a
# bare cdhash; for a Developer ID it would be an identifier-and-authority requirement, and
# nothing else here would have to change - which is why the requirement is stored rather
# than the hash.
REQUIREMENT="$(codesign -dr - --verbose=0 "${APP}" 2>&1 | sed -n 's/^.*designated => //p')"

if [[ -z "${REQUIREMENT}" ]]; then
    echo "  ${APP} has no code signature to pin." >&2
    echo "  build-app.sh signs ad-hoc; if that was skipped, rebuild with: make app" >&2
    exit 1
fi

echo "  requirement: ${REQUIREMENT}"

mkdir -p "${PIN_DIR}"
STAGED="$(mktemp)"
cat > "${STAGED}" << PIN_FILE
# The program allowed to change what Beholder blocks.
#
# Written by Scripts/install-control-pin.sh from:
#   ${APP}
#
# Rebuilding the app changes its cdhash and therefore this file must be rewritten.
# That is not a bug: an identity that survived the code changing would not be one.
${REQUIREMENT}
PIN_FILE

install -o root -g wheel -m 644 "${STAGED}" "${PIN}"
rm -f "${STAGED}"
echo "  wrote ${PIN}"

# Checked with the same loader the daemon uses, rather than assumed. A requirement that
# does not parse would otherwise surface as a daemon that quietly opens no control socket.
DAEMON="${ROOT}/.build/debug/beholderd"
[[ -x "${DAEMON}" ]] || DAEMON="${ROOT}/.build/release/beholderd"
[[ -x "${DAEMON}" ]] || DAEMON="/usr/local/libexec/beholderd"

if [[ -x "${DAEMON}" ]] && "${DAEMON}" --check-control-pin > /dev/null 2>&1; then
    echo "  the daemon can load it"
elif [[ -x "${DAEMON}" ]]; then
    echo "  WARNING: the daemon cannot load it:" >&2
    "${DAEMON}" --check-control-pin 2>&1 | sed 's/^/    /' >&2
    exit 1
fi

cat << 'EOF'

Done. Restart the daemon for it to take effect:

  make reload

The app can change what is blocked only while the daemon runs with --block.
EOF
