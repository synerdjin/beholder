#!/bin/bash
#
# Installs the pf anchor Beholder blocks with.
#
# Blocking is the one thing Beholder does that changes what this machine can reach, and
# this is the one script that changes the system to allow it. It is separate from
# install-daemon.sh on purpose: capturing and blocking are different decisions, and
# installing the daemon should not quietly arm a firewall.
#
# It touches exactly two things, and uninstall-pf-anchor.sh removes both:
#
#   /etc/pf.anchors/com.beholder   the rules
#   /etc/pf.conf                   three lines naming and loading them
#
# The second is unavoidable. A nested anchor is only evaluated if the main ruleset names
# it, so an anchor file alone loads without complaint and blocks nothing. Apple's own
# comment at the top of pf.conf says the main ruleset must not be flushed for exactly this
# reason, which is also why this script validates before it commits and keeps a backup.
#
# It also creates an empty block list at /usr/local/etc/beholder/blocklist.conf, owned by
# root, because the file decides what a root process adds to the firewall and anything
# that can write it can block anything.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${BEHOLDER_CONFIG:-release}"
PF_CONF="/etc/pf.conf"
ANCHOR_FILE="/etc/pf.anchors/com.beholder"
BACKUP="/etc/pf.conf.beholder-backup"
BLOCKLIST_DIR="/usr/local/etc/beholder"
BLOCKLIST="${BLOCKLIST_DIR}/blocklist.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This needs root: it edits ${PF_CONF} and writes ${ANCHOR_FILE}." >&2
    echo "Run: sudo $0" >&2
    exit 1
fi

echo "Installing Beholder's pf anchor"
echo

# A previous run that failed part-way leaves this behind. Removing it first keeps a stale
# one from ever being mistaken for the real file.
rm -f "${ANCHOR_FILE}.new" "${PF_CONF}.new"

# The rules come from the binary rather than from a copy kept here. Two files that have to
# contain the same pf rules, edited in different languages, eventually disagree - and the
# disagreement shows up as an anchor that loads cleanly and matches nothing.
#
# "The binary exists" is the wrong test, and getting it wrong here cost a run: a .build
# copy from before --print-pf-anchor existed answered with its usage text, and the redirect
# put 65 lines of it into /etc/pf.anchors before set -e caught up. It is the same mistake
# `make restart` makes with the installed daemon, which is why `make reload` exists. So the
# binary is rebuilt, and then asked whether it understands the option at all.
#
# Built as the invoking user, never as root: `sudo swift build` leaves root-owned objects
# in .build/ and every ordinary build after it fails on them.
build_daemon() {
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        sudo -u "${SUDO_USER}" swift build --package-path "${ROOT}" \
            --configuration "${CONFIGURATION}" --product beholderd > /dev/null
    else
        swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}" \
            --product beholderd > /dev/null
    fi
}

speaks_pf() {
    [[ -x "$1" ]] && "$1" --print-pf-anchor 2> /dev/null | grep -q "table <beholder_blocked>"
}

DAEMON="${ROOT}/.build/${CONFIGURATION}/beholderd"
echo "  building beholderd (${CONFIGURATION}) to read the rules from"
build_daemon || true

if ! speaks_pf "${DAEMON}"; then
    if speaks_pf /usr/local/libexec/beholderd; then
        DAEMON=/usr/local/libexec/beholderd
    else
        echo "  no beholderd here knows how to print its pf rules." >&2
        echo "  Build one first, as yourself rather than under sudo:" >&2
        echo "      make daemon-bin" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------- the anchor file

# Generated somewhere harmless and checked before it goes anywhere near /etc. The rules are
# a system file, and "whatever that subprocess wrote to stdout" is not good enough to put in
# one - a binary that does not understand the option answers with its usage text, and a
# stray print() anywhere in the startup path would answer with that.
STAGED="$(mktemp)"
"${DAEMON}" --print-pf-anchor > "${STAGED}" 2> /dev/null

# `grep -q` is deliberately not combined with `-v` below: BSD grep reports the status of
# the *match* rather than of the inverted selection, so `grep -qv` answered "no stray
# lines" for a file that had one. Taking the first stray line as text instead is
# unambiguous on any grep.
STRAY_LINE="$(grep -vE '^(#.*|[[:space:]]*|table <beholder_blocked> persist|block return out log quick from any to <beholder_blocked>)$' "${STAGED}" | head -1 || true)"

if ! grep -q "^table <beholder_blocked> persist$" "${STAGED}" \
    || ! grep -q "^block return out log quick from any to <beholder_blocked>$" "${STAGED}" \
    || [[ -n "${STRAY_LINE}" ]]; then
    echo "  what beholderd printed is not a Beholder ruleset; nothing was written:" >&2
    [[ -n "${STRAY_LINE}" ]] && echo "    unexpected line: ${STRAY_LINE}" >&2
    sed 's/^/    /' < "${STAGED}" | head -5 >&2
    rm -f "${STAGED}"
    exit 1
fi

install -o root -g wheel -m 644 "${STAGED}" "${ANCHOR_FILE}"
rm -f "${STAGED}"
echo "  wrote ${ANCHOR_FILE}"

# ---------------------------------------------------------------- pf.conf

# The markers come from the binary, like the rules do. They are what makes this script
# idempotent and what lets the uninstaller find its own block again, so a marker reworded in
# Swift and not here would mean every re-run appends a *second* anchor block to /etc/pf.conf
# while the uninstaller quietly stops removing any of it.
PF_CONF_BLOCK="$("${DAEMON}" --print-pf-conf 2> /dev/null)"
BEGIN_MARKER="$(head -1 <<< "${PF_CONF_BLOCK}")"

if [[ -z "${BEGIN_MARKER}" ]]; then
    echo "  beholderd printed no pf.conf block to look for." >&2
    exit 1
fi

if grep -qF "${BEGIN_MARKER}" "${PF_CONF}" 2> /dev/null; then
    echo "  ${PF_CONF} already names the anchor"
else
    if [[ ! -f "${BACKUP}" ]]; then
        cp -p "${PF_CONF}" "${BACKUP}"
        echo "  backed up ${PF_CONF} to ${BACKUP}"
    fi

    # Built and validated as a separate file, then moved into place. A pf.conf that does
    # not parse is not a cosmetic problem: it is the file the system loads at boot, and
    # leaving a broken one behind would be a much worse outcome than failing here.
    cp -p "${PF_CONF}" "${PF_CONF}.new"
    {
        echo ""
        echo "${PF_CONF_BLOCK}"
    } >> "${PF_CONF}.new"

    # Plain if/then rather than a pipeline: with pipefail set, piping through grep would
    # report failure on the success case, where pfctl prints nothing and grep matches
    # nothing.
    CHECK_OUTPUT="$(mktemp)"
    if ! /sbin/pfctl -n -f "${PF_CONF}.new" > "${CHECK_OUTPUT}" 2>&1; then
        echo "  the edited ${PF_CONF} does not parse; leaving the original alone:" >&2
        sed 's/^/    /' < "${CHECK_OUTPUT}" >&2
        rm -f "${PF_CONF}.new" "${CHECK_OUTPUT}"
        exit 1
    fi
    rm -f "${CHECK_OUTPUT}"
    mv "${PF_CONF}.new" "${PF_CONF}"
    echo "  added the anchor to ${PF_CONF}"
fi

# ---------------------------------------------------------------- load it

# Reloading the main ruleset drops anchors that running services inserted into it
# dynamically — Internet Sharing does this, and so do some VPN clients. They re-insert
# theirs when they next start, and a reboot settles everything, but it is worth knowing
# about rather than discovering.
echo
echo "Loading ${PF_CONF}. Any anchor a running service inserted dynamically"
echo "(Internet Sharing, some VPN clients) is dropped until that service restarts."
/sbin/pfctl -f "${PF_CONF}" 2>&1 | sed 's/^/  /' || true

if /sbin/pfctl -a com.beholder -s rules 2> /dev/null | grep -q beholder_blocked; then
    echo "  anchor loaded"
else
    echo "  anchor did not load - blocking would refuse to start" >&2
    exit 1
fi

# ---------------------------------------------------------------- the block list

if [[ ! -f "${BLOCKLIST}" ]]; then
    mkdir -p "${BLOCKLIST_DIR}"
    cat > "${BLOCKLIST}" << 'LIST'
# Beholder block list.
#
# One destination per line: an address, or a network in CIDR form. Anything after a '#'
# is a note, and the note is worth writing - a list of bare addresses is unreadable a
# month later, when the question is "what is this and can I remove it".
#
#   93.184.216.34        # example.com
#   10.0.0.0/8           # the whole lab network
#   2606:2800:220:1::/64
#
# Host names are not accepted. pf matches addresses, and resolving a name here would
# freeze one answer for a record that rotates - it would stop matching within the hour
# and give no sign that it had.
#
# Two things to know before adding anything:
#
#   Blocking is by destination, not by process. pf has no concept of a process, so a
#   block applies to every program on this machine.
#
#   One address commonly serves many names. Blocking a CDN address to stop one tracker
#   stops everything else behind that address too, and there is no way to tell from the
#   outside what those are.
#
# beholderd reloads this file on SIGHUP, and refuses to start if any line here cannot be
# used rather than enforcing the part that happens to parse. Check an edit first with:
#
#   beholderd --check-blocklist
LIST
    chown root:wheel "${BLOCKLIST}"
    chmod 644 "${BLOCKLIST}"
    echo
    echo "  created ${BLOCKLIST} (empty)"
else
    echo
    echo "  kept the existing ${BLOCKLIST}"
fi

cat << EOF

Done. Nothing is blocked yet - the list is what decides that.

  sudo \$EDITOR ${BLOCKLIST}
  make check-blocklist          # what it would block, no root needed
  sudo ./.build/${CONFIGURATION}/beholderd --serve --block

Blocking lasts as long as the daemon does. If it is killed outright and leaves rules
behind, 'make unblock' clears them.
EOF
