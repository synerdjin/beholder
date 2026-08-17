#!/bin/bash
#
# Installs or updates Beholder, one decision at a time.
#
# Beholder is deliberately assembled from parts you can decline: two optional databases
# with licences of their own, a launchd daemon that is a real change to your system, and
# an MCP server that sends what it reads to a third party. Every one of those is a
# separate `make` target for exactly that reason, which is honest but leaves a first-time
# reader with six targets and no order to run them in — and the order matters, because
# `install-daemon.sh` copies whatever databases exist at the moment it runs.
#
# So this asks, in the order the answers depend on each other, and does nothing it did not
# ask about first. It is the same set of steps, not a shortcut past them:
#
#   1. build                    (no privilege)
#   2. geolocation database     (~124 MB, CC BY 4.0, downloaded)
#   3. tracker index            (CC BY-NC-SA, downloaded)
#   4. continuous capture       (root: a launchd daemon)
#   5. MCP server               (root to install; registering it is yours to do)
#   6. verify
#
# Re-running it is the update path. It surveys what is already installed and defaults each
# question to "keep doing what you are already doing", so the second run is mostly Enter.
# For a rebuild-and-restart with no questions at all — the thing you want after editing
# code — use `make reload` instead, which is not interactive and installs nothing new.
#
# Usage:  Scripts/wizard.sh [--yes]
#
# BEHOLDER_CONFIG chooses debug or release (default release), as install-daemon.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="com.beholder.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
INSTALLED_DAEMON="/usr/local/libexec/beholderd"
INSTALLED_MCP="/usr/local/libexec/beholder-mcp"
SHARED="/usr/local/share/beholder"

ASSUME_YES=0

# BEHOLDER_CONFIG rather than a --config flag, because that is the name install-daemon.sh
# has always taken this setting under and the wizard passes it straight through.
CONFIGURATION="${BEHOLDER_CONFIG:-release}"
if [[ "${CONFIGURATION}" != "debug" && "${CONFIGURATION}" != "release" ]]; then
    echo "BEHOLDER_CONFIG takes 'debug' or 'release', not '${CONFIGURATION}'." >&2
    exit 2
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y) ASSUME_YES=1; shift ;;
        # The header comment above IS the documentation, so --help prints it rather than
        # a second, shorter description that would drift from it.
        -h|--help) awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Running the whole wizard under sudo would build as root and leave .build owned by root,
# after which every later `swift build` as yourself fails on permissions. The two steps
# that genuinely need root ask for it themselves.
if [[ "${EUID}" -eq 0 ]]; then
    echo "Do not run the wizard with sudo — it would build as root and leave .build" >&2
    echo "owned by root. Run it as yourself; it asks for your password at the two" >&2
    echo "steps that need it." >&2
    exit 1
fi

if [[ ! -t 0 && "${ASSUME_YES}" -eq 0 ]]; then
    echo "The wizard asks questions and stdin is not a terminal." >&2
    echo "Run it in a terminal, or pass --yes to take every default." >&2
    echo "Note that --yes answers the questions, not the password prompts: the daemon" >&2
    echo "and MCP steps still need sudo, so a genuinely unattended run needs cached" >&2
    echo "credentials or it will stop there." >&2
    exit 2
fi

# ------------------------------------------------------------------------------ output

BOLD=""; DIM=""; RESET=""
if [[ -t 1 ]]; then BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'; fi

step() {
    echo
    echo "${BOLD}── $* ${RESET}"
}

# ask "question" Y|N  -> 0 for yes, 1 for no. Always call it as an `if` condition:
# under `set -e` a bare call that answers no would end the script.
ask() {
    local prompt="$1" default="$2" reply="" hint="[y/N]"
    [[ "${default}" == "Y" ]] && hint="[Y/n]"
    if [[ "${ASSUME_YES}" -eq 1 ]]; then
        echo "  ${prompt} ${hint} ${DIM}-> ${default} (--yes)${RESET}"
        [[ "${default}" == "Y" ]]
        return
    fi
    read -r -p "  ${prompt} ${hint} " reply || reply=""
    reply="${reply:-${default}}"
    [[ "${reply}" =~ ^[Yy] ]]
}

DID=()
SKIPPED=()
did()     { DID+=("$1"); }
skipped() { SKIPPED+=("$1"); }

# ------------------------------------------------------------------------ what is here

daemon_installed() { launchctl print "system/${LABEL}" > /dev/null 2>&1; }

# Either copy counts: the daemon reads /usr/local/share when it is installed, and
# Resources/ when it is run from the checkout.
# Prints the path, or nothing when neither copy exists. Always succeeds: a status nobody
# reads would only have to be suppressed with `|| true` at the call sites, since `set -e`
# ends the script on a failing command substitution.
database_path() {
    local name="$1" directory="$2" path
    for path in "${SHARED}/${name}" "${ROOT}/Resources/${directory}/${name}"; do
        [[ -f "${path}" ]] && { echo "${path}"; break; }
    done
    return 0
}

GEOIP_PATH="$(database_path geoip.mmdb geoip)"
TRACKERS_PATH="$(database_path trackers.json trackers)"

echo "${BOLD}Beholder — install and update${RESET}"
echo "$(date '+%Y-%m-%d %H:%M:%S %Z')  ${ROOT}"
echo
echo "Where you are now:"
printf '  %-22s %s\n' "build configuration" "${CONFIGURATION}"
printf '  %-22s %s\n' "geolocation" "${GEOIP_PATH:-not installed}"
printf '  %-22s %s\n' "tracker index" "${TRACKERS_PATH:-not installed}"
if daemon_installed; then
    printf '  %-22s %s\n' "continuous capture" "installed (${LABEL})"
elif [[ -f "${PLIST}" ]]; then
    printf '  %-22s %s\n' "continuous capture" "plist present but not loaded"
else
    printf '  %-22s %s\n' "continuous capture" "not installed"
fi
printf '  %-22s %s\n' "MCP server" "$([[ -x "${INSTALLED_MCP}" ]] && echo "${INSTALLED_MCP}" || echo "not installed")"

# ------------------------------------------------------------------------- 0. preflight

step "Checking prerequisites"

if ! command -v swift > /dev/null 2>&1; then
    echo "  No Swift toolchain. Install Xcode or the Command Line Tools:" >&2
    echo "    xcode-select --install" >&2
    exit 1
fi
echo "  swift: $(swift --version 2>&1 | head -1)"

MACOS="$(sw_vers -productVersion)"
if [[ "${MACOS%%.*}" -lt 14 ]]; then
    echo "  macOS ${MACOS}: the app requires 14.0 or later (LSMinimumSystemVersion)." >&2
    exit 1
fi
echo "  macOS: ${MACOS}"
if command -v python3 > /dev/null 2>&1; then
    echo "  python3: $(python3 --version 2>&1)"
else
    echo "  python3: missing — the tracker index needs it to build the ownership index"
fi

# --------------------------------------------------------------------------- 1. build

step "Build (${CONFIGURATION})"
echo "  Building the daemon, the app and the MCP server."
swift build --package-path "${ROOT}" --configuration "${CONFIGURATION}"
# A plain `swift build` covers every product, so build-app.sh is told to assemble the
# bundle without repeating it.
BEHOLDER_SKIP_BUILD=1 "${ROOT}/Scripts/build-app.sh" "${CONFIGURATION}" > /dev/null
echo "  Built .build/${CONFIGURATION}/beholderd, .build/Beholder.app, .build/${CONFIGURATION}/BeholderMCP"
did "built ${CONFIGURATION}"

# --------------------------------------------------------------- 2 and 3. the databases
#
# Both come before the daemon step on purpose: install-daemon.sh copies whatever is in
# Resources/ into /usr/local/share at the moment it runs, so fetching afterwards would
# leave the installed daemon reading nothing until the next install.

# Both steps ask the same three-way question — refresh it, download it, or leave it — so
# only the licence prose above each call is written out twice. Whatever a third database
# would need, it needs once.
#
# database_step "label" "current path or empty" fetch-script make-target
database_step() {
    local label="$1" path="$2" fetcher="$3" target="$4"
    if [[ -n "${path}" ]]; then
        echo "  ${DIM}Installed: ${path}${RESET}"
        if ask "Download a fresh copy?" N; then
            "${ROOT}/Scripts/${fetcher}"; did "refreshed the ${label}"
        else
            skipped "${label} (kept the copy you have)"
        fi
    elif ask "Download it now?" Y; then
        "${ROOT}/Scripts/${fetcher}"; did "downloaded the ${label}"
    else
        skipped "${label} (make ${target} later)"
    fi
}

step "Geolocation — where in the world an address is"
echo "  DB-IP City Lite and ASN Lite, about 124 MB, CC BY 4.0, downloaded from db-ip.com."
echo "  Without it, addresses are still shown; they just have no country or network."
echo "  ${DIM}DB-IP republishes monthly, so a copy you have is worth refreshing.${RESET}"
database_step "geolocation database" "${GEOIP_PATH}" fetch-geoip.sh geoip

step "Tracker index — who owns the other end"
echo "  Derived from DuckDuckGo Tracker Radar, CC BY-NC-SA 4.0: NonCommercial and"
echo "  ShareAlike. Fine for personal use; check the licence before anything else."
database_step "tracker index" "${TRACKERS_PATH}" fetch-trackers.sh trackers

# ----------------------------------------------------------------- 4. continuous capture

step "Continuous capture — history that fills while you are not watching"
echo "  Installs a launchd daemon so capture runs in the background and at boot."
echo "  It puts exactly two things on your system, and 'make uninstall' removes both:"
echo "    ${INSTALLED_DAEMON}"
echo "    ${PLIST}"
echo "  Your captured history is never deleted by the uninstaller."
DAEMON_PROMPT="Install it? (asks for your password)"
if daemon_installed; then
    echo "  ${DIM}Already installed. Reinstalling points it at the build above.${RESET}"
    DAEMON_PROMPT="Reinstall it with the current build?"
fi
if ask "${DAEMON_PROMPT}" Y; then
    # `sudo env VAR=...` rather than `sudo VAR=...`: the latter depends on the sudoers
    # setenv policy, and this has to work on a machine whose sudoers nobody has touched.
    sudo env "BEHOLDER_CONFIG=${CONFIGURATION}" "${ROOT}/Scripts/install-daemon.sh"
    did "installed the capture daemon"
else
    skipped "continuous capture (make install later)"
    echo "  ${DIM}Without it, only a foreground 'make run' feeds the app.${RESET}"
fi

# ------------------------------------------------------------------------ 5. MCP server

step "MCP server — asking an assistant about the history"
echo "  Read-only, and it never runs on its own: your assistant starts it per question."
echo "  Be clear about what it means, because it is the one part that sends data off this"
echo "  machine: what it reads — hostnames, process names, addresses, byte counts, times —"
echo "  goes to whoever runs the assistant. That is the point of it, and it is opt-in."
MCP_PROMPT_DEFAULT=N
[[ -x "${INSTALLED_MCP}" ]] && MCP_PROMPT_DEFAULT=Y
if ask "Install the server binary to ${INSTALLED_MCP}?" "${MCP_PROMPT_DEFAULT}"; then
    # install-mcp.sh, not an `install` line here: it owns the destination and, more to the
    # point, the registration guidance it prints afterwards — which is advice with a
    # reason behind it, and was the part that would have drifted between copies. It is
    # printed rather than run there for the same reason it is not run here: registering
    # edits your assistant's configuration, not this machine.
    sudo env "BEHOLDER_CONFIG=${CONFIGURATION}" BEHOLDER_SKIP_BUILD=1 \
        "${ROOT}/Scripts/install-mcp.sh"
    did "installed the MCP server"
else
    skipped "MCP server (make mcp-install later)"
fi

# ---------------------------------------------------------------------------- 6. verify

step "Checking it works"
# Unconditionally, including when nothing is installed: doctor.sh is written for that case
# and names the next step ("make install") more precisely than a branch here would.
"${ROOT}/Scripts/doctor.sh" || true

# --------------------------------------------------------------------------- 7. summary

step "Done — $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "  This run:"
# ${arr[@]+"${arr[@]}"} rather than "${arr[@]}": macOS ships bash 3.2, where an empty
# array under `set -u` is an unbound variable and would end the script on the last line
# of a successful run — the one place a crash is least explicable.
for item in ${DID[@]+"${DID[@]}"}; do echo "    + ${item}"; done
for item in ${SKIPPED[@]+"${SKIPPED[@]}"}; do echo "    - skipped ${item}"; done
echo
echo "  Watch it:        make open-app"
echo "  Ask it:          make history"
echo "  After editing:   make reload"
echo "  If it is quiet:  make doctor"
