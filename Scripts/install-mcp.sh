#!/bin/bash
#
# Installs the MCP server, so an assistant can be asked about the captured history.
#
# The daemon has install-daemon.sh; this is the same thing for the other installable
# binary, and it exists because the install was previously written out wherever it was
# needed — in the Makefile, and again in anything else that wanted to install it. The
# duplicated part was never the `install` line but the registration guidance printed
# after it, which is real advice with a reason behind it and was drifting between copies.
#
# It installs exactly one thing:
#
#   /usr/local/libexec/beholder-mcp
#
# It does NOT register the server with your assistant, and neither should anything else.
# That edits your configuration rather than this machine's, which is a separate decision;
# the command to do it is printed instead.
#
# Usage:  sudo Scripts/install-mcp.sh [--quiet]
#
#   --quiet             install and say so in one line, for callers that are already
#                       reporting (make reload). The registration guidance is for a
#                       first install, not for the tenth rebuild of the day.
#   BEHOLDER_CONFIG     debug or release, default release, as install-daemon.sh
#   BEHOLDER_SKIP_BUILD 1 when the caller has just built this configuration itself

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${BEHOLDER_CONFIG:-release}"
INSTALLED_MCP="/usr/local/libexec/beholder-mcp"
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet) QUIET=1; shift ;;
        # The header comment above IS the documentation, so --help prints it rather than
        # a second, shorter description that would drift from it.
        -h|--help) awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "Installing into /usr/local/libexec needs root:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

# As install-daemon.sh does: build as the user who ran sudo, so .build is not left owned
# by root and the next plain `swift build` still works.
REAL_USER="${SUDO_USER:-root}"

if [[ "${BEHOLDER_SKIP_BUILD:-0}" != "1" ]]; then
    sudo -u "${REAL_USER}" swift build --package-path "${ROOT}" \
        --configuration "${CONFIGURATION}" --product BeholderMCP
fi

install -d -m 755 /usr/local/libexec
install -m 755 "${ROOT}/.build/${CONFIGURATION}/BeholderMCP" "${INSTALLED_MCP}"

if [[ "${QUIET}" -eq 1 ]]; then
    echo "  Installed ${INSTALLED_MCP} (${CONFIGURATION})."
    exit 0
fi

echo
echo "Installed to ${INSTALLED_MCP}."
echo
# `claude mcp add` refuses rather than replaces when the name is taken, and the common
# path here is re-pointing an existing registration from the .build copy to this one — so
# lead with the remove. It is harmless when nothing is registered.
echo "Point your assistant at it by running:"
echo
echo "  claude mcp remove beholder 2>/dev/null; \\"
echo "  claude mcp add beholder -- ${INSTALLED_MCP}"
echo
echo "Registering this copy rather than the one under .build means 'make clean' cannot"
echo "leave the registration pointing at a binary that is no longer there."
echo
echo "Worth knowing before you do: when the assistant calls one of its tools, what it"
echo "reads — hostnames, process names, addresses, byte counts, times — leaves this"
echo "machine. That is the point of it, and it is why registering is a separate step."
