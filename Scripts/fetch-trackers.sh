#!/bin/bash
#
# Builds a compact ownership index from DuckDuckGo's tracker blocklist.
#
# LICENCE: the Tracker Radar data this is derived from is CC BY-NC-SA 4.0 —
# NonCommercial and ShareAlike. That is fine for personal use, and it is why the index
# is fetched here rather than committed: redistributing it would carry the licence into
# this repository, and using it commercially would need permission from DuckDuckGo.
#
# https://github.com/duckduckgo/tracker-radar — Copyright (c) 2020 Duck Duck Go, Inc.
#
# What it knows and does not know: Tracker Radar is built by crawling websites, so it
# covers third-party web trackers well and native application telemetry not at all.
# Endpoints like crash.steampowered.com are absent from it entirely. Beholder pairs this
# with a naming-convention signal to cover some of that gap.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESTINATION="${1:-${ROOT}/Resources/trackers}"
TARGET="${DESTINATION}/trackers.json"
SOURCE_URL="https://staticcdn.duckduckgo.com/trackerblocking/v5/current/macos-tds.json"

mkdir -p "${DESTINATION}"

echo "Fetching ${SOURCE_URL}"
curl --fail --location --silent --show-error --output "${DESTINATION}/.tds.json" "${SOURCE_URL}"

echo "Building index..."
python3 - "${DESTINATION}/.tds.json" "${TARGET}" <<'PYTHON'
import json, sys, datetime

source, target = sys.argv[1], sys.argv[2]
data = json.load(open(source))

entries = {}

# The broad ownership map: thousands of domains, owner only.
for domain, owner in data.get("domains", {}).items():
    entries[domain] = {"o": owner}

# The tracker list is narrower but carries categories, so it wins where both apply.
for domain, tracker in data.get("trackers", {}).items():
    owner = tracker.get("owner", {})
    name = owner.get("displayName") or owner.get("name") or owner.get("ownedBy")
    if not name:
        continue
    entry = {"o": name}
    categories = tracker.get("categories") or []
    if categories:
        entry["c"] = categories
    prevalence = tracker.get("prevalence")
    if prevalence:
        entry["p"] = round(prevalence, 4)
    entries[domain] = entry

index = {
    "version": 1,
    "generated": datetime.date.today().isoformat(),
    "source": "DuckDuckGo Tracker Radar",
    "licence": "CC BY-NC-SA 4.0",
    "entries": entries,
}
with open(target, "w") as handle:
    json.dump(index, handle, separators=(",", ":"), sort_keys=True)

categorised = sum(1 for entry in entries.values() if "c" in entry)
print(f"  {len(entries)} domains, {categorised} with categories")
PYTHON

rm -f "${DESTINATION}/.tds.json"

SIZE="$(du -h "${TARGET}" | cut -f1)"
echo
echo "Installed ${TARGET} (${SIZE})"
echo
echo "Tracker data from DuckDuckGo Tracker Radar, Copyright (c) 2020 Duck Duck Go, Inc.,"
echo "licensed CC BY-NC-SA 4.0. NonCommercial: personal use only without permission."
