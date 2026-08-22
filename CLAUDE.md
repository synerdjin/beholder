# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Beholder is a macOS network traffic visualizer: which process is talking to whom, where in
the world that is, and how much data is moving. It observes by default; with `--block` it
also stops traffic to destinations named in a root-owned list.

## Commands

```bash
make check          # the gate: build (fails on ANY warning) + tests + the shell tests
make build          # daemon + app bundle
swift test          # unit tests only
make help           # every target
```

Needing root (capture reads `/dev/bpf*`, mode 0600 root:wheel):

```bash
make run            # build both halves, start the daemon, open the app
make serve          # capture and publish, drawing nothing
make top            # live connection table in the terminal
make stop
make reload         # rebuild, then restart whatever is already running
make wizard         # install or update, asking about each piece
```

`make reload` (`Scripts/reload.sh`) is the after-an-edit command, and the reason it is not
`make restart` matters: the launchd job runs `/usr/local/libexec/beholderd`, a **copy taken
at install time**, so `restart` kickstarts the old binary and the change appears not to
have worked. `reload` reinstalls the binary first, quits and reopens the app around the
bundle rebuild, and restarts only what was already running — it installs nothing new. It
follows the installed configuration (release when a daemon is installed, debug otherwise)
and ignores the Makefile's `CONFIG`; `BEHOLDER_CONFIG` overrides, the same name
`install-daemon.sh` takes. `make wizard` (`Scripts/wizard.sh`) is the opposite end:
interactive, re-runnable as the update path, and it asks before every step. Neither
replaces the individual targets; both are composed of them, so a change to
`install-daemon.sh`, `install-mcp.sh` or `fetch-*.sh` is picked up by both.

`reload` deliberately does **not** delegate the daemon swap to `install-daemon.sh`: that
replaces the job by `bootout`/`bootstrap`, which for an unsigned daemon can land back in
the "registered but never started, waiting for Login Items approval" state `doctor.sh`
exists to diagnose. `kickstart -k` keeps the job registered. The cost is that the plist is
not rewritten, so `reload` warns when `install-daemon.sh` is newer than the installed
plist and points at `make install`.

Needing no root — use these when iterating:

```bash
make selftest       # timers, rendering and shutdown with no capture
make sockets        # socket-to-process table (compare against `lsof -nP -i TCP`)
make route          # which interface currently carries the default route
make history        # query the history database
make doctor         # diagnose why the app cannot see the daemon
```

### Running a single test

`--filter` matches Swift **type and function names**, not the `@Test("display name")`
string. Filtering on the display name silently matches zero tests and still exits 0.

```bash
swift test --filter 'SnapshotClientTests/timesOutOnSilence'   # one test
swift test --filter 'SnapshotClientTests'                     # one suite
```

### Optional databases

`Resources/geoip/` and `Resources/trackers/` are gitignored and fetched at runtime
(`make geoip`, `make trackers`, or `make data`). They are downloaded rather than committed
for licence reasons — the DuckDuckGo tracker index is CC BY-NC-SA (NonCommercial). Tests
that need them skip cleanly when absent; don't add them to the repo.

## Architecture

Five SwiftPM targets plus a test target. **There is no Xcode project and none is wanted** —
`Scripts/build-app.sh` arranges an `Info.plist` around the SwiftPM binary to make
`.build/Beholder.app`.

| Target | Role |
|---|---|
| `CBeholderShim` | C shim re-exporting pcap, libproc, route and sqlite3 headers |
| `BeholderCore` | All pure, testable logic. No privilege. |
| `beholderd` | The root capture daemon |
| `BeholderApp` | SwiftUI viewer, unprivileged |
| `BeholderMCP` | MCP server, unprivileged, read-only |

**The daemon holds all privilege and all state; every other binary is a reader.** The app
and the MCP server can be closed, crash, or never run without interrupting capture.

### Channels out of the daemon, and the one in

1. **Live** — a Unix domain socket (`/var/run/beholder.sock`) carrying newline-delimited
   JSON, one whole `FlowSnapshot` per second. Not XPC: that wants a `MachServices` entry
   and a signing identity this project deliberately does without. This socket is **strictly
   read-only** — it accepts no command at all, so an unauthenticated reader learns only what
   `lsof` would already tell them. Preserve that: widening it would make every reader a
   potential writer, and a writer here gets a firewall.
2. **Historical** — a SQLite database that readers open **read-only**, so it works when
   nothing is capturing, which is exactly when you want to look at it.
3. **Control** — a *second* socket (`/var/run/beholder-control.sock`) that does accept
   commands, and therefore authenticates its peer against a pinned code identity. Only
   blocking travels over it; see below.

`WireProtocol.swift` is the contract for (1) and lives in Core precisely so the two ends
cannot disagree about it. Bump `WireProtocol.version` on any incompatible change; both
sides check it and fail with a clear message rather than decoding into nonsense.

Adding a field is *not* an incompatible change, provided you keep it decodable when absent
— and Swift will not do that for you. Synthesised `Codable` ignores property defaults, so a
plain `var x = 0` still fails to decode when the key is missing. New `WireFlow` and
`FlowSnapshot` fields are therefore `Optional`, and `WireStatistics` has a hand-written
`init(from:)` that reads every counter with `decodeIfPresent`. `WireCompatibilityTests`
decodes a literal snapshot from an older daemon to keep that honest; if it fails, bump the
version rather than loosening the test.

### Capture pipeline

`CaptureEngine` (pcap, snaplen 1024, filter `ip or ip6`, promiscuous off) → `PacketParser`
→ `FlowTable.record` → enrichment → published and persisted. `FlowMonitor` is the hub that
orchestrates enrichment and is where most cross-cutting behaviour lives.

Enrichment sources, each independent and each degrading gracefully when absent: `Attributor`
(libproc socket table, adaptively polled), `PayloadInspector` (TLS SNI, DNS answers,
protocol identification, and optionally payload bytes), `ReverseResolver`, `GeoIPDatabase`,
`ASNDatabase`, `TrackerDatabase`, `ProxyDetection`.

**`PayloadInspector.inspect` is the only place payload bytes are reachable.** It runs
synchronously inside the pcap callback because the buffer dies when that returns; anything
that wants payload must extract it there and return an owned value. Do not add a second
pass over the same bytes — widen `PacketObservation` instead.

### Payload reading is opt-in and memory-only

`--read-cleartext` keeps the opening 4 KB per direction of connections that are not
encrypted, so the app's `Cleartext` view can display them. `PayloadExcerptStore`
(flowQueue-confined, bounded at 64 flows, released on flow retirement) holds them, and
`FlowSnapshot.cleartextExcerpts` publishes them.

Three rules that are load-bearing, not stylistic:

- **Payload never reaches `FlowStore`, `RunLog`, or `MCPToolbox`.** The README states this
  plainly to the user. Do not add a persistence column, a transcript section, or an MCP
  tool that returns bytes.
- **`cleartextExcerpts` is `Optional` and nil ≠ empty.** Nil means nothing is reading
  payload; empty means it is reading and found nothing. The app renders four different
  screens off that distinction.
- **The capture-queue gate is `shouldCopy`.** A packet is copied unless it was *read* as
  encrypted. A port-only `encrypted` reading does not exempt it — plaintext on 443 is the
  single most interesting thing this feature can find.

The per-snapshot budget lives in `PayloadExcerptStore.publishable(budget:)` and the
display parsers in `PayloadRendering.swift` (`HTTPPreview`, `HexDump`) — all in Core, not
in the daemon or the app, because they are the parts worth testing. `HTTPPreview` in
particular parses bytes chosen by whoever is on the far end.

### Blocking is by destination, opt-in, and configured by file

`--block` fills a pf table from a root-owned block list. Five rules that are load-bearing:

- **The ruleset is static; only the table changes.** `PacketFilterPlan.anchorRuleset` is
  written once by `install-pf-anchor.sh` and never generated. Nothing derived from a list,
  a packet or a DNS answer is concatenated into a pf rule — the only runtime change is
  table membership, and every entry has been through `IPAddress` and back out of
  `inet_ntop`. `pfctl` is spawned with an argv and an absolute path, never a shell, never
  `PATH`. Do not add a code path that builds rule text at run time.
- **The publishing socket stays read-only; commands go over a second socket that
  authenticates its peer.** Widening the first would have made every reader a potential
  writer. `ControlServer` admits a connection only when the peer's audit token
  (`LOCAL_PEERTOKEN`, never `LOCAL_PEERPID` — pids get reused) yields a `SecCode` satisfying
  a requirement pinned in a root-owned file. An ad-hoc `cdhash` is a perfectly good identity;
  no Developer ID is involved. The MCP server reaches none of it.
- **Two list files, and only one is rewritten.** `blocklist.conf` is a person's, and the
  daemon never regenerates it; `blocklist.app.conf` is the daemon's. pf enforces the union,
  and `EnforcedBlockList` marks fixed entries non-removable so the UI cannot offer a button
  that would fail. Both files must be root-owned and not group- or other-writable —
  `BlockList.verdict` decides that, and takes a `readerUID` so an unprivileged process can
  apply the same rule to a file it owns without loosening it.
- **Anything that writes to a socket must guard SIGPIPE.** The control server authenticates
  on *accept* and refuses by replying and closing, so a client can find the peer gone before
  it has written a byte. `SnapshotClient.connect` sets `SO_NOSIGPIPE`, the app ignores SIGPIPE
  process-wide as the daemon does, and `ControlClient` reads the reply even when the write
  failed — the refusal explaining why is already in the receive buffer. Without this the app
  died on exit 141 with no message and no crash report. A python3-driven shell test cannot
  catch it, because Python ignores SIGPIPE by default; `ControlClientTests` uses a real
  in-process server that hangs up immediately.
- **A note is the only free text that becomes file content.** `BlockList.render` strips
  newlines and `#` from it; without that, a note could write a destination of its own onto
  the next line. There is a test pinning it.
- **It refuses rather than half-works.** No anchor, an unreadable list, one unparsable line
  — all of them stop the daemon. Enforcing the part of a list that happens to parse leaves
  someone believing a destination is blocked when it is not, which is the same failure
  `ProtocolSniffer` avoids by never guessing `encrypted`.
- **Blocking lasts exactly as long as the daemon.** Teardown is an `atexit` hook, so it
  covers every path that calls `exit` including `fail()`. `SIGKILL` runs nothing, which is
  what `make unblock` is for. Do not make blocks persist across a stop.
- **By destination, never by process.** pf cannot match a process and no entitlement-free
  API can. `BlockList.Entry` deliberately has no process field, and any UI built on this
  must not imply otherwise.

`quick`, `return`, `out` and `log` in the rule were each chosen against a named alternative
and are pinned by tests; the reasoning is in `PacketFilterPlan` and in the README. The
anchor text has exactly one source — `beholderd --print-pf-anchor` — because two copies of a
pf ruleset in two languages drift, and the drift shows up as an anchor that loads cleanly
and matches nothing.

### `cleartext` is proof, `encrypted` is inference, `unknown` is neither

`ProtocolSniffer` classifies every connection, always, whether or not payload reading is
on. The asymmetry is deliberate and there are tests pinning it: unrecognised bytes are
`unknown`, never `encrypted`, because failing to parse something is not evidence that it is
protected — and being wrong in the reassuring direction is the worst way to be wrong here.

`ProtocolSniffer.Evidence` is a `Comparable` ladder (`.port < .payload`) copying
`NameSource`. `FlowTable.applyReading` never downgrades, and additionally treats proven
cleartext as sticky: a connection that carried bytes in the clear did carry them, and a
later TLS record — real STARTTLS, or binary in an HTTP body that happens to look like a
record header — must not turn that into "encrypted".

**Capture follows the default route.** With a VPN up the route moves to a `utun` and `en0`
carries nothing but encrypted tunnel packets — capturing the wrong interface produces
output that looks plausible and means nothing. `InterfaceSupervisor` re-opens capture on
every transition. Naming interfaces explicitly disables following: that is read as an
instruction to stay put, not a hint.

### Concurrency

- **`@main` on a type, never top-level code.** Top-level code in Swift 6 is
  `@MainActor`-isolated, which makes any dispatch-queue callback touching top-level state
  trap at runtime. Every executable here follows this.
- **`FlowStore` and `FlowTable` are not thread-safe.** In the daemon they are confined to
  `FlowMonitor.flowQueue`. Readers open their own short-lived instance instead of sharing one.
- Objects owning dispatch sources must be retained for the process lifetime —
  `dispatchMain()` never returns, so the compiler may otherwise release `main()`'s locals
  and leave the process alive but silent.

## Conventions that will trip you up

**Zero third-party dependencies, and this is a hard value.** The `.mmdb` reader, the JSON
value type, and the MCP JSON-RPC layer are all hand-written for this reason. Do not add a
package to solve a problem of this size.

**`make check` fails on any warning.** Not just errors.

**Executable targets cannot be reached by unit tests**, so behaviour that only exists in a
binary is covered by shell tests in `Scripts/` (`test-publishing-socket.sh`,
`test-mcp-stdio.sh`, `test-pf-anchor.sh`, `test-control-socket.sh`), sharing their assertions
from `Scripts/lib/test-helpers.sh`. All four are wired into `make check`. **A python3-driven
shell test proves the daemon, never the Swift client** — Python ignores SIGPIPE and buffers
writes, so two client faults hid behind a passing suite: the app dying on SIGPIPE, and every
control request failing to send because `SnapshotClient.connect` ends in `shutdown(SHUT_WR)`.
Anything the app does over a socket needs an in-process test with a real peer, and the fake
peer must *read the request* before replying or it cannot tell a working client from one whose
every write fails. The control one proves peer authentication in *both* directions and discovers
the peer's identity from the daemon's own refusal rather than from the interpreter's path —
because Homebrew's `python3` re-execs into `Python.app`, which is the same trap the
authenticator exists to avoid. The pf one guards the same class of bug as the MCP one with a
worse blast radius: `install-pf-anchor.sh` redirects `--print-pf-anchor` straight into
`/etc/pf.anchors`, so a stray `print()` in the startup path writes a corrupt ruleset into a
system file rather than producing a confusing message.

If you add logic to an executable, either move it into `BeholderCore` where a test can reach
it, or extend the matching shell test.

**Put contracts in `BeholderCore`, not in the executable.** The rule "no privilege, testable
without root" is what Core is protecting — value types and pure functions belong there even
when they describe I/O. `UnixSocket` (bind, connect, the `sockaddr_un` dance, the stale-socket
probe), `SecureFile` (the "not writable by anyone less privileged than its reader" rule) and
`EnforcedBlockList.read` all live there because each had been written two or three times
across the two servers and the two list readers. The tell is always the same: a preview
command and the daemon it previews disagreeing, or one copy of a security check being subtly
kinder than the next.

**`BeholderPaths` resolves `SUDO_USER`.** Capture runs under `sudo` and must write to the
invoking user's Application Support, never root's. A tool started via `su -` rather than
`sudo` writes to `/var/root/…` and then looks empty from a normal shell — which is why
diagnostics always print the path they checked.

**`logs/` is personal data** — run transcripts list every host the machine contacted. It is
gitignored, along with the databases. Never commit either.

**The MCP server's stdout carries nothing but JSON-RPC.** There is no framing header to
resynchronise from, so a single stray `print()` anywhere in its startup path corrupts the
stream permanently and surfaces only as an unexplained client-side parse error. Use stderr
for anything human-facing. This is also why it is a separate binary from the chatty `beholderd`.

**The MCP surface is five tools, and the count is a budget.** Every tool's schema sits in
the client's context on every turn, including conversations that have nothing to do with
networking. `network_quality` was added as a fifth because it answers a different *kind* of
question from the other four — keyed by time rather than by identity — and folding it into
`network_history` would have given one tool two schemas. Three places pin the list and all
three must move together: `MCPProtocolTests`, `Scripts/test-mcp-stdio.sh`, and the design
note at the top of `MCPTools.swift`.

**`FlowStore` migrations are versioned and append-only.** `migrate()` runs an ordered list
keyed on `PRAGMA user_version`; a database from a newer build is refused rather than read,
for the same reason `WireProtocol.version` refuses a snapshot it cannot decode. Never edit a
shipped step — a database in the field has already run it, so the edit reaches only new
databases and quietly gives two files the same version and different shapes. Append instead.
`readOnly: true` still skips migration entirely, which is what keeps a viewer from altering
what the daemon recorded.

**Nil is not zero, for anything measured.** A latency of nil means nothing measured it; zero
would mean a perfect connection. QUIC yields no round trips at all, so absence is a common
and honest state, and the UI shows an em dash rather than a number. The same distinction
runs through `WireStatistics` (optional quality counters), `FlowQuality`, and the reports:
what is counted is *retransmissions*, never "packet loss", because a passive observer sees
the repeat and not the drop.

**Quality measurement is on by default; payload reading is not.** The asymmetry is
principled and belongs in any comment that touches it: cleartext reading touches the
contents of traffic, while measurement reads only headers the kernel already handed over.
More decisively, measurement has to be running when the trouble happens, so an opt-in flag
would leave the data missing exactly when someone goes looking for it.

**`--probe` is the only thing here that sends, and `--block` the only thing that changes
what the machine can reach.** Both are off by default and announce themselves on startup;
neither is something to make implicit. `--probe` exists for the two questions passive
capture cannot answer at all — whether the link worked while idle, and whether a fault is
the local Wi-Fi or the uplink — and its results are excluded from Beholder's own
measurements *by process*, never by a capture filter, since a filter on those addresses
would also hide genuine traffic to them.

**There is no `query_sql` MCP tool and there should never be one.** Read-only SQLite still
reaches other files via `ATTACH`, still returns unbounded results, and turns a fixed set of
questions into an injection surface fed by generated text.

## Writing style

The README is the design document, not a quickstart, and it is unusually detailed on
purpose. Comments and prose here explain **why** a decision was made — naming the
alternative that was rejected and, where relevant, the bug that motivated it. Several
comments exist specifically because getting something wrong once cost real time (the
socket framing bug, the crash-loop-versus-pending-approval diagnosis, the mDNSResponder
false positive in proxy detection). Match that register: when you fix something subtle,
record why in the code or the README rather than only in a commit message.

Two rules that recur throughout and are worth keeping:

- **Every report states the window it actually covers**, because an empty result is
  otherwise ambiguous between "nothing happened" and "nothing was watching".
- **Caveats travel with the data.** A UI or an answer that shows totals without saying they
  are an undercount is worse than one that shows nothing. Attribution can be defeated by a
  transparent proxy, byte counts can be undercounts when packets drop, and DNS-derived
  hostnames are a good guess where SNI is proof — all of these are surfaced rather than
  smoothed over.
