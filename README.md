# Beholder

A network traffic visualizer for macOS — see which process on your laptop is talking to
whom, where in the world that is, and how much data is moving.

Inspired by Little Snitch's Network Monitor. **Beholder observes; it does not block.**

```bash
git clone https://github.com/synerdjin/beholder.git && cd beholder
make run          # builds both halves, asks for your password once, opens the app
```

Requires macOS 14+ and Xcode's Swift toolchain. Nothing else — no Apple Developer account,
no third-party packages. `make help` lists every target; `make check` builds, runs the 101
tests and exercises the daemon's socket without needing root.

For the full setup — the optional databases, continuous capture, the MCP server — there is
a wizard that asks about each piece in the order the answers depend on each other, and does
nothing it did not ask about first:

```bash
make wizard       # install or update, one decision at a time
make reload       # after editing code: rebuild and restart whatever is running
```

Neither replaces the individual targets below; both are made of them. `make reload` is the
one to reach for during development, and it exists because **`make restart` restarts the
installed daemon, which is a copy taken at install time** — after an edit it faithfully
restarts the old binary. Updating and restarting are different operations; `reload` does
both, and touches only what was already running.

## Why not just do what Little Snitch does?

Little Snitch uses a Network System Extension built on `NEFilterDataProvider`. That
requires a paid Apple Developer account *and* the `content-filter-provider` entitlement,
which Apple grants by individual application. Without both, the extension will not start.

Beholder instead takes the packet-capture route:

- **libpcap** on the interface carrying the default route, for ground truth about bytes on
  the wire.
- **libproc**'s socket table, polled, to attribute each connection to a process.

Both are public API and need no entitlement — only root, because `/dev/bpf*` is
`root:wheel` mode 0600. The trade-off is that Beholder cannot intercept or block
connections, and attribution of very short-lived connections is best-effort.

## Architecture

```
beholderd (root, launchd)                    Beholder.app (user, SwiftUI)
  CaptureEngine   libpcap        ──socket──▶   live connection list
  Attributor      libproc          JSON        world map / throughput charts
  FlowTable       aggregation                  history browser
  Enricher        DNS, TLS SNI, GeoIP
  FlowStore       SQLite
```

The daemon holds all privilege and all state; the app is a pure view that can be closed or
crash without interrupting capture.

The link between them is a Unix domain socket carrying newline-delimited JSON, one
snapshot per second, mode 0600 and owned by the user who started it. Not XPC: that wants a
`MachServices` entry and, to validate the peer on the other end, a signing identity this
project does not have. The daemon is therefore strictly read-only over the socket — it
exposes no command that changes state, so an unauthenticated reader can learn only what
`lsof` would already tell it, whereas an unauthenticated *writer* would be a real hole.

## Following the VPN

This is the detail that makes or breaks the tool. When a VPN is connected, the default
route runs through a `utun` interface, and the physical `en0` carries nothing but
encrypted tunnel packets. Capturing the wrong interface produces output that looks
plausible and tells you nothing.

Beholder resolves the interface with an `RTM_GET` request on a routing socket — the same
answer `route -n get default` gives — and re-opens the capture when the route moves.

`utun` interfaces are also `DLT_NULL` (a 4-byte address-family word), not Ethernet.
Beholder resolves the link type per capture handle and refuses interfaces whose link type
it does not recognise, rather than guessing and misparsing everything.

Verified on a live connect / drop / reconnect cycle:

```
11:24:08  capture moved en0 → utun8      VPN connected
11:24:46  capture moved utun8 → en0      VPN dropped
11:25:46  capture moved en0 → utun8      VPN reconnected
```

Checked afterwards against the history database for gaps in new-flow arrival across the
whole window: **no gap longer than three seconds**. Capture followed the route each time
and kept counting, with no crash and no permanent blind spot. Note the direction — a
`utun8 → en0` line is the VPN going *down*, which is easy to read backwards.

## Status

**Phase 0 — capture foundation. Done, verified on-device.**

- [x] Link-layer handling: `DLT_NULL`, `DLT_EN10MB` (incl. VLAN), `DLT_RAW`, `DLT_LOOP`
- [x] IPv4/IPv6 parsing with extension-header walking and fragment handling
- [x] TCP/UDP/ICMP, with graceful handling of packets that carry no ports
- [x] Default-route discovery via routing socket
- [x] Capture engine: non-blocking pcap on a dispatch source, per-interface statistics

Measured on a live machine: 100% parse rate on a `utun` tunnel (224/224 packets) and
loopback (20/20), `ps_recv` matching the delivered packet count exactly, zero kernel
drops.

**Phase 1 — flows and attribution. Done, measured on-device.**

- [x] Process attribution via libproc, verified against `lsof`
- [x] Direction-normalised flow table with idle expiry and bounded eviction
- [x] Adaptive attribution polling, plus an immediate pass when a new flow appears
- [x] `--top`: live connections by process, sorted by volume
- [x] Transparent-proxy detection

Measured over a 45-second run with 211 flows: **95.3% of attributable flows named**. The
remainder were two-packet DNS exchanges on ephemeral sockets that are gone before any
poll can see them. ICMP is reported separately, since without ports there is no socket to
attribute it to at all.

### Transparent proxies defeat attribution

An earlier run named `com.nordvpn.macos.Shield` — NordVPN's Threat Protection system
extension — as the source of ~20 MB of web browsing, and attribution sat at 49.5%. That
was correct but useless: a transparent proxy intercepts an application's connection and
re-originates it from its own socket, so the originating application never appears on the
wire. Packet capture cannot recover the link; only a socket-layer filter can.

With Threat Protection disabled the same traffic correctly resolves to
`com.apple.WebKit.Networking`, and attribution rose to 95.3%.

Beholder detects a process that both dominates the flow table and reaches many distinct
hosts, and says so, rather than quietly presenting the proxy as the culprit.

**Phase 3a — hostnames. Done.**

- [x] DNS answer parsing, including CNAME chains and AAAA records
- [x] TLS SNI extraction from ClientHello
- [x] Name cache with retention that outlives short DNS time-to-live values
- [x] iCloud Private Relay ingress and egress recognition

Names come from two sources. SNI names the host for one specific connection and is
proof; a DNS answer says some name once resolved to an address, which is a good guess but
not proof, since one address commonly serves many names. DNS-derived names are shown with
a leading `·` so the two are never confused.

Neither source can see through Encrypted Client Hello or DNS-over-HTTPS, and neither can
see past iCloud Private Relay, which is labelled explicitly rather than shown as an
unexplained Apple address.

#### Private Relay does not simply switch off under a VPN

Apple disables Private Relay while a VPN is active, so relay connections appearing with a
VPN up look like a bug. They are not, and the distinction is between two different kinds
of host. From one machine's record across a VPN connect/disconnect cycle:

| | interface | when |
|---|---|---|
| **egress** (`apple-relay.cloudflare.com`) — traffic genuinely being relayed | en0 only | VPN down |
| **ingress / encrypted DNS** (`mask.*`) | en0 **and** utun8 | throughout |

The egress hosts — the second hop, where a destination really is hidden from this machine
— appear only while the VPN is down and stop entirely once it comes up. What continues is
almost all `mDNSResponder` talking to `mask.icloud.com:443`: macOS resolving names
privately, which runs over Private Relay infrastructure but is not browsing being relayed.
Apple *is* the destination there, and nothing is forwarded onward.

Beholder therefore says these connections' contents are encrypted and unreadable from
here, which is true of both, rather than claiming a hidden third-party destination that
for most of them does not exist.

**Phase 3b — capture follows the route. Done.**

Capture used to resolve the default route once at startup. Connect a VPN and the route
moves to a `utun`; drop it and it returns to `en0` — either way capture carried on
reading an interface nothing used any more, reporting a confident, well-formatted zero.
Changes are now detected by `NWPathMonitor` plus a slow backstop poll, and every
transition is shown, so a reconnect is visible rather than inferred from a gap.

Naming interfaces explicitly disables following: that is read as an instruction to stay
put, not a hint.

**Phase 2 — the app. Done.**

- [x] Daemon publishes snapshots over a Unix domain socket
- [x] SwiftUI viewer: connections grouped by process, with application icons
- [x] Menu bar extra showing live throughput
- [x] Throughput chart (Swift Charts)
- [x] Caveats surfaced in the UI rather than buried

```bash
make run
```

That builds both halves, asks for your password once, starts the daemon and opens the
app. Ctrl-C stops the daemon and quits the app. `make help` lists everything else —
`make top` for the terminal view, `make sockets` and `make selftest` for the parts that
need no root, `make report` to print the last run's summary.

#### The socket contract

Two bugs in the publishing socket were subtle enough to be worth recording, because both
presented as something other than what they were, and `make check` now guards each.

**Snapshots must arrive whole.** Client sockets are non-blocking, so a snapshot larger
than the kernel send buffer takes several writes. Giving up when the buffer fills does not
skip a snapshot — it destroys the framing. The terminating newline is never sent, the next
snapshot is appended to a truncated one, and the reader can never resynchronise. The
daemon looked healthy from outside while delivering 65,536 bytes containing zero complete
messages, and the app showed an empty window. Messages are now queued per client and
finished across writes, with at most one whole snapshot held behind the one in flight.

**A reader leaving must not kill the daemon.** Writing to a socket whose peer has gone
raises `SIGPIPE`, whose default disposition terminates the process — so quitting the app
could stop capture. `SO_NOSIGPIPE` per socket is not enough: `setsockopt` returns `EINVAL`
when the peer closed before the connection was accepted, leaving the option unset on
exactly the socket that needed it. The signal is ignored process-wide instead.

It stays two processes on purpose. Capture reads `/dev/bpf*` and needs root; a GUI must
not run as root, or it owns windows as root and writes root-owned preferences into your
home directory. The only question is who arranges the two, and a `sudo` prompt in your
own terminal is more honest than an app escalating behind a dialog. Running them by hand
also works:

```bash
sudo ./.build/debug/beholderd --serve --loopback   # capture, needs root
./Scripts/build-app.sh && open .build/Beholder.app # viewer, does not
```

`--serve` draws nothing so it can sit in the background; add `--top` to watch it in the
terminal at the same time.

The plan called for XPC. XPC to a root daemon means registering it under
`/Library/LaunchDaemons` — a persistent system change, and realistically one wanting a
signing identity to be pleasant. A Unix socket carrying newline-delimited JSON needs
neither, so the app works today and the daemon stays something started and stopped by
hand. The socket is 0600 and owned by the user who ran `sudo`, for the same reason the
transcript is.

The daemon publishes and never accepts commands. While there is no signing identity to
validate a peer with, an unauthenticated *reader* can only see what `lsof` would already
show it; an unauthenticated writer would be a real hole.

There is no Xcode project. A macOS app bundle is a directory with an `Info.plist` in it,
and `Scripts/build-app.sh` arranges one around the SwiftPM binary.

**Later**

- [ ] GeoIP and the world map — rest of Phase 3
- [ ] SQLite history — Phase 4

## Building and running

```bash
swift build
swift test
```

Capture requires root. For the live connection view:

```bash
sudo ./.build/debug/beholderd --top --loopback
```

For per-interface capture statistics instead, drop `--top`. In that view the **parsed**
column is the one to watch: if packets are arriving but `parsed` stays near zero, the
link-layer assumption for that interface is wrong. **BPF-RECV** climbing while **PKTS/S**
stays at zero means packets are being captured but not drained.

With no interface arguments it captures whatever carries the default route. Pass names to
override, or `--loopback` to add `lo0`.

### Run transcripts

Every run writes a transcript to `logs/`, with the newest always at `logs/latest.log`.
It records the starting conditions, a snapshot every 30 seconds, every interface change,
and a full final report — the complete flow list, not the excerpt the console shows.
Snapshots mean a run that is killed rather than stopped cleanly still leaves evidence.

Use `--log DIR` to put it elsewhere, or `--no-log` to turn it off.

The file is created mode 0600 and handed to the user who invoked `sudo`, rather than left
owned by root. It lists every host this machine contacted, so it is personal data: it is
readable only by its owner, and `logs/` is in `.gitignore`.

Two subcommands need no root:

```bash
./.build/debug/beholderd --sockets
```

dumps the socket-to-process table for comparison against `lsof -nP -i TCP`, and
`--self-test` runs the timers and render path without capturing, which is enough to catch
the isolation and object-lifetime faults that otherwise only appear under `sudo`.

## Privacy

Beholder sees everything this machine does, so it is deliberately conservative:

- Metadata only. Packet payloads are never stored; the 512-byte snaplen exists to read
  headers, DNS answers and TLS SNI, and bulk payload stays in the kernel.
- Promiscuous mode is off. Beholder watches this host, not the local network.
- No telemetry. Beholder never contacts anything on its own. Two things can send data off
  this machine, both explicit and both started by you: downloading the GeoIP and tracker
  databases, and the MCP server.

The MCP server is the one worth stating plainly rather than leaving to be inferred. When
you register it and an assistant calls one of its tools, what it read goes to Anthropic:
**hostnames, process names, IP addresses, byte counts, timestamps, and the country,
network and company behind each address** — the contents of this database, unredacted, for
whatever window was asked about. That is the entire point of the thing. There is no way to
answer "what did Slack talk to overnight" without the answer leaving the machine.

A redacting mode was considered and dropped. Pseudonymised hostnames make the answers
worthless — "host-4f2a used 2 GB" answers nothing anyone asked — and a half-private mode
is worse than none, because it invites you to believe less left the machine than did. So
it is full fidelity, off until registered, and written down here instead of buried.

Hostnames arrive from the network, which means anyone who can make this machine resolve a
name chooses a string that ends up in an assistant's context. They are sent as delimited
data rather than prose, truncated to the length a real name can be, and stripped of
control characters. They are deliberately **not** filtered on content: a keyword blocklist
would hide the interesting hostname, and a network-visibility tool that quietly omits the
suspicious host has defeated its own purpose.

## Known limitations

- Very short-lived connections may show as "unknown" — an inherent race in socket-table
  polling that only a kernel-level filter avoids.
- Hostnames are unavailable for connections using TLS Encrypted Client Hello.
- Per-process **blocking** is out of scope; it cannot be built without the Apple
  entitlement described above.
- Byte counts are wire bytes on the captured interface. Capturing the tunnel excludes VPN
  encapsulation overhead, so totals will differ slightly from what `en0` sees.
- A transparent proxy — NordVPN's Threat Protection is one — re-originates connections
  from its own socket, so the originating application is not on the wire to be found.
  Beholder says so rather than presenting the proxy as the culprit, but it cannot recover
  the link. The historical view carries a coarser version of that caveat than the live one:
  the warning is computed over live flows and the `flows` table has no column to record it,
  so it is re-derived from the same thresholds at query time and names the process rather
  than the individual connections it affected.
- ICMP has no ports and therefore no socket, so it is never attributed to a process and is
  counted separately rather than inflating the unattributed figure.
- Unsigned, so installing the daemon needs a `sudo` script rather than `SMAppService`, and
  macOS may require a one-time approval in Login Items & Extensions. A Developer ID would
  remove both.

## Geolocation

Connections are placed on a map using a local database, installed separately:

```bash
make geoip
```

That fetches DB-IP City Lite (~124 MB). DB-IP publishes it free and monthly with no
account, under CC BY 4.0 — MaxMind's better-known GeoLite2 now requires signing up for a
licence key, which is a poor fit for something you should be able to build and run
without registering anywhere.

Lookups are entirely offline. A tool for watching what your machine talks to has no
business querying a geolocation API, because the query would leak exactly the information
it exists to show you.

The `.mmdb` reader is written here rather than pulled in as a dependency: the format is
well specified, the code is testable, and the file is memory-mapped so a 124 MB database
costs a daemon almost no resident memory.

> This product includes GeoLite data created by DB-IP, available from
> <https://db-ip.com/>, licensed under CC BY 4.0.

## Who is on the other end

```bash
make trackers
```

Installs an ownership index built from DuckDuckGo's tracker blocklist, letting the app
group connections by the company operating them rather than only by the app making them —
"Google, 14 connections" is a question no per-process listing can answer, since one
company is reached by many apps and one app talks to many companies.

**Licence:** the Tracker Radar data is CC BY-NC-SA 4.0 — NonCommercial and ShareAlike.
That is why it is fetched rather than committed. Personal use is fine; commercial use
needs permission from DuckDuckGo.

> Tracker data from DuckDuckGo Tracker Radar, Copyright (c) 2020 Duck Duck Go, Inc.,
> licensed under CC BY-NC-SA 4.0.

### What it does and does not know

Tracker Radar is built by crawling websites, so it covers third-party web trackers
thoroughly and native application telemetry not at all. Measured against real capture
transcripts from this machine, `static.xx.fbcdn.net` and `mobile.events.data.microsoft.com`
are identified, while `telemetry.individual.githubcopilot.com` and `crash.steampowered.com`
appear in no tracker list whatsoever.

Beholder therefore reports a second, separate signal: whether the hostname contains a word
operators conventionally use for data collection. That is a fact about the *name*, not
about behaviour, and it is labelled that way.

Nothing here is a verdict. `api.anthropic.com` is an application doing its job and
`browser-intake-us5-datadoghq.com` is telemetry, yet both are an app talking to its vendor
over TLS — only the person using the machine can judge which they mind. Being
**unrecognised** is likewise the ordinary condition of most of the internet, not a finding.

## History

Finished connections are written to a SQLite database as they retire, so the picture
survives the daemon stopping.

The app has a **History** tab, and there are command-line equivalents:

```bash
make history           # the last day
make history-week      # the last week
make history-csv       # export
```

The History tab reads the database directly rather than asking the daemon, so it works
when nothing is capturing — which is exactly when you want to look at it. It opens the
file read-only, so a viewer can never alter what was recorded.

Querying needs no root and no running capture. `--match` filters on app, host, address,
company or network — the same fields the live view searches, so a query learned in one
place works in the other.

Two tables: `flows` keeps one row per completed conversation for 30 days, and `rollups`
keeps per-minute totals per process for a year. A chart spanning weeks reads the rollups;
scanning millions of flow rows to draw it would not do.

The database lives beside the name cache under your own Application Support directory,
mode 0600, owned by you rather than root — it records every host this machine contacted.

Every report states the window it actually covers, because an empty result is otherwise
ambiguous between "nothing happened" and "nothing was watching".

## Asking it questions

The history database answers questions the History tab cannot phrase. Beholder ships an
MCP server so an assistant can read it on your behalf — "what did Slack talk to
overnight", "have I ever contacted this address", "what was the biggest thing this laptop
downloaded this week".

```bash
make mcp
make mcp-add     # prints the claude mcp add line; run it yourself
```

It is off until you register it, and `claude mcp remove beholder` ends it.

Four tools: recorded history, one endpoint's whole story, a live snapshot, and a health
check. Four rather than a dozen on purpose — every tool's description sits in the
assistant's context on every turn of every conversation, including the ones that have
nothing to do with networking, so the set is a budget rather than a catalogue.

Answers are grouped, not dumped. Two days of capture here is 24,000 connection rows across
480 hostnames — about thirty rows for every host-and-application pair, and over a thousand
for one busy API endpoint. Handing those to a reader to add up is both expensive and
unreliable when the answer wanted was one number, so the grouping happens in SQLite and
the summary is what travels.

It is read-only by construction: the database is opened `SQLITE_OPEN_READONLY`, no tool
takes a path or a SQL string, not one byte is written to the daemon's socket, and no
subprocess is ever spawned. There is no SQL passthrough tool and there will not be one —
read-only SQL still reaches other files through `ATTACH`, still returns unbounded results,
and turns a fixed set of questions into an injection surface fed by generated text.

**Do not run it under `sudo`.** It would resolve paths under root's home rather than
yours, find an empty database, and hand an assistant's tool calls a root process for
nothing. It says so on stderr if you do.

The socket is mode 0600 and owned by whoever started capture. If that was a different
account the server gets `EACCES`, and `beholder_status` reports it as that — naming the
uid that owns the socket — rather than as a daemon that is not running, because those two
have entirely different fixes.

## Capturing continuously

```bash
make install     # asks for your password
make status
make uninstall
```

`make wizard` reaches the same place while explaining each step, and re-running it is the
update path. Whichever you use, `make reload` is what puts a code change into the running
daemon afterwards: it reinstalls the binary and only then kickstarts the job.

This is what makes history worth having. A database that only fills while you are watching
answers the same questions the live view already does; one that filled while you were not
is what answers "what did this app do on Tuesday".

### If the daemon does not appear to run

Since Ventura, macOS registers daemons from unidentified developers and can decline to
start them until approved, with no prompt. If that is what is happening, open **System
Settings → General → Login Items & Extensions**, find Beholder, and turn it on. This is a
consequence of having no Developer ID: a signed daemon would appear under a real name,
while an unsigned one shows up as something opaque that a user has little reason to trust
— which is precisely what the gate is for.

**Check before assuming that is the cause.** A daemon that crash-loops looks almost
identical from the outside: no process, `runs` climbing steadily, and both log files
empty — because a process killed by a signal never flushes buffered output, so one that
dies during startup leaves nothing behind. The two are told apart by a single field:

```
launchctl print system/com.beholder.daemon | grep "last terminating signal"
```

If that field is set, the job has been running and dying, and no amount of approving it
in System Settings will help. `make doctor` reads it and says which case you are in.

This distinction is in the README because getting it wrong cost real time: a crash loop
was read as approval-pending and left restarting four thousand times.

It is a genuine change to your system, so it is a separate opt-in rather than something
`make run` does quietly. It installs exactly two things — `/usr/local/libexec/beholderd`
and `/Library/LaunchDaemons/com.beholder.daemon.plist` — plus any optional databases, and
`make uninstall` removes all of it. **Your captured history is never deleted by the
uninstaller**; deleting a record of everywhere your machine has been is not a decision an
uninstall script should make for you.

With a Developer ID this would be `SMAppService` instead, letting the app install and
remove the daemon itself with a proper entry in System Settings.

## Licence

Beholder is MIT licensed — see [LICENSE](LICENSE).

That covers the code in this repository. The two optional databases are **fetched at
runtime and never redistributed here**, and keep their own terms:

| Data | Licence | Fetched by |
|---|---|---|
| DB-IP City Lite / ASN Lite | CC BY 4.0 | `make geoip` |
| DuckDuckGo Tracker Radar | CC BY-NC-SA 4.0 — **NonCommercial**, ShareAlike | `make trackers` |

The tracker index being NonCommercial is why it is downloaded rather than committed:
personal use is fine, commercial use needs permission from DuckDuckGo.
