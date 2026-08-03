# Beholder

A network traffic visualizer for macOS — see which process on your laptop is talking to
whom, where in the world that is, and how much data is moving.

Inspired by Little Snitch's Network Monitor. **Beholder observes; it does not block.**

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
beholderd (root, launchd)                Beholder.app (user, SwiftUI)
  CaptureEngine   libpcap        ──XPC──▶  live connection list
  Attributor      libproc                  world map / throughput charts
  FlowTable       aggregation              history browser
  Enricher        DNS, TLS SNI, GeoIP
  FlowStore       SQLite
```

The daemon holds all privilege and all state; the app is a pure view that can be closed or
crash without interrupting capture.

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
- No telemetry. The only outbound request it ever makes is an explicit, user-initiated
  GeoIP database download.

## Known limitations

- Very short-lived connections may show as "unknown" — an inherent race in socket-table
  polling that only a kernel-level filter avoids.
- Hostnames are unavailable for connections using TLS Encrypted Client Hello.
- Per-process **blocking** is out of scope; it cannot be built without the Apple
  entitlement described above.
- Byte counts are wire bytes on the captured interface. Capturing the tunnel excludes VPN
  encapsulation overhead, so totals will differ slightly from what `en0` sees.

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

## Capturing continuously

```bash
make install     # asks for your password
make status
make uninstall
```

This is what makes history worth having. A database that only fills while you are watching
answers the same questions the live view already does; one that filled while you were not
is what answers "what did this app do on Tuesday".

It is a genuine change to your system, so it is a separate opt-in rather than something
`make run` does quietly. It installs exactly two things — `/usr/local/libexec/beholderd`
and `/Library/LaunchDaemons/com.beholder.daemon.plist` — plus any optional databases, and
`make uninstall` removes all of it. **Your captured history is never deleted by the
uninstaller**; deleting a record of everywhere your machine has been is not a decision an
uninstall script should make for you.

With a Developer ID this would be `SMAppService` instead, letting the app install and
remove the daemon itself with a proper entry in System Settings.
