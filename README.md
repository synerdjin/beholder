# Beholder

A network traffic visualizer for macOS — see which process on your laptop is talking to
whom, where in the world that is, and how much data is moving.

Inspired by Little Snitch's Network Monitor. **Beholder observes by default**, and it also
measures how well the network is working — latency, retransmissions, jitter — and can tell
you whether a bad stretch was your connection's fault or the far end's.

Two things it can do beyond watching, both off unless asked for and both announced when
they are on: it can [send](#--probe-the-one-thing-that-sends) a small probe, and it can
[block](#blocking) destinations you name. Everything else here reads and reports.

```bash
git clone https://github.com/synerdjin/beholder.git && cd beholder
make run          # builds both halves, asks for your password once, opens the app
```

Requires macOS 14+ and Xcode's Swift toolchain. Nothing else — no Apple Developer account,
no third-party packages. `make help` lists every target; `make check` builds, runs the 389
tests and exercises the daemon's socket without needing root.

For the optional databases, continuous capture and the MCP server there is a wizard that
asks about each in the order the answers depend on each other, and does nothing it did not
ask about first. [Blocking](#blocking) is installed separately, on purpose:

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
`root:wheel` mode 0600. The trade-off is that Beholder cannot *intercept* a connection —
it sees packets, it does not sit in the path — and attribution of very short-lived
connections is best-effort.

Blocking is a separate question from interception, and the answer is different. Beholder
can block, using **pf**, the packet filter macOS inherits from OpenBSD: it is in the kernel
already, `pfctl` configures it, and root is the only requirement. What pf cannot do is
match on a process, so Beholder blocks by destination. See [Blocking](#blocking), which is
where that distinction is spelled out rather than left to be discovered.

## Architecture

```
beholderd (root, launchd)                    Beholder.app (user, SwiftUI)
  CaptureEngine   libpcap        ──socket──▶   live connection list
  Attributor      libproc          JSON        world map / throughput charts
  FlowTable       aggregation                  history browser
  Enricher        DNS, TLS SNI, GeoIP
  FlowStore       SQLite
```

The daemon holds all privilege and all state; the app can be closed or crash without
interrupting capture. It reads snapshots, and — with blocking installed — is the one program
allowed to ask the daemon to change what is blocked.

The link between them is a Unix domain socket carrying newline-delimited JSON, one
snapshot per second, mode 0600 and owned by the user who started it. Not XPC: that wants a
`MachServices` entry and, to validate the peer on the other end, a signing identity this
project does not have.

**That socket is strictly read-only** — it exposes no command at all, so an unauthenticated
reader learns only what `lsof` would already tell it, whereas an unauthenticated *writer*
would be a real hole. Blocking, which does change state, travels over a second socket that
authenticates its peer; see [Blocking](#blocking).

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

There is no Xcode project. A macOS app bundle is a directory with an `Info.plist` in it,
and `Scripts/build-app.sh` arranges one around the SwiftPM binary.

**Phase 3c — geolocation and ownership. Done.**

- [x] Hand-written `.mmdb` reader, world map, autonomous-system and tracker lookup

See [Geolocation](#geolocation) and [Who is on the other end](#who-is-on-the-other-end).

**Phase 4 — history. Done.**

- [x] SQLite store with versioned migrations, read-only for every viewer

See [History](#history).

**Phase 5 — what is unprotected. Done.**

- [x] Every connection classified cleartext / encrypted / unknown, on by default
- [x] Protocol identification from payload signatures, falling back to port convention
- [x] Evidence recorded alongside every reading, so a guess never reads as an observation
- [x] `--read-cleartext`: the opening bytes of unencrypted connections, in memory only
- [x] `Cleartext` view — the exposed connections, and a reader for what they carry

See [Reading unprotected traffic](#reading-unprotected-traffic), which is where the
trade-off this makes is written down rather than left to be discovered.

**Phase 6 — blocking. Done, from the file and from the app.**

- [x] pf anchor with a static ruleset and a dynamic table
- [x] `--block`, off by default and announced, refusing rather than half-working
- [x] Block list owned by root, reloaded on `SIGHUP`, refused whole if any line is unusable
- [x] Blocking released on every exit path; `make unblock` for the one that runs no cleanup
- [x] `make doctor` reports an anchor a system update has silently unloaded
- [x] Control socket admitting only a pinned code identity — no Developer ID required
- [x] Blocking tab, and a block action on any connection

See [Blocking](#blocking). The *publishing* socket is still strictly read-only; commands
travel over a second socket that authenticates its peer.

**Later**

- [ ] Blocking by host name, which needs addresses learned from observed DNS answers rather
      than resolved once when a list is read.

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

Add `--read-cleartext` to keep the opening bytes of connections that are not encrypted, so
the app can show what they carry. Off by default, memory only, and described in
[Reading unprotected traffic](#reading-unprotected-traffic).

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

- Metadata only **unless you ask otherwise**. By default no packet payload is kept: the
  1024-byte snaplen exists to read headers, DNS answers and TLS SNI, and bulk payload stays
  in the kernel. `--read-cleartext` changes that, and is described in full below.
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

### Reading unprotected traffic

Every connection is classified as **cleartext**, **encrypted** or **unknown**, always and
for free — that is metadata like any other, and the `Cleartext` view lists what is exposed
without reading a single byte of it.

`--read-cleartext` is the other thing. It keeps the opening 4 KB of each direction of
connections that are not encrypted, so the app can show what is actually being sent, and it
is a real reversal of the bullet above: without it Beholder holds facts about traffic, and
with it Beholder holds some of the traffic. It is worth being blunt about what that means,
because the interesting connections are interesting precisely for what they carry:

- Session cookies, `Authorization` headers, API keys in query strings and form posts are
  all displayed verbatim, in a window, to whoever is at the keyboard.
- Redaction was considered and dropped, for the same reason it was dropped for hostnames:
  blanking the interesting value defeats the purpose of looking, and a half-redacted view
  invites the belief that less is exposed than actually is.

What bounds it instead:

- **Off by default.** No flag, no copying — the code path is not merely unused, it is
  never entered.
- **Memory only.** The bytes live in the running daemon and are released when a connection
  ends. They are never written to the history database and never written to the run
  transcript, so nothing survives the daemon exiting.
- **Bounded.** 4 KB per direction, 64 connections at a time, oldest released first. Enough
  for a request line, its headers and the start of a response — the part that says what a
  connection is for.
- **Never over MCP.** The MCP server gained the `security` and `protocol` fields on
  `live_connections` and nothing else. No tool returns payload, and none should: it would
  mean sending exactly the credentials above to an assistant on any turn.

What the reader shows depends on what the bytes turn out to be. HTTP is displayed as its
start line, its header block and its body, and DNS — which on a Mac means mostly mDNS — as its records:
the service name, the type, its time to live, and for a TXT record every string it carries.
An AirPlay or AirPrint announcement is entirely plain text and entirely unreadable as hex,
which is a poor way to show something every machine on the same network can read. The hex
dump stays below the decode rather than being replaced by it; a decode is a reading of the
bytes, and the two disagreeing is exactly what someone at this screen needs to be able to
see.

A body gets whatever has to come off before it can be read: chunked transfer framing first,
then a `Content-Encoding` of `gzip` or `deflate`, using the zlib that ships with the system.
This is the one place the "shallow parser" line has moved, and it moved for a specific
reason: **a compressed body rendered as raw bytes is indistinguishable from ciphertext**,
and being mistaken for encryption is precisely the failure this view exists to prevent.
Compression is reversible without a key, so leaving it undone was reporting something as
unreadable that had merely not been read. Encodings with no system library behind them —
Brotli, zstd — are named rather than attempted.

The same rules apply as everywhere else. A record type with no reader is reported as a byte
count rather than guessed at, a record cut short by the 4 KB bound says so rather than
presenting its surviving strings as the whole thing, a message showing one record of
twenty-three says that too, and a body that decompressed to something that is not text —
an image, an archive — is named rather than rendered, because a decoder that cannot fail is
not evidence that what it produced is readable. A 4 KB excerpt of a larger body is a
*truncated* deflate stream, which general-purpose decompression APIs reject outright as
corrupt; the prefix is decoded and labelled `cut short by the excerpt` instead, since the
prefix is the part worth reading.

```bash
make cleartext                                     # from a checkout
sudo ./Scripts/install-daemon.sh --read-cleartext  # when the launchd job is the one capturing
```

The second form exists because an installed daemon cannot be talked out of the way: it
holds the socket, a second daemon refuses rather than stealing it, and `KeepAlive` restarts
it after a kill. Re-running that script without the flag turns payload reading back off.

**Cleartext is proof; encrypted is an inference; unknown is neither.** A plaintext protocol
marker was read off the wire, so `cleartext` says something observed. `encrypted` rests on
a TLS record header, an SSH banner, or a port convention — evidence that a handshake
happened, not that it succeeded. And bytes matching nothing are reported as `unknown`,
never as encrypted: unrecognised binary looks exactly like ciphertext, and calling it
encrypted would be claiming something never observed, in the direction that reassures.
`unknown` is listed alongside cleartext in the exposed view — an unidentified protocol on a
high port is exactly what a person looking at this screen wants to see — but it is labelled
separately everywhere, because one is an observation and the other is the lack of one.

One consequence worth knowing: a connection proven to carry cleartext stays reported that
way even if it later negotiates TLS. A STARTTLS session did carry bytes in the clear, and
that does not stop being true.

The way out of `unknown` is to learn the framing, not to relax the rule. WireGuard — which
is what NordLynx and Tailscale speak, both of them over loopback — used to sit in the
exposed list as an unidentified binary protocol, and on a machine with a VPN up it was the
largest UDP conversation there. It is now read from its header: a message type, three
reserved zero bytes, and a length the protocol fixes. That is a stronger claim than the TLS
record header above rather than a weaker one, because a transport-data message only exists
once the handshake has completed. It also stops the excerpt store spending its bounded 4 KB
per direction on ciphertext, which was displacing the cleartext it exists to show.

Hostnames arrive from the network, which means anyone who can make this machine resolve a
name chooses a string that ends up in an assistant's context. They are sent as delimited
data rather than prose, truncated to the length a real name can be, and stripped of
control characters. They are deliberately **not** filtered on content: a keyword blocklist
would hide the interesting hostname, and a network-visibility tool that quietly omits the
suspicious host has defeated its own purpose.

## Known limitations

- Very short-lived connections may show as "unknown" — an inherent race in socket-table
  polling that only a kernel-level filter avoids.
- **QUIC carries no round trips a passive observer can read.** HTTP/3 runs over UDP and
  exposes no sequence numbers, no acknowledgements and no handshake to time, so latency and
  loss simply cannot be measured for it. That is a large and growing share of browser
  traffic, which is why every figure in the Quality tab publishes what proportion of the
  bytes it actually covers rather than quietly averaging over what it could see.
- Retransmissions are counted, not dropped packets. From one end of a connection, an
  acknowledgement lost on the way back looks exactly like data lost on the way out, so the
  figure is a floor on loss rather than a measurement of it. It is labelled accordingly
  everywhere it appears.
- Passive measurement only covers paths actually used, while they were being used. A quiet
  night is not evidence the connection was working, and it is not evidence it was not —
  `--probe` exists because that is the only way to tell those apart.
- macOS coalesces received segments before handing them to libpcap on some interfaces. Where
  that happens, segment and retransmission counts are undercounts; Beholder detects it and
  says so rather than reporting the low numbers as fact.
- Hostnames are unavailable for connections using TLS Encrypted Client Hello.
- **Blocking is by destination, never by process, and host names cannot be blocked.** pf
  matches addresses and has no concept of a process, so a block applies to every program on
  the machine — and one address commonly serves many names. Spelled out under
  [Blocking](#it-blocks-destinations-not-processes), because it shapes what the feature can
  usefully be asked to do.
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
- A connection is only identified once it says something Beholder recognises. One that was
  already open when capture started, and whose handshake is long past, is classified from
  its port alone — which the display labels as inferred rather than read.
- Payload reading sees whole packets, not a reassembled stream. A request line split across
  a TCP segment boundary, or arriving out of order, will not match; in practice a request
  and its headers arrive in the first segment, which is why this is a limitation rather
  than a defect. It is also why `unknown` exists. The same applies to a compressed body:
  segments are appended in the order they were captured, so reordering corrupts the deflate
  stream — which surfaces as "would not decode" rather than as plausible wrong text.
- Nothing here decrypts anything. `encrypted` means Beholder can see that a connection is
  protected and therefore cannot read it — which is the answer, not a failure.
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
downloaded this week", "was my internet bad on Tuesday evening".

```bash
make mcp
make mcp-add     # prints the claude mcp add line; run it yourself
```

It is off until you register it, and `claude mcp remove beholder` ends it.

Five tools: recorded history, one endpoint's whole story, a live snapshot, a health check,
and network quality. Five rather than a dozen on purpose — every tool's description sits in
the assistant's context on every turn of every conversation, including the ones that have
nothing to do with networking, so the set is a budget rather than a catalogue.

It was four for a long time. `network_quality` was added rather than folded into one of the
others because it answers a different *kind* of question: the other four are all forms of
"who talked to whom", keyed by identity and returning endpoints and byte counts, while this
one is keyed by time and asks how well the path worked. Bending `network_history` to carry
it would have given one tool two schemas wearing a trench coat, which costs the reader more
than a fifth name does. Its answers carry their caveats — the window covered, the share of
traffic that was measurable, and whether the numbers describe a VPN tunnel rather than the
link beneath it.

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

## Measuring the connection

Beholder measures how well the network is working, not just who is using it. This is on by
default, needs no extra flag, and reads nothing beyond header fields the kernel has already
handed over.

What it measures, per connection:

- **Round-trip time**, from three sources on a ladder of decreasing trust. The TCP timestamp
  option is best — continuous, and unambiguous when a segment has been sent twice. The
  handshake is the cleanest single sample there is: nothing but the path can delay an answer
  to a SYN. Timing an acknowledgement is the fallback, and carries the far end's delayed-ACK
  timer with it, which is why it ranks last.
- **The minimum**, kept separately and shown first. The typical round trip includes whatever
  delay the far end added before answering; the minimum over many samples is the closest a
  passive observer gets to the path's real propagation delay. Everything above it is
  queueing.
- **Retransmissions**, per direction, because the directions answer different questions.
  Data of yours resent means loss on the way out; data of theirs resent means loss on the
  way in.
- **Jitter** — RFC 6298's variation for TCP, and inter-arrival spacing for UDP, which is
  labelled as the different thing it is.
- **Connection outcomes**, keeping timeouts apart from refusals. A connection that got no
  answer is evidence the path failed. One answered with a reset is the far end declining,
  which is not the network's doing.

`--no-quality` turns it off. The asymmetry with `--read-cleartext` is deliberate: payload
reading touches the *contents* of traffic, so it is opt-in and announced. Measurement reads
only headers and learns nothing about what anyone is doing. It is on by default for a second
reason too — it has to be running when the trouble happens, and a switch you flip afterwards
has nothing to say about a connection that has already gone bad.

### Is it my ISP?

A round trip to a server measures the whole path, so no single number can answer this. What
can answer it is **common mode**: when several networks that share nothing except your uplink
all slow down in the same minute, the thing they share is the thing at fault. When one slows
down alone, it is that one.

Beholder groups destinations by autonomous system precisely so this comparison is possible —
a hundred addresses behind one CDN are one network, and counting them as a hundred would make
any single CDN's bad afternoon look like everything failing at once. Each network gets its own
baseline, and a minute is only judged against a network that contributed enough samples in it
to be worth judging.

The Quality tab's **Over time** half reports this, along with latency by hour of day (where
evening congestion shows up and nowhere else), latency under load, and stretches where
connections got no answer. It reads the database directly, so it works when nothing is
capturing.

It will not tell you your ISP was down. Passively, an outage and an idle laptop are the same
observation. It will tell you that connections were attempted and failed, which is a
different claim and a stronger one.

### Latency under load

Probably the most useful single reading here, and the one a speed test will never give you.
A connection can hit its advertised rate and still feel broken because something between you
and the exchange holds a large buffer that fills under load. Beholder can see it because it
has both numbers for the same minute: latency at rest, and latency while the link is busy.

Where the gap is large, the fix is usually fair queueing on your own router rather than
anything your ISP can do.

### `--probe`: the one thing that sends

Everything above watches traffic somebody else asked for. That is enough for almost every
question and deliberately not enough for two:

- **Was the connection working while nobody was using it?** An outage at four in the morning
  is indistinguishable from being asleep.
- **Is it my Wi-Fi or my ISP?** Loss on the local radio and loss upstream of the router look
  identical from the far end of a path that runs through both.

`--probe` sends one ICMP echo to your default gateway and to a few fixed addresses every
thirty seconds. Timing the first hop *separately* is the only way to split your own network
from everything beyond it — a clean gateway with slow anchors puts the trouble upstream of
your router; a slow gateway puts it on your own cable or radio.

It is **off by default**, and when it is on the daemon says so on startup, naming its targets
and interval. It alters nobody else's traffic — that is `--block`'s department, and equally
opt-in — but with this flag it is no longer true that Beholder only listens, and that
distinction is worth stating rather than leaving to be discovered.

Probes are excluded from Beholder's own measurements by process, not by a capture filter: a
filter on those addresses would also hide the genuine DNS this machine sends to them all day.

```bash
sudo ./.build/debug/beholderd --serve --probe     # gateway plus the built-in anchors
sudo ./.build/debug/beholderd --serve --probe --probe-target 192.0.2.1 --probe-interval 60
```

## Blocking

Everything above reports. This stops traffic leaving, and it is the only thing here that
changes what the machine can reach, so it is off unless asked for and says so when it is on.

```bash
sudo ./Scripts/install-pf-anchor.sh    # once, and it says exactly what it changes
sudo ./Scripts/install-control-pin.sh  # once, so the app may change what is blocked
make block                             # capture, publish and enforce
```

**With the daemon installed, use `make install-blocking` instead.** The launchd job is the
only daemon that can serve — a second one finds the socket answering and refuses rather than
stealing it — so "start it with `--block`" is not an instruction anyone can follow while it
is installed. Reinstalling with the flag is, and it survives reboots. `make uninstall-blocking`
takes it back off.

Then use the app's **Blocking** tab, or edit the list by hand:

```bash
sudo $EDITOR /usr/local/etc/beholder/blocklist.conf
make check-blocklist                   # what that would block, changing nothing
sudo kill -HUP $(pgrep -x beholderd)
```

### It blocks destinations, not processes

This is the first thing to understand about it and the hardest to design around, so it is
not buried in the limitations list. **A block applies to every program on this machine.**

macOS has exactly one API that can filter per application, `NEFilterDataProvider`, and it
needs the entitlement this project exists to avoid. The mechanism Beholder can reach — pf —
matches addresses, ports, protocols and interfaces, and has no concept of a process. So
attribution answers *what is worth blocking* and the block then applies to everything.

The other half of the same limit: one address commonly serves many names. Blocking a CDN
address to stop one tracker stops everything else behind that address, and there is no
passive way to find out from the outside what those are. Beholder is unusually well placed
to *tell* you which application is talking to something, and no better placed than anything
else to stop only that application from doing it.

Host names are refused for a related reason. A name is not something pf can match on, and
resolving one when the list is read would freeze a single answer for a record that rotates —
it would stop matching within the hour and give no sign that it had. The list takes
addresses and networks:

```
93.184.216.34        # example.com
10.0.0.0/8           # the whole lab network
2606:2800:220:1::/64
```

The note after the `#` is worth writing. A list of bare addresses is unreadable a month
later, when the question is "what is this and can I remove it".

### The rules

Four words, each chosen against an alternative, and there are tests pinning all of them:

```
table <beholder_blocked> persist
block return out log quick from any to <beholder_blocked>
```

- **`quick`** — pf is last-match-wins. Without it, a rule in an anchor that some system
  service inserted while Beholder was not looking could pass a packet this rule had already
  matched.
- **`return`, not `drop`** — pf generates the refusal itself, a TCP RST or an ICMP
  unreachable, from the kernel, addressed to the local program that sent the packet. The
  application fails immediately instead of hanging until its own timeout. The alternative
  considered and rejected was injecting a reset from userspace, which would have meant
  Beholder crafting packets — a far larger claim than this project should make, and worse in
  every particular: TCP only, racy, and after the first data has already gone.
- **`out`** — this machine's own traffic. Inbound filtering is the built-in firewall's job.
- **`log`** — blocked packets go to `pflog0`, so "did that actually block anything" has an
  answer instead of being inferred from an absence:

```bash
sudo tcpdump -n -e -ttt -i pflog0
```

**The ruleset is static and the table is dynamic, and that split is the security design.**
Rule text is written once, at install time. Nothing derived from a block list, a captured
packet or a DNS answer is ever concatenated into a pf rule; the only thing that changes
while running is which addresses are in a table, and every one of those has been through
the address parser and been re-rendered by `inet_ntop`. `pfctl` is spawned with an argument
vector and an absolute path — no shell, so nothing in an argument can be read as syntax, and
no `PATH` lookup, so a root process cannot be pointed at a different `pfctl`.

### Changing what is blocked, and who may

The daemon's **publishing socket is still strictly read-only**. It accepts no command, and
everything that merely watches — the terminal view, the MCP server, anything else you
connect — still cannot change anything by any route. Blocking is changed over a **second,
separate socket** that authenticates its peer.

Splitting them rather than widening the first is what keeps the old guarantee intact. A
reader on the publishing socket learns only what `lsof` would already tell it, so it needs
no admission control; a writer needs a great deal, and the two do not belong on one path.

#### File permissions cannot guard a writer

This is the part that kept the socket read-only for so long, and the reasoning that was
wrong. Both ends run as **you**. Mode 0600 keeps other accounts out and keeps nothing else
out — anything running as your account can open the socket. For a reader that is fine. For a
writer it is not, and the thing worth blocking is not your browsing but your update server,
or whatever else would notice something was wrong.

The missing piece was thought to be a signing identity, which this project has no way to
obtain. It is not. What is needed is a **stable** identity, not an Apple-issued one — and an
ad-hoc signature already provides one:

```bash
codesign -dr - --verbose=0 .build/Beholder.app
# designated => cdhash H"1efb2e37dba21cbc79bc7e8ee9b039cb0a0fb42b"
```

`install-control-pin.sh` records that requirement in a root-owned file, and the daemon admits
a connection only from a process that satisfies it. Three details make it hold:

- **The peer is identified by audit token, never by pid.** `LOCAL_PEERPID` names a process
  that can exit between the lookup and the check, with the number reused by something else.
  `LOCAL_PEERTOKEN` names *that* process and cannot be recycled.
- **The check is on the running code, not on a file.** `SecCodeCheckValidity` against a
  `SecCode` built from the audit token validates the process as it is now. Reading the cdhash
  of an executable's path checks a file that need not be what is running — and that is not a
  hypothetical: Homebrew's `python3` re-execs into `Python.app`, so the binary you invoked and
  the code that runs have different hashes. `test-control-socket.sh` exercises exactly this.
- **The app is signed with the hardened runtime.** Without it, another process as your account
  could inject code into the app and speak as it; library validation closes the ordinary path.
  An account-level attacker with a debugger remains out of scope, and saying otherwise would
  be the reassuring kind of wrong.

**Rebuilding the app changes its cdhash**, so a rebuilt app is a different program until it is
pinned again. That is the point of an identity rather than a name. `make reload` re-pins as
part of the rebuild; a manual `make app` needs `make control-pin` after it.

One consequence of authenticating on accept is worth knowing, because it cost an
afternoon: the daemon refuses by **replying and then closing**, so a client that fails the
check can find the socket gone before it has written anything. Writing to it then raises
SIGPIPE, which by default kills the process with no message and no crash report — which is
exactly how a stale pin presented, as the app silently quitting the moment anyone opened the
Blocking tab. The client sets `SO_NOSIGPIPE`, the app ignores the signal process-wide as the
daemon has always done, and a failed write no longer discards the refusal that explains it.

The MCP server reaches none of this. It is read-only by construction, and a surface driven by
generated text is the last thing that should be able to change a firewall — the same reasoning
that keeps [`query_sql` from existing](#asking-it-questions).

#### Two lists, and only one of them is rewritten

`blocklist.conf` is written by a person and carries their comments; the daemon never
regenerates it. What the app blocks goes to `blocklist.app.conf` beside it, which the daemon
owns and rewrites freely. pf enforces the union.

The asymmetry that falls out is deliberate and shown in the UI rather than hidden: **the app
can take back what the app added, and cannot take back what the file pinned.** Something
blocked by the root-only file stays blocked until root edits that file. A program that
regenerated a hand-edited config would eventually eat the notes explaining why each line is
there.

The file can still be edited directly, with no app involved:

```bash
sudo $EDITOR /usr/local/etc/beholder/blocklist.conf
sudo kill -HUP $(pgrep -x beholderd)
```

#### From the app

The **Blocking** tab lists what is blocked and by which file, and any connection's context
menu offers to block its address. The menu item says "Block 93.184.216.34 **for everything**"
rather than naming the process, because pf has no concept of one — a label naming the app
would be the reassuring lie this whole section exists to avoid.

### It refuses rather than half-working

Every failure stops the daemon instead of continuing without enforcement: no anchor, an
unreadable list, a list your account can write, a single line that does not parse. Capture
carrying on quietly while blocking is off would leave someone believing a destination is
unreachable when it is not, and being wrong in the reassuring direction is the worst way to
be wrong. It is the same rule `ProtocolSniffer` follows in never guessing `encrypted`.

That is why a list with one bad line is refused whole. Enforcing the part that happens to
parse means the entry you got wrong is the one silently not blocked.

### It lasts exactly as long as the daemon

Stopping capture unblocks everything: the table is emptied and pf's reference handed back
on the way out, including from `Ctrl-C`, `SIGTERM` and every internal failure path. The
alternative — leaving the table populated so blocks survive — was rejected because it turns
a crash into a machine with a firewall nobody is managing and no obvious reason why a site
stopped loading. Being able to stop the observer and have the network return to normal is
worth more than blocks that persist.

A daemon killed with `SIGKILL` runs no cleanup, which is the one case that leaves rules
behind:

```bash
make unblock        # empty the table, now
make block-status   # what pf is blocking for Beholder right now
```

### What it changes on your system

`Scripts/uninstall-pf-anchor.sh` removes the first two; the rest are Beholder's own files
under `/usr/local/etc/beholder`, which no uninstaller deletes:

| | |
|---|---|
| `/etc/pf.anchors/com.beholder` | the rules |
| `/etc/pf.conf` | three marked lines naming and loading them |
| `blocklist.conf` | what you asked to block. Yours; never rewritten |
| `blocklist.app.conf` | what the app asked to block. The daemon's; rewritten freely |
| `control-peer.requirement` | the code identity allowed to change blocking |

The second is unavoidable and worth understanding. **A nested anchor is only evaluated if
the main ruleset names it** — an anchor file on its own loads without complaint and blocks
nothing. Apple's comment at the top of `pf.conf` says the main ruleset must not be flushed
for exactly this reason, which is also why the installer validates with `pfctl -n` and keeps
a backup before it commits.

Two consequences to know before running it:

- **Loading `pf.conf` drops anchors that running services inserted dynamically.** Internet
  Sharing does this, and so do some VPN clients. They re-insert theirs when they next start,
  and a reboot settles everything.
- **A macOS update can restore the stock `pf.conf`**, which removes those three lines and
  silently disarms every block. `beholderd --block` checks for this at startup and refuses
  to run rather than pretending, and `make doctor` reports it — but a daemon installed
  without `--block` gives no sign, so it is worth knowing the failure exists.

pf itself is shared. Beholder takes a reference with `pfctl -E` and gives it back with
`-X`, never `-e`/`-d`, because `/etc/pf.conf` asks for exactly that in its own comments:
switching pf off underneath Internet Sharing or a VPN client that had switched it on is a
fault that surfaces as somebody else's firewall quietly not working.

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
