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

**Later**

- [ ] XPC + SwiftUI app — Phase 2
- [ ] DNS/SNI enrichment, GeoIP, map — Phase 3
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
