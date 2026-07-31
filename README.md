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

Phase 0 (capture foundation) is implemented:

- [x] Link-layer handling: `DLT_NULL`, `DLT_EN10MB` (incl. VLAN), `DLT_RAW`, `DLT_LOOP`
- [x] IPv4/IPv6 parsing with extension-header walking and fragment handling
- [x] TCP/UDP/ICMP, with graceful handling of packets that carry no ports
- [x] Default-route discovery via routing socket
- [x] Capture engine: non-blocking pcap on a dispatch source, per-interface statistics
- [ ] Flow table and process attribution — Phase 1
- [ ] XPC + SwiftUI app — Phase 2
- [ ] DNS/SNI enrichment, GeoIP, map — Phase 3
- [ ] SQLite history — Phase 4

## Building and running

```bash
swift build
swift test
```

Capture requires root:

```bash
sudo ./.build/debug/beholderd
```

With no arguments it captures the default-route interface. Pass interface names to
override, or `--loopback` to add `lo0`.

The **parsed** column is the one to watch: if packets are arriving but `parsed` stays near
zero, the link-layer assumption for that interface is wrong.

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
