import BeholderCore
import Darwin
import Dispatch
import Foundation

/// A live, full-screen table of current connections, sorted by traffic volume.
///
/// This is the Phase 1 milestone: everything downstream — the map, the charts, the
/// history browser — is a different presentation of exactly this data.
final class TopView: @unchecked Sendable {
    private let monitor: FlowMonitor
    private let interfaces: [String]
    private let queue = DispatchQueue(label: "com.beholder.topview")
    private var timer: DispatchSourceTimer?
    private var signalSources: [DispatchSourceSignal] = []

    // Confined to queue.
    private var previousBytesOut: UInt64 = 0
    private var previousBytesIn: UInt64 = 0
    private var previousSampleAt = Date()
    private var ticksRemaining: Int?
    private let startedAt = Date()

    private static let clearScreen = "\u{1B}[H\u{1B}[J"

    init(monitor: FlowMonitor, interfaces: [String]) {
        self.monitor = monitor
        self.interfaces = interfaces
    }

    /// `stopAfterTicks` bounds the run, used by `--self-test` to exercise the render path
    /// without needing root.
    func start(stopAfterTicks: Int? = nil) {
        queue.async { [self] in
            previousSampleAt = Date()
            ticksRemaining = stopAfterTicks
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1.0)
        timer.setEventHandler { [weak self] in self?.render() }
        self.timer = timer
        timer.resume()
    }

    func installSignalHandlers() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { [weak self] in self?.shutDown() }
            source.resume()
            signalSources.append(source)
        }
    }

    // MARK: - Rendering

    private func render() {
        let summary = monitor.summary()
        let now = Date()
        let elapsed = max(now.timeIntervalSince(previousSampleAt), 0.001)
        previousSampleAt = now

        // Counters only ever grow, but flows are retired, so a total can fall. Clamp
        // rather than underflowing an unsigned subtraction.
        let outRate = Double(summary.totalBytesOut &- min(previousBytesOut, summary.totalBytesOut)) / elapsed
        let inRate = Double(summary.totalBytesIn &- min(previousBytesIn, summary.totalBytesIn)) / elapsed
        previousBytesOut = summary.totalBytesOut
        previousBytesIn = summary.totalBytesIn

        let rows = max(terminalRows() - 8, 5)
        let flows = summary.flows
            .sorted { $0.totalBytes > $1.totalBytes }
            .prefix(rows)

        var output = Self.clearScreen

        output += """
            Beholder — \(interfaces.joined(separator: ", "))\
              ·  \(summary.flowCount) flows, \(summary.processCount) processes\
              ·  up \(formatBytes(outRate))/s  down \(formatBytes(inRate))/s
            \(formatTimestamp(now))  ·  running \(formatDuration(now.timeIntervalSince(startedAt)))

            """
        if summary.unattributedCount > 0 || summary.evictedFlowCount > 0 {
            var notes: [String] = []
            if summary.unattributedCount > 0 {
                let share = Double(summary.unattributedCount) / Double(max(summary.flowCount, 1))
                notes.append(
                    "\(summary.unattributedCount) unattributed (\(Int(share * 100))%)"
                )
            }
            if summary.evictedFlowCount > 0 {
                notes.append("\(summary.evictedFlowCount) flows evicted (table full)")
            }
            output += notes.joined(separator: "  ·  ") + "\n"
        }
        output += "\n"

        output += Self.flowTable(Array(flows))

        if summary.flowCount > flows.count {
            output += "\n… \(summary.flowCount - flows.count) more flows not shown\n"
        }
        output += "\nCtrl-C to stop."

        print(output)

        if let remaining = ticksRemaining {
            ticksRemaining = remaining - 1
            if remaining - 1 <= 0 {
                print("")
                print("Self-test complete: the live view rendered without faulting.")
                monitor.stop()
                exit(0)
            }
        }
    }

    /// How to label the far end of a flow.
    ///
    /// A hostname if one was established, otherwise the address — never a blank, since
    /// the address is always true even when the name is unknown. Private Relay ingress is
    /// called out because the real destination behind it is unknowable by design, and an
    /// unexplained Apple address looks like a failure rather than a privacy feature.
    private static func describeRemote(_ flow: Flow) -> String {
        let port = flow.key.remotePort
        guard let hostName = flow.hostName else {
            return flow.key.remote.endpoint(port: port)
        }
        if NameResolutionCache.classify(hostName: hostName) == .privateRelay {
            return "\(hostName):\(port)  [Private Relay]"
        }
        // A dot marks a name inferred from DNS rather than read from this connection's
        // own handshake, so a shared address is never mistaken for proof.
        let marker = flow.hostNameSource == .dns ? "·" : ""
        return "\(marker)\(hostName):\(port)"
    }

    /// Renders flows as a plain table. Shared by the live view and the shutdown summary
    /// so that what stays on screen after Ctrl-C matches what was being watched.
    private static func flowTable(_ flows: [Flow]) -> String {
        var output =
            Column.left("PROCESS", 22) + Column.right("PID", 7) + "  "
            + Column.left("PROTO", 6) + Column.left("REMOTE", 40)
            + Column.right("UP", 11) + Column.right("DOWN", 11) + "  "
            + "STATE\n"

        for flow in flows {
            let remote = describeRemote(flow)
            let state = flow.tcpState.map(String.init(describing:))
                ?? (flow.key.transport == .udp ? "—" : "")
            output +=
                Column.left(flow.owner?.name ?? "(unknown)", 22)
                + Column.right(flow.owner.map { String($0.pid) } ?? "—", 7) + "  "
                + Column.left(flow.key.transport.name, 6)
                + Column.left(remote, 40)
                + Column.right(formatBytes(Double(flow.bytesOut)), 11)
                + Column.right(formatBytes(Double(flow.bytesIn)), 11) + "  "
                + state + "\n"
        }
        return output
    }

    private func terminalRows() -> Int {
        var size = winsize()
        guard ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0, size.ws_row > 0 else {
            return 30
        }
        return Int(size.ws_row)
    }

    /// Prints a self-contained final report.
    ///
    /// Deliberately does not clear the screen: the live view is redrawn in place and is
    /// therefore impossible to copy out of a terminal, so this is what survives and gets
    /// shared. It repeats the table rather than assuming the last frame is still legible.
    private func shutDown() {
        let summary = monitor.summary()
        let byBytes = summary.flows.sorted { $0.totalBytes > $1.totalBytes }

        let endedAt = Date()
        print("")
        print(String(repeating: "─", count: 100))
        print("Beholder summary — \(interfaces.joined(separator: ", "))")
        print(
            "Started \(formatTimestamp(startedAt))  ·  ended \(formatTimestamp(endedAt))"
                + "  ·  ran \(formatDuration(endedAt.timeIntervalSince(startedAt)))"
        )
        print(String(repeating: "─", count: 100))
        print(
            """
            \(summary.flowCount) flows, \(summary.processCount) processes, \
            \(formatBytes(Double(summary.totalBytesOut))) up, \
            \(formatBytes(Double(summary.totalBytesIn))) down, \
            \(summary.attributionPasses) attribution passes \
            (\(summary.onDemandPasses) triggered by new flows).
            """
        )

        // The miss rate is measured against flows that *could* be attributed. Protocols
        // with no ports have no socket to match, so counting them as failures would
        // overstate the problem and point at a fix that does not exist.
        let attributable = summary.flowCount - summary.unattributableCount
        if attributable > 0 {
            let named = attributable - summary.unattributedCount
            let percentage = Double(named) / Double(attributable) * 100
            print(
                String(
                    format: "Attribution: %d of %d attributable flows named (%.1f%%), %d missed.",
                    named, attributable, percentage, summary.unattributedCount
                )
            )
        }
        if summary.unattributableCount > 0 {
            print(
                "\(summary.unattributableCount) flows carry no ports (ICMP and similar), "
                    + "so no socket exists to attribute them to — these are system traffic."
            )
        }

        if summary.flowCount > 0 {
            let share = Double(summary.namedFlowCount) / Double(summary.flowCount) * 100
            print(
                String(
                    format: "Hostnames: %d of %d flows named (%.1f%%), %d addresses cached.",
                    summary.namedFlowCount, summary.flowCount, share, summary.cachedNameCount
                )
            )
        }
        if summary.privateRelayFlowCount > 0 {
            print(
                """
                \(summary.privateRelayFlowCount) flows go through iCloud Private Relay. \
                Their real destinations are encrypted end-to-end to Apple and cannot be \
                determined from this machine — that is the feature working, not a gap in \
                Beholder.
                """
            )
        }
        if summary.evictedFlowCount > 0 {
            print(
                "\(summary.evictedFlowCount) flows were evicted — the table hit its cap, "
                    + "so these totals are an undercount."
            )
        }

        // A proxy fronting other apps makes every per-process number below misleading,
        // so this is stated before the table rather than as a footnote after it.
        for finding in ProxyDetection.findLikelyProxies(in: summary.flows) {
            print("")
            print("⚠︎  \(finding.advice)")
        }

        print("")
        print(Self.flowTable(Array(byBytes.prefix(40))))
        if byBytes.count > 40 {
            print("… \(byBytes.count - 40) further flows omitted.")
        }

        // Unattributed flows are the interesting failure mode, so list them explicitly
        // rather than leaving them buried in the table above.
        let unknown = byBytes.filter { $0.owner == nil }
        if !unknown.isEmpty {
            print("Unattributed flows (\(unknown.count)):")
            for flow in unknown.prefix(15) {
                print(
                    "  \(Column.left(flow.key.transport.name, 7))"
                        + "\(flow.key.local.endpoint(port: flow.key.localPort)) → "
                        + "\(flow.key.remote.endpoint(port: flow.key.remotePort))  "
                        + "\(flow.totalPackets) packets, "
                        + formatBytes(Double(flow.totalBytes))
                )
            }
            if unknown.count > 15 {
                print("  … and \(unknown.count - 15) more.")
            }
        }

        monitor.stop()
        exit(0)
    }
}
