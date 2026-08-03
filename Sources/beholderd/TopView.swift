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
    private let engine: CaptureEngine
    private let supervisor: InterfaceSupervisor?
    private let queue = DispatchQueue(label: "com.beholder.topview")
    private var timer: DispatchSourceTimer?
    private var signalSources: [DispatchSourceSignal] = []

    // Confined to queue.
    private var previousBytesOut: UInt64 = 0
    private var previousBytesIn: UInt64 = 0
    private var previousSampleAt = Date()
    private var ticksRemaining: Int?
    private var tickCount = 0
    private let startedAt = Date()

    private static let clearScreen = "\u{1B}[H\u{1B}[J"

    private let log: RunLog?

    /// How often the transcript gets a snapshot. Far slower than the one-second display:
    /// the file is for review after the fact, and a snapshot every second would bury the
    /// interesting parts.
    private static let snapshotInterval = 30

    /// When false, the session runs without drawing anything: snapshots, transcript and
    /// clean shutdown all still happen. That is what `--serve` needs, since a full-screen
    /// redraw would fight with whatever is sharing the terminal.
    private let rendersToTerminal: Bool

    init(
        monitor: FlowMonitor,
        engine: CaptureEngine,
        supervisor: InterfaceSupervisor?,
        log: RunLog?,
        rendersToTerminal: Bool = true
    ) {
        self.monitor = monitor
        self.engine = engine
        self.supervisor = supervisor
        self.log = log
        self.rendersToTerminal = rendersToTerminal
    }

    /// Read live rather than captured at startup, so a route change is reflected in the
    /// header instead of the display insisting on an interface no longer in use.
    private var interfaces: [String] {
        engine.activeInterfaces
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

        // Serving the app needs the session running but nothing drawn: a full-screen
        // redraw would fight with whatever else is using the terminal. Snapshots,
        // transcript and shutdown all still happen below.
        guard rendersToTerminal else {
            advanceTick()
            return
        }

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

        // A route change mid-run is exactly the event a user would otherwise mistake for
        // the tool breaking, so the most recent one stays on screen.
        if let latest = supervisor?.recordedTransitions().last {
            output += "↻ \(latest.summary)\n"
        }
        output += "\n"

        output += Self.flowTable(Array(flows))

        if summary.flowCount > flows.count {
            output += "\n… \(summary.flowCount - flows.count) more flows not shown\n"
        }
        output += "\nCtrl-C to stop."

        print(output)
        advanceTick()
    }

    /// Snapshot cadence and self-test countdown, shared by both display modes.
    private func advanceTick() {
        tickCount += 1
        if tickCount % Self.snapshotInterval == 0 {
            writePeriodicSnapshot()
        }

        if let remaining = ticksRemaining {
            ticksRemaining = remaining - 1
            if remaining - 1 <= 0 {
                print("")
                print("Self-test complete: the session ran without faulting.")
                if let log {
                    log.section(
                        "FINAL REPORT",
                        buildReport(endedAt: Date(), flowLimit: .max, unattributedLimit: .max)
                    )
                    log.close()
                    print("Full transcript: \(log.url.path)")
                }
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

    /// Builds a self-contained report.
    ///
    /// One renderer for both the console and the log file, so what gets written to disk
    /// is exactly what was on screen. It repeats the table rather than assuming the last
    /// live frame is still legible — the live view redraws in place and cannot be copied
    /// out of a terminal.
    ///
    /// `flowLimit` is the only difference between the two: the console shows a readable
    /// excerpt, while the log keeps everything, since the whole point of the file is not
    /// having to reconstruct what was omitted.
    private func buildReport(
        endedAt: Date,
        flowLimit: Int,
        unattributedLimit: Int
    ) -> String {
        let summary = monitor.summary()
        let byBytes = summary.flows.sorted { $0.totalBytes > $1.totalBytes }
        let rule = String(repeating: "─", count: 100)
        var lines: [String] = []

        lines.append("")
        lines.append(rule)
        lines.append("Beholder summary — \(interfaces.joined(separator: ", "))")
        lines.append(
            "Started \(formatTimestamp(startedAt))  ·  ended \(formatTimestamp(endedAt))"
                + "  ·  ran \(formatDuration(endedAt.timeIntervalSince(startedAt)))"
        )
        lines.append(rule)
        lines.append(
            "Direction: \(summary.outgoingCount) outgoing, "
                + "\(summary.incomingCount) incoming, "
                + "\(summary.undeterminedDirectionCount) undetermined."
        )
        lines.append(
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
            lines.append(
                String(
                    format: "Attribution: %d of %d attributable flows named (%.1f%%), %d missed.",
                    named, attributable, percentage, summary.unattributedCount
                )
            )
        }
        if summary.unattributableCount > 0 {
            lines.append(
                "\(summary.unattributableCount) flows carry no ports (ICMP and similar), "
                    + "so no socket exists to attribute them to — these are system traffic."
            )
        }
        if summary.flowCount > 0 {
            let share = Double(summary.namedFlowCount) / Double(summary.flowCount) * 100
            lines.append(
                String(
                    format: "Hostnames: %d of %d flows named (%.1f%%), %d addresses cached.",
                    summary.namedFlowCount, summary.flowCount, share, summary.cachedNameCount
                )
            )
            lines.append(
                "  by source: \(summary.namedBySNI) from TLS SNI, "
                    + "\(summary.namedByDNS) from observed DNS, "
                    + "\(summary.namedByReverseLookup) from reverse lookup."
            )
            lines.append(
                "  \(summary.restoredNameCount) names carried over from earlier runs; "
                    + "\(summary.reverseLookupsSucceeded) of "
                    + "\(summary.reverseLookupsAttempted) reverse lookups answered."
            )
        }
        if summary.privateRelayFlowCount > 0 {
            lines.append(
                """
                \(summary.privateRelayFlowCount) flows go through iCloud Private Relay. \
                Their real destinations are encrypted end-to-end to Apple and cannot be \
                determined from this machine — that is the feature working, not a gap in \
                Beholder.
                """
            )
        }
        if summary.evictedFlowCount > 0 {
            lines.append(
                "\(summary.evictedFlowCount) flows were evicted — the table hit its cap, "
                    + "so these totals are an undercount."
            )
        }

        // Capture health belongs in the flow report too, not only in the statistics view.
        // A kernel drop means the byte totals above are short by an unknown amount, and a
        // report that cannot say so is quietly lying about its own accuracy.
        let statistics = engine.statistics()
        let dropped = statistics.reduce(0) { $0 + UInt64($1.kernelDropped) }
        let captured = statistics.reduce(0) { $0 + $1.counters.packets }
        lines.append(
            "Capture: \(captured) packets across "
                + statistics.map { "\($0.interfaceName) (\($0.linkLayer.name))" }
                .joined(separator: ", ")
                + "."
        )
        if dropped > 0 {
            let share = Double(dropped) / Double(max(captured + dropped, 1)) * 100
            lines.append(
                String(
                    format: """
                        ⚠︎  %llu packets were dropped by the kernel (%.2f%%) — the BPF buffer \
                        filled faster than Beholder drained it, so every byte total above is \
                        an undercount.
                        """,
                    dropped, share
                )
            )
        }

        let transitions = supervisor?.recordedTransitions() ?? []
        if !transitions.isEmpty {
            lines.append("")
            lines.append("Interface changes during this run:")
            for transition in transitions {
                lines.append("  \(transition.summary)")
            }
        }

        // A proxy fronting other apps makes every per-process number below misleading,
        // so this is stated before the table rather than as a footnote after it.
        for finding in ProxyDetection.findLikelyProxies(in: summary.flows) {
            lines.append("")
            lines.append("⚠︎  \(finding.advice)")
        }

        lines.append("")
        lines.append(Self.flowTable(Array(byBytes.prefix(flowLimit))))
        if byBytes.count > flowLimit {
            lines.append("… \(byBytes.count - flowLimit) further flows omitted.")
        }

        // Unattributed flows are the interesting failure mode, so list them explicitly
        // rather than leaving them buried in the table above.
        let unknown = byBytes.filter { $0.owner == nil }
        if !unknown.isEmpty {
            lines.append("Unattributed flows (\(unknown.count)):")
            for flow in unknown.prefix(unattributedLimit) {
                lines.append(
                    "  \(Column.left(flow.key.transport.name, 7))"
                        + "\(flow.key.local.endpoint(port: flow.key.localPort)) → "
                        + "\(flow.key.remote.endpoint(port: flow.key.remotePort))  "
                        + "\(flow.totalPackets) packets, "
                        + formatBytes(Double(flow.totalBytes))
                )
            }
            if unknown.count > unattributedLimit {
                lines.append("  … and \(unknown.count - unattributedLimit) more.")
            }
        }

        return lines.joined(separator: "\n")
    }

    private func shutDown() {
        let endedAt = Date()
        print(buildReport(endedAt: endedAt, flowLimit: 40, unattributedLimit: 15))

        if let log {
            // Everything, with nothing elided — reconstructing an omitted flow after the
            // fact is impossible, and the file exists precisely to avoid that.
            log.section(
                "FINAL REPORT",
                buildReport(endedAt: endedAt, flowLimit: .max, unattributedLimit: .max)
            )
            log.close()
            print("")
            print("Full transcript: \(log.url.path)")
        }

        monitor.stop()
        exit(0)
    }

    /// Writes a periodic snapshot, so a run that is killed rather than stopped cleanly
    /// still leaves usable evidence behind.
    private func writePeriodicSnapshot() {
        guard let log else { return }
        log.section(
            "SNAPSHOT \(formatTimestamp(Date()))",
            buildReport(endedAt: Date(), flowLimit: 60, unattributedLimit: 20)
        )
    }
}
