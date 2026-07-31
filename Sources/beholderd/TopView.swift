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

        let timestamp = DateFormatter.localizedString(
            from: now, dateStyle: .none, timeStyle: .medium
        )
        output += """
            Beholder — \(interfaces.joined(separator: ", "))\
              ·  \(summary.flowCount) flows, \(summary.processCount) processes\
              ·  up \(formatBytes(outRate))/s  down \(formatBytes(inRate))/s\
              ·  \(timestamp)

            """
        if summary.unattributedCount > 0 || summary.evictedFlowCount > 0 {
            var notes: [String] = []
            if summary.unattributedCount > 0 {
                notes.append("\(summary.unattributedCount) flows unattributed")
            }
            if summary.evictedFlowCount > 0 {
                notes.append("\(summary.evictedFlowCount) flows evicted (table full)")
            }
            output += notes.joined(separator: "  ·  ") + "\n"
        }
        output += "\n"

        output +=
            Column.left("PROCESS", 22) + Column.right("PID", 7) + "  "
            + Column.left("PROTO", 6) + Column.left("REMOTE", 40)
            + Column.right("UP", 11) + Column.right("DOWN", 11) + "  "
            + "STATE\n"

        for flow in flows {
            let remote = "\(flow.key.remote):\(flow.key.remotePort)"
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

    private func terminalRows() -> Int {
        var size = winsize()
        guard ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0, size.ws_row > 0 else {
            return 30
        }
        return Int(size.ws_row)
    }

    private func shutDown() {
        let summary = monitor.summary()
        print("")
        print("Stopping.")
        print(
            """
            \(summary.flowCount) flows tracked, \(summary.processCount) processes, \
            \(summary.unattributedCount) unattributed, \
            \(summary.attributionPasses) attribution passes.
            """
        )
        if summary.flowCount > 0 {
            let attributed = summary.flowCount - summary.unattributedCount
            let percentage = Double(attributed) / Double(summary.flowCount) * 100
            print(String(format: "Attribution rate: %.1f%%", percentage))
        }
        monitor.stop()
        exit(0)
    }
}
