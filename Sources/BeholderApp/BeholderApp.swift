import BeholderCore
import Charts
import SwiftUI

@main
struct BeholderApp: App {
    @State private var client = FlowClient()

    var body: some Scene {
        Window("Beholder", id: "main") {
            MainView(client: client)
                .frame(minWidth: 760, minHeight: 460)
                .task { client.start() }
        }
        .defaultSize(width: 980, height: 640)

        MenuBarExtra {
            MenuBarContent(client: client)
        } label: {
            MenuBarLabel(client: client)
        }
    }
}

// MARK: - Menu bar

private struct MenuBarLabel: View {
    let client: FlowClient

    var body: some View {
        // Rates rather than totals: the menu bar answers "is anything happening right
        // now", and a running total never changes fast enough to be worth a glance.
        //
        // Up and down are shown separately. An earlier version summed them into one bare
        // number, which was ambiguous enough that the first person to see it had to ask
        // what it meant — and merging the directions threw away the distinction the whole
        // tool exists to draw.
        HStack(spacing: 4) {
            Image(systemName: "eye")
            if let latest = client.history.last {
                Text(
                    "↑\(compactRate(latest.bytesOutPerSecond)) "
                        + "↓\(compactRate(latest.bytesInPerSecond))"
                )
                .font(.system(size: 10, design: .monospaced))
                .monospacedDigit()
            }
        }
        .help(
            client.history.last.map {
                "Beholder — sending \(formatBytes($0.bytesOutPerSecond))/s, "
                    + "receiving \(formatBytes($0.bytesInPerSecond))/s"
            } ?? "Beholder — waiting for the capture daemon"
        )
    }

    /// Deliberately terse: the menu bar has very little room, and the exact figure with
    /// units is one click away in the menu itself.
    private func compactRate(_ bytesPerSecond: Double) -> String {
        let units = ["B", "K", "M", "G"]
        var value = bytesPerSecond
        var index = 0
        while value >= 1024, index < units.count - 1 {
            value /= 1024
            index += 1
        }
        return value >= 100 || index == 0
            ? "\(Int(value))\(units[index])"
            : String(format: "%.1f%@", value, units[index])
    }
}

private struct MenuBarContent: View {
    let client: FlowClient
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let snapshot = client.snapshot {
            Text(
                "\(pluralised(snapshot.statistics.flowCount, "connection")), "
                    + "\(pluralised(snapshot.statistics.processCount, "process", plural: "processes"))"
            )
            // The menu is where the numbers get their units, since the bar itself has no
            // room for them.
            if let latest = client.history.last {
                Text(
                    "Now: ↑ \(formatBytes(latest.bytesOutPerSecond))/s  "
                        + "↓ \(formatBytes(latest.bytesInPerSecond))/s"
                )
            }
            Text(
                "Total: ↑ \(formatBytes(Double(snapshot.statistics.totalBytesOut)))  "
                    + "↓ \(formatBytes(Double(snapshot.statistics.totalBytesIn)))"
            )
            Divider()
            ForEach(topProcesses(snapshot), id: \.name) { entry in
                Text("\(entry.name) — \(formatBytes(Double(entry.bytes)))")
            }
            Divider()
        } else {
            Text(statusText)
            Divider()
        }

        Button("Open Beholder") { openWindow(id: "main") }
        Button("Quit") { NSApplication.shared.terminate(nil) }
            .keyboardShortcut("q")
    }

    private var statusText: String {
        switch client.state {
        case .connected: return "Connected, waiting for data…"
        case .connecting, .idle: return "Connecting…"
        case .waitingForDaemon: return "Daemon not running"
        case .failed(let message): return message
        }
    }

    private func topProcesses(_ snapshot: FlowSnapshot) -> [(name: String, bytes: UInt64)] {
        var totals: [String: UInt64] = [:]
        for flow in snapshot.flows {
            totals[flow.processName ?? "Unattributed", default: 0] += flow.totalBytes
        }
        return totals.map { (name: $0.key, bytes: $0.value) }
            .sorted { $0.bytes > $1.bytes }
            .prefix(5)
            .map { $0 }
    }
}

// MARK: - Main window

private struct MainView: View {
    let client: FlowClient

    var body: some View {
        VStack(spacing: 0) {
            if let snapshot = client.snapshot {
                HeaderView(snapshot: snapshot, history: client.history)
                Divider()
                WarningsView(statistics: snapshot.statistics)
                ConnectionsView(snapshot: snapshot)
            } else {
                WaitingView(state: client.state)
            }
        }
    }
}

private struct WaitingView: View {
    let state: FlowClient.State

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "eye.slash")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)

            switch state {
            case .waitingForDaemon(let message), .failed(let message):
                Text(message)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            default:
                ProgressView()
                Text("Connecting to the capture daemon…")
                    .foregroundStyle(.secondary)
            }

            // Capture needs root and is started by hand, so an idle app is the expected
            // state on launch, not a fault. Say what to do about it.
            Text("Capture requires root, so the daemon is started separately:")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("sudo ./.build/debug/beholderd --serve --loopback")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

private struct HeaderView: View {
    let snapshot: FlowSnapshot
    let history: [FlowClient.ThroughputSample]

    var body: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(snapshot.interfaces.joined(separator: ", "))
                    .font(.headline)
                Text(
                    "\(snapshot.statistics.flowCount) connections · "
                        + "\(snapshot.statistics.processCount) processes"
                )
                .foregroundStyle(.secondary)

                let attributable = snapshot.statistics.attributableCount
                if attributable > 0 {
                    let share =
                        Double(snapshot.statistics.attributedCount) / Double(attributable) * 100
                    Text(String(format: "%.0f%% attributed", share))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .help(
                            "\(snapshot.statistics.unattributedCount) connections could not be "
                                + "traced to a process — usually very short-lived sockets."
                        )
                }
            }

            Spacer()

            if !history.isEmpty {
                ThroughputChart(history: history)
                    .frame(width: 320, height: 74)
            }
        }
        .padding(12)
    }
}

private struct ThroughputChart: View {
    let history: [FlowClient.ThroughputSample]

    var body: some View {
        Chart {
            ForEach(history) { sample in
                AreaMark(
                    x: .value("Time", sample.at),
                    y: .value("Bytes/s", sample.bytesInPerSecond),
                    series: .value("Direction", "Down")
                )
                .foregroundStyle(.blue.opacity(0.5))

                AreaMark(
                    x: .value("Time", sample.at),
                    y: .value("Bytes/s", sample.bytesOutPerSecond),
                    series: .value("Direction", "Up")
                )
                .foregroundStyle(.orange.opacity(0.5))
            }
        }
        .chartLegend(.hidden)
        .chartXAxis(.hidden)
        .chartYAxis {
            AxisMarks(position: .trailing) { value in
                if let bytes = value.as(Double.self) {
                    AxisValueLabel { Text(formatBytes(bytes) + "/s").font(.caption2) }
                }
            }
        }
    }
}

/// Anything that makes the numbers above misleading, stated rather than buried.
private struct WarningsView: View {
    let statistics: WireStatistics

    private var notices: [(icon: String, text: String)] {
        var result: [(String, String)] = []
        for warning in statistics.warnings {
            result.append(("exclamationmark.triangle.fill", warning))
        }
        if statistics.packetsDropped > 0 {
            result.append(
                (
                    "exclamationmark.triangle.fill",
                    "\(statistics.packetsDropped) packets were dropped by the kernel, so "
                        + "these totals are an undercount."
                )
            )
        }
        if statistics.evictedFlowCount > 0 {
            result.append(
                (
                    "tray.full",
                    "\(statistics.evictedFlowCount) connections were evicted because the "
                        + "table is full, so these totals are an undercount."
                )
            )
        }
        if statistics.privateRelayFlowCount > 0 {
            result.append(
                (
                    "lock.shield",
                    "\(statistics.privateRelayFlowCount) connections go through iCloud "
                        + "Private Relay. Their real destinations are encrypted end-to-end "
                        + "to Apple and cannot be determined from this machine."
                )
            )
        }
        if let latest = statistics.interfaceTransitions.last {
            result.append(("arrow.triangle.swap", latest))
        }
        return result.map { (icon: $0.0, text: $0.1) }
    }

    var body: some View {
        if !notices.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(notices, id: \.text) { notice in
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: notice.icon)
                            .foregroundStyle(.orange)
                        Text(notice.text)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(.orange.opacity(0.08))
            Divider()
        }
    }
}
