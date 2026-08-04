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
        // The count of connections this machine has opened. Byte rates were harder to
        // read at a glance — they change every second and carry a unit — whereas "how
        // many things is my laptop talking to" is a single number that means something
        // on its own. The rates are still a click away in the menu.
        HStack(spacing: 4) {
            Image(systemName: "eye")
            if let statistics = client.snapshot?.statistics {
                Text("↗\(String(statistics.outgoingCount))")
                    .font(.system(size: 11, design: .monospaced))
                    .monospacedDigit()
            }
        }
        .help(helpText)
    }

    private var helpText: String {
        guard let statistics = client.snapshot?.statistics else {
            return "Beholder — waiting for the capture daemon"
        }
        var text = "Beholder — \(pluralised(statistics.outgoingCount, "outgoing connection"))"
        if statistics.incomingCount > 0 {
            text += ", \(statistics.incomingCount) incoming"
        }
        if let latest = client.history.last {
            text += "\n↑ \(formatBytes(latest.bytesOutPerSecond))/s"
                + "  ↓ \(formatBytes(latest.bytesInPerSecond))/s"
        }
        return text
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
                "\(pluralised(snapshot.statistics.outgoingCount, "outgoing connection"))"
                    + (snapshot.statistics.incomingCount > 0
                        ? ", \(snapshot.statistics.incomingCount) incoming" : "")
            )
            Text(
                "\(pluralised(snapshot.statistics.processCount, "process", plural: "processes"))"
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

private enum Presentation: String, CaseIterable, Identifiable {
    case connections = "Connections"
    case map = "Map"
    case history = "History"
    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .connections: return "list.bullet"
        case .map: return "globe"
        case .history: return "clock.arrow.circlepath"
        }
    }
}

private struct MainView: View {
    let client: FlowClient
    @State private var presentation: Presentation = .connections
    @State private var grouping: Grouping = .process
    @State private var unidentifiedOnly = false
    @State private var history = HistoryModel()

    var body: some View {
        VStack(spacing: 0) {
            // History reads the database directly and needs no daemon, so it works even
            // when nothing is capturing — which is exactly when you want to look at it.
            if presentation == .history {
                HistoryHeader(presentation: $presentation)
                Divider()
                HistoryView(model: history)
            } else if let snapshot = client.snapshot {
                HeaderView(
                    snapshot: snapshot,
                    history: client.history,
                    presentation: $presentation
                )
                Divider()
                WarningsView(statistics: snapshot.statistics)
                switch presentation {
                case .connections:
                    GroupingBar(
                        grouping: $grouping,
                        unidentifiedOnly: $unidentifiedOnly,
                        snapshot: snapshot
                    )
                    Divider()
                    ConnectionsView(
                        snapshot: snapshot,
                        grouping: $grouping,
                        unidentifiedOnly: $unidentifiedOnly
                    )
                case .map:
                    ConnectionMapView(snapshot: snapshot)
                case .history:
                    // Handled above; history needs no live snapshot.
                    EmptyView()
                }
            } else {
                VStack(spacing: 0) {
                    HistoryHeader(presentation: $presentation)
                    Divider()
                    WaitingView(state: client.state)
                }
            }
        }
    }
}

/// The view switcher on its own, for the screens that have no live snapshot to summarise.
private struct HistoryHeader: View {
    @Binding var presentation: Presentation

    var body: some View {
        HStack {
            Text("Beholder").font(.headline)
            Spacer()
            Picker("View", selection: $presentation) {
                ForEach(Presentation.allCases) { option in
                    Label(option.rawValue, systemImage: option.symbol).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
        }
        .padding(12)
    }
}

/// Shown whenever there is no daemon to read.
///
/// Capture needs root and is started separately, so an idle app is the ordinary state on
/// launch rather than a fault. The screen therefore explains rather than apologises, and
/// gives exactly one command to run — an earlier version stated the problem twice and
/// offered two subtly different commands, which is worse than saying nothing.
private struct WaitingView: View {
    let state: FlowClient.State

    /// The app bundle lives at `<project>/.build/Beholder.app`, so the project root is
    /// two levels up. Showing the real path means the command can be pasted as-is
    /// instead of being adjusted for wherever the user happens to be.
    private var projectRoot: String? {
        let root = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let makefile = root.appendingPathComponent("Makefile")
        return FileManager.default.fileExists(atPath: makefile.path) ? root.path : nil
    }

    private var command: String {
        guard let projectRoot else { return "make run" }
        return "cd \(projectRoot) && make run"
    }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "eye.slash")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)

            switch state {
            case .failed(let message):
                Text(message)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            case .waitingForDaemon(let message):
                VStack(spacing: 6) {
                    Text("The capture daemon isn't running")
                        .font(.headline)
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            case .connected:
                // Connected but holding no snapshot yet. Worth saying distinctly:
                // reporting this as "connecting" once hid a daemon that was streaming
                // perfectly well but whose messages the app could not decode, and sent
                // the search to the socket instead of to the data crossing it.
                ProgressView()
                Text("Connected — waiting for the first snapshot")
                    .foregroundStyle(.secondary)
            default:
                ProgressView()
                Text("Connecting to the capture daemon")
                    .foregroundStyle(.secondary)
            }

            if case .failed = state {} else {
                Text(
                    "Capture reads /dev/bpf*, which is root-only, so it runs as a "
                        + "separate process. Start it with:"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)

                HStack(spacing: 8) {
                    Text(command)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy the command")
                }
                .padding(10)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

                Text("This window connects on its own once the daemon is up.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

/// "5 outgoing · 2 incoming · 1 undetermined · 7 processes", omitting whatever is zero.
func directionSummary(_ statistics: WireStatistics) -> String {
    var parts = [pluralised(statistics.outgoingCount, "outgoing connection")]
    if statistics.incomingCount > 0 {
        parts.append("\(statistics.incomingCount) incoming")
    }
    if statistics.undeterminedDirectionCount > 0 {
        parts.append("\(statistics.undeterminedDirectionCount) undetermined")
    }
    parts.append(pluralised(statistics.processCount, "process", plural: "processes"))
    return parts.joined(separator: " · ")
}

private struct HeaderView: View {
    let snapshot: FlowSnapshot
    let history: [FlowClient.ThroughputSample]
    @Binding var presentation: Presentation

    var body: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(snapshot.interfaces.joined(separator: ", "))
                    .font(.headline)
                Text(directionSummary(snapshot.statistics))
                    .foregroundStyle(.secondary)
                    .help(
                        "Direction comes from the opening handshake where it was seen, "
                            + "and from port allocation otherwise. Connections that "
                            + "cannot be established either way are counted separately "
                            + "rather than assumed."
                    )

                let attributable = snapshot.statistics.attributableCount
                if attributable > 0 {
                    let share =
                        Double(snapshot.statistics.attributedCount) / Double(attributable) * 100
                    Text(String(format: "%.0f%% attributed", share))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .help(
                            "\(pluralised(snapshot.statistics.unattributedCount, "connection")) could not be "
                                + "traced to a process — usually very short-lived sockets."
                        )
                }
            }

            Spacer()

            Picker("View", selection: $presentation) {
                ForEach(Presentation.allCases) { option in
                    Label(option.rawValue, systemImage: option.symbol).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()

            if !history.isEmpty {
                ThroughputChart(history: history)
                    .frame(width: 260, height: 74)
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
                    "\(pluralised(statistics.packetsDropped, "packet")) dropped by the kernel, so "
                        + "these totals are an undercount."
                )
            )
        }
        if statistics.evictedFlowCount > 0 {
            result.append(
                (
                    "tray.full",
                    "\(pluralised(statistics.evictedFlowCount, "connection")) evicted because the "
                        + "table is full, so these totals are an undercount."
                )
            )
        }
        if statistics.privateRelayFlowCount > 0 {
            result.append(
                (
                    "lock.shield",
                    "\(pluralised(statistics.privateRelayFlowCount, "connection")) to iCloud "
                        + "Private Relay hosts. What travels over them — DNS queries, or "
                        + "relayed connections — is encrypted, so it cannot be read from "
                        + "this machine. Most are macOS resolving names privately, which "
                        + "continues even while a VPN is up."
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
