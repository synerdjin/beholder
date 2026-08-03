import BeholderCore
import SwiftUI

/// Byte counts, rendered the way people read them.
func formatBytes(_ bytes: Double) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var value = bytes
    var unitIndex = 0
    while value >= 1024, unitIndex < units.count - 1 {
        value /= 1024
        unitIndex += 1
    }
    return unitIndex == 0
        ? String(format: "%.0f %@", value, units[unitIndex])
        : String(format: "%.1f %@", value, units[unitIndex])
}

/// Connections grouped by the process that owns them.
struct ConnectionsView: View {
    let snapshot: FlowSnapshot
    @State private var expanded: Set<String> = []
    @State private var searchText = ""

    private struct Group: Identifiable {
        let id: String
        let name: String
        let pid: Int32?
        let flows: [WireFlow]
        var bytesOut: UInt64 { flows.reduce(0) { $0 + $1.bytesOut } }
        var bytesIn: UInt64 { flows.reduce(0) { $0 + $1.bytesIn } }
        var totalBytes: UInt64 { bytesOut + bytesIn }
    }

    private var groups: [Group] {
        let matching = searchText.isEmpty
            ? snapshot.flows
            : snapshot.flows.filter { flow in
                let haystack = [
                    flow.processName, flow.hostName, flow.remoteAddress,
                    String(flow.remotePort),
                ]
                .compactMap { $0 }.joined(separator: " ").lowercased()
                return haystack.contains(searchText.lowercased())
            }

        var byProcess: [String: [WireFlow]] = [:]
        for flow in matching {
            // Unattributed flows are collected rather than hidden: a connection nobody
            // can account for is the most interesting row on the screen.
            let key = flow.pid.map(String.init) ?? "unknown"
            byProcess[key, default: []].append(flow)
        }

        return byProcess.map { key, flows in
            Group(
                id: key,
                name: flows.first?.processName ?? "Unattributed",
                pid: flows.first?.pid,
                flows: flows.sorted { $0.totalBytes > $1.totalBytes }
            )
        }
        .sorted { $0.totalBytes > $1.totalBytes }
    }

    var body: some View {
        List {
            ForEach(groups) { group in
                DisclosureGroup(
                    isExpanded: Binding(
                        get: { expanded.contains(group.id) },
                        set: { isExpanded in
                            if isExpanded { expanded.insert(group.id) } else {
                                expanded.remove(group.id)
                            }
                        }
                    )
                ) {
                    ForEach(group.flows) { flow in
                        FlowRow(flow: flow)
                    }
                } label: {
                    ProcessRow(
                        name: group.name,
                        pid: group.pid,
                        connectionCount: group.flows.count,
                        bytesOut: group.bytesOut,
                        bytesIn: group.bytesIn
                    )
                }
            }
        }
        .searchable(text: $searchText, prompt: "Filter by process, host or port")
    }
}

private struct ProcessRow: View {
    let name: String
    let pid: Int32?
    let connectionCount: Int
    let bytesOut: UInt64
    let bytesIn: UInt64

    var body: some View {
        HStack(spacing: 10) {
            Image(nsImage: ProcessIcons.icon(forPid: pid))
                .resizable()
                .frame(width: 20, height: 20)

            VStack(alignment: .leading, spacing: 1) {
                Text(name)
                    .fontWeight(.medium)
                    .foregroundStyle(pid == nil ? .secondary : .primary)
                Text(
                    pid.map { "pid \($0) · \(connectionCount) connections" }
                        ?? "\(connectionCount) connections with no identifiable owner"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Spacer()
            TrafficFigures(bytesOut: bytesOut, bytesIn: bytesIn)
        }
        .padding(.vertical, 2)
    }
}

private struct FlowRow: View {
    let flow: WireFlow

    var body: some View {
        HStack(spacing: 8) {
            Text(flow.transport)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 46, alignment: .leading)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(flow.remoteDescription)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if flow.hostName != nil && !flow.hostNameIsProof {
                        // A DNS-derived name is a good guess, not proof: one address can
                        // serve many names. Saying so is cheap; implying certainty is not.
                        Image(systemName: "questionmark.circle")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .help("Name inferred from a DNS answer, not from this connection")
                    }
                    if flow.isPrivateRelay {
                        Text("Private Relay")
                            .font(.caption2)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(.quaternary, in: Capsule())
                            .help(
                                "Encrypted end-to-end to Apple. The real destination "
                                    + "cannot be determined from this machine."
                            )
                    }
                }
                Text(
                    "port \(flow.remotePort)"
                        + (flow.tcpState.map { " · \($0)" } ?? "")
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Spacer()
            TrafficFigures(bytesOut: flow.bytesOut, bytesIn: flow.bytesIn)
        }
        .padding(.leading, 6)
        .padding(.vertical, 1)
    }
}

private struct TrafficFigures: View {
    let bytesOut: UInt64
    let bytesIn: UInt64

    var body: some View {
        HStack(spacing: 12) {
            Label(formatBytes(Double(bytesOut)), systemImage: "arrow.up")
                .foregroundStyle(.secondary)
            Label(formatBytes(Double(bytesIn)), systemImage: "arrow.down")
        }
        .font(.system(.caption, design: .monospaced))
        .labelStyle(.titleAndIcon)
        .monospacedDigit()
    }
}

/// Application icons, looked up by pid and cached.
///
/// The daemon deliberately reports only an executable path — icons are a presentation
/// concern and need AppKit, which has no business in a root process.
enum ProcessIcons {
    nonisolated(unsafe) private static var cache: [Int32: NSImage] = [:]

    static func icon(forPid pid: Int32?) -> NSImage {
        guard let pid else {
            return NSImage(
                systemSymbolName: "questionmark.app.dashed", accessibilityDescription: nil
            ) ?? NSImage()
        }
        if let cached = cache[pid] { return cached }

        let icon: NSImage
        if let application = NSRunningApplication(processIdentifier: pid),
            let applicationIcon = application.icon
        {
            icon = applicationIcon
        } else {
            icon =
                NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)
                ?? NSImage()
        }
        cache[pid] = icon
        return icon
    }
}
