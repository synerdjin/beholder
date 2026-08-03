import BeholderCore
import SwiftUI

/// Counts with a correctly pluralised noun. "1 connections" is the kind of small wrongness
/// that makes a tool feel unfinished.
func pluralised(_ count: Int, _ singular: String, plural: String? = nil) -> String {
    let noun = count == 1 ? singular : (plural ?? singular + "s")
    return "\(count) \(noun)"
}

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

/// How the connection list is organised.
enum Grouping: String, CaseIterable, Identifiable {
    /// What is running on this machine.
    case process = "By app"
    /// Who is on the other end. This is the view that answers "how much of my traffic
    /// goes to Google", which no per-process listing can show — one company is reached by
    /// many apps, and one app talks to many companies.
    case company = "By company"

    var id: String { rawValue }
}

/// Connections grouped by the process that owns them, or by the company on the far end.
struct ConnectionsView: View {
    let snapshot: FlowSnapshot
    @Binding var grouping: Grouping
    @Binding var unrecognisedOnly: Bool
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
        var matching = snapshot.flows

        if !searchText.isEmpty {
            let needle = searchText.lowercased()
            matching = matching.filter { flow in
                let haystack = [
                    flow.processName, flow.hostName, flow.remoteAddress,
                    String(flow.remotePort), flow.classification?.owner,
                ]
                .compactMap { $0 }.joined(separator: " ").lowercased()
                return haystack.contains(needle)
            }
        }

        if unrecognisedOnly {
            matching = matching.filter { $0.classification?.isRecognised != true }
        }

        var buckets: [String: [WireFlow]] = [:]
        for flow in matching {
            // Flows with no owner are collected rather than hidden: a connection nobody
            // can account for is the most interesting row on the screen.
            let key: String
            switch grouping {
            case .process:
                key = flow.pid.map(String.init) ?? "unattributed"
            case .company:
                key = flow.classification?.owner ?? "unrecognised"
            }
            buckets[key, default: []].append(flow)
        }

        return buckets.map { key, flows in
            let first = flows.first
            switch grouping {
            case .process:
                return Group(
                    id: key,
                    name: first?.processName ?? "Unattributed",
                    pid: first?.pid,
                    flows: flows.sorted { $0.totalBytes > $1.totalBytes }
                )
            case .company:
                return Group(
                    id: key,
                    name: first?.classification?.owner ?? "Unrecognised",
                    // No single pid represents a company, so no icon.
                    pid: nil,
                    flows: flows.sorted { $0.totalBytes > $1.totalBytes }
                )
            }
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
                        bytesIn: group.bytesIn,
                        grouping: grouping
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
    let grouping: Grouping

    /// Dimmed only for the catch-all buckets, not for every company row — in company
    /// grouping there is no pid, and dimming on that basis would grey out everything.
    private var isPlaceholder: Bool {
        grouping == .process ? pid == nil : name == "Unrecognised"
    }

    private var subtitle: String {
        let connections = pluralised(connectionCount, "connection")
        guard grouping == .process else {
            // Being unrecognised is the ordinary case for most of the internet, so it is
            // stated plainly rather than dressed up as a finding.
            return name == "Unrecognised"
                ? "\(connections) to hosts no tracker database lists"
                : connections
        }
        guard let pid else { return "\(connections) with no identifiable owner" }
        // String(pid) rather than interpolating the number directly: SwiftUI applies
        // locale grouping to interpolated integers, which turned pid 1365 into "1,365".
        // A process identifier is a name, not a quantity.
        return "pid \(String(pid)) · \(connections)"
    }

    var body: some View {
        HStack(spacing: 10) {
            if grouping == .process {
                Image(nsImage: ProcessIcons.icon(forPid: pid))
                    .resizable()
                    .frame(width: 20, height: 20)
            } else {
                Image(systemName: name == "Unrecognised" ? "questionmark.circle" : "building.2")
                    .frame(width: 20, height: 20)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 1) {
                Text(name)
                    .fontWeight(.medium)
                    .foregroundStyle(isPlaceholder ? .secondary : .primary)
                Text(subtitle)
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
                // String(port) for the same reason as the pid: a port number is an
                // identifier, and "port 8,080" is nonsense.
                HStack(spacing: 5) {
                    Text(
                        "port \(String(flow.remotePort))"
                            + (flow.tcpState.map { " · \($0)" } ?? "")
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    ClassificationBadges(classification: flow.classification)
                }
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
