import BeholderCore
import Charts
import SwiftUI

/// What happened while you were not watching.
///
/// The live view answers "what is my machine doing"; this answers "what did it do". Those
/// are different questions, and the second is the one you cannot get any other way.
struct HistoryView: View {
    @Bindable var model: HistoryModel

    var body: some View {
        VStack(spacing: 0) {
            controls
            Divider()

            switch model.state {
            case .idle, .loading:
                loading
            case .unavailable(let message):
                unavailable(message)
            case .loaded:
                if model.totals.isEmpty && model.flows.isEmpty {
                    empty
                } else {
                    content
                }
            }
        }
        .task { model.reload() }
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("Range", selection: $model.range) {
                ForEach(HistoryModel.ranges) { range in
                    Text(range.rawValue).tag(range)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .fixedSize()

            TextField("Filter by app, host, address, company or network", text: $model.searchText)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 380)

            Spacer()

            if case .loaded = model.state {
                Text(
                    "↑ \(formatBytes(Double(model.totalBytesOut)))  "
                        + "↓ \(formatBytes(Double(model.totalBytesIn)))"
                )
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.secondary)
            }

            Button {
                model.reload()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Reload")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var loading: some View {
        VStack(spacing: 10) {
            ProgressView()
            Text("Reading history…").foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func unavailable(_ message: String) -> some View {
        ContentUnavailableView {
            Label("No history yet", systemImage: "clock.arrow.circlepath")
        } description: {
            VStack(spacing: 10) {
                Text(message)
                // Capture must be running for history to accumulate, and it is started
                // separately — so an empty database is the expected state before that,
                // not a fault.
                Text(
                    "History is written as connections finish. Run a capture, or install "
                        + "the daemon to record continuously:"
                )
                .multilineTextAlignment(.center)
                Text("make install")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
            .frame(maxWidth: 440)
        }
    }

    private var empty: some View {
        ContentUnavailableView {
            Label("Nothing in this window", systemImage: "clock")
        } description: {
            Text(
                model.windowExceedsCoverage
                    ? "History only goes back to "
                        + (model.coverage.map { formatDate($0.earliest) } ?? "recently")
                        + ". Try a shorter range."
                    : "No connections were recorded in this period."
            )
        }
    }

    private var content: some View {
        VStack(spacing: 0) {
            if let coverage = model.coverage {
                // What the database actually covers, so an empty stretch is never
                // mistaken for a quiet one.
                HStack(spacing: 6) {
                    Image(systemName: "clock.arrow.circlepath")
                    Text(
                        "Recorded from \(formatDate(coverage.earliest)) "
                            + "to \(formatDate(coverage.latest))"
                    )
                    if model.windowExceedsCoverage {
                        Text("· the selected range reaches further back than that")
                            .foregroundStyle(.orange)
                    }
                    Spacer()
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                Divider()
            }

            HSplitView {
                processTotals
                    .frame(minWidth: 280, idealWidth: 340)
                flowList
                    .frame(minWidth: 380)
            }
        }
    }

    private var processTotals: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("BY APPLICATION")
                .font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 6)

            if model.totals.isEmpty {
                Text("No totals in this window.")
                    .foregroundStyle(.secondary)
                    .padding(12)
                Spacer()
            } else {
                // A bar per application, because "who used the most" is the first thing
                // anyone asks of a period of history.
                Chart(model.totals.prefix(12), id: \.processPath) { total in
                    BarMark(
                        x: .value("Bytes", total.totalBytes),
                        y: .value("Process", total.processName)
                    )
                    .foregroundStyle(.blue.opacity(0.7))
                }
                .chartXAxis {
                    AxisMarks { value in
                        if let bytes = value.as(Double.self) {
                            AxisValueLabel { Text(formatBytes(bytes)).font(.caption2) }
                        }
                    }
                }
                .frame(height: min(CGFloat(model.totals.prefix(12).count) * 26 + 30, 350))
                .padding(.horizontal, 12)

                List(model.totals, id: \.processPath) { total in
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(total.processName).fontWeight(.medium)
                            Text(pluralised(total.flowCount, "connection"))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 1) {
                            Text("↑ \(formatBytes(Double(total.bytesOut)))")
                            Text("↓ \(formatBytes(Double(total.bytesIn)))")
                        }
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var flowList: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("CONNECTIONS")
                Spacer()
                if model.flows.count >= 500 {
                    // Never silently truncate: a capped list that does not say so reads
                    // as the whole picture.
                    Text("showing the heaviest 500")
                }
            }
            .font(.caption).foregroundStyle(.secondary)
            .padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 6)

            List(model.flows, id: \.self) { flow in
                HistoricalFlowRow(flow: flow)
            }
        }
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "d MMM, HH:mm"
        return formatter.string(from: date)
    }
}

private struct HistoricalFlowRow: View {
    let flow: HistoricalFlow

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    Text(flow.remoteDescription)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1).truncationMode(.middle)
                        .textSelection(.enabled)
                    if let company = flow.ownerCompany {
                        Text(company)
                            .font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.quaternary, in: Capsule())
                    }
                }
                HStack(spacing: 6) {
                    Text(flow.processName ?? "(unattributed)")
                    Text("·")
                    Text("\(flow.transport) \(String(flow.remotePort))")
                    if let country = flow.country {
                        Text("·")
                        Text(country)
                    }
                    Text("·")
                    Text(relativeTime(flow.lastSeen))
                }
                .font(.caption).foregroundStyle(.secondary)
            }

            Spacer()
            VStack(alignment: .trailing, spacing: 1) {
                Text("↑ \(formatBytes(Double(flow.bytesOut)))")
                Text("↓ \(formatBytes(Double(flow.bytesIn)))")
            }
            .font(.system(.caption, design: .monospaced))
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Copy address") { copy(flow.remoteAddress) }
            if let hostName = flow.hostName {
                Button("Copy hostname") { copy(hostName) }
            }
            Button("Copy row") {
                copy(
                    [
                        flow.processName ?? "(unattributed)", flow.transport,
                        flow.remoteDescription, String(flow.remotePort),
                        formatBytes(Double(flow.bytesOut)) + " up",
                        formatBytes(Double(flow.bytesIn)) + " down",
                    ].joined(separator: "  ")
                )
            }
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func relativeTime(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}
