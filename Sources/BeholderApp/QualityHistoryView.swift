import BeholderCore
import Charts
import SwiftUI

/// The long view: whether the network has been reliable, and whose fault it was when not.
///
/// Reads the database rather than the daemon, so it works when nothing is capturing.
struct QualityHistoryView: View {
    let model: QualityModel

    var body: some View {
        VStack(spacing: 0) {
            QualityRangeBar(model: model)
            Divider()

            switch model.state {
            case .idle, .loading:
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            case .unavailable(let message):
                QualityUnavailableView(message: message)
            case .loaded:
                if let report = model.report, report.minutesObserved > 0 {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 18) {
                            VerdictBox(report: report)
                            LatencyOverTime(series: model.series)
                            HourOfDayChart(hours: report.hours)
                            if let bufferbloat = report.bufferbloat {
                                BufferbloatBox(reading: bufferbloat)
                            }
                            if !report.failures.isEmpty {
                                FailureList(failures: report.failures)
                            }
                            NetworkBaselines(report: report)
                            CaveatList(caveats: report.caveats)
                        }
                        .padding(14)
                    }
                } else {
                    QualityUnavailableView(
                        message: "Nothing has been measured in this window yet."
                    )
                }
            }
        }
        .task { if model.state == .idle { model.reload() } }
    }
}

private struct QualityRangeBar: View {
    let model: QualityModel

    var body: some View {
        HStack(spacing: 10) {
            Picker("Range", selection: Binding(get: { model.range }, set: { model.range = $0 })) {
                ForEach(QualityModel.ranges) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()

            if model.availableInterfaces.count > 1 {
                Picker(
                    "Interface",
                    selection: Binding(get: { model.interface }, set: { model.interface = $0 })
                ) {
                    Text("All interfaces").tag(String?.none)
                    ForEach(model.availableInterfaces, id: \.name) { entry in
                        Text(entry.name).tag(String?.some(entry.name))
                    }
                }
                .fixedSize()
                .help(
                    "Measurements on a utun interface describe a VPN tunnel, not the "
                        + "connection underneath it. Separating them is the difference "
                        + "between measuring your ISP and measuring your VPN provider."
                )
            }

            Spacer()

            if let coverage = model.coverage {
                Text(
                    "\(pluralised(coverage.minutes, "minute")) recorded, "
                        + "since \(coverage.earliest.formatted(date: .abbreviated, time: .shortened))"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            if model.windowExceedsCoverage {
                Text("shorter than the window asked for")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .help(
                        "Recording started later than this window begins, so the earlier "
                            + "part is not a quiet network — it is no network being watched."
                    )
            }
        }
        .padding(12)
    }
}

private struct QualityUnavailableView: View {
    let message: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "clock.badge.questionmark")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(message).font(.headline)
            Text(
                "The daemon records a row a minute while it runs. An empty window means "
                    + "either nothing was asked of the network, or nothing was watching — "
                    + "and from here those look the same."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 440)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

// MARK: - The verdict

private struct VerdictBox: View {
    let report: Reliability.Report

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: report.commonModeMinutes > 0 ? "exclamationmark.triangle" : "checkmark.seal")
                    .foregroundStyle(report.commonModeMinutes > 0 ? .orange : .green)
                Text("What the numbers support").font(.headline)
            }
            Text(report.verdict)
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Charts

private struct LatencyOverTime: View {
    /// Collapsed by `Reliability.series` on the query queue, not here. One point per minute
    /// across every network would be a smear; how the networks combine into one point is a
    /// statistical decision, and it belongs where a test can reach it.
    let series: [Reliability.Point]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Round trip over time").font(.headline)
            Text("The floor is the honest baseline; the gap above it is queueing.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Chart {
                ForEach(series, id: \.at) { point in
                    if let typical = point.typicalMs {
                        AreaMark(
                            x: .value("Time", point.at),
                            yStart: .value("Floor", point.floorMs),
                            yEnd: .value("Typical", max(typical, point.floorMs))
                        )
                        .foregroundStyle(.orange.opacity(0.25))
                    }
                    LineMark(x: .value("Time", point.at), y: .value("Floor", point.floorMs))
                        .foregroundStyle(.blue)
                }
            }
            .chartYAxis {
                AxisMarks(position: .trailing) { value in
                    if let milliseconds = value.as(Double.self) {
                        AxisValueLabel { Text("\(Int(milliseconds)) ms").font(.caption2) }
                    }
                }
            }
            .frame(height: 150)
        }
    }
}

/// The shape a contended residential link makes: fine all day, worse from seven.
private struct HourOfDayChart: View {
    let hours: [Reliability.HourReading]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("By hour of day").font(.headline)
            Text(
                "Averaged over every day in the window. Evening congestion, if it is there, "
                    + "shows up here and nowhere else."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            Chart {
                ForEach(hours.filter { $0.samples > 0 }, id: \.hour) { reading in
                    if let typical = reading.typicalMs {
                        BarMark(
                            x: .value("Hour", reading.hour),
                            y: .value("Typical round trip", typical)
                        )
                        .foregroundStyle(
                            reading.degradedMinutes > 0 ? .orange : .blue
                        )
                    }
                }
            }
            .chartXAxis {
                AxisMarks(values: Array(stride(from: 0, through: 23, by: 3))) { value in
                    if let hour = value.as(Int.self) {
                        AxisValueLabel { Text("\(hour):00").font(.caption2) }
                    }
                }
            }
            .chartYAxis {
                AxisMarks(position: .trailing) { value in
                    if let milliseconds = value.as(Double.self) {
                        AxisValueLabel { Text("\(Int(milliseconds)) ms").font(.caption2) }
                    }
                }
            }
            .frame(height: 130)
        }
    }
}

private struct BufferbloatBox: View {
    let reading: Reliability.BufferbloatReading

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Latency under load").font(.headline)
            HStack(spacing: 26) {
                labelled("At rest", "\(Int(reading.idleFloorMs.rounded())) ms")
                labelled("Under load", "\(Int(reading.loadedTypicalMs.rounded())) ms")
                labelled("Added by queueing", "\(Int(reading.inflationMs.rounded())) ms")
            }
            Text(
                reading.isSignificant
                    ? "That much queueing is felt on a call or in a game. It is bufferbloat: "
                        + "a buffer somewhere between here and the exchange filling under "
                        + "load. Usually fixed at the router with fair queueing, not by the ISP."
                    : "Latency stays close to its floor under load, which is what a link "
                        + "with sensible queueing looks like."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    private func labelled(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.title3, design: .rounded)).monospacedDigit()
        }
    }
}

private struct FailureList: View {
    let failures: [Reliability.FailureWindow]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Connections that got no answer").font(.headline)
            Text(
                "Direct evidence the path failed while it was being used — which is a "
                    + "different claim from an outage, and a stronger one."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            ForEach(failures.indices, id: \.self) { index in
                let failure = failures[index]
                HStack {
                    Text(failure.start.formatted(date: .abbreviated, time: .shortened))
                        .font(.system(.caption, design: .monospaced))
                    Spacer()
                    Text(
                        "\(pluralised(failure.timeouts, "attempt")) across "
                            + pluralised(failure.networks, "network")
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct NetworkBaselines: View {
    let report: Reliability.Report

    private var ordered: [Reliability.Baseline] {
        report.baselines.values.sorted { $0.minutes > $1.minutes }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Networks compared").font(.headline)
            Text(
                "Each network's own floor. Independence is what makes the verdict possible: "
                    + "several of these slowing at once is what points at the shared path."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            ForEach(ordered.prefix(12), id: \.group) { baseline in
                HStack {
                    Text(baseline.label ?? baseline.group)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                    Spacer()
                    Text("floor \(formatMilliseconds(baseline.floorMs))")
                        .font(.caption)
                        .monospacedDigit()
                    Text(pluralised(baseline.minutes, "minute"))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .frame(width: 90, alignment: .trailing)
                }
            }
        }
    }
}

/// Caveats travel with the data, not in a footnote nobody scrolls to.
private struct CaveatList: View {
    let caveats: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("What this cannot tell you").font(.headline)
            ForEach(caveats, id: \.self) { caveat in
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(caveat)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(.top, 4)
    }
}
