import BeholderCore
import Charts
import SwiftUI

/// How well the network is working, as opposed to who is using it.
///
/// Two rules run through this whole screen, and both are about refusing to fill a gap with
/// a reassuring number:
///
/// - A conversation with no measurement shows an em dash, never a zero. HTTP/3 runs over
///   QUIC, which offers a passive observer no round trips at all, so "no figure" is a
///   common and honest state — and 0 ms would read as a flawless connection.
/// - Every total says what share of the traffic it covers, because a latency figure over a
///   fifth of the bytes and one over nearly all of them look identical otherwise.
struct QualityView: View {
    let snapshot: FlowSnapshot?
    let history: [FlowClient.ThroughputSample]
    let model: QualityModel
    let waitingState: FlowClient.State

    enum Half: String, CaseIterable, Identifiable {
        case live = "Live"
        case overTime = "Over time"
        var id: String { rawValue }
    }

    @State private var half: Half = .live

    var body: some View {
        VStack(spacing: 0) {
            Picker("Half", selection: $half) {
                ForEach(Half.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .padding(.horizontal, 12)
            .padding(.top, 8)
            .padding(.bottom, 6)
            Divider()

            switch half {
            case .live:
                if let snapshot {
                    LiveQualityView(snapshot: snapshot, history: history)
                } else {
                    // The long view still works with no daemon, so only this half waits.
                    WaitingView(state: waitingState)
                }
            case .overTime:
                QualityHistoryView(model: model)
            }
        }
    }
}

private struct LiveQualityView: View {
    let snapshot: FlowSnapshot
    let history: [FlowClient.ThroughputSample]

    var body: some View {
        if snapshot.statistics.measuredByteShare == nil,
            snapshot.statistics.measuredFlowCount == nil
        {
            MeasurementOffView()
        } else {
            VStack(spacing: 0) {
                QualityHeadline(statistics: snapshot.statistics, history: history)
                Divider()
                QualityFlowList(flows: snapshot.flows, generatedAt: snapshot.generatedAt)
            }
        }
    }
}

/// The state a reader must not confuse with a healthy network.
private struct MeasurementOffView: View {
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "speedometer")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("Not measuring quality")
                .font(.headline)
            Text(
                "The daemon was started with --no-quality, so no round trips, "
                    + "retransmissions or jitter are being recorded. This is not a "
                    + "statement about the network."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

// MARK: - Headline figures

private struct QualityHeadline: View {
    let statistics: WireStatistics
    let history: [FlowClient.ThroughputSample]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 22) {
                QualityStat(
                    label: "Latency floor",
                    value: formatMilliseconds(statistics.minRttMs),
                    detail: "lowest round trip",
                    help: "The lowest round trip seen. The closest a passive observer "
                        + "gets to the path's actual propagation delay — the typical "
                        + "figure carries whatever delay the far end added before "
                        + "answering, and this does not."
                )
                QualityStat(
                    label: "Typical",
                    value: formatMilliseconds(statistics.medianRttMs),
                    detail: "median round trip",
                    help: "The median smoothed round trip across every connection that "
                        + "yielded a sample. How far this sits above the floor is "
                        + "queueing, not distance."
                )
                QualityStat(
                    label: "Resent out",
                    value: percentage(statistics.retransmitRateOut),
                    detail: "of segments sent",
                    help: "Segments this machine had to send again, as a share of "
                        + "segments sent. Evidence of loss on the way out — or of an "
                        + "acknowledgement lost coming back, which is indistinguishable "
                        + "from here. Not a packet loss rate: what is observed is the "
                        + "repeat, not the drop."
                )
                QualityStat(
                    label: "Resent in",
                    value: percentage(statistics.retransmitRateIn),
                    detail: "of segments received",
                    help: "Segments the far end had to send again — loss on the way in."
                )
                QualityStat(
                    label: "Coverage",
                    value: percentage(statistics.measuredByteShare),
                    detail: "of bytes measurable",
                    help: "The share of bytes moving on connections a round trip could "
                        + "be measured on. QUIC — which is what HTTP/3 uses — carries no "
                        + "round trips a passive observer can read, so everything above "
                        + "covers this much of the traffic and no more."
                )

                Spacer()

                if !history.isEmpty {
                    ThroughputChart(history: history)
                        .frame(width: 240, height: 62)
                }
            }

            ConnectionOutcomes(statistics: statistics)
        }
        .padding(12)
    }

    private func percentage(_ value: Double?) -> String {
        guard let value else { return "—" }
        let scaled = value * 100
        return scaled < 1 && scaled > 0
            ? String(format: "%.2f%%", scaled) : String(format: "%.1f%%", scaled)
    }
}

private struct QualityStat: View {
    let label: String
    let value: String
    let detail: String
    let help: String

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.title3, design: .rounded))
                .monospacedDigit()
            Text(detail)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .help(help)
    }
}

/// Attempts, timeouts and refusals, kept apart because they mean different things.
private struct ConnectionOutcomes: View {
    let statistics: WireStatistics

    var body: some View {
        if let attempts = statistics.connectionAttempts, attempts > 0 {
            HStack(spacing: 6) {
                Text(pluralised(attempts, "connection attempt"))
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let timeouts = statistics.connectionTimeouts, timeouts > 0 {
                    Text("· \(timeouts) unanswered")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .help(
                            "A connection this machine opened that got no reply at all. "
                                + "Evidence the path failed while it was being used — "
                                + "which is a different thing from the far end declining."
                        )
                }
                if let refusals = statistics.connectionRefusals, refusals > 0 {
                    Text("· \(refusals) refused")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .help(
                            "Answered with a reset: the far end declined. That is the "
                                + "other end's doing, not the network's, so it is counted "
                                + "apart from the unanswered ones."
                        )
                }
                if let discarded = statistics.discardedRttSamples, discarded > 0 {
                    Text("· \(discarded) samples discarded")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .help(
                            "Round-trip samples thrown out as impossible, which is what a "
                                + "clock corrected by NTP looks like from here. Shown so a "
                                + "stepped clock is not mistaken for a quiet network."
                        )
                }
            }
        }
    }
}

// MARK: - Per-connection detail

private struct QualityFlowList: View {
    let flows: [WireFlow]
    /// The snapshot these flows came from, so the sort below can tell a new one from a
    /// redraw of the same one.
    let generatedAt: Date

    /// Measured connections first, worst round trip at the top — the list is for finding
    /// what is slow. Unmeasurable ones keep their place at the bottom rather than being
    /// hidden, so the size of the blind spot stays visible.
    /// Sorted once per snapshot rather than once per redraw.
    ///
    /// A computed property re-runs on every access, and this one copies and sorts every
    /// live flow — up to the 8192-flow ceiling, each carrying several strings — from inside
    /// `body`, on the main thread. `@State` keyed on the snapshot's own timestamp means the
    /// work happens when the data changes instead.
    @State private var ordered: [WireFlow] = []
    @State private var orderedAt: Date?

    private static func sort(_ flows: [WireFlow]) -> [WireFlow] {
        flows.sorted { lhs, rhs in
            switch (lhs.rttMs, rhs.rttMs) {
            case let (left?, right?): return left > right
            case (_?, nil): return true
            case (nil, _?): return false
            case (nil, nil): return lhs.totalBytes > rhs.totalBytes
            }
        }
    }

    var body: some View {
        List {
            Section {
                ForEach(ordered) { flow in
                    QualityRow(flow: flow)
                }
            } header: {
                HStack(spacing: 8) {
                    Text("Connection").frame(maxWidth: .infinity, alignment: .leading)
                    Text("Round trip").frame(width: 130, alignment: .trailing)
                    Text("Jitter").frame(width: 70, alignment: .trailing)
                    Text("Resent").frame(width: 90, alignment: .trailing)
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
        }
        .listStyle(.inset)
        .onAppear { refresh() }
        .onChange(of: generatedAt) { refresh() }
    }

    private func refresh() {
        guard orderedAt != generatedAt else { return }
        ordered = Self.sort(flows)
        orderedAt = generatedAt
    }
}

private struct QualityRow: View {
    let flow: WireFlow

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(flow.processName ?? flow.remoteDescription)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 5) {
                    Text(flow.remoteDescription)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if let hops = flow.hopCount {
                        Text("· ~\(hops) hops")
                            .help(
                                "Estimated from the hop limit that arrived, assuming the "
                                    + "sender started at a conventional value. A guess."
                            )
                    }
                    if flow.segmentOffload == true {
                        Image(systemName: "exclamationmark.triangle")
                            .help(
                                "The interface coalesced segments before handing them "
                                    + "over, so the counts for this connection are "
                                    + "undercounts."
                            )
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            roundTrip
            jitter
            resent
        }
        .padding(.vertical, 1)
    }

    /// An em dash, never a zero. A connection nothing could measure and a connection with
    /// no latency are the same pixels otherwise, and only one of them is good news.
    @ViewBuilder private var roundTrip: some View {
        VStack(alignment: .trailing, spacing: 1) {
            if let smoothed = flow.rttMs {
                Text(formatMilliseconds(smoothed))
                    .font(.system(.body, design: .monospaced))
                    .monospacedDigit()
                HStack(spacing: 3) {
                    if let floor = flow.rttMinMs {
                        Text("min \(formatMilliseconds(floor))")
                    }
                    if let source = flow.rttSource {
                        Text("·").foregroundStyle(.tertiary)
                        Text(source)
                            .help(
                                "Where the figure comes from. TCP timestamps are the most "
                                    + "reliable; an acknowledgement-derived sample carries "
                                    + "the far end's delayed-acknowledgement timer with it."
                            )
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            } else {
                Text("—")
                    .foregroundStyle(.tertiary)
                    .help(
                        "No round trip could be measured. Usual reason: the connection is "
                            + "QUIC or another UDP protocol, which carries nothing a "
                            + "passive observer can time."
                    )
            }
        }
        .frame(width: 130, alignment: .trailing)
    }

    @ViewBuilder private var jitter: some View {
        Group {
            if let variation = flow.rttVarMs {
                Text(formatMilliseconds(variation)).monospacedDigit()
            } else if let arrival = flow.arrivalJitterMs {
                Text(formatMilliseconds(arrival))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .help(
                        "Variation in the gap between arriving packets, not round-trip "
                            + "variation — there is no round trip here to vary. Means "
                            + "something for a call or a video stream, little for a "
                            + "bulk transfer."
                    )
            } else {
                Text("—").foregroundStyle(.tertiary)
            }
        }
        .font(.system(.caption, design: .monospaced))
        .frame(width: 70, alignment: .trailing)
    }

    @ViewBuilder private var resent: some View {
        Group {
            if let out = flow.retransmitsOut, let incoming = flow.retransmitsIn {
                if out == 0 && incoming == 0 {
                    Text("none").foregroundStyle(.tertiary)
                } else {
                    Text("↑\(out) ↓\(incoming)")
                        .monospacedDigit()
                        .foregroundStyle(.orange)
                        .help(
                            flow.retransmitsAreProven == true
                                ? "Proven retransmissions: this connection negotiated TCP "
                                    + "timestamps, which is what tells a resent segment "
                                    + "from one the network merely delivered late."
                                : "Segments covering ground already seen. Without TCP "
                                    + "timestamps a retransmission and a reordered arrival "
                                    + "cannot be told apart, so this may be either."
                        )
                }
            } else {
                Text("—").foregroundStyle(.tertiary)
            }
        }
        .font(.system(.caption, design: .monospaced))
        .frame(width: 90, alignment: .trailing)
    }

}
