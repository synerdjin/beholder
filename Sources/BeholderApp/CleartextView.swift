import BeholderCore
import SwiftUI

/// Connections that are not known to be protected, and — when the daemon was started with
/// `--read-cleartext` — what they are actually carrying.
///
/// The list works with or without payload reading: identifying unprotected traffic costs
/// nothing and is on by default. Only the right-hand reader needs the flag.
struct CleartextView: View {
    let snapshot: FlowSnapshot
    @Binding var selection: WireFlow.ID?

    var body: some View {
        // Derived once per snapshot rather than per read. Both were computed properties,
        // and `exposed` alone was being filtered and sorted four times per body pass —
        // once more inside the row closure for every rendered row.
        let exposed = snapshot.flows
            .filter(\.isUnprotected)
            .sorted { $0.totalBytes > $1.totalBytes }
        let excerpts = snapshot.cleartextExcerpts.map {
            Dictionary($0.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        }

        return VStack(spacing: 0) {
            if excerpts != nil {
                RetentionNotice()
                Divider()
            }
            if exposed.isEmpty {
                NothingExposedView(snapshot: snapshot, isReadingPayload: excerpts != nil)
            } else {
                HSplitView {
                    list(exposed, excerpts)
                        .frame(minWidth: 300, idealWidth: 360)
                    reader(exposed, excerpts)
                        .frame(minWidth: 380)
                }
            }
        }
    }

    /// Everything not established to be encrypted.
    ///
    /// Cleartext and unknown are listed together because the question this screen answers
    /// is "what is exposed", and an unidentified binary protocol on a high port belongs in
    /// that answer. They are never merged in the *labelling*, though: each row says which
    /// it is, because one is an observation and the other is the lack of one.
    private func list(
        _ exposed: [WireFlow],
        _ excerpts: [WireFlow.ID: WireExcerpt]?
    ) -> some View {
        List(exposed, selection: $selection) { flow in
            ExposedRow(flow: flow, excerpt: excerpts?[flow.id])
                .tag(flow.id)
        }
        .listStyle(.inset)
    }

    /// Only reached when `exposed` is non-empty, so the fallback to the first row is total
    /// and there is no "nothing selected" state to render.
    private func reader(
        _ exposed: [WireFlow],
        _ excerpts: [WireFlow.ID: WireExcerpt]?
    ) -> some View {
        let flow = exposed.first { $0.id == selection } ?? exposed[0]
        return PayloadReader(
            flow: flow,
            excerpt: excerpts?[flow.id],
            isReadingPayload: excerpts != nil,
            startedAt: snapshot.startedAt
        )
    }
}

/// Stated on screen rather than in the README alone, because this is the one view where
/// Beholder holds the contents of traffic rather than facts about it, and the person
/// looking at it should not have to go and find out what happens to what they are reading.
private struct RetentionNotice: View {
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "memorychip")
            Text(
                "Payload is held in memory by the running daemon and released when a "
                    + "connection ends. It is never written to the history database or the "
                    + "run transcript, and never sent over MCP."
            )
            .fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}

// MARK: - The list

private struct ExposedRow: View {
    let flow: WireFlow
    let excerpt: WireExcerpt?

    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: ProcessIcons.icon(forPid: flow.pid))
                .resizable()
                .frame(width: 16, height: 16)

            VStack(alignment: .leading, spacing: 1) {
                Text(flow.processName ?? "unattributed")
                    .font(.callout)
                    .foregroundStyle(flow.processName == nil ? .secondary : .primary)
                    .lineLimit(1)
                HStack(spacing: 5) {
                    Text("\(flow.remoteDescription):\(String(flow.remotePort))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    SecurityBadge(
                        security: flow.security,
                        protocolName: flow.protocolName,
                        isProof: flow.securityIsProof
                    )
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 1) {
                Text(formatBytes(Double(flow.totalBytes)))
                    .font(.system(.caption, design: .monospaced))
                    .monospacedDigit()
                // Says whether there is anything to read before the reader is opened, so
                // clicking through every row to find out is unnecessary.
                if let excerpt {
                    Text("\(formatBytes(Double(excerpt.sentCaptured + excerpt.receivedCaptured)) ) read")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 1)
    }
}

// MARK: - Empty states

/// Four states that look identical if you are careless, and mean entirely different things.
///
/// The rule this exists for: an empty result must never be ambiguous between "nothing
/// happened" and "nothing was watching". A blank list here could mean the daemon is not
/// reading payload, or that it is and everything is properly encrypted — which is
/// excellent news and should read as such.
private struct NothingExposedView: View {
    let snapshot: FlowSnapshot
    let isReadingPayload: Bool

    /// Connections a reading could be taken for. A flow with no ports never gets one.
    private var classifiedCount: Int {
        snapshot.flows.filter { $0.security != nil }.count
    }

    var body: some View {
        ContentUnavailableView {
            Label(
                classifiedCount == 0 ? "No connections yet" : "Nothing unprotected",
                systemImage: classifiedCount == 0 ? "wifi.slash" : "lock"
            )
        } description: {
            VStack(spacing: 10) {
                Text(
                    classifiedCount == 0
                        ? "Capture is running on "
                            + snapshot.interfaces.joined(separator: ", ")
                            + ", but nothing has said anything to classify yet."
                        // Counts only connections that were actually classified. Saying
                        // "all N are encrypted" over a total that includes flows nothing
                        // could characterise — ICMP has no ports, so it never gets a
                        // reading — would claim an observation that was never made.
                        : "All \(pluralised(classifiedCount, "classified connection")) are "
                            + "encrypted, since capture started \(relativeStart)."
                )
                .multilineTextAlignment(.center)
                if !isReadingPayload {
                    PayloadDisabledNote()
                }
            }
            .frame(maxWidth: 440)
        }
    }

    /// Every report states the window it covers, so "nothing unprotected" cannot be read
    /// as a verdict on more time than was actually watched.
    private var relativeStart: String {
        let seconds = Date().timeIntervalSince(snapshot.startedAt)
        if seconds < 90 { return "\(Int(seconds)) seconds ago" }
        if seconds < 5400 { return "\(Int(seconds / 60)) minutes ago" }
        return "\(Int(seconds / 3600)) hours ago"
    }
}

/// Shown wherever payload would appear if the daemon had been asked to read it.
///
/// This is the state the `cleartextExcerpts` field is optional for: nil means nothing is
/// reading payload, an empty array means something is reading and found nothing. Without
/// that distinction this note could not be told apart from "we looked and there was
/// nothing there".
private struct PayloadDisabledNote: View {
    private let command = "sudo beholderd --serve --read-cleartext"

    var body: some View {
        VStack(spacing: 6) {
            Text("This daemon is not reading payload.")
                .font(.callout)
            Text("Connections are still classified, but their contents are not kept.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(spacing: 6) {
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
                .help("Copy")
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

// MARK: - The reader

private struct PayloadReader: View {
    let flow: WireFlow
    let excerpt: WireExcerpt?
    let isReadingPayload: Bool
    let startedAt: Date

    @State private var direction: Direction = .sent

    private enum Direction: String, CaseIterable, Identifiable {
        case sent = "Sent"
        case received = "Received"
        var id: String { rawValue }
    }

    private var bytes: [UInt8] {
        guard let excerpt else { return [] }
        let data = direction == .sent ? excerpt.sent : excerpt.received
        return data.map(Array.init) ?? []
    }

    private var observed: UInt64 {
        guard let excerpt else { return 0 }
        return direction == .sent ? excerpt.sentObserved : excerpt.receivedObserved
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if !isReadingPayload {
                PayloadDisabledNote()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if excerpt == nil {
                waiting
            } else {
                Picker("Direction", selection: $direction) {
                    ForEach(Direction.allCases) { option in Text(option.rawValue).tag(option) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                Divider()
                content
                Divider()
                coverage
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(flow.remoteDescription):\(String(flow.remotePort))")
                .font(.headline)
                .textSelection(.enabled)
            Text(
                (flow.processName ?? "unattributed process")
                    + " · " + flow.transport
                    + (securityDescription(
                        flow.security,
                        protocolName: flow.protocolName,
                        isProof: flow.securityIsProof
                    ).map { " · \($0)" } ?? "")
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
    }

    /// The classification arrived, the bytes have not.
    ///
    /// Distinguished from "not reading payload" because the fix is different: this one
    /// needs no restart, only for the connection to say something.
    private var waiting: some View {
        VStack(spacing: 8) {
            Text("Nothing read yet.")
                .font(.headline)
            Text(
                flow.securityIsProof == true
                    ? "This connection has been identified, but no payload has been captured "
                        + "from it yet."
                    : "This connection was classified from its port number alone — nothing has "
                        + "been read from it. It may carry no payload, or may have been open "
                        + "before capture started."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder
    private var content: some View {
        if bytes.isEmpty {
            Text("Nothing captured in this direction.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if let message = HTTPPreview.parse(bytes) {
                        HTTPSection(message: message)
                        Divider()
                    }
                    Text(HexDump.render(bytes))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
            }
        }
    }

    /// Says how much of the conversation is on screen.
    ///
    /// A fragment presented without this reads as the whole thing, which is the same
    /// failure as a byte total that does not admit it is an undercount.
    private var coverage: some View {
        HStack(spacing: 4) {
            Image(systemName: observed > UInt64(bytes.count) ? "scissors" : "checkmark")
                .font(.caption2)
            Text(coverageText)
            Spacer()
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var coverageText: String {
        let captured = bytes.count
        if observed > UInt64(captured) {
            return
                "First \(captured.formatted()) of \(observed.formatted()) payload bytes "
                + "\(direction == .sent ? "sent" : "received"). The rest was not kept."
        }
        return
            "All \(captured.formatted()) payload bytes "
            + "\(direction == .sent ? "sent" : "received") on this connection."
    }
}

// MARK: - HTTP

private struct HTTPSection: View {
    let message: HTTPPreview.Message

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(message.startLine)
                .font(.system(size: 12, design: .monospaced))
                .fontWeight(.medium)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)

            // Header values are shown exactly as they arrived, including cookies and
            // authorization. Redaction was considered and rejected for the same reason it
            // was rejected for hostnames: hiding the interesting value defeats the purpose
            // of looking, and a half-redacted view invites the belief that less is exposed
            // than actually is. The honest move is to show it and say plainly, in the
            // notice above, where it is being held.
            ForEach(Array(message.headers.enumerated()), id: \.offset) { _, header in
                HStack(alignment: .top, spacing: 6) {
                    Text(header.name)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    Text(header.value)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
            }

            if !message.isComplete {
                Text("Headers continue past what was captured.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
