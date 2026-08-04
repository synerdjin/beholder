import BeholderCore
import Darwin
import Foundation
import Observation

/// Reads snapshots from the daemon's socket.
///
/// Deliberately tolerant of the daemon not being there. Capture needs root and is started
/// by hand, so "no daemon yet" is the normal state on launch rather than an error — the
/// client keeps trying and says plainly what it is waiting for.
@MainActor
@Observable
final class FlowClient {
    enum State: Equatable {
        case idle
        case connecting
        case connected
        case waitingForDaemon(String)
        case failed(String)
    }

    private(set) var state: State = .idle
    private(set) var snapshot: FlowSnapshot?
    private(set) var lastUpdate: Date?

    /// Recent throughput, for the chart. Bounded so a long-running window cannot grow
    /// without limit.
    private(set) var history: [ThroughputSample] = []
    private static let historyLimit = 300

    /// Shared with `SnapshotClient` so the streaming reader and the one-shot reader cannot
    /// disagree about how much unframed output is too much.
    private static let maximumMessageBytes = SnapshotClient.maximumMessageBytes

    private let path: String
    private var readerTask: Task<Void, Never>?
    private var previousBytesOut: UInt64?
    private var previousBytesIn: UInt64?

    struct ThroughputSample: Identifiable, Equatable {
        let id = UUID()
        let at: Date
        let bytesOutPerSecond: Double
        let bytesInPerSecond: Double
    }

    init(path: String = WireProtocol.defaultSocketPath) {
        self.path = path
    }

    func start() {
        guard readerTask == nil else { return }
        readerTask = Task { [weak self] in
            await self?.runForever()
        }
    }

    func stop() {
        readerTask?.cancel()
        readerTask = nil
    }

    /// Reconnects indefinitely. The daemon is expected to come and go.
    private func runForever() async {
        while !Task.isCancelled {
            state = .connecting

            let descriptor: Int32
            do {
                descriptor = try SnapshotClient.connect(to: path)
            } catch {
                // Just the situation. What to do about it is the view's business, and
                // saying it in both places guarantees the two drift apart.
                //
                // SnapshotClient tells the cases apart, so this now distinguishes a daemon
                // that is not running from a socket owned by another user — which used to
                // both read as "nothing is listening" and sent people looking in the wrong
                // place.
                state = .waitingForDaemon(
                    (error as? SnapshotClient.Failure)?.description
                        ?? "Nothing is listening on \(path)."
                )
                try? await Task.sleep(for: .seconds(2))
                continue
            }

            state = .connected
            await readLines(from: descriptor)
            close(descriptor)

            guard !Task.isCancelled else { return }
            state = .waitingForDaemon("The capture daemon stopped.")
            try? await Task.sleep(for: .seconds(2))
        }
    }

    /// Reads newline-delimited JSON until the connection ends.
    private func readLines(from descriptor: Int32) async {
        var buffer = Data()
        let chunkSize = 64 * 1024

        while !Task.isCancelled {
            let chunk: Data? = await Task.detached(priority: .utility) {
                var bytes = [UInt8](repeating: 0, count: chunkSize)
                let count = read(descriptor, &bytes, chunkSize)
                guard count > 0 else { return nil }
                return Data(bytes[0..<count])
            }.value

            guard let chunk else { return }
            buffer.append(chunk)

            // A stream with no newline in it is not a slow snapshot, it is a broken one,
            // and appending forever turns that into unbounded memory growth: this window
            // quietly accumulated tens of megabytes against a daemon whose framing was
            // wrong. Cap it, say so, and drop the connection to resynchronise.
            if buffer.count > Self.maximumMessageBytes {
                state = .failed(
                    "The daemon sent \(buffer.count) bytes without completing a single "
                        + "snapshot. Its output is not framed as this app expects."
                )
                return
            }

            // A snapshot can span several reads, so consume only whole lines.
            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = buffer[buffer.index(after: newline)...]
                apply(line)
            }
        }
    }

    private func apply(_ line: Data) {
        guard !line.isEmpty else { return }

        let decoded: FlowSnapshot
        do {
            decoded = try FlowSnapshot.decoder().decode(FlowSnapshot.self, from: line)
        } catch {
            // Say so rather than discarding it. A silently dropped line is
            // indistinguishable from no line at all, so a daemon sending something this
            // app cannot read looked exactly like a daemon that was not there.
            state = .failed(
                "Received \(line.count) bytes from the daemon that this app could not "
                    + "decode: \(error.localizedDescription)"
            )
            return
        }

        guard decoded.version == WireProtocol.version else {
            state = .failed(
                "The daemon speaks protocol \(decoded.version) but this app expects "
                    + "\(WireProtocol.version). Rebuild both from the same source."
            )
            return
        }

        recordThroughput(from: decoded)
        snapshot = decoded
        lastUpdate = Date()
        state = .connected
    }

    private func recordThroughput(from decoded: FlowSnapshot) {
        defer {
            previousBytesOut = decoded.statistics.totalBytesOut
            previousBytesIn = decoded.statistics.totalBytesIn
        }
        guard let previousOut = previousBytesOut, let previousIn = previousBytesIn,
            let last = lastUpdate
        else { return }

        let elapsed = max(decoded.generatedAt.timeIntervalSince(last), 0.001)
        // Totals fall when flows retire, so clamp instead of underflowing.
        let out = decoded.statistics.totalBytesOut >= previousOut
            ? decoded.statistics.totalBytesOut - previousOut : 0
        let incoming = decoded.statistics.totalBytesIn >= previousIn
            ? decoded.statistics.totalBytesIn - previousIn : 0

        history.append(
            ThroughputSample(
                at: decoded.generatedAt,
                bytesOutPerSecond: Double(out) / elapsed,
                bytesInPerSecond: Double(incoming) / elapsed
            )
        )
        if history.count > Self.historyLimit {
            history.removeFirst(history.count - Self.historyLimit)
        }
    }

}
