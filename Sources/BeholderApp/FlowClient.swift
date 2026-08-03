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
            let descriptor = Self.connect(to: path)

            guard descriptor >= 0 else {
                state = .waitingForDaemon(
                    "No daemon on \(path). Start it with:  sudo ./.build/debug/beholderd --serve"
                )
                try? await Task.sleep(for: .seconds(2))
                continue
            }

            state = .connected
            await readLines(from: descriptor)
            close(descriptor)

            guard !Task.isCancelled else { return }
            state = .waitingForDaemon("Daemon stopped. Waiting for it to come back…")
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
        guard let decoded = try? FlowSnapshot.decoder().decode(FlowSnapshot.self, from: line)
        else { return }

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

    /// Opens a Unix domain socket. Returns -1 if the daemon is not listening.
    private nonisolated static func connect(to path: String) -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return -1 }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            close(descriptor)
            return -1
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            close(descriptor)
            return -1
        }
        return descriptor
    }
}
