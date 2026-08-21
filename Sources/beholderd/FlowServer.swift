import BeholderCore
import Darwin
import Dispatch
import Foundation

/// Publishes snapshots to connected clients over a Unix domain socket.
///
/// Newline-delimited JSON, one snapshot per line, pushed on a timer. Clients never send
/// anything: the daemon is strictly a source of information and exposes no command that
/// changes state. That is deliberate while there is no signing identity to validate a
/// peer with — an unauthenticated reader can only see what it could already obtain by
/// running `lsof`, whereas an unauthenticated *writer* would be a genuine hole.
final class FlowServer: @unchecked Sendable {
    private let path: String
    private let snapshotProvider: @Sendable () -> FlowSnapshot
    private let queue = DispatchQueue(label: "com.beholder.server")

    private var listenDescriptor: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private var publishTimer: DispatchSourceTimer?
    private var clients: Set<Int32> = []

    /// Per-client outbound state, all confined to `queue`.
    ///
    /// `outbox` is the unwritten remainder of the message currently going out, which must
    /// be finished before any other byte is sent — the peer has already seen its first
    /// half. `queued` holds at most one whole message to follow it.
    private var outbox: [Int32: Data] = [:]
    private var queued: [Int32: Data] = [:]
    private var writeSources: [Int32: DispatchSourceWrite] = [:]

    /// Once a second. Fast enough to feel live, slow enough that a few hundred flows of
    /// JSON is nothing. Deltas would be the answer at a much larger scale; at this size
    /// they would be complexity without benefit.
    private static let publishInterval: TimeInterval = 1.0

    /// A deliberately small send buffer for client sockets, when the environment asks.
    ///
    /// This is a test seam and nothing else. The framing bug it guards against only
    /// appears once a snapshot exceeds the kernel's send buffer, which in production means
    /// a busy machine with hundreds of enriched flows — not something a self-test can
    /// produce. AF_UNIX honours SO_SNDBUF exactly, so shrinking it reproduces the same
    /// partial writes against a small snapshot. Unset in normal use.
    private static let testSendBuffer: Int32? = {
        guard let text = ProcessInfo.processInfo.environment["BEHOLDER_TEST_SEND_BUFFER"],
            let size = Int32(text), size > 0
        else { return nil }
        return size
    }()

    init(path: String, snapshotProvider: @escaping @Sendable () -> FlowSnapshot) {
        self.path = path
        self.snapshotProvider = snapshotProvider
    }

    func start() throws {
        let descriptor = try UnixSocket.listen(
            at: path, backlog: 8, role: "publishing socket")
        listenDescriptor = descriptor

        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptClient() }
        acceptSource = source
        source.resume()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + Self.publishInterval,
            repeating: Self.publishInterval,
            leeway: .milliseconds(100)
        )
        timer.setEventHandler { [weak self] in self?.publish() }
        publishTimer = timer
        timer.resume()

        // Prove the socket actually accepts, rather than assuming bind and listen were
        // enough. A socket file that exists but refuses connections looks identical to a
        // healthy one from the outside, and is exactly what a user would report as "the
        // app cannot see the daemon".
        queue.asyncAfter(deadline: .now() + 0.2) { [weak self] in
            guard let self, self.listenDescriptor >= 0 else { return }
            if !UnixSocket.isAccepting(at: self.path) {
                let message =
                    "beholderd: the publishing socket at \(self.path) is not accepting "
                    + "connections. Nothing will be able to read from it.\n"
                FileHandle.standardError.write(Data(message.utf8))
            }
        }
    }

    func stop() {
        queue.sync {
            publishTimer?.cancel()
            publishTimer = nil
            acceptSource?.cancel()
            acceptSource = nil
            // A copy: drop mutates `clients` as it goes.
            for client in Array(clients) { drop(client) }
            if listenDescriptor >= 0 {
                close(listenDescriptor)
                listenDescriptor = -1
            }
            unlink(path)
        }
    }

    var clientCount: Int {
        queue.sync { clients.count }
    }

    // MARK: - Queue-confined work

    private func acceptClient() {
        let client = accept(listenDescriptor, nil, nil)
        guard client >= 0 else { return }

        // Never let a stalled reader block the daemon: a client that cannot keep up is
        // dropped rather than allowed to apply back-pressure to capture.
        // Best-effort only, and deliberately not load-bearing: setsockopt returns EINVAL
        // when the peer has already closed by the time we accept, which is exactly the
        // case SO_NOSIGPIPE exists to handle. The process-wide SIGPIPE disposition set in
        // Beholderd.main() is what actually keeps a write to a departed reader survivable.
        var enabled: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        _ = fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK)

        if var size = Self.testSendBuffer {
            setsockopt(client, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        }

        clients.insert(client)
        send(snapshotProvider(), to: [client])
    }

    private func publish() {
        guard !clients.isEmpty else { return }
        send(snapshotProvider(), to: clients)
    }

    private func send(_ snapshot: FlowSnapshot, to targets: Set<Int32>) {
        guard var data = try? FlowSnapshot.encoder().encode(snapshot) else { return }
        data.append(0x0A)  // newline terminator

        for client in targets { enqueue(data, to: client) }
    }

    /// Queues a whole message for a client. Never a fragment of one.
    ///
    /// The distinction is the entire point. Clients are non-blocking, so a snapshot larger
    /// than the kernel's send buffer cannot be written in one call — and abandoning the
    /// rest when the buffer fills does not "skip a snapshot", it destroys the framing: the
    /// terminating newline never arrives, the next snapshot is appended to a truncated
    /// one, and the reader can never resynchronise. A daemon doing that looks perfectly
    /// healthy from outside while no client can decode a single message from it.
    private func enqueue(_ message: Data, to client: Int32) {
        guard clients.contains(client) else { return }

        if outbox[client] != nil {
            // Still finishing the previous snapshot. Hold at most one more and let the
            // newer win: consecutive snapshots carry the same information, so a reader
            // that has fallen behind wants the latest, not a backlog of stale ones. This
            // is what bounds memory for a slow client.
            queued[client] = message
            return
        }
        outbox[client] = message
        flush(client)
    }

    /// Writes as much of a client's pending message as the kernel will take.
    private func flush(_ client: Int32) {
        while let remaining = outbox[client] {
            if remaining.isEmpty {
                outbox[client] = queued.removeValue(forKey: client)
                continue
            }

            var wrote = 0
            var failed = false
            remaining.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
                let written = write(client, buffer.baseAddress, buffer.count)
                if written > 0 {
                    wrote = written
                } else if written < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                    wrote = 0
                } else {
                    failed = true
                }
            }

            if failed {
                drop(client)
                return
            }
            if wrote == 0 {
                // The buffer is full. Wait to be told it has drained rather than
                // spinning, blocking, or abandoning the rest of the message.
                armWriteSource(for: client)
                return
            }
            outbox[client] = remaining.dropFirst(wrote)
        }
        disarmWriteSource(for: client)
    }

    private func armWriteSource(for client: Int32) {
        guard writeSources[client] == nil else { return }
        let source = DispatchSource.makeWriteSource(fileDescriptor: client, queue: queue)
        source.setEventHandler { [weak self] in self?.flush(client) }
        writeSources[client] = source
        source.resume()
    }

    private func disarmWriteSource(for client: Int32) {
        writeSources.removeValue(forKey: client)?.cancel()
    }

    /// Forgets a client and closes its descriptor.
    ///
    /// Closing goes through the write source's cancel handler when one exists: dispatch
    /// forbids closing a descriptor a live source still refers to.
    private func drop(_ client: Int32) {
        outbox.removeValue(forKey: client)
        queued.removeValue(forKey: client)
        clients.remove(client)

        if let source = writeSources.removeValue(forKey: client) {
            source.setCancelHandler { close(client) }
            source.cancel()
        } else {
            close(client)
        }
    }


}
