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

    /// Once a second. Fast enough to feel live, slow enough that a few hundred flows of
    /// JSON is nothing. Deltas would be the answer at a much larger scale; at this size
    /// they would be complexity without benefit.
    private static let publishInterval: TimeInterval = 1.0

    init(path: String, snapshotProvider: @escaping @Sendable () -> FlowSnapshot) {
        self.path = path
        self.snapshotProvider = snapshotProvider
    }

    func start() throws {
        // A socket file can outlive the process that made it — a hard kill, a panic, a
        // reboot without cleanup. Removing it blindly, though, would steal the path from
        // a daemon that is alive and serving, leaving that instance listening on an
        // unlinked inode nobody can reach. So probe first: if something answers, refuse.
        if FileManager.default.fileExists(atPath: path) {
            if Self.isAccepting(at: path) {
                throw ServerError.alreadyServing(path: path)
            }
            unlink(path)
        }

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw ServerError.cannotCreateSocket(errno: errno)
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            close(descriptor)
            throw ServerError.pathTooLong(path)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: pathBytes)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            close(descriptor)
            throw ServerError.cannotBind(path: path, errno: errno)
        }

        // The socket exposes everywhere this machine has been, so it is not world
        // readable, and it belongs to the user who ran sudo rather than to root — the app
        // runs as them and could not otherwise connect.
        chmod(path, 0o600)
        giveToInvokingUser(path)

        guard listen(descriptor, 8) == 0 else {
            close(descriptor)
            unlink(path)
            throw ServerError.cannotListen(errno: errno)
        }

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
            if !Self.isAccepting(at: self.path) {
                let message =
                    "beholderd: the publishing socket at \(self.path) is not accepting "
                    + "connections. Nothing will be able to read from it.\n"
                FileHandle.standardError.write(Data(message.utf8))
            }
        }
    }

    /// Whether a process is listening on this path right now.
    ///
    /// Connecting is the only reliable test: the file existing says nothing about whether
    /// anyone holds it open, and a stale file refuses connections exactly as an absent
    /// daemon would.
    static func isAccepting(at path: String) -> Bool {
        let probe = socket(AF_UNIX, SOCK_STREAM, 0)
        guard probe >= 0 else { return false }
        defer { close(probe) }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { return false }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(probe, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        return result == 0
    }

    func stop() {
        queue.sync {
            publishTimer?.cancel()
            publishTimer = nil
            acceptSource?.cancel()
            acceptSource = nil
            for client in clients { close(client) }
            clients.removeAll()
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

        for client in targets {
            var offset = 0
            var failed = false

            while offset < data.count {
                let written = data.withUnsafeBytes { buffer -> Int in
                    write(client, buffer.baseAddress!.advanced(by: offset), data.count - offset)
                }
                if written > 0 {
                    offset += written
                    continue
                }
                // EAGAIN means the client's buffer is full. Rather than spin or block,
                // give up on this snapshot; the next one is a second away and carries
                // the same information, so nothing is lost by skipping it.
                if written < 0, errno == EAGAIN || errno == EWOULDBLOCK { break }
                failed = true
                break
            }

            if failed {
                close(client)
                clients.remove(client)
            }
        }
    }

    private func giveToInvokingUser(_ path: String) {
        let environment = ProcessInfo.processInfo.environment
        guard
            let uidText = environment["SUDO_UID"], let uid = uid_t(uidText),
            let gidText = environment["SUDO_GID"], let gid = gid_t(gidText)
        else { return }
        chown(path, uid, gid)
    }

    enum ServerError: Error, CustomStringConvertible {
        case alreadyServing(path: String)
        case cannotCreateSocket(errno: Int32)
        case cannotBind(path: String, errno: Int32)
        case cannotListen(errno: Int32)
        case pathTooLong(String)

        var description: String {
            switch self {
            case .alreadyServing(let path):
                return """
                    another Beholder daemon is already publishing on \(path). \
                    Stop it first — 'make status' shows which one is running.
                    """
            case .cannotCreateSocket(let code):
                return "cannot create the publishing socket: \(String(cString: strerror(code)))"
            case .cannotBind(let path, let code):
                return "cannot bind \(path): \(String(cString: strerror(code)))"
            case .cannotListen(let code):
                return "cannot listen on the publishing socket: \(String(cString: strerror(code)))"
            case .pathTooLong(let path):
                return "socket path is too long for sockaddr_un: \(path)"
            }
        }
    }
}
