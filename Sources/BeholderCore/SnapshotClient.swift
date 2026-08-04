import Darwin
import Foundation

/// Reads a single snapshot from the daemon's publishing socket, and gives up.
///
/// The app wants a stream and reconnects forever; a question answered on demand wants one
/// sample and a bounded wait. The connect half is shared — it used to live privately in
/// `FlowClient`, and the `sockaddr_un` dance is fiddly enough that two copies would drift.
///
/// What is added here is telling the failures apart. `FlowClient` collapsed every one into
/// `-1`, which is all a "waiting for the daemon" spinner needs. A health check cannot
/// afford that: "nothing is listening" and "the socket belongs to another user" look
/// identical from a return code and have completely different fixes.
public enum SnapshotClient {

    public enum Failure: Error, Sendable, CustomStringConvertible {
        case notRunning(path: String)
        case notYours(path: String, ownerUID: uid_t, ourUID: uid_t)
        case cannotConnect(path: String, reason: String)
        case timedOut(path: String, seconds: TimeInterval, bytesRead: Int)
        case unframed(bytesRead: Int)
        case undecodable(String)
        case wrongVersion(theirs: Int, ours: Int)

        public var description: String {
            switch self {
            case .notRunning(let path):
                return "Nothing is listening on \(path). The capture daemon is not running."
            case .notYours(let path, let owner, let ours):
                return """
                    \(path) exists but belongs to uid \(owner), and this process is uid \
                    \(ours). Capture was started by a different user, so its socket is not \
                    readable here — it is created mode 0600 on purpose, because it lists \
                    every host this machine contacts.
                    """
            case .cannotConnect(let path, let reason):
                return "Could not connect to \(path): \(reason)."
            case .timedOut(let path, let seconds, let bytes):
                return """
                    Connected to \(path) but no complete snapshot arrived within \
                    \(Int(seconds)) seconds (\(bytes) bytes read). The daemon may be \
                    starting up or wedged.
                    """
            case .unframed(let bytes):
                return """
                    The daemon sent \(bytes) bytes without completing a single snapshot. \
                    Its output is not framed as this client expects.
                    """
            case .undecodable(let message):
                return "The daemon sent a snapshot that could not be decoded: \(message)."
            case .wrongVersion(let theirs, let ours):
                return """
                    The daemon speaks protocol \(theirs) but this build expects \(ours). \
                    Rebuild both from the same source.
                    """
            }
        }
    }

    /// Generous next to a real snapshot — a busy machine's runs to a few hundred kilobytes
    /// — and small enough that a stream which never completes one is caught in seconds.
    public static let maximumMessageBytes = 8 * 1024 * 1024

    /// How long to wait for one whole snapshot.
    ///
    /// Three seconds rather than one, and the reason is in `FlowServer`: it publishes on a
    /// repeating one-second timer and does not send anything on accept, so a freshly
    /// connected reader legitimately waits up to a full second before the first byte. A
    /// one-second budget would report a perfectly healthy daemon as absent, intermittently,
    /// which is the worst kind of wrong answer for a diagnostic to give.
    public static let defaultDeadline: TimeInterval = 3.0

    /// Opens the publishing socket.
    ///
    /// The caller owns the descriptor and must close it.
    public static func connect(to path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw Failure.cannotConnect(path: path, reason: errorText(errno))
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            close(descriptor)
            throw Failure.cannotConnect(
                path: path, reason: "the path is too long for a Unix domain socket"
            )
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            // Captured before anything else can run and overwrite it.
            let code = errno
            close(descriptor)
            throw failure(forConnectErrno: code, path: path)
        }

        // This client never sends. Closing the write half makes that structural rather
        // than merely true, so a future edit cannot quietly turn a reader into a writer:
        // the daemon accepts no commands and an unauthenticated writer would be a real hole.
        shutdown(descriptor, SHUT_WR)
        return descriptor
    }

    /// Reads exactly one snapshot, or fails within `deadline`.
    public static func readOne(
        from path: String,
        deadline: TimeInterval = defaultDeadline
    ) throws -> FlowSnapshot {
        let descriptor = try connect(to: path)
        defer { close(descriptor) }

        // Bound each individual read as well as the whole operation. Without this a
        // connected-but-silent daemon parks the caller in `read` forever and no overall
        // deadline can fire, because nothing ever returns to check it. The same shape as
        // `RouteLookup.defaultRoute()`, which sets a receive timeout on the routing socket
        // so the kernel having nothing to say cannot block the caller indefinitely.
        var timeout = timeval(tv_sec: 0, tv_usec: 500_000)
        setsockopt(
            descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)
        )

        let started = Date()
        var buffer = Data()
        var bytes = [UInt8](repeating: 0, count: 64 * 1024)

        while Date().timeIntervalSince(started) < deadline {
            let count = read(descriptor, &bytes, bytes.count)
            if count > 0 {
                buffer.append(contentsOf: bytes[0..<count])
                if let newline = buffer.firstIndex(of: 0x0A) {
                    return try decode(buffer[buffer.startIndex..<newline])
                }
                guard buffer.count <= maximumMessageBytes else {
                    throw Failure.unframed(bytesRead: buffer.count)
                }
                continue
            }
            if count == 0 {
                // The daemon closed the connection. Anything buffered is a partial line
                // and there will be no more, so this is the same fault as a missing frame.
                throw Failure.unframed(bytesRead: buffer.count)
            }
            // EAGAIN is the receive timeout expiring, which is expected while waiting for
            // the daemon's next tick; EINTR is a signal. Both mean "look at the clock and
            // try again". Anything else is real.
            guard errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR else {
                throw Failure.cannotConnect(path: path, reason: errorText(errno))
            }
        }

        throw Failure.timedOut(path: path, seconds: deadline, bytesRead: buffer.count)
    }

    private static func decode(_ line: Data) throws -> FlowSnapshot {
        let snapshot: FlowSnapshot
        do {
            snapshot = try FlowSnapshot.decoder().decode(FlowSnapshot.self, from: line)
        } catch {
            throw Failure.undecodable(error.localizedDescription)
        }
        guard snapshot.version == WireProtocol.version else {
            throw Failure.wrongVersion(theirs: snapshot.version, ours: WireProtocol.version)
        }
        return snapshot
    }

    /// Separates "not running" from "not yours", which is the whole point of this type.
    private static func failure(forConnectErrno code: Int32, path: String) -> Failure {
        switch code {
        case ENOENT, ECONNREFUSED:
            return .notRunning(path: path)
        case EACCES, EPERM:
            var info = stat()
            if stat(path, &info) == 0 {
                return .notYours(path: path, ownerUID: info.st_uid, ourUID: geteuid())
            }
            return .cannotConnect(path: path, reason: errorText(code))
        default:
            return .cannotConnect(path: path, reason: errorText(code))
        }
    }

    private static func errorText(_ code: Int32) -> String {
        String(cString: strerror(code))
    }
}
