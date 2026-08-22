import Darwin
import Foundation

/// The `sockaddr_un` plumbing, in one place.
///
/// Beholder now opens Unix sockets from four directions — the publishing server, the control
/// server, the snapshot reader and the control client — and each one needs the same fiddly
/// sequence: fill a `sockaddr_un`, check the path fits `sun_path`, rebind the pointer to
/// `sockaddr` to satisfy the C prototype. `SnapshotClient` said the quiet part when the
/// second copy appeared: "the `sockaddr_un` dance is fiddly enough that two copies would
/// drift." By the fourth that had stopped being a warning and become a description.
///
/// In Core rather than in the daemon so the part worth testing — whether a path fits, and
/// what happens when it does not — is reachable from a unit test, which it was not while it
/// lived inside two executable-target servers.
public enum UnixSocket {

    public enum Failure: Error, Sendable, CustomStringConvertible {
        case alreadyServing(path: String, role: String)
        case cannotCreateSocket(role: String, errno: Int32)
        case cannotBind(path: String, errno: Int32)
        case cannotListen(role: String, errno: Int32)
        case pathTooLong(path: String)

        public var description: String {
            switch self {
            case .alreadyServing(let path, let role):
                return """
                    something is already answering on the \(role) at \(path). \
                    Stop it first — 'make status' shows which one is running.
                    """
            case .cannotCreateSocket(let role, let code):
                return "cannot create the \(role): \(String(cString: strerror(code)))"
            case .cannotBind(let path, let code):
                return "cannot bind \(path): \(String(cString: strerror(code)))"
            case .cannotListen(let role, let code):
                return "cannot listen on the \(role): \(String(cString: strerror(code)))"
            case .pathTooLong(let path):
                return "socket path is too long for sockaddr_un: \(path)"
            }
        }
    }

    /// The longest path a Unix socket can have, which is far shorter than a filesystem path.
    ///
    /// Exposed so a test can pin it without constructing a socket: this is the check that
    /// turns a plausible-looking configuration into a daemon that cannot bind, and it is
    /// silent until it is not.
    public static var maximumPathLength: Int {
        MemoryLayout.size(ofValue: sockaddr_un().sun_path) - 1
    }

    /// Builds the address, or reports that the path will not fit.
    public static func address(for path: String) -> sockaddr_un? {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }

    /// Runs `body` with the address as the `sockaddr` the C prototypes want.
    private static func withSockaddr<T>(
        _ address: sockaddr_un,
        _ body: (UnsafePointer<sockaddr>, socklen_t) -> T
    ) -> T {
        var mutable = address
        return withUnsafePointer(to: &mutable) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
    }

    /// Whether a process is listening on this path right now.
    ///
    /// Connecting is the only reliable test: the file existing says nothing about whether
    /// anyone holds it open, and a stale file refuses connections exactly as an absent
    /// daemon would.
    public static func isAccepting(at path: String) -> Bool {
        guard let address = address(for: path) else { return false }
        let probe = socket(AF_UNIX, SOCK_STREAM, 0)
        guard probe >= 0 else { return false }
        defer { close(probe) }
        return withSockaddr(address) { Darwin.connect(probe, $0, $1) } == 0
    }

    /// Opens a connection. The caller owns the descriptor and must close it.
    ///
    /// `SO_NOSIGPIPE` is set here, on every client socket this project opens, because
    /// writing to one whose peer has closed otherwise raises SIGPIPE and the default
    /// disposition kills the process — silently, with no message and no crash report. The
    /// control socket has a case where the peer closes before the first byte is sent: the
    /// daemon authenticates on accept, so a client that fails the check gets its refusal and
    /// a closed socket before it has written anything.
    public static func connect(to path: String) -> Result<Int32, Failure> {
        guard let address = address(for: path) else { return .failure(.pathTooLong(path: path)) }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            return .failure(.cannotCreateSocket(role: "socket", errno: errno))
        }

        var enabled: Int32 = 1
        setsockopt(
            descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))

        guard withSockaddr(address, { Darwin.connect(descriptor, $0, $1) }) == 0 else {
            let code = errno
            close(descriptor)
            return .failure(.cannotBind(path: path, errno: code))
        }
        return .success(descriptor)
    }

    /// Writes every byte, waiting for the socket when it fills.
    ///
    /// **A message can be much larger than the send buffer**, and code that assumes otherwise
    /// does not merely truncate — it destroys the framing. The terminating newline never
    /// arrives, so the reader waits for a message that can never complete while the writer
    /// believes it answered. `net.local.stream.sendspace` is 8 KB, which a control reply
    /// listing a few hundred blocked destinations passes comfortably.
    ///
    /// This is the publishing socket's framing bug, which the README records so it would not
    /// be made twice, and was made twice anyway. It lives in Core so that the loop itself is
    /// reachable from a test rather than only from a running daemon.
    ///
    /// Bounded by `deadline`, so a peer that connects and then stops reading cannot pin the
    /// caller's queue indefinitely.
    public static func writeWhole(
        _ data: Data,
        to descriptor: Int32,
        deadline: TimeInterval = 2
    ) -> Bool {
        let started = Date()
        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return true }
            var offset = 0
            while offset < raw.count {
                let written = write(descriptor, base.advanced(by: offset), raw.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                guard written < 0 else { return false }

                switch errno {
                case EINTR:
                    continue
                case EAGAIN, EWOULDBLOCK:
                    guard Date().timeIntervalSince(started) < deadline else { return false }
                    var poller = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
                    _ = poll(&poller, 1, 100)
                default:
                    return false
                }
            }
            return true
        }
    }

    /// Binds and listens, leaving the socket owned by the invoking user and mode 0600.
    ///
    /// A socket file can outlive the process that made it — a hard kill, a panic, a reboot
    /// without cleanup. Removing it blindly would steal the path from a daemon that is alive
    /// and serving, leaving that instance listening on an unlinked inode nobody can reach.
    /// So it probes first and refuses if something answers.
    public static func listen(
        at path: String,
        backlog: Int32,
        role: String
    ) throws -> Int32 {
        if FileManager.default.fileExists(atPath: path) {
            if isAccepting(at: path) { throw Failure.alreadyServing(path: path, role: role) }
            unlink(path)
        }

        guard let address = address(for: path) else { throw Failure.pathTooLong(path: path) }

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw Failure.cannotCreateSocket(role: role, errno: errno)
        }

        guard withSockaddr(address, { Darwin.bind(descriptor, $0, $1) }) == 0 else {
            let code = errno
            close(descriptor)
            throw Failure.cannotBind(path: path, errno: code)
        }

        // Not world readable, and owned by the user who ran sudo rather than by root: the app
        // runs as them and could not otherwise connect, and what travels here is a list of
        // everywhere this machine has been.
        chmod(path, 0o600)
        BeholderPaths.giveToInvokingUser(path)

        guard Darwin.listen(descriptor, backlog) == 0 else {
            let code = errno
            close(descriptor)
            unlink(path)
            throw Failure.cannotListen(role: role, errno: code)
        }
        return descriptor
    }
}
