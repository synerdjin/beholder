import Darwin
import Foundation
import Testing

@testable import BeholderCore

/// A stand-in daemon: accepts one connection, says one thing, and hangs up.
///
/// The behaviour being imitated is specific and is the one that broke the app. The real
/// control server authenticates on *accept*, before it reads anything, so a client that
/// fails the check has its answer written and its socket closed before it has sent a single
/// byte. Everything about that sequence is hostile to a naive client, and none of it is
/// exercised by a client that happens to ignore SIGPIPE — which is why the shell test, driven
/// by python3, was perfectly happy while the app died.
private final class RefusingServer {
    let path: String

    /// What the client actually managed to send.
    ///
    /// Asserted on, because a server that replies without reading cannot tell a working
    /// client from one whose every write fails — and that is not hypothetical. `ControlClient`
    /// briefly opened its socket with `SnapshotClient.connect`, which ends in
    /// `shutdown(SHUT_WR)`; every request died with EPIPE before leaving the machine, and a
    /// reply-first fake server called it a pass. The python3-driven shell test could not see
    /// it either: that exercises the daemon, not this client.
    private let received = Received()
    final class Received: @unchecked Sendable {
        private let lock = NSLock()
        private var value = ""
        var text: String {
            get { lock.lock(); defer { lock.unlock() }; return value }
            set { lock.lock(); value = newValue; lock.unlock() }
        }
    }
    var requestSeen: String { received.text }

    private var listenDescriptor: Int32 = -1
    private let queue = DispatchQueue(label: "test.refusing-server")

    init(reply reply_: String, closeImmediately: Bool) {
        path = NSTemporaryDirectory() + "beholder-test-\(UUID().uuidString.prefix(8)).sock"

        listenDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        _ = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listenDescriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        listen(listenDescriptor, 4)

        let descriptor = listenDescriptor
        let received = self.received
        queue.async {
            let client = accept(descriptor, nil, nil)
            guard client >= 0 else { return }

            func reply(_ text: String) {
                var line = text + "\n"
                _ = line.withUTF8 { write(client, $0.baseAddress, $0.count) }
            }

            if closeImmediately {
                // Reply and hang up without reading a byte — exactly what the daemon does to
                // a peer it will not talk to, since it authenticates on accept.
                reply(reply_)
                close(client)
                return
            }

            // Otherwise behave like the daemon's ordinary path: read the request first, and
            // answer only if one arrived.
            var scratch = [UInt8](repeating: 0, count: 256)
            let count = read(client, &scratch, scratch.count)
            if count > 0 {
                received.text = String(bytes: scratch[0..<count], encoding: .utf8) ?? ""
                reply(reply_)
            }
            close(client)
        }
    }

    func stop() {
        if listenDescriptor >= 0 { close(listenDescriptor) }
        unlink(path)
    }
}

@Suite("Control client")
struct ControlClientTests {

    /// The regression. Before the fix this did not fail — it killed the whole process with
    /// SIGPIPE, which is why the app vanished with no message and no crash report.
    @Test("A peer that replies and hangs up is read, not fatal")
    func refusalIsReadRatherThanFatal() throws {
        let server = RefusingServer(
            reply: #"{"version":1,"ok":false,"error":"not authorised: nope"}"#,
            closeImmediately: true)
        defer { server.stop() }

        let response = try ControlClient.send(
            ControlRequest(action: .status), to: server.path, deadline: 2)

        #expect(response.ok == false)
        #expect(response.error == "not authorised: nope")
    }

    /// The regression that the reply-first server above could not see: the client has to
    /// actually deliver the request, not merely survive the round trip.
    @Test("The request reaches the far end")
    func requestIsDelivered() throws {
        let server = RefusingServer(
            reply: #"{"version":1,"ok":true,"state":{"isBlocking":true,"entries":[]}}"#,
            closeImmediately: false)
        defer { server.stop() }

        let response = try ControlClient.send(
            ControlRequest(action: .block, destination: "1.1.1.1", note: "a tracker"),
            to: server.path, deadline: 2)

        #expect(response.ok)
        #expect(response.state?.isBlocking == true)

        let sent = server.requestSeen
        #expect(sent.contains("\"action\":\"block\""))
        #expect(sent.contains("1.1.1.1"))
        #expect(sent.hasSuffix("\n"), "the daemon frames on newlines")
    }

    @Test("A socket nobody is listening on is reported, not fatal")
    func absentSocket() {
        #expect(throws: SnapshotClient.Failure.self) {
            try ControlClient.send(
                ControlRequest(action: .status),
                to: NSTemporaryDirectory() + "beholder-absent-\(getpid()).sock",
                deadline: 1)
        }
    }
}


@Suite("Whole-message writes")
struct UnixSocketWriteTests {

    /// The regression, pinned against a socket small enough to fill.
    ///
    /// A reply larger than the send buffer used to stop at the first short write, which does
    /// not truncate the message so much as destroy the framing: the newline never arrives and
    /// the reader waits for something that can never complete. On a real machine that meant a
    /// block list of a few hundred entries made the Blocking tab permanently unreachable while
    /// the daemon reported itself healthy.
    @Test("A message larger than the send buffer still arrives whole")
    func largeMessageSurvivesAFullBuffer() throws {
        var pair: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        let writer = pair[0]
        let reader = pair[1]
        defer { close(reader) }

        // Small enough that a 256 KB message cannot possibly fit, and non-blocking so the
        // writer sees EAGAIN rather than simply blocking until it drains.
        var size: Int32 = 2048
        setsockopt(writer, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(reader, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        var flags = fcntl(writer, F_GETFL, 0)
        flags |= O_NONBLOCK
        _ = fcntl(writer, F_SETFL, flags)

        let payload = Data(repeating: UInt8(ascii: "x"), count: 256 * 1024) + Data([0x0A])

        final class Tally: @unchecked Sendable {
            let lock = NSLock()
            var bytes = 0
            var sawNewline = false
        }
        let tally = Tally()
        let done = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            var chunk = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = read(reader, &chunk, chunk.count)
                if count <= 0 { break }
                tally.lock.lock()
                tally.bytes += count
                if chunk[0..<count].contains(0x0A) { tally.sawNewline = true }
                tally.lock.unlock()
            }
            done.signal()
        }

        let delivered = UnixSocket.writeWhole(payload, to: writer, deadline: 10)
        close(writer)
        _ = done.wait(timeout: .now() + 10)

        #expect(delivered)
        tally.lock.lock()
        defer { tally.lock.unlock() }
        #expect(tally.bytes == payload.count)
        #expect(tally.sawNewline, "the terminating newline is what makes the message readable")
    }

    /// The bound that keeps a peer which stops reading from pinning the daemon's queue.
    @Test("A peer that never drains is given up on rather than waited for forever")
    func stalledPeerIsBounded() throws {
        var pair: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        let writer = pair[0]
        let reader = pair[1]
        defer { close(writer); close(reader) }

        var size: Int32 = 2048
        setsockopt(writer, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(reader, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        var flags = fcntl(writer, F_GETFL, 0)
        flags |= O_NONBLOCK
        _ = fcntl(writer, F_SETFL, flags)

        // Nothing ever reads from the far end.
        let started = Date()
        let delivered = UnixSocket.writeWhole(
            Data(repeating: 0x78, count: 1024 * 1024), to: writer, deadline: 0.5)
        let elapsed = Date().timeIntervalSince(started)

        #expect(delivered == false)
        #expect(elapsed < 5, "it gave up near its deadline rather than hanging")
    }
}
