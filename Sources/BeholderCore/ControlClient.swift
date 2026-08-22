import Darwin
import Foundation

/// Sends one request to the daemon's control socket and reads the reply.
///
/// One connection per request, deliberately. A control request is rare — someone pressed a
/// button — and a long-lived connection would need reconnection logic, liveness handling and
/// a story for a daemon restarting underneath it, all to save a `connect` on an operation
/// that happens by hand. `FlowClient` keeps a stream open because it consumes one a second;
/// nothing here does.
///
/// The connect half is `UnixSocket`'s and the failure vocabulary is `SnapshotClient`'s:
/// "nothing is listening" and "the socket belongs to another user" are the same two
/// situations with the same two fixes on either socket.
///
/// It deliberately does **not** use `SnapshotClient.connect`, and that is worth stating
/// because it looked like the obvious reuse and was briefly done that way. That function ends
/// with `shutdown(SHUT_WR)` — closing the write half so that a reader cannot quietly become a
/// writer, which is a property the publishing socket genuinely wants. A client that then
/// writes gets `EPIPE` on every request, and nothing this side can do will make one arrive.
/// The two clients want opposite things from the same socket type, so they share the
/// plumbing and not the policy.
public enum ControlClient {

    /// How long to wait for a reply.
    ///
    /// Shorter than the snapshot deadline because nothing here is on a timer: the daemon
    /// answers a control request as soon as it has one, so a wait of seconds means something
    /// is wrong rather than something is pending.
    public static let defaultDeadline: TimeInterval = 3.0

    /// A reply is one small line. Anything approaching this is a daemon that is not speaking
    /// this protocol, and reading further would only make the eventual error slower.
    public static let maximumReplyBytes = 1024 * 1024

    public static func send(
        _ request: ControlRequest,
        to path: String = ControlProtocol.defaultSocketPath,
        deadline: TimeInterval = defaultDeadline
    ) throws -> ControlResponse {
        let descriptor: Int32
        switch UnixSocket.connect(to: path) {
        case .success(let opened):
            descriptor = opened
        case .failure(let failure):
            throw SnapshotClient.failure(forConnect: failure, path: path)
        }
        defer { close(descriptor) }

        var payload = try JSONEncoder().encode(request)
        payload.append(UInt8(ascii: "\n"))

        // A failed write is not the end of the story here, which is why it is held rather
        // than thrown. The daemon authenticates on accept and refuses by *replying and then
        // closing*, so a client that fails the check can find the connection gone before it
        // has sent anything — and the answer explaining why is already sitting in the receive
        // buffer. Throwing on the broken pipe would discard the one thing worth reading and
        // report "could not connect" for a daemon that connected fine and said no.
        var deliveryFailure: Error?
        do {
            try writeAll(payload, to: descriptor, path: path)
        } catch {
            deliveryFailure = error
        }

        let line: Data
        do {
            line = try SnapshotClient.readLine(
                from: descriptor, path: path, deadline: deadline,
                maximum: maximumReplyBytes, closeCompletesMessage: true)
        } catch {
            throw deliveryFailure ?? error
        }

        do {
            return try JSONDecoder().decode(ControlResponse.self, from: line)
        } catch {
            throw deliveryFailure ?? SnapshotClient.Failure.undecodable("\(error)")
        }
    }

    private static func writeAll(_ data: Data, to descriptor: Int32, path: String) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let written = write(
                    descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0, errno == EINTR { continue }
                throw SnapshotClient.Failure.cannotConnect(
                    path: path, reason: String(cString: strerror(errno)))
            }
        }
    }

}
