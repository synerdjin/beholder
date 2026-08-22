import BeholderCore
import Darwin
import Dispatch
import Foundation
import Security

/// The socket that accepts commands, as opposed to the one that only publishes.
///
/// Deliberately a second socket rather than a widening of the first. The publishing socket
/// still takes no command at all, so everything that merely watches — `--top`, the MCP
/// server, anything else someone connects — cannot become a writer by accident, and the two
/// can carry different admission rules. This one authenticates its peer against a pinned
/// code identity; see `PeerAuthenticator` for why file permissions cannot do that job.
///
/// The listening socket itself is `UnixSocket.listen`, shared with `FlowServer`: binding,
/// permissions, the stale-socket probe and the error vocabulary are identical for both and
/// were briefly written twice.
///
/// What is left here is much simpler than `FlowServer` and stays that way on purpose. There is no
/// streaming, no back-pressure and no publishing timer: a client sends a line, gets a line,
/// and the request is bounded so a peer cannot make a root process buffer without limit. The
/// framing bug that cost real time on the publishing socket cannot recur here because
/// nothing here is ever large enough to be split across writes — and if a reply ever did
/// approach that size, the right fix would be to make the reply smaller.
final class ControlServer {

    /// Performs one request. Supplied by the daemon, which owns the packet filter.
    typealias Handler = (ControlRequest) -> ControlResponse

    private let path: String
    private let requirement: SecRequirement
    private let handle: Handler
    private let queue = DispatchQueue(label: "com.beholder.control")

    private var listenDescriptor: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private var readSources: [Int32: DispatchSourceRead] = [:]
    private var buffers: [Int32: Data] = [:]

    init(path: String, requirement: SecRequirement, handle: @escaping Handler) {
        self.path = path
        self.requirement = requirement
        self.handle = handle
    }

    func start() throws {
        listenDescriptor = try UnixSocket.listen(at: path, backlog: 4, role: "control socket")

        let source = DispatchSource.makeReadSource(fileDescriptor: listenDescriptor, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptClient() }
        acceptSource = source
        source.resume()
    }

    func stop() {
        queue.sync {
            acceptSource?.cancel()
            acceptSource = nil
            for (descriptor, source) in readSources {
                source.setCancelHandler { close(descriptor) }
                source.cancel()
            }
            readSources.removeAll()
            buffers.removeAll()
            if listenDescriptor >= 0 {
                close(listenDescriptor)
                listenDescriptor = -1
            }
            unlink(path)
        }
    }

    // MARK: - Connections

    private func acceptClient() {
        let client = accept(listenDescriptor, nil, nil)
        guard client >= 0 else { return }

        var enabled: Int32 = 1
        setsockopt(
            client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))

        // Authenticated before a single byte is read. A peer that does not match the pin
        // never gets to submit anything, so no parser here is ever exposed to a process that
        // was not allowed to talk to it in the first place.
        switch PeerAuthenticator.authorise(descriptor: client, against: requirement) {
        case .denied(let reason, let pid):
            Beholderd.note("control connection refused (pid \(pid)): \(reason)")
            // Answered rather than dropped silently, so a legitimate app whose signature has
            // changed — every rebuild changes it — sees why instead of a closed socket.
            send(ControlResponse.failure("not authorised: \(reason)"), to: client)
            close(client)
            return

        case .allowed(let pid):
            Beholderd.note("control connection accepted (pid \(pid))")
        }

        var flags = fcntl(client, F_GETFL, 0)
        flags |= O_NONBLOCK
        _ = fcntl(client, F_SETFL, flags)

        buffers[client] = Data()
        let source = DispatchSource.makeReadSource(fileDescriptor: client, queue: queue)
        source.setEventHandler { [weak self] in self?.readFrom(client) }
        readSources[client] = source
        source.resume()
    }

    private func readFrom(_ client: Int32) {
        var chunk = [UInt8](repeating: 0, count: 4096)
        let count = read(client, &chunk, chunk.count)

        guard count > 0 else {
            // 0 is the peer closing; a negative that is not EAGAIN is a real error. Either
            // way the connection is finished with.
            if count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) { drop(client) }
            return
        }

        var buffer = buffers[client] ?? Data()
        buffer.append(contentsOf: chunk[0..<count])

        // Bounded before anything is parsed. A request is one line naming one destination,
        // so a peer that has sent this much without a newline is not going to send one.
        guard buffer.count <= ControlProtocol.maximumRequestBytes else {
            send(ControlResponse.failure("request too large"), to: client)
            drop(client)
            return
        }

        while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
            let line = buffer[buffer.startIndex..<newline]
            buffer = buffer[buffer.index(after: newline)...]
            respond(to: Data(line), on: client)
        }
        buffers[client] = buffer
    }

    private func respond(to line: Data, on client: Int32) {
        guard !line.isEmpty else { return }

        let request: ControlRequest
        do {
            request = try JSONDecoder().decode(ControlRequest.self, from: line)
        } catch {
            send(ControlResponse.failure("could not read that request: \(error)"), to: client)
            return
        }

        // Checked here rather than inside the handler, so every action gets it and a new
        // action cannot be added that forgets. Both ends check, exactly as they do for
        // `WireProtocol.version`, so a mismatch is a sentence rather than a decode into
        // something plausible and wrong.
        guard request.version == ControlProtocol.version else {
            send(
                ControlResponse.failure(
                    "control protocol version \(request.version), but this daemon speaks "
                        + "\(ControlProtocol.version) — the app and the daemon are different builds"
                ), to: client)
            return
        }

        send(handle(request), to: client)
    }

    private func send(_ response: ControlResponse, to client: Int32) {
        guard var data = try? JSONEncoder().encode(response) else { return }
        data.append(UInt8(ascii: "\n"))

        if !UnixSocket.writeWhole(data, to: client) {
            // Logged rather than dropped quietly. The client is about to time out waiting for
            // a newline, and "the daemon could not deliver its reply" is the only version of
            // that story with a cause in it.
            Beholderd.note("could not deliver a control reply whole (\(data.count) bytes)")
        }
    }

    private func drop(_ client: Int32) {
        buffers.removeValue(forKey: client)
        if let source = readSources.removeValue(forKey: client) {
            source.setCancelHandler { close(client) }
            source.cancel()
        } else {
            close(client)
        }
    }

}
