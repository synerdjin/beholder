import BeholderCore
import Darwin
import Foundation

/// Newline-delimited JSON-RPC over the standard streams.
///
/// The transport rule that governs everything here: one message per line on stdout, and
/// **nothing** on stdout that is not a message. There is no framing header to resynchronise
/// from, so a single stray byte — a `print` left in for debugging, a warning from a library
/// — corrupts the stream permanently, and the only symptom the user sees is their client
/// reporting a parse error with no clue where it came from. stderr is explicitly free for
/// logging; clients are told not to treat output there as failure.
struct StdioTransport {

    private let handler: MCPHandler
    /// Guards stdout. Responses are written from one place, but a future progress
    /// notification would be a second writer, and interleaved halves of two lines are
    /// unrecoverable.
    private let writeLock = NSLock()

    init(handler: MCPHandler) {
        self.handler = handler
    }

    /// Reads until stdin closes. Returns when the client goes away.
    func run() {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)

        while true {
            let count = read(STDIN_FILENO, &chunk, chunk.count)

            if count < 0 {
                if errno == EINTR { continue }
                FileHandle.standardError.write(
                    Data("beholder-mcp: stdin: \(String(cString: strerror(errno)))\n".utf8)
                )
                return
            }
            // End of file. The client closing our stdin is the primary graceful-shutdown
            // signal and the only portable one, so returning promptly here is what keeps a
            // process from being left behind on every client restart.
            if count == 0 { return }

            buffer.append(contentsOf: chunk[0..<count])

            // A message may span several reads, so consume only whole lines.
            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = Data(buffer[buffer.startIndex..<newline])
                buffer = Data(buffer[buffer.index(after: newline)...])
                guard !line.isEmpty else { continue }
                if let response = handler.handle(line: line) {
                    guard write(line: response) else { return }
                }
            }
        }
    }

    /// Writes one message and its newline. Returns false when the client has gone.
    private func write(line: Data) -> Bool {
        // Belt and braces. JSONEncoder escapes a newline inside a string as the two
        // characters `\n`, so an encoded message cannot contain a raw one — but this is the
        // single choke point where that invariant is cheap to check, and a hand-built
        // string in some future error path would otherwise break the stream silently.
        assert(!line.contains(0x0A), "an MCP message must not contain a raw newline")

        var payload = line
        payload.append(0x0A)

        writeLock.lock()
        defer { writeLock.unlock() }

        return payload.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return true }
            var offset = 0
            // Loop until every byte is out. A write to a pipe can return having written
            // only part of the buffer, and this project has already been bitten by exactly
            // that on the publishing socket: a snapshot larger than the send buffer was
            // abandoned half-written and no reader could ever resynchronise.
            // Scripts/test-publishing-socket.sh exists because of it.
            while offset < raw.count {
                let written = Darwin.write(STDOUT_FILENO, base + offset, raw.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                // EPIPE: the client closed the other end. That is a normal end to a
                // session, not a failure to report.
                return false
            }
            return true
        }
    }
}
