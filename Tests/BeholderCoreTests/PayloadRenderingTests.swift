import Foundation
import Testing

@testable import BeholderCore

private func bytes(_ text: String) -> [UInt8] { Array(text.utf8) }

@Suite("Reading an HTTP message out of an excerpt")
struct HTTPPreviewTests {

    @Test("A request line and its headers are pulled out")
    func parsesARequest() throws {
        let message = try #require(
            HTTPPreview.parse(
                bytes("GET /login HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\nbody")
            )
        )
        #expect(message.startLine == "GET /login HTTP/1.1")
        #expect(message.headers.count == 2)
        #expect(message.headers.first?.name == "Host")
        #expect(message.headers.first?.value == "example.com")
        #expect(message.isComplete)
    }

    @Test("A response is parsed as readily as a request")
    func parsesAResponse() throws {
        let message = try #require(
            HTTPPreview.parse(bytes("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"))
        )
        #expect(message.startLine == "HTTP/1.1 200 OK")
        #expect(message.headers.first?.name == "Content-Type")
    }

    /// The common case for a 4 KB excerpt of a real request: the headers run past what was
    /// kept. That is the useful case rather than a failure, so it must still parse — and
    /// must say that it is incomplete.
    @Test("Headers cut short by the excerpt limit still parse, and say they were cut")
    func truncatedHeadersStillParse() throws {
        let message = try #require(
            HTTPPreview.parse(bytes("POST /x HTTP/1.1\r\nHost: example.com\r\nCooki"))
        )
        #expect(message.startLine == "POST /x HTTP/1.1")
        #expect(message.headers.count == 1, "the partial line is not a header")
        #expect(!message.isComplete)
    }

    @Test("Bare LF line endings are accepted as well as CRLF")
    func bareLineFeeds() throws {
        let message = try #require(HTTPPreview.parse(bytes("GET / HTTP/1.1\nHost: x\n\n")))
        #expect(message.headers.first?.value == "x")
        #expect(message.isComplete)
    }

    @Test("Anything that is not an HTTP message is declined")
    func declinesNonHTTP() {
        #expect(HTTPPreview.parse(bytes("SSH-2.0-OpenSSH_9.6\r\n")) == nil)
        #expect(HTTPPreview.parse([]) == nil)
        #expect(HTTPPreview.parse([0x16, 0x03, 0x01, 0x00]) == nil)
    }

    /// A header value carrying a stray high byte should cost its neighbours nothing.
    @Test("Invalid UTF-8 falls back rather than losing the whole block")
    func invalidUTF8() throws {
        var raw = bytes("GET / HTTP/1.1\r\nX-Tag: ")
        raw += [0xFF, 0xFE]
        raw += bytes("\r\n\r\n")

        let message = try #require(HTTPPreview.parse(raw))
        #expect(message.startLine == "GET / HTTP/1.1")
        #expect(message.headers.first?.name == "X-Tag")
    }

    /// One list, so a connection the daemon calls HTTP is one the reader will render. Two
    /// copies would diverge, and the symptom — headers not rendering for one method —
    /// only shows up against live traffic.
    @Test("Every method the sniffer recognises is one the reader will parse")
    func methodsAgreeWithTheSniffer() {
        for token in ProtocolSniffer.httpStartTokens where token != "HTTP/1." {
            let request = bytes("\(token)/ HTTP/1.1\r\nHost: x\r\n\r\n")
            #expect(HTTPPreview.parse(request) != nil, "\(token)")
        }
    }
}

@Suite("Rendering bytes for a person to read")
struct HexDumpTests {

    @Test("A short line carries its offset, hex and printable characters")
    func rendersOneLine() {
        let rendered = HexDump.render(Array("GET /".utf8))
        #expect(rendered.hasPrefix("00000000  47 45 54 20 2f"))
        #expect(rendered.hasSuffix("|GET /|"))
    }

    @Test("Unprintable bytes become dots rather than mangling the column")
    func unprintableBytes() {
        let rendered = HexDump.render([0x00, 0x41, 0xFF, 0x7F])
        #expect(rendered.hasSuffix("|.A..|"))
    }

    /// The ASCII column has to start at the same character position on every line, or the
    /// dump cannot be read down a column — which is the entire point of the format.
    @Test("A short final line stays aligned with the full ones")
    func shortFinalLineIsPadded() throws {
        let rendered = HexDump.render(Array(repeating: 0x41, count: 20))
        let lines = rendered.split(separator: "\n").map(String.init)
        #expect(lines.count == 2)

        let first = try #require(lines.first).distance(
            from: lines[0].startIndex,
            to: #require(lines[0].firstIndex(of: "|"))
        )
        let second = lines[1].distance(
            from: lines[1].startIndex,
            to: try #require(lines[1].firstIndex(of: "|"))
        )
        #expect(first == second, "the ASCII column moved on the short line")
    }

    @Test("Sixteen bytes to a line")
    func lineLength() {
        let lines = HexDump.render(Array(repeating: 0x41, count: 33))
            .split(separator: "\n")
        #expect(lines.count == 3)
        #expect(lines[1].hasPrefix("00000010"))
        #expect(lines[2].hasPrefix("00000020"))
    }

    @Test("Nothing in, nothing out")
    func empty() {
        #expect(HexDump.render([]).isEmpty)
    }

    @Test("A full excerpt renders every byte")
    func fullExcerpt() {
        let size = PayloadExcerptStore.maximumBytesPerDirection
        let lines = HexDump.render(Array(repeating: 0x41, count: size))
            .split(separator: "\n")
        #expect(lines.count == size / 16)
    }
}
