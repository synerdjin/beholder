import Foundation

/// The headers of an HTTP message, when an excerpt turns out to hold one.
///
/// Deliberately shallow: this finds the start line and the header block and stops. It is
/// not an HTTP parser and should not become one — chunked bodies, content negotiation and
/// compression all belong to a different program. What it is for is answering "what did
/// this actually ask for", which lives entirely in the first few hundred bytes.
///
/// In Core rather than in the view that displays it, for the same reason `DNSMessage` and
/// `TLSClientHello` are: it parses bytes chosen by whoever is on the other end of the
/// connection, and that is exactly the code a test needs to reach.
public enum HTTPPreview {
    public struct Message: Sendable, Equatable {
        public let startLine: String
        public let headers: [Header]
        /// False when the excerpt ran out inside the header block, which is the ordinary
        /// case for a large request.
        ///
        /// Deliberately a flag rather than the body's offset. An offset would have to be
        /// in bytes to mean anything, and every natural way to compute one here counts
        /// Swift `Character`s — where a CRLF is a single element — so the number would be
        /// quietly wrong on exactly the input this parser is for. Nothing needs it.
        public let isComplete: Bool
    }

    public struct Header: Sendable, Equatable {
        public let name: String
        public let value: String

        public init(name: String, value: String) {
            self.name = name
            self.value = value
        }
    }

    public static func parse(_ bytes: [UInt8]) -> Message? {
        // Latin-1 as a fallback because it cannot fail: a header value carrying a stray
        // high byte should still render its neighbours rather than losing the whole block.
        guard
            let text = String(bytes: bytes, encoding: .utf8)
                ?? String(bytes: bytes, encoding: .isoLatin1)
        else { return nil }

        // The header block ends at a blank line. When the excerpt was cut short before
        // that, everything captured is still headers — the useful case rather than a
        // failure — so a missing terminator is not an error here.
        let terminator = text.range(of: "\r\n\r\n") ?? text.range(of: "\n\n")
        let headerText = terminator.map { String(text[text.startIndex..<$0.lowerBound]) } ?? text

        // Split on any newline rather than on "\n". Swift treats CRLF as a *single*
        // `Character`, so `split(separator: "\n")` finds nothing at all in an HTTP message
        // — it returns the whole header block as one line, and every header is lost.
        // `isNewline` is true for that combined character, which is what makes this work
        // for both line endings without hunting for stray carriage returns afterwards.
        var lines = headerText.split(whereSeparator: \.isNewline).map(String.init)
        guard let startLine = lines.first, isStartLine(startLine) else { return nil }
        lines.removeFirst()

        let headers = lines.compactMap { line -> Header? in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = String(line[line.startIndex..<colon])
            let value = String(line[line.index(after: colon)...])
                .trimmingCharacters(in: .whitespaces)
            return name.isEmpty ? nil : Header(name: name, value: value)
        }

        return Message(
            startLine: startLine,
            headers: headers,
            isComplete: terminator != nil
        )
    }

    /// Matches the same token set `ProtocolSniffer` uses to classify a connection as HTTP.
    ///
    /// One list, deliberately. Two would let the daemon call a connection HTTP while the
    /// reader declined to render its headers, and that divergence is only reproducible by
    /// running the app against live traffic.
    private static func isStartLine(_ line: String) -> Bool {
        ProtocolSniffer.httpStartTokens.contains { line.hasPrefix($0) }
    }
}

/// Offset, hex, and the printable characters — the layout every other tool uses, because
/// the point of looking at bytes is to compare them with something else.
public enum HexDump {
    private static let bytesPerLine = 16
    private static let digits = Array("0123456789abcdef".utf8)

    /// Renders into one byte buffer rather than formatting per byte.
    ///
    /// `String(format: "%02x")` is a varargs call through Foundation's formatter, on the
    /// order of a microsecond each; at the 4 KB excerpt bound that was several thousand of
    /// them, and this runs on the main thread every time the view redraws. A nibble table
    /// into a preallocated buffer does the same job about fifty times faster.
    public static func render(_ bytes: [UInt8]) -> String {
        guard !bytes.isEmpty else { return "" }

        let lineWidth = 10 + bytesPerLine * 3 + 1 + bytesPerLine + 3
        var out = [UInt8]()
        out.reserveCapacity((bytes.count / bytesPerLine + 1) * lineWidth)

        let space = UInt8(ascii: " ")
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + bytesPerLine, bytes.count)

            // Offset, eight hex digits.
            for shift in stride(from: 28, through: 0, by: -4) {
                out.append(digits[(offset >> shift) & 0xF])
            }
            out.append(space)
            out.append(space)

            for index in 0..<bytesPerLine {
                if offset + index < end {
                    let byte = bytes[offset + index]
                    out.append(digits[Int(byte >> 4)])
                    out.append(digits[Int(byte & 0x0F)])
                } else {
                    // Pad a short final line so the ASCII column stays aligned.
                    out.append(space)
                    out.append(space)
                }
                out.append(space)
                // A gap at the halfway mark, so counting to a column by eye is possible.
                if index == bytesPerLine / 2 - 1 { out.append(space) }
            }

            out.append(UInt8(ascii: "|"))
            for index in offset..<end {
                let byte = bytes[index]
                out.append((0x20...0x7E).contains(byte) ? byte : UInt8(ascii: "."))
            }
            out.append(UInt8(ascii: "|"))

            offset = end
            if offset < bytes.count { out.append(UInt8(ascii: "\n")) }
        }
        return String(decoding: out, as: UTF8.self)
    }
}
