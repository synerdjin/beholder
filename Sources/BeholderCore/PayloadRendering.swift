import Foundation

/// Which reading applies to an excerpt.
///
/// The precedence rule — a payload is not both, and HTTP is tried first because it is the
/// cheaper parse — is a fact about payloads, not about the view that draws them, so it
/// belongs here where a test can reach it rather than in a SwiftUI `body`, which is the one
/// place in this project nothing can reach. It is also where the next reader gets added,
/// as a case rather than as another clause in a view.
public enum PayloadPreview: Sendable, Equatable {
    case http(HTTPPreview.Message)
    case dns([DNSPreview.Message])
    /// Nothing recognised it, and the hex dump is the whole reading. Not a failure: most
    /// of what a machine sends is a protocol nothing here parses.
    case unrecognised

    public static func of(_ bytes: [UInt8]) -> PayloadPreview {
        if let message = HTTPPreview.parse(bytes) { return .http(message) }
        let messages = DNSPreview.parse(bytes)
        return messages.isEmpty ? .unrecognised : .dns(messages)
    }
}

/// The headers of an HTTP message, when an excerpt turns out to hold one.
///
/// Deliberately shallow, and the boundary has moved once: this finds the start line, the
/// header block, and the body — undoing chunked framing and a `Content-Encoding` if one is
/// in the way — and stops there. It is still not an HTTP parser and should not become one;
/// content negotiation, caching and persistent-connection framing all belong to a different
/// program.
///
/// The line now sits where it does because of what the alternative looked like on screen. A
/// gzip-encoded body rendered as raw bytes is indistinguishable from ciphertext to anyone
/// reading it, and being mistaken for encryption is the one failure this whole view exists
/// to prevent. Compression is reversible without a key, so leaving it undone was reporting
/// something as unreadable that simply had not been read.
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
        /// This stayed a flag when the body reader arrived, and the reasoning behind it
        /// held: an offset derived from the decoded text would count Swift `Character`s —
        /// where a CRLF is a *single* element — and so be quietly wrong on exactly the
        /// input this parser is for. The boundary is found in the byte array instead,
        /// before anything is decoded, which is what a body reader needs anyway and is why
        /// the offset never has to appear here.
        public let isComplete: Bool

        /// What followed the headers, once any framing and encoding was undone. Nil when
        /// the excerpt held no body at all.
        public let body: Body?
    }

    /// A message body, decoded as far as it can be.
    public struct Body: Sendable, Equatable {
        /// The body as text, when it is text. Nil for an image, an archive, or anything
        /// else whose bytes are not meant to be read — the hex dump below covers those,
        /// and inventing a rendering for them would only obscure that.
        public let text: String?
        /// One line saying what was done to it and what is missing from it.
        ///
        /// The size lives in here rather than in a field of its own: every caller wants it
        /// alongside "gzip undone" and "cut short by the excerpt" rather than instead of
        /// them, and a separate number invites showing one without the other.
        ///
        /// Always present, never optional. A body shown without saying how much of it is
        /// there reads as all of it, which is the same failure as a byte total that does
        /// not admit to being an undercount.
        public let note: String
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
        // The header block ends at a blank line. When the excerpt was cut short before
        // that, everything captured is still headers — the useful case rather than a
        // failure — so a missing terminator is not an error here.
        let boundary = headerBoundary(bytes)
        let headerBytes = boundary.map { bytes[0..<$0.headerEnd] } ?? bytes[...]

        // Latin-1 as a fallback because it cannot fail: a header value carrying a stray
        // high byte should still render its neighbours rather than losing the whole block.
        guard
            let headerText = String(bytes: headerBytes, encoding: .utf8)
                ?? String(bytes: headerBytes, encoding: .isoLatin1)
        else { return nil }

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
            isComplete: boundary != nil,
            body: boundary.flatMap { readBody(bytes[$0.bodyStart...], headers: headers) }
        )
    }

    /// Finds the blank line separating headers from body, in the bytes.
    ///
    /// Both terminators are accepted. The four-byte form is checked first at each position
    /// so that a CRLF pair is never mistaken for the shorter one.
    private static func headerBoundary(_ bytes: [UInt8]) -> (headerEnd: Int, bodyStart: Int)? {
        let cr = UInt8(ascii: "\r")
        let lf = UInt8(ascii: "\n")
        var index = 0
        while index + 1 < bytes.count {
            if index + 3 < bytes.count,
                bytes[index] == cr, bytes[index + 1] == lf,
                bytes[index + 2] == cr, bytes[index + 3] == lf
            {
                return (index, index + 4)
            }
            if bytes[index] == lf, bytes[index + 1] == lf {
                return (index, index + 2)
            }
            index += 1
        }
        return nil
    }

    // MARK: - The body

    /// Undoes whatever stands between the body bytes and reading them.
    ///
    /// Order matters and is not interchangeable: chunked framing wraps the encoded bytes,
    /// so it has to come off before the encoding underneath can be recognised at all.
    private static func readBody(_ raw: ArraySlice<UInt8>, headers: [Header]) -> Body? {
        guard !raw.isEmpty else { return nil }

        var bytes = Array(raw)
        var clauses: [String] = []
        var isPartial = false

        if headerValue("transfer-encoding", in: headers)?.contains("chunked") == true {
            let unchunked = unchunk(bytes)
            bytes = unchunked.bytes
            isPartial = isPartial || !unchunked.isComplete
            clauses.append("de-chunked")
            guard !bytes.isEmpty else {
                return Body(text: nil, note: "chunked, and none of it captured")
            }
        }

        let encoding = headerValue("content-encoding", in: headers) ?? "identity"
        if !["identity", ""].contains(encoding) {
            guard ["gzip", "x-gzip", "deflate"].contains(encoding) else {
                // Brotli and zstd have no system library to lean on here, and a guess at
                // their contents would be worse than naming them. This is the same rule the
                // protocol sniffer follows: what was not read is reported as not read.
                return Body(
                    text: nil,
                    note: "\(bytes.count) bytes · \(encoding), which is not decoded here"
                )
            }
            // `deflate` is specified as zlib-wrapped and frequently sent bare, so both are
            // tried. The wrapped form goes first: a bare stream offered to it is rejected
            // outright, where a wrapped stream read as bare can emit a few bytes of nonsense
            // before failing, and nonsense that renders is worse than nothing.
            guard
                let result = Inflate.decompress(bytes, format: .gzipOrZlib)
                    ?? Inflate.decompress(bytes, format: .raw)
            else {
                return Body(
                    text: nil,
                    note: "\(bytes.count) bytes · \(encoding), which would not decode"
                )
            }
            bytes = result.bytes
            isPartial = isPartial || result.isPartial
            clauses.append("\(encoding) undone")
            if result.hitLimit {
                clauses.append("stopped at \(Inflate.defaultLimit / 1024) KB")
            }
        }

        let text = readableText(bytes)
        var note = ["\(bytes.count) bytes"] + clauses
        if text == nil { note.append("not text") }
        // The caveat travels with the body rather than being left to the coverage line
        // below it, which counts wire bytes and so cannot speak for a decoded one.
        if isPartial { note.append("cut short by the excerpt") }

        return Body(text: text, note: note.joined(separator: " · "))
    }

    /// Undoes chunked transfer framing.
    ///
    /// Reads what arrived rather than requiring a terminating chunk, since an excerpt
    /// almost never contains one. A chunk header may carry extensions after a semicolon,
    /// which are not part of the size.
    private static func unchunk(_ bytes: [UInt8]) -> (bytes: [UInt8], isComplete: Bool) {
        var output = [UInt8]()
        var cursor = 0

        while cursor < bytes.count {
            guard let line = lineEnd(bytes, from: cursor) else { return (output, false) }
            let header = String(decoding: bytes[cursor..<line.contentEnd], as: UTF8.self)
            let sizeText = header.split(separator: ";").first.map(String.init) ?? header
            guard
                let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16),
                size >= 0
            else { return (output, false) }

            if size == 0 { return (output, true) }
            let start = line.next
            guard start + size <= bytes.count else {
                // The excerpt ended inside a chunk. Its bytes are still body bytes.
                if start < bytes.count { output.append(contentsOf: bytes[start...]) }
                return (output, false)
            }
            output.append(contentsOf: bytes[start..<start + size])
            cursor = start + size + 2  // past the CRLF that closes the chunk
        }
        return (output, false)
    }

    private static func lineEnd(
        _ bytes: [UInt8],
        from start: Int
    ) -> (contentEnd: Int, next: Int)? {
        guard let index = bytes[start...].firstIndex(of: UInt8(ascii: "\n")) else { return nil }
        let hasReturn = index > start && bytes[index - 1] == UInt8(ascii: "\r")
        return (hasReturn ? index - 1 : index, index + 1)
    }

    /// Whether these bytes are text — which is a different question from whether they
    /// decode.
    ///
    /// A PNG decodes perfectly well and is not text. What separates the two is how much of
    /// the result is control characters and replacement marks, so that is what is measured
    /// rather than trusting a decoder that cannot fail.
    private static func readableText(_ bytes: [UInt8]) -> String? {
        guard !bytes.isEmpty else { return nil }
        let text = String(decoding: bytes, as: UTF8.self)

        var suspicious = 0
        var total = 0
        for scalar in text.unicodeScalars {
            total += 1
            if scalar == "\u{FFFD}" {
                suspicious += 1
            } else if scalar.value < 0x20, scalar != "\n", scalar != "\r", scalar != "\t" {
                suspicious += 1
            }
        }

        guard total > 0, Double(suspicious) / Double(total) <= 0.05 else { return nil }
        return text
    }

    /// Header lookup is case-insensitive because the field name is, and HTTP/2 origins
    /// routinely send them lowercased where HTTP/1.1 origins do not.
    private static func headerValue(_ name: String, in headers: [Header]) -> String? {
        headers.first { $0.name.lowercased() == name }?
            .value.lowercased().trimmingCharacters(in: .whitespaces)
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
