import Foundation

/// A DNS or mDNS message, decoded far enough to read.
///
/// `DNSMessage` answers a narrower question — "what address did this name resolve to" —
/// and declines everything carrying no address. That excludes almost all of what a Mac
/// says on a local network: an mDNS announcement has no question section and its payload
/// is service metadata rather than addresses, so `parseResponse` returns nil for exactly
/// the packets someone opens this view to read. This walks the whole message instead.
///
/// In Core with the other display parsers, for the same reason `HTTPPreview` is: it reads
/// bytes chosen by whoever else is on the network, and that is the code a test must reach.
public enum DNSPreview {

    public struct Message: Sendable, Equatable {
        public let isResponse: Bool
        public let isAuthoritative: Bool
        public let responseCode: UInt8
        /// What the header said each section holds — which is not what `records` holds once
        /// an excerpt has been cut short.
        public let declaredCounts: Counts
        public let questions: [Question]
        public let records: [Record]

        /// True when fewer records were read than the header promised, the ordinary case
        /// for the last message in a 4 KB excerpt.
        ///
        /// Derived here rather than left to the caller so that a short list cannot be
        /// presented as a whole message. Six of eighteen answers shown without this reads
        /// as "this machine announced six things".
        public var isIncomplete: Bool {
            records.count < declaredCounts.recordTotal || records.contains(where: \.isTruncated)
        }

        /// One line naming what the message is, for a heading above the records.
        public var summary: String {
            var parts = [isResponse ? "Response" : "Query"]
            if isResponse && isAuthoritative { parts.append("authoritative") }
            if responseCode != 0 { parts.append("rcode \(responseCode)") }
            parts.append(contentsOf: declaredCounts.described)
            return parts.joined(separator: " · ")
        }
    }

    public struct Counts: Sendable, Equatable {
        public let questions: Int
        public let answers: Int
        public let authorities: Int
        public let additionals: Int

        public init(questions: Int, answers: Int, authorities: Int, additionals: Int) {
            self.questions = questions
            self.answers = answers
            self.authorities = authorities
            self.additionals = additionals
        }

        public var recordTotal: Int { answers + authorities + additionals }

        /// Only the sections that hold anything. A message described as carrying "0
        /// authority, 0 additional" spends two thirds of the line saying nothing.
        var described: [String] {
            var parts: [String] = []
            if questions > 0 { parts.append(pluralised(questions, "question")) }
            if answers > 0 { parts.append(pluralised(answers, "answer")) }
            if authorities > 0 { parts.append(pluralised(authorities, "authority", plural: "authorities")) }
            if additionals > 0 { parts.append(pluralised(additionals, "additional")) }
            return parts.isEmpty ? ["empty"] : parts
        }

    }

    public struct Question: Sendable, Equatable {
        public let name: String
        public let type: String
        /// mDNS borrows the top class bit on a question to ask for a unicast reply.
        public let wantsUnicastReply: Bool
    }

    public struct Record: Sendable, Equatable {
        public enum Section: String, Sendable, Equatable {
            case answer, authority, additional
        }

        public let section: Section
        public let name: String
        public let type: String
        public let timeToLive: UInt32
        /// mDNS borrows the top class bit on a record to mean "replace what you have
        /// cached" rather than "add to it".
        public let isCacheFlush: Bool
        /// True when the excerpt ended inside this record's data.
        ///
        /// The record is still reported rather than dropped, because a partly-read TXT is
        /// the ordinary shape of the last record in a 4 KB excerpt and the strings that did
        /// arrive are the readable part — dropping it would discard precisely what someone
        /// opened this view to see.
        public let isTruncated: Bool
        /// The contents, one entry per line. TXT yields one entry per string, which is
        /// what makes a service announcement readable; most types yield one; a type with
        /// no reader here yields its byte count rather than a guess at its shape.
        public let values: [String]
    }

    private static let headerLength = 12

    /// Every message in an excerpt.
    ///
    /// A UDP excerpt is datagrams laid end to end — the store appends each packet's payload
    /// — so one mDNS excerpt holds a run of separate announcements. They are parsed one at
    /// a time against their own base rather than as a single stream, because **compression
    /// pointers are offsets from the start of their own message**. Walking the second
    /// datagram against the first one's base resolves every pointer to some unrelated name
    /// and yields confident nonsense, which is worse than yielding nothing.
    public static func parse(_ bytes: [UInt8]) -> [Message] {
        guard bytes.count >= headerLength else { return [] }

        var messages: [Message] = []
        bytes.withUnsafeBytes { buffer in
            var start = 0
            // The cap is a backstop against a walk that stops making progress, not a
            // display limit: 4 KB of minimum-size datagrams cannot reach it.
            while start + headerLength <= buffer.count, messages.count < 64 {
                let rebased = UnsafeRawBufferPointer(rebasing: buffer[start...])
                guard let parsed = parseOne(rebased), parsed.consumed > 0 else { break }
                messages.append(parsed.message)
                start += parsed.consumed
            }
        }
        return messages
    }

    /// Reads one message and reports how many bytes it occupied.
    ///
    /// Returns nil rather than an empty message when the bytes are not a DNS message at
    /// all. That matters because the view offers this to every excerpt, the way it offers
    /// `HTTPPreview.parse`: the gates below — a zero opcode, section counts a datagram
    /// could actually carry, and at least one record or question that genuinely parsed —
    /// are what stop an arbitrary binary payload from being rendered as a DNS message.
    private static func parseOne(
        _ buffer: UnsafeRawBufferPointer
    ) -> (message: Message, consumed: Int)? {
        guard
            let flags = DNSMessage.uint16(buffer, 2),
            let questionCount = DNSMessage.uint16(buffer, 4),
            let answerCount = DNSMessage.uint16(buffer, 6),
            let authorityCount = DNSMessage.uint16(buffer, 8),
            let additionalCount = DNSMessage.uint16(buffer, 10),
            (flags >> 11) & 0x0F == 0
        else { return nil }

        let counts = Counts(
            questions: Int(questionCount),
            answers: Int(answerCount),
            authorities: Int(authorityCount),
            additionals: Int(additionalCount)
        )
        // Every entry costs at least a byte of name and ten of fixed fields, so a count
        // this side of the buffer's length is the cheap way to reject a false header.
        guard counts.questions + counts.recordTotal <= buffer.count / 11 + 1 else { return nil }

        var cursor = headerLength
        var questions: [Question] = []
        var records: [Record] = []
        var ranOut = false

        walk: do {
            for _ in 0..<counts.questions {
                guard
                    let name = DNSMessage.readName(buffer, at: cursor),
                    let type = DNSMessage.uint16(buffer, name.next),
                    let klass = DNSMessage.uint16(buffer, name.next + 2)
                else {
                    ranOut = true
                    break walk
                }
                questions.append(
                    Question(
                        name: displayName(name.name),
                        type: typeName(type),
                        wantsUnicastReply: klass & 0x8000 != 0
                    ))
                cursor = name.next + 4
            }

            let sections: [(Record.Section, Int)] = [
                (.answer, counts.answers),
                (.authority, counts.authorities),
                (.additional, counts.additionals),
            ]
            for (section, count) in sections {
                for _ in 0..<count {
                    guard
                        let name = DNSMessage.readName(buffer, at: cursor),
                        let type = DNSMessage.uint16(buffer, name.next),
                        let klass = DNSMessage.uint16(buffer, name.next + 2),
                        let timeToLive = DNSMessage.uint32(buffer, name.next + 4),
                        let dataLength = DNSMessage.uint16(buffer, name.next + 8)
                    else {
                        ranOut = true
                        break walk
                    }
                    let dataStart = name.next + 10
                    guard dataStart <= buffer.count else {
                        ranOut = true
                        break walk
                    }
                    // Read what arrived rather than requiring the whole record. An excerpt
                    // is a cut of a conversation, so its last record is usually a partial
                    // one, and a TXT record cut in half still holds readable strings.
                    let available = min(Int(dataLength), buffer.count - dataStart)
                    let isTruncated = available < Int(dataLength)
                    records.append(
                        Record(
                            section: section,
                            name: displayName(name.name),
                            type: typeName(type),
                            timeToLive: timeToLive,
                            isCacheFlush: klass & 0x8000 != 0,
                            isTruncated: isTruncated,
                            values: readData(
                                buffer, type: type, at: dataStart, length: available)
                        ))
                    if isTruncated {
                        ranOut = true
                        break walk
                    }
                    cursor = dataStart + Int(dataLength)
                }
            }
        }

        guard !questions.isEmpty || !records.isEmpty else { return nil }

        let message = Message(
            isResponse: flags & 0x8000 != 0,
            isAuthoritative: flags & 0x0400 != 0,
            responseCode: UInt8(flags & 0x000F),
            declaredCounts: counts,
            questions: questions,
            records: records
        )
        // A message whose walk lost its place consumes the rest of the excerpt: there is
        // no length field to resynchronise from, so guessing where the next datagram
        // begins would decode padding as records.
        return (message, ranOut ? buffer.count : cursor)
    }

    /// Renders a record's data by type.
    ///
    /// The default is a byte count, not an attempt. A record type nothing here understands
    /// is the same situation as an unrecognised protocol: saying "48 bytes" is true, and
    /// inventing a shape for it would be the reassuring kind of wrong.
    private static func readData(
        _ buffer: UnsafeRawBufferPointer,
        type: UInt16,
        at start: Int,
        length: Int
    ) -> [String] {
        switch type {
        case 1 where length == 4:
            if let raw = DNSMessage.uint32Raw(buffer, start) {
                return [IPAddress(v4NetworkOrder: raw).description]
            }
        case 28 where length == 16:
            if let base = buffer.baseAddress {
                return [IPAddress(v6NetworkOrderBytes: base.advanced(by: start)).description]
            }
        case 2, 5, 12:  // NS, CNAME, PTR — all a single name
            if let name = DNSMessage.readName(buffer, at: start) {
                return [displayName(name.name)]
            }
        case 16:  // TXT
            return textStrings(buffer, at: start, length: length)
        case 15:  // MX
            if let preference = DNSMessage.uint16(buffer, start),
                let exchange = DNSMessage.readName(buffer, at: start + 2)
            {
                return ["\(displayName(exchange.name)) · preference \(preference)"]
            }
        case 33:  // SRV
            if let priority = DNSMessage.uint16(buffer, start),
                let weight = DNSMessage.uint16(buffer, start + 2),
                let port = DNSMessage.uint16(buffer, start + 4),
                let target = DNSMessage.readName(buffer, at: start + 6)
            {
                return [
                    "\(displayName(target.name)):\(port) · priority \(priority), weight \(weight)"
                ]
            }
        default:
            break
        }
        return ["\(length) bytes"]
    }

    /// The character strings inside a TXT record, each length-prefixed.
    ///
    /// This is the part worth having. An AirPlay or AirPrint announcement carries its whole
    /// configuration here, and as raw bytes it is the single least readable thing in the
    /// Cleartext view despite being entirely plain text.
    private static func textStrings(
        _ buffer: UnsafeRawBufferPointer,
        at start: Int,
        length: Int
    ) -> [String] {
        var strings: [String] = []
        var cursor = start
        let end = min(start + length, buffer.count)

        while cursor < end, strings.count < 64 {
            let stringLength = Int(buffer[cursor])
            guard cursor + 1 + stringLength <= end else { break }
            var bytes = [UInt8]()
            bytes.reserveCapacity(stringLength)
            for offset in 0..<stringLength {
                bytes.append(buffer[cursor + 1 + offset])
            }
            strings.append(sanitised(String(decoding: bytes, as: UTF8.self), limit: textLimit))
            cursor += 1 + stringLength
        }

        return strings.isEmpty ? ["\(length) bytes"] : strings
    }

    /// The root name is an empty label list, and rendering it as nothing at all reads as a
    /// parse failure rather than as the root.
    private static func displayName(_ name: String) -> String {
        let cleaned = sanitised(name, limit: nameLimit)
        return cleaned.isEmpty ? "." : cleaned
    }

    /// Everything here was chosen by another machine on the network and ends up in a
    /// window, so it gets the same treatment a hostname does on its way to an assistant:
    /// one policy, not two. `MCPToolbox.cleaned` is that policy — it also catches the line
    /// separators a hand-rolled `controlCharacters` filter misses, and bounds the length,
    /// which a label chain or a TXT string from a hostile responder otherwise does not have.
    /// The content itself is never filtered, for the reason stated there: a tool that
    /// quietly omits the interesting announcement has defeated its own purpose.
    private static func sanitised(_ text: String, limit: Int) -> String {
        MCPToolbox.cleaned(text, limit: limit)
    }

    /// The longest a name can be, and the longest one TXT string can be. Anything past
    /// either is already not the thing it claims to be.
    private static let nameLimit = 253
    private static let textLimit = 255

    /// The types worth naming. Anything else is shown as its number: `TYPE65` is honest,
    /// greppable, and obviously a gap, where an invented label would be none of those.
    private static func typeName(_ type: UInt16) -> String {
        switch type {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 13: return "HINFO"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 35: return "NAPTR"
        case 41: return "OPT"
        case 47: return "NSEC"
        case 64: return "SVCB"
        case 65: return "HTTPS"
        case 255: return "ANY"
        default: return "TYPE\(type)"
        }
    }
}
