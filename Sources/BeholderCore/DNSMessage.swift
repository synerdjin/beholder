import Foundation

/// Extracts name-to-address mappings from DNS responses seen on the wire.
///
/// This is how a raw address becomes something a person can read. It only works while
/// DNS is in the clear: DNS-over-HTTPS and DNS-over-TLS both hide these answers, and on
/// such a machine hostnames have to come from TLS SNI instead. Both sources are used.
public enum DNSMessage {

    public struct Answer: Sendable, Equatable {
        /// The name that was queried. Deliberately the question's name rather than an
        /// answer record's owner name: after a CNAME chain the final record is owned by
        /// some CDN alias, and the user asked about the name they typed.
        public let name: String
        public let addresses: [IPAddress]
        public let timeToLive: UInt32
    }

    /// Parses a DNS response, returning the queried name and every address it resolved
    /// to. Returns nil for queries, errors, and answers carrying no addresses.
    public static func parseResponse(_ buffer: UnsafeRawBufferPointer) -> Answer? {
        guard buffer.count >= 12 else { return nil }
        guard let flags = uint16(buffer, 2) else { return nil }

        // Must be a response (QR set) with no error (RCODE 0).
        guard flags & 0x8000 != 0, flags & 0x000F == 0 else { return nil }

        guard
            let questionCount = uint16(buffer, 4),
            let answerCount = uint16(buffer, 6),
            questionCount >= 1, answerCount >= 1
        else { return nil }

        var cursor = 12
        guard let question = readName(buffer, at: cursor) else { return nil }
        let queriedName = question.name
        cursor = question.next + 4  // QTYPE and QCLASS

        // Skip any further questions; in practice there is only ever one.
        for _ in 1..<questionCount {
            guard let extra = readName(buffer, at: cursor) else { return nil }
            cursor = extra.next + 4
        }

        var addresses: [IPAddress] = []
        var lowestTimeToLive = UInt32.max

        for _ in 0..<answerCount {
            guard let owner = readName(buffer, at: cursor) else { break }
            var position = owner.next

            guard
                let type = uint16(buffer, position),
                let timeToLive = uint32(buffer, position + 4),
                let dataLength = uint16(buffer, position + 8)
            else { break }
            position += 10

            guard position + Int(dataLength) <= buffer.count else { break }

            switch (type, dataLength) {
            case (1, 4):  // A
                if let raw = uint32Raw(buffer, position) {
                    addresses.append(IPAddress(v4NetworkOrder: raw))
                    lowestTimeToLive = min(lowestTimeToLive, timeToLive)
                }
            case (28, 16):  // AAAA
                if let base = buffer.baseAddress {
                    addresses.append(
                        IPAddress(v6NetworkOrderBytes: base.advanced(by: position))
                    )
                    lowestTimeToLive = min(lowestTimeToLive, timeToLive)
                }
            default:
                break  // CNAME, and everything else, carries no address of its own.
            }

            cursor = position + Int(dataLength)
        }

        guard !addresses.isEmpty, !queriedName.isEmpty else { return nil }
        return Answer(
            name: queriedName,
            addresses: addresses,
            timeToLive: lowestTimeToLive == .max ? 60 : lowestTimeToLive
        )
    }

    /// Reads a DNS name, following compression pointers.
    ///
    /// Returns the decoded name and the offset just past the name *as encoded at
    /// `start`* — which for a compressed name is two bytes on, not wherever the pointer
    /// led. Getting that wrong desynchronises the whole record walk.
    static func readName(
        _ buffer: UnsafeRawBufferPointer,
        at start: Int
    ) -> (name: String, next: Int)? {
        var labels: [String] = []
        var cursor = start
        var continuation: Int?
        var pointerFollows = 0
        var totalLength = 0

        while true {
            guard cursor >= 0, cursor < buffer.count else { return nil }
            let length = buffer[cursor]

            if length == 0 {
                cursor += 1
                return (labels.joined(separator: "."), continuation ?? cursor)
            }

            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < buffer.count else { return nil }
                let target = (Int(length & 0x3F) << 8) | Int(buffer[cursor + 1])
                if continuation == nil { continuation = cursor + 2 }
                // A malicious or corrupt message can point in a loop; bound the chase.
                pointerFollows += 1
                guard pointerFollows <= 16, target < buffer.count else { return nil }
                cursor = target
                continue
            }

            let labelLength = Int(length)
            guard cursor + 1 + labelLength <= buffer.count else { return nil }
            totalLength += labelLength + 1
            guard totalLength <= 255 else { return nil }

            var bytes = [UInt8]()
            bytes.reserveCapacity(labelLength)
            for offset in 0..<labelLength {
                bytes.append(buffer[cursor + 1 + offset])
            }
            labels.append(String(decoding: bytes, as: UTF8.self))
            cursor += 1 + labelLength
        }
    }

    // MARK: Bounds-checked reads
    //
    // Internal rather than private because `DNSPreview` walks the same wire format and
    // must read it the same way. Two copies would be two chances to get a bound wrong.

    @inline(__always)
    static func uint16(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= buffer.count else { return nil }
        return UInt16(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
    }

    @inline(__always)
    static func uint32(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= buffer.count else { return nil }
        return UInt32(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
    }

    @inline(__always)
    static func uint32Raw(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= buffer.count else { return nil }
        return buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
    }
}
