import Foundation

/// Building and reading ICMP echo messages.
///
/// In Core rather than beside the prober that uses it, because a test cannot reach into an
/// executable target — and these are exactly the parts worth testing. A checksum that is
/// wrong by one bit produces a probe that is silently dropped, which from the outside is
/// indistinguishable from an unreachable network: the failure would look like the very
/// finding the prober exists to report.
public enum ICMPEcho {

    /// An 8-byte echo request.
    ///
    /// The checksum is computed here even though the kernel recomputes it on a `SOCK_DGRAM`
    /// socket, because a wrong one is discarded without a word and being right costs four
    /// lines.
    public static func request(identifier: UInt16, sequence: UInt16) -> [UInt8] {
        var packet: [UInt8] = [
            8, 0,  // echo request, code 0
            0, 0,  // checksum, filled in below
            UInt8(identifier >> 8), UInt8(truncatingIfNeeded: identifier),
            UInt8(sequence >> 8), UInt8(truncatingIfNeeded: sequence),
        ]
        let sum = checksum(packet)
        packet[2] = UInt8(sum >> 8)
        packet[3] = UInt8(truncatingIfNeeded: sum)
        return packet
    }

    /// The sequence number out of an echo reply, or nil if this is not one.
    ///
    /// Replies are matched on sequence rather than identifier: a `SOCK_DGRAM` ICMP socket
    /// lets the kernel own the identifier and rewrite it, while the sequence is passed
    /// through untouched.
    ///
    /// Both framings are accepted. Whether the IP header comes along with the message
    /// varies by platform and by socket type, and assuming one shape would mean reading
    /// the wrong two bytes on the other — quietly, as a reply that never matched.
    public static func replySequence(in buffer: [UInt8], count: Int) -> UInt16? {
        guard count > 0 else { return nil }
        var offset = 0
        if buffer[0] >> 4 == 4 {
            offset = Int(buffer[0] & 0x0F) * 4
            guard offset >= 20 else { return nil }
        }
        guard count >= offset + 8, buffer[offset] == 0 else { return nil }  // type 0: echo reply
        return UInt16(buffer[offset + 6]) << 8 | UInt16(buffer[offset + 7])
    }

    /// The internet checksum: the one's complement of the one's complement sum of the
    /// message read as 16-bit big-endian words.
    public static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum &+= UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { sum &+= UInt32(bytes[index]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return UInt16(truncatingIfNeeded: ~sum)
    }
}
