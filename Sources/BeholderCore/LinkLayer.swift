import CBeholderShim

/// The link-layer encapsulation of a capture handle, as reported by `pcap_datalink()`.
///
/// This matters more than it looks. On this machine the default route runs through a
/// `utun` interface (VPN), which is `DLT_NULL` — a 4-byte address-family word, not an
/// Ethernet header. Assuming Ethernet would silently misparse every single packet while
/// still producing plausible-looking output, so the link type is resolved per handle and
/// unknown types are refused rather than guessed at.
public enum LinkLayer: Sendable, Equatable {
    /// `DLT_NULL` (0): 4-byte address family in host byte order. Loopback and utun.
    case null
    /// `DLT_EN10MB` (1): 14-byte Ethernet header, optionally with 802.1Q tags.
    case ethernet
    /// `DLT_RAW` (12): the IP header starts immediately.
    case raw
    /// `DLT_LOOP` (108): like `null`, but the address family is big-endian.
    case loop

    public init?(datalink: Int32) {
        switch datalink {
        case DLT_NULL: self = .null
        case DLT_EN10MB: self = .ethernet
        case DLT_RAW: self = .raw
        case DLT_LOOP: self = .loop
        default: return nil
        }
    }

    public var name: String {
        switch self {
        case .null: return "DLT_NULL"
        case .ethernet: return "DLT_EN10MB"
        case .raw: return "DLT_RAW"
        case .loop: return "DLT_LOOP"
        }
    }
}

/// What the link layer claims the next header is. `.unknown` means the caller should
/// fall back to reading the IP version nibble.
public enum NetworkLayerHint: Sendable, Equatable {
    case ipv4
    case ipv6
    case unknown
    /// Explicitly not an IP packet (ARP, etc.) — should be skipped, not sniffed at.
    case notIP
}

extension LinkLayer {
    /// Locates the start of the network-layer header within a captured frame.
    /// Returns `nil` when the frame is too short to contain a complete link-layer header.
    public func networkLayerStart(
        in buffer: UnsafeRawBufferPointer
    ) -> (offset: Int, hint: NetworkLayerHint)? {
        switch self {
        case .raw:
            return (0, .unknown)

        case .null, .loop:
            guard buffer.count >= 4 else { return nil }
            let word = buffer.loadUnaligned(fromByteOffset: 0, as: UInt32.self)
            // DLT_NULL is host order; DLT_LOOP is network order. Accept either
            // interpretation rather than trusting the label, because a byte-swapped
            // read here yields nonsense that is hard to trace back later.
            let candidates = self == .loop
                ? [UInt32(bigEndian: word), word]
                : [word, UInt32(bigEndian: word)]
            for family in candidates {
                if family == UInt32(AF_INET) { return (4, .ipv4) }
                if family == UInt32(AF_INET6) { return (4, .ipv6) }
            }
            return (4, .notIP)

        case .ethernet:
            guard buffer.count >= 14 else { return nil }
            var offset = 12
            var etherType = UInt16(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
            offset += 2
            // Walk up to two stacked VLAN tags (802.1Q / 802.1ad QinQ).
            var vlanTags = 0
            while etherType == 0x8100 || etherType == 0x88A8, vlanTags < 2 {
                guard buffer.count >= offset + 4 else { return nil }
                offset += 2  // skip the tag control information
                etherType = UInt16(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
                offset += 2
                vlanTags += 1
            }
            switch etherType {
            case 0x0800: return (offset, .ipv4)
            case 0x86DD: return (offset, .ipv6)
            default: return (offset, .notIP)
            }
        }
    }
}
