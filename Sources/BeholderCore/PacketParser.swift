import CBeholderShim

// MARK: - Transport protocol

public enum TransportProtocol: Hashable, Sendable {
    case tcp
    case udp
    case icmp
    case icmpv6
    case other(UInt8)

    public init(ipProtocol: UInt8) {
        switch ipProtocol {
        case 6: self = .tcp
        case 17: self = .udp
        case 1: self = .icmp
        case 58: self = .icmpv6
        default: self = .other(ipProtocol)
        }
    }

    public var ipProtocolNumber: UInt8 {
        switch self {
        case .tcp: return 6
        case .udp: return 17
        case .icmp: return 1
        case .icmpv6: return 58
        case .other(let value): return value
        }
    }

    /// Whether this protocol carries the port numbers a flow key needs.
    public var hasPorts: Bool {
        self == .tcp || self == .udp
    }

    public var name: String {
        switch self {
        case .tcp: return "TCP"
        case .udp: return "UDP"
        case .icmp: return "ICMP"
        case .icmpv6: return "ICMPv6"
        case .other(let value): return "IP/\(value)"
        }
    }
}

// MARK: - TCP flags

public struct TCPFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 0x01)
    public static let syn = TCPFlags(rawValue: 0x02)
    public static let rst = TCPFlags(rawValue: 0x04)
    public static let psh = TCPFlags(rawValue: 0x08)
    public static let ack = TCPFlags(rawValue: 0x10)
    public static let urg = TCPFlags(rawValue: 0x20)
    public static let ece = TCPFlags(rawValue: 0x40)
    public static let cwr = TCPFlags(rawValue: 0x80)

    /// A connection-opening SYN (not a SYN-ACK). This is the moment to ask the
    /// attributor who owns the socket, while it is still guaranteed to be open.
    public var isConnectionOpen: Bool {
        contains(.syn) && !contains(.ack)
    }

    public var isConnectionClose: Bool {
        contains(.fin) || contains(.rst)
    }
}

// MARK: - Parsed packet

public struct ParsedPacket: Sendable, Equatable {
    public let transport: TransportProtocol
    public let source: IPAddress
    public let destination: IPAddress
    /// Zero when the protocol has no ports, or when this is a non-initial fragment.
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let tcpFlags: TCPFlags

    /// The frame's true length on the wire, taken from pcap's `pkthdr.len`.
    ///
    /// This is deliberately *not* `caplen`: at any snaplen Beholder uses, every full-MTU
    /// packet arrives truncated, so counting captured bytes would undercount throughput
    /// badly and consistently. All byte accounting must use this field.
    public let wireBytes: UInt32

    /// True for a non-initial IP fragment, whose ports live in the first fragment only.
    public let isFragment: Bool

    /// Where the transport payload begins within the captured buffer, and how much of it
    /// was actually captured. Used by the SNI and DNS parsers.
    public let payloadOffset: Int
    public let payloadCapturedLength: Int
}

public enum PacketParseFailure: Error, Sendable, Equatable {
    case truncatedLinkLayer
    case notIP
    case truncatedNetworkHeader
    case unsupportedIPVersion(UInt8)
    case badHeaderLength
    case truncatedTransportHeader
    case tooManyExtensionHeaders
}

// MARK: - Parser

public enum PacketParser {
    /// Maximum IPv6 extension headers to walk before giving up. Real traffic uses at most
    /// two or three; a longer chain means either a hostile packet or a parsing bug.
    private static let maxExtensionHeaders = 8

    public static func parse(
        _ buffer: UnsafeRawBufferPointer,
        linkLayer: LinkLayer,
        wireBytes: UInt32
    ) -> Result<ParsedPacket, PacketParseFailure> {
        guard let (offset, hint) = linkLayer.networkLayerStart(in: buffer) else {
            return .failure(.truncatedLinkLayer)
        }
        if hint == .notIP {
            return .failure(.notIP)
        }

        // The link layer's claim is a hint, not gospel — DLT_RAW gives none at all, so
        // fall back to the IP version nibble.
        let version: UInt8
        switch hint {
        case .ipv4: version = 4
        case .ipv6: version = 6
        case .unknown, .notIP:
            guard let first = byte(buffer, offset) else {
                return .failure(.truncatedNetworkHeader)
            }
            version = first >> 4
        }

        switch version {
        case 4: return parseIPv4(buffer, at: offset, wireBytes: wireBytes)
        case 6: return parseIPv6(buffer, at: offset, wireBytes: wireBytes)
        default: return .failure(.unsupportedIPVersion(version))
        }
    }

    // MARK: IPv4

    private static func parseIPv4(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int,
        wireBytes: UInt32
    ) -> Result<ParsedPacket, PacketParseFailure> {
        guard let versionAndIHL = byte(buffer, offset) else {
            return .failure(.truncatedNetworkHeader)
        }
        let headerLength = Int(versionAndIHL & 0x0F) * 4
        guard headerLength >= 20 else { return .failure(.badHeaderLength) }
        guard offset + headerLength <= buffer.count else {
            return .failure(.truncatedNetworkHeader)
        }

        guard
            let protocolNumber = byte(buffer, offset + 9),
            let flagsAndFragment = uint16BigEndian(buffer, offset + 6),
            let sourceRaw = uint32Raw(buffer, offset + 12),
            let destinationRaw = uint32Raw(buffer, offset + 16)
        else {
            return .failure(.truncatedNetworkHeader)
        }

        let fragmentOffset = flagsAndFragment & 0x1FFF
        let moreFragments = (flagsAndFragment & 0x2000) != 0
        // Only the *first* fragment carries the transport header. A later fragment is
        // still real traffic worth counting, it just cannot be keyed by port.
        let isNonInitialFragment = fragmentOffset != 0

        return finish(
            buffer: buffer,
            transportOffset: offset + headerLength,
            transport: TransportProtocol(ipProtocol: protocolNumber),
            source: IPAddress(v4NetworkOrder: sourceRaw),
            destination: IPAddress(v4NetworkOrder: destinationRaw),
            isFragment: isNonInitialFragment || moreFragments,
            skipTransportHeader: isNonInitialFragment,
            wireBytes: wireBytes
        )
    }

    // MARK: IPv6

    private static func parseIPv6(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int,
        wireBytes: UInt32
    ) -> Result<ParsedPacket, PacketParseFailure> {
        let fixedHeaderLength = 40
        guard offset + fixedHeaderLength <= buffer.count else {
            return .failure(.truncatedNetworkHeader)
        }
        guard let firstNextHeader = byte(buffer, offset + 6) else {
            return .failure(.truncatedNetworkHeader)
        }

        let source = buffer.baseAddress!.advanced(by: offset + 8)
        let destination = buffer.baseAddress!.advanced(by: offset + 24)

        var nextHeader = firstNextHeader
        var cursor = offset + fixedHeaderLength
        var isFragment = false
        var isNonInitialFragment = false
        var walked = 0

        walk: while walked < maxExtensionHeaders {
            switch nextHeader {
            case 0, 43, 60, 135:  // hop-by-hop, routing, destination options, mobility
                guard
                    let following = byte(buffer, cursor),
                    let extensionLength = byte(buffer, cursor + 1)
                else { return .failure(.truncatedNetworkHeader) }
                nextHeader = following
                cursor += (Int(extensionLength) + 1) * 8

            case 44:  // fragment header — fixed 8 bytes
                guard
                    let following = byte(buffer, cursor),
                    let fragmentField = uint16BigEndian(buffer, cursor + 2)
                else { return .failure(.truncatedNetworkHeader) }
                isFragment = true
                isNonInitialFragment = (fragmentField >> 3) != 0
                nextHeader = following
                cursor += 8

            case 51:  // authentication header — length is in 4-byte units, plus 2
                guard
                    let following = byte(buffer, cursor),
                    let extensionLength = byte(buffer, cursor + 1)
                else { return .failure(.truncatedNetworkHeader) }
                nextHeader = following
                cursor += (Int(extensionLength) + 2) * 4

            case 59:  // explicitly no next header
                break walk

            default:  // a transport protocol — stop walking
                break walk
            }
            walked += 1
        }

        guard walked < maxExtensionHeaders else {
            return .failure(.tooManyExtensionHeaders)
        }

        return finish(
            buffer: buffer,
            transportOffset: cursor,
            transport: TransportProtocol(ipProtocol: nextHeader),
            source: IPAddress(v6NetworkOrderBytes: source),
            destination: IPAddress(v6NetworkOrderBytes: destination),
            isFragment: isFragment,
            skipTransportHeader: isNonInitialFragment,
            wireBytes: wireBytes
        )
    }

    // MARK: Transport

    private static func finish(
        buffer: UnsafeRawBufferPointer,
        transportOffset: Int,
        transport: TransportProtocol,
        source: IPAddress,
        destination: IPAddress,
        isFragment: Bool,
        skipTransportHeader: Bool,
        wireBytes: UInt32
    ) -> Result<ParsedPacket, PacketParseFailure> {
        // A packet with no readable transport header is still a real packet carrying real
        // bytes. Report it with zero ports rather than discarding it — dropping traffic
        // would quietly understate what the machine is doing, which is the one thing this
        // tool must never do.
        guard !skipTransportHeader, transport.hasPorts else {
            return .success(
                ParsedPacket(
                    transport: transport,
                    source: source,
                    destination: destination,
                    sourcePort: 0,
                    destinationPort: 0,
                    tcpFlags: [],
                    wireBytes: wireBytes,
                    isFragment: isFragment,
                    payloadOffset: min(transportOffset, buffer.count),
                    payloadCapturedLength: max(0, buffer.count - transportOffset)
                )
            )
        }

        guard
            let sourcePort = uint16BigEndian(buffer, transportOffset),
            let destinationPort = uint16BigEndian(buffer, transportOffset + 2)
        else {
            return .failure(.truncatedTransportHeader)
        }

        var flags = TCPFlags()
        var payloadOffset = transportOffset

        switch transport {
        case .tcp:
            guard
                let dataOffsetByte = byte(buffer, transportOffset + 12),
                let flagsByte = byte(buffer, transportOffset + 13)
            else {
                return .failure(.truncatedTransportHeader)
            }
            let tcpHeaderLength = Int(dataOffsetByte >> 4) * 4
            guard tcpHeaderLength >= 20 else { return .failure(.badHeaderLength) }
            flags = TCPFlags(rawValue: flagsByte)
            payloadOffset = transportOffset + tcpHeaderLength

        case .udp:
            payloadOffset = transportOffset + 8

        default:
            break
        }

        let clampedPayloadOffset = min(payloadOffset, buffer.count)
        return .success(
            ParsedPacket(
                transport: transport,
                source: source,
                destination: destination,
                sourcePort: sourcePort,
                destinationPort: destinationPort,
                tcpFlags: flags,
                wireBytes: wireBytes,
                isFragment: isFragment,
                payloadOffset: clampedPayloadOffset,
                payloadCapturedLength: buffer.count - clampedPayloadOffset
            )
        )
    }

    // MARK: Bounds-checked reads

    @inline(__always)
    private static func byte(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt8? {
        guard offset >= 0, offset < buffer.count else { return nil }
        return buffer.loadUnaligned(fromByteOffset: offset, as: UInt8.self)
    }

    @inline(__always)
    private static func uint16BigEndian(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= buffer.count else { return nil }
        return UInt16(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
    }

    /// Reads 4 bytes without byte-swapping — the caller interprets the order.
    @inline(__always)
    private static func uint32Raw(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= buffer.count else { return nil }
        return buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
    }
}
