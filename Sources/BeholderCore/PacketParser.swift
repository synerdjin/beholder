import CBeholderShim
import Foundation

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

// MARK: - Transport detail

/// The TCP header fields beyond the flags, read for measurement rather than for naming.
///
/// Nil on anything that is not TCP, and on a non-initial fragment, so the absence of this
/// is what "we cannot measure this conversation" looks like further up.
public struct TCPDetail: Sendable, Equatable {
    public let sequence: UInt32
    public let acknowledgement: UInt32
    public let window: UInt16

    /// RFC 7323 timestamps, option kind 8. The best round-trip-time source available to a
    /// passive observer: present on most connections, sampled once per round trip, and —
    /// unlike inferring the time from an acknowledgement — unambiguous when a segment has
    /// been retransmitted, because the echo names which transmission it answers.
    public let timestampValue: UInt32?
    public let timestampEcho: UInt32?

    /// How many selective-acknowledgement blocks this segment carries, option kind 5.
    /// A block means the sender of *this* packet has a hole in what it received, which is
    /// direct evidence of loss on the path towards it.
    public let sackBlockCount: UInt8

    /// Negotiated on the SYN only, and nil everywhere else.
    public let maximumSegmentSize: UInt16?
    public let windowScale: UInt8?

    public init(
        sequence: UInt32,
        acknowledgement: UInt32,
        window: UInt16,
        timestampValue: UInt32? = nil,
        timestampEcho: UInt32? = nil,
        sackBlockCount: UInt8 = 0,
        maximumSegmentSize: UInt16? = nil,
        windowScale: UInt8? = nil
    ) {
        self.sequence = sequence
        self.acknowledgement = acknowledgement
        self.window = window
        self.timestampValue = timestampValue
        self.timestampEcho = timestampEcho
        self.sackBlockCount = sackBlockCount
        self.maximumSegmentSize = maximumSegmentSize
        self.windowScale = windowScale
    }
}

/// Just enough ICMP to tell an unreachable from a time-exceeded from an echo. The rest of
/// the message quotes the packet that provoked it, which is not read here.
public struct ICMPDetail: Sendable, Equatable {
    public let type: UInt8
    public let code: UInt8

    public init(type: UInt8, code: UInt8) {
        self.type = type
        self.code = code
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

    /// When the kernel saw this packet, from pcap's `pkthdr.ts`.
    ///
    /// Every interval derived from this is derived from BPF's clock, not from when the
    /// flow queue got round to the packet — which is the difference between a round-trip
    /// time and a measurement of how busy Beholder was. It is a *wall* clock, so it can
    /// step under NTP; anything computing a difference has to survive a negative one.
    public let timestamp: Date

    /// The transport payload's true length, from the IP header's own length field.
    ///
    /// Distinct from `payloadCapturedLength`, which snaplen truncates and Ethernet padding
    /// inflates. Sequence-number arithmetic needs the real figure and would silently
    /// mis-detect retransmissions with either of the other two.
    public let transportPayloadLength: Int

    /// IPv4 TTL or IPv6 hop limit, as sent by whoever last forwarded it.
    public let hopLimit: UInt8

    public let tcp: TCPDetail?
    public let icmp: ICMPDetail?

    /// The new fields default so that call sites predating them — chiefly test fixtures
    /// building a packet by hand — keep compiling and keep meaning what they meant.
    public init(
        transport: TransportProtocol,
        source: IPAddress,
        destination: IPAddress,
        sourcePort: UInt16,
        destinationPort: UInt16,
        tcpFlags: TCPFlags,
        wireBytes: UInt32,
        isFragment: Bool,
        payloadOffset: Int,
        payloadCapturedLength: Int,
        timestamp: Date = Date(),
        transportPayloadLength: Int = 0,
        hopLimit: UInt8 = 0,
        tcp: TCPDetail? = nil,
        icmp: ICMPDetail? = nil
    ) {
        self.transport = transport
        self.source = source
        self.destination = destination
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.tcpFlags = tcpFlags
        self.wireBytes = wireBytes
        self.isFragment = isFragment
        self.payloadOffset = payloadOffset
        self.payloadCapturedLength = payloadCapturedLength
        self.timestamp = timestamp
        self.transportPayloadLength = transportPayloadLength
        self.hopLimit = hopLimit
        self.tcp = tcp
        self.icmp = icmp
    }
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
        wireBytes: UInt32,
        timestamp: Date = Date()
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
        case 4: return parseIPv4(buffer, at: offset, wireBytes: wireBytes, timestamp: timestamp)
        case 6: return parseIPv6(buffer, at: offset, wireBytes: wireBytes, timestamp: timestamp)
        default: return .failure(.unsupportedIPVersion(version))
        }
    }

    // MARK: IPv4

    private static func parseIPv4(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int,
        wireBytes: UInt32,
        timestamp: Date
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
            let totalLength = uint16BigEndian(buffer, offset + 2),
            let hopLimit = byte(buffer, offset + 8),
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
            wireBytes: wireBytes,
            timestamp: timestamp,
            hopLimit: hopLimit,
            // Zero means the length was left to the hardware — segmentation offload —
            // so there is nothing here to trust and the frame length has to stand in.
            datagramEnd: totalLength == 0 ? nil : offset + Int(totalLength)
        )
    }

    // MARK: IPv6

    private static func parseIPv6(
        _ buffer: UnsafeRawBufferPointer,
        at offset: Int,
        wireBytes: UInt32,
        timestamp: Date
    ) -> Result<ParsedPacket, PacketParseFailure> {
        let fixedHeaderLength = 40
        guard offset + fixedHeaderLength <= buffer.count else {
            return .failure(.truncatedNetworkHeader)
        }
        guard
            let firstNextHeader = byte(buffer, offset + 6),
            let hopLimit = byte(buffer, offset + 7),
            let payloadLength = uint16BigEndian(buffer, offset + 4)
        else {
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
            wireBytes: wireBytes,
            timestamp: timestamp,
            hopLimit: hopLimit,
            // The payload length covers the extension headers too, so it is measured from
            // the end of the fixed header rather than from the transport header. Zero is a
            // jumbogram, whose real length lives in a hop-by-hop option that is not read.
            datagramEnd: payloadLength == 0 ? nil : offset + fixedHeaderLength + Int(payloadLength)
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
        wireBytes: UInt32,
        timestamp: Date,
        hopLimit: UInt8,
        datagramEnd: Int?
    ) -> Result<ParsedPacket, PacketParseFailure> {
        // Where the IP datagram really ends, in the same coordinates as the buffer.
        //
        // Neither obvious alternative works. `buffer.count` is the captured length, which
        // snaplen cuts short on anything near full MTU. `wireBytes` includes the Ethernet
        // padding a runt frame carries, so it overstates a bare ACK by up to fourteen
        // bytes — enough to make a zero-length segment look like data and be counted as a
        // retransmission. The IP header's own length field is the only honest source, and
        // the frame length stands in only when the header declined to give one.
        let datagramLimit = min(datagramEnd ?? Int(wireBytes), Int(wireBytes))

        // Read before the guard below, because ICMP takes the no-ports path out of here
        // and its type is the whole point of noticing it.
        var icmp: ICMPDetail?
        if !skipTransportHeader, transport == .icmp || transport == .icmpv6,
            let type = byte(buffer, transportOffset),
            let code = byte(buffer, transportOffset + 1)
        {
            icmp = ICMPDetail(type: type, code: code)
        }

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
                    payloadCapturedLength: max(0, buffer.count - transportOffset),
                    timestamp: timestamp,
                    transportPayloadLength: max(0, datagramLimit - transportOffset),
                    hopLimit: hopLimit,
                    tcp: nil,
                    icmp: icmp
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
        var tcp: TCPDetail?

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

            // Everything here sits below byte 20, so any packet whose flags were readable
            // has these too; the optional binding is bounds-checking, not a real branch.
            if let sequence = uint32BigEndian(buffer, transportOffset + 4),
                let acknowledgement = uint32BigEndian(buffer, transportOffset + 8),
                let window = uint16BigEndian(buffer, transportOffset + 14)
            {
                let options = tcpOptions(
                    buffer,
                    from: transportOffset + 20,
                    to: min(transportOffset + tcpHeaderLength, buffer.count)
                )
                tcp = TCPDetail(
                    sequence: sequence,
                    acknowledgement: acknowledgement,
                    window: window,
                    timestampValue: options.timestampValue,
                    timestampEcho: options.timestampEcho,
                    sackBlockCount: options.sackBlockCount,
                    maximumSegmentSize: options.maximumSegmentSize,
                    windowScale: options.windowScale
                )
            }

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
                payloadCapturedLength: buffer.count - clampedPayloadOffset,
                timestamp: timestamp,
                // Measured from the true payload offset, not the clamped one: a truncated
                // capture must not be allowed to inflate the segment length.
                transportPayloadLength: max(0, datagramLimit - payloadOffset),
                hopLimit: hopLimit,
                tcp: tcp,
                icmp: nil
            )
        )
    }

    // MARK: TCP options

    /// Walks the TCP option region for the four options worth reading.
    ///
    /// Bounded by construction — the region is at most 40 bytes — but the loop still has
    /// to be written as if the far end were hostile, because it is: a length byte below
    /// two would never advance the cursor, and one pointing past the end would read into
    /// whatever follows. Both stop the walk rather than being repaired, since an option
    /// region that fails to parse tells us nothing we should be guessing about.
    private static func tcpOptions(
        _ buffer: UnsafeRawBufferPointer,
        from start: Int,
        to end: Int
    ) -> (
        timestampValue: UInt32?, timestampEcho: UInt32?, sackBlockCount: UInt8,
        maximumSegmentSize: UInt16?, windowScale: UInt8?
    ) {
        var timestampValue: UInt32?
        var timestampEcho: UInt32?
        var sackBlockCount: UInt8 = 0
        var maximumSegmentSize: UInt16?
        var windowScale: UInt8?

        var cursor = start
        while cursor < end {
            guard let kind = byte(buffer, cursor) else { break }
            if kind == 0 { break }  // end of option list
            if kind == 1 {  // no-op padding, the one kind with no length byte
                cursor += 1
                continue
            }
            guard
                let length = byte(buffer, cursor + 1),
                length >= 2,
                cursor + Int(length) <= end
            else { break }

            switch kind {
            case 2 where length == 4:
                maximumSegmentSize = uint16BigEndian(buffer, cursor + 2)
            case 3 where length == 3:
                windowScale = byte(buffer, cursor + 2)
            case 5:
                sackBlockCount = UInt8((Int(length) - 2) / 8)
            case 8 where length == 10:
                timestampValue = uint32BigEndian(buffer, cursor + 2)
                timestampEcho = uint32BigEndian(buffer, cursor + 6)
            default:
                break
            }
            cursor += Int(length)
        }

        return (timestampValue, timestampEcho, sackBlockCount, maximumSegmentSize, windowScale)
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

    @inline(__always)
    private static func uint32BigEndian(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32?
    {
        guard offset >= 0, offset + 4 <= buffer.count else { return nil }
        return UInt32(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
    }

    /// Reads 4 bytes without byte-swapping — the caller interprets the order.
    @inline(__always)
    private static func uint32Raw(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= buffer.count else { return nil }
        return buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
    }
}
