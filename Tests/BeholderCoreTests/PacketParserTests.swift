import Foundation
import Testing

@testable import BeholderCore

// MARK: - Fixture builders

private enum Fixture {
    static let ethernetIPv4: [UInt8] = [
        0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,  // destination MAC
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5,  // source MAC
        0x08, 0x00,                          // EtherType: IPv4
    ]

    static let ethernetIPv6: [UInt8] = Array(ethernetIPv4.dropLast(2)) + [0x86, 0xDD]

    static let ethernetARP: [UInt8] = Array(ethernetIPv4.dropLast(2)) + [0x08, 0x06]

    /// 802.1Q tag carrying VLAN 100, followed by an IPv4 EtherType.
    static let ethernetVLANIPv4: [UInt8] =
        Array(ethernetIPv4.dropLast(2)) + [0x81, 0x00, 0x00, 0x64, 0x08, 0x00]

    /// DLT_NULL prefixes frames with the address family in host byte order.
    /// This is what `utun` interfaces use — the case that matters most here, since the
    /// default route runs through a VPN tunnel.
    static let nullIPv4: [UInt8] = [0x02, 0x00, 0x00, 0x00]   // AF_INET = 2
    static let nullIPv6: [UInt8] = [0x1E, 0x00, 0x00, 0x00]   // AF_INET6 = 30

    /// DLT_LOOP is the same idea with the family in network byte order.
    static let loopIPv4: [UInt8] = [0x00, 0x00, 0x00, 0x02]

    static func ipv4(
        protocolNumber: UInt8,
        source: [UInt8] = [192, 168, 1, 10],
        destination: [UInt8] = [93, 184, 216, 34],
        fragmentOffset: UInt16 = 0,
        moreFragments: Bool = false
    ) -> [UInt8] {
        let flagsAndFragment = (moreFragments ? UInt16(0x2000) : 0) | (fragmentOffset & 0x1FFF)
        return [
            0x45, 0x00,                    // version 4, IHL 5 words
            0x00, 0x3C,                    // total length
            0x1C, 0x46,                    // identification
            UInt8(flagsAndFragment >> 8), UInt8(truncatingIfNeeded: flagsAndFragment),
            0x40,                          // TTL
            protocolNumber,
            0x00, 0x00,                    // header checksum (not validated)
        ] + source + destination
    }

    static func ipv6(nextHeader: UInt8, payloadLength: UInt16 = 20) -> [UInt8] {
        let source: [UInt8] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]
        let destination: [UInt8] = [
            0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
        ]
        return [
            0x60, 0x00, 0x00, 0x00,        // version 6, traffic class, flow label
            UInt8(payloadLength >> 8), UInt8(truncatingIfNeeded: payloadLength),
            nextHeader,
            0x40,                          // hop limit
        ] + source + destination
    }

    static func tcp(
        sourcePort: UInt16 = 51234,
        destinationPort: UInt16 = 443,
        flags: UInt8 = 0x02
    ) -> [UInt8] {
        [
            UInt8(sourcePort >> 8), UInt8(truncatingIfNeeded: sourcePort),
            UInt8(destinationPort >> 8), UInt8(truncatingIfNeeded: destinationPort),
            0x00, 0x00, 0x00, 0x01,        // sequence number
            0x00, 0x00, 0x00, 0x00,        // acknowledgement number
            0x50,                          // data offset: 5 words
            flags,
            0x72, 0x10,                    // window
            0x00, 0x00,                    // checksum
            0x00, 0x00,                    // urgent pointer
        ]
    }

    static func udp(sourcePort: UInt16 = 55555, destinationPort: UInt16 = 53) -> [UInt8] {
        [
            UInt8(sourcePort >> 8), UInt8(truncatingIfNeeded: sourcePort),
            UInt8(destinationPort >> 8), UInt8(truncatingIfNeeded: destinationPort),
            0x00, 0x14,                    // length
            0x00, 0x00,                    // checksum
        ]
    }

    /// A hop-by-hop options header of the minimum 8-byte size.
    static func ipv6Extension(nextHeader: UInt8) -> [UInt8] {
        [nextHeader, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]
    }
}

private func parse(
    _ bytes: [UInt8],
    linkLayer: LinkLayer,
    wireBytes: UInt32? = nil
) -> Result<ParsedPacket, PacketParseFailure> {
    bytes.withUnsafeBytes { buffer in
        PacketParser.parse(
            buffer,
            linkLayer: linkLayer,
            wireBytes: wireBytes ?? UInt32(bytes.count)
        )
    }
}

private func expectSuccess(
    _ result: Result<ParsedPacket, PacketParseFailure>,
    _ comment: Comment? = nil
) -> ParsedPacket? {
    switch result {
    case .success(let packet):
        return packet
    case .failure(let failure):
        Issue.record("expected a parsed packet, got failure \(failure). \(comment?.description ?? "")")
        return nil
    }
}

// MARK: - Tests

@Suite("Packet parsing")
struct PacketParserTests {

    @Test("Ethernet IPv4 TCP")
    func ethernetIPv4TCP() throws {
        let bytes = Fixture.ethernetIPv4 + Fixture.ipv4(protocolNumber: 6) + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.transport == .tcp)
        #expect(packet.source.description == "192.168.1.10")
        #expect(packet.destination.description == "93.184.216.34")
        #expect(packet.sourcePort == 51234)
        #expect(packet.destinationPort == 443)
        #expect(packet.tcpFlags.contains(.syn))
        #expect(packet.tcpFlags.isConnectionOpen)
        #expect(!packet.isFragment)
    }

    /// The case that decides whether Beholder works at all on this machine: the default
    /// route is a `utun` interface, which is DLT_NULL, not Ethernet.
    @Test("DLT_NULL IPv4 UDP — the VPN tunnel case")
    func nullIPv4UDP() throws {
        let bytes = Fixture.nullIPv4 + Fixture.ipv4(protocolNumber: 17) + Fixture.udp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .null)))

        #expect(packet.transport == .udp)
        #expect(packet.sourcePort == 55555)
        #expect(packet.destinationPort == 53)
    }

    @Test("DLT_NULL IPv6")
    func nullIPv6() throws {
        let bytes = Fixture.nullIPv6 + Fixture.ipv6(nextHeader: 6) + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .null)))

        #expect(packet.transport == .tcp)
        #expect(packet.source.family == .v6)
    }

    @Test("DLT_LOOP uses network byte order for the family")
    func loopByteOrder() throws {
        let bytes = Fixture.loopIPv4 + Fixture.ipv4(protocolNumber: 6) + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .loop)))
        #expect(packet.transport == .tcp)
    }

    @Test("Ethernet IPv6 TCP")
    func ethernetIPv6TCP() throws {
        let bytes = Fixture.ethernetIPv6 + Fixture.ipv6(nextHeader: 6) + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.transport == .tcp)
        #expect(packet.source.description == "2001:db8::1")
        #expect(packet.destination.description == "2606:2800::42")
        #expect(packet.destinationPort == 443)
    }

    @Test("IPv6 extension headers are walked to reach the transport header")
    func ipv6ExtensionHeaders() throws {
        let bytes = Fixture.ethernetIPv6
            + Fixture.ipv6(nextHeader: 0)              // hop-by-hop follows
            + Fixture.ipv6Extension(nextHeader: 6)     // ...which points at TCP
            + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.transport == .tcp)
        #expect(packet.destinationPort == 443)
    }

    @Test("VLAN-tagged frames are unwrapped")
    func vlanTagged() throws {
        let bytes = Fixture.ethernetVLANIPv4 + Fixture.ipv4(protocolNumber: 6) + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))
        #expect(packet.destinationPort == 443)
    }

    @Test("Non-IP frames are reported as such, not misparsed")
    func arpIsNotIP() {
        let bytes = Fixture.ethernetARP + [UInt8](repeating: 0, count: 28)
        #expect(parse(bytes, linkLayer: .ethernet) == .failure(.notIP))
    }

    @Test("A frame shorter than its link-layer header is rejected")
    func truncatedLinkLayer() {
        #expect(parse([0x00, 0x1a, 0x2b], linkLayer: .ethernet) == .failure(.truncatedLinkLayer))
        #expect(parse([0x02, 0x00], linkLayer: .null) == .failure(.truncatedLinkLayer))
    }

    @Test("A truncated IP header is rejected rather than read past")
    func truncatedNetworkHeader() {
        let bytes = Fixture.ethernetIPv4 + Array(Fixture.ipv4(protocolNumber: 6).prefix(12))
        #expect(parse(bytes, linkLayer: .ethernet) == .failure(.truncatedNetworkHeader))
    }

    /// A later fragment carries real bytes but no transport header. It must still be
    /// counted — silently dropping it would understate the machine's traffic.
    @Test("Non-initial fragments are counted with no ports")
    func nonInitialFragment() throws {
        let bytes = Fixture.ethernetIPv4
            + Fixture.ipv4(protocolNumber: 6, fragmentOffset: 185)
            + Fixture.tcp()
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.isFragment)
        #expect(packet.sourcePort == 0)
        #expect(packet.destinationPort == 0)
        #expect(packet.transport == .tcp)
    }

    @Test("ICMP is preserved rather than discarded")
    func icmpIsKept() throws {
        let bytes = Fixture.ethernetIPv4 + Fixture.ipv4(protocolNumber: 1) + [0x08, 0x00, 0x00, 0x00]
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.transport == .icmp)
        #expect(packet.sourcePort == 0)
    }

    /// Guards the single easiest bug to ship: byte accounting must use the wire length
    /// from pcap's header, not the captured length, or every packet larger than the
    /// snaplen is undercounted.
    @Test("Wire byte count is taken from the caller, not the captured buffer")
    func wireBytesAreNotCaptureLength() throws {
        let bytes = Fixture.ethernetIPv4 + Fixture.ipv4(protocolNumber: 6) + Fixture.tcp()
        let packet = try #require(
            expectSuccess(parse(bytes, linkLayer: .ethernet, wireBytes: 1514))
        )

        #expect(packet.wireBytes == 1514)
        #expect(packet.wireBytes != UInt32(bytes.count))
    }
}

@Suite("IP addresses")
struct IPAddressTests {

    @Test("IPv4 round-trips through bytes and text")
    func ipv4RoundTrip() throws {
        let address = try #require(IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4))
        #expect(address.description == "93.184.216.34")
        #expect(address.networkOrderBytes == [93, 184, 216, 34])
    }

    @Test("IPv6 round-trips through bytes and text")
    func ipv6RoundTrip() throws {
        let bytes: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        let address = try #require(IPAddress(networkOrderBytes: bytes, family: .v6))
        #expect(address.description == "2001:db8::1")
        #expect(address.networkOrderBytes == bytes)
    }

    @Test("Addresses of different families never compare equal")
    func familiesAreDistinct() throws {
        let v4 = try #require(IPAddress(networkOrderBytes: [0, 0, 0, 1], family: .v4))
        let v6 = try #require(
            IPAddress(networkOrderBytes: [UInt8](repeating: 0, count: 15) + [1], family: .v6)
        )
        #expect(v4 != v6)
    }

    @Test(
        "Address scope is classified correctly",
        arguments: [
            ([10, 0, 0, 5] as [UInt8], false, "private 10/8"),
            ([172, 16, 0, 1], false, "private 172.16/12"),
            ([172, 32, 0, 1], true, "172.32 is public, just outside 172.16/12"),
            ([192, 168, 1, 1], false, "private 192.168/16"),
            ([127, 0, 0, 1], false, "loopback"),
            ([169, 254, 1, 1], false, "link-local"),
            ([224, 0, 0, 251], false, "multicast"),
            // RFC 6598 shared address space: carrier NAT, and this machine's VPN resolver.
            ([100, 64, 0, 2], false, "CGNAT 100.64/10"),
            ([100, 127, 255, 255], false, "CGNAT upper bound"),
            ([100, 128, 0, 1], true, "100.128 is public, just outside 100.64/10"),
            ([100, 63, 255, 255], true, "100.63 is public, just below 100.64/10"),
            ([93, 184, 216, 34], true, "public"),
            ([8, 8, 8, 8], true, "public"),
        ]
    )
    func addressScope(bytes: [UInt8], expectedGlobal: Bool, note: String) throws {
        let address = try #require(IPAddress(networkOrderBytes: bytes, family: .v4))
        #expect(address.isGloballyRoutable == expectedGlobal, "\(note): \(address)")
    }

    @Test("IPv6 scope is classified correctly")
    func ipv6Scope() throws {
        func address(_ bytes: [UInt8]) throws -> IPAddress {
            try #require(
                IPAddress(
                    networkOrderBytes: bytes + [UInt8](repeating: 0, count: 16 - bytes.count),
                    family: .v6
                )
            )
        }
        #expect(try address([0xfe, 0x80]).isLinkLocal)
        #expect(try address([0xfd, 0x00]).isPrivate)
        #expect(try address([0xff, 0x02]).isMulticast)
        #expect(try address([0x20, 0x01, 0x0d, 0xb8]).isGloballyRoutable)

        let loopback = try #require(
            IPAddress(
                networkOrderBytes: [UInt8](repeating: 0, count: 15) + [1], family: .v6
            )
        )
        #expect(loopback.isLoopback)
    }
}

// MARK: - Measurement fixtures

/// Headers whose length fields agree with what actually follows them, which the older
/// fixtures above do not need to and deliberately do not.
private enum Measured {
    static func ipv4(protocolNumber: UInt8, payloadBytes: Int, ttl: UInt8 = 64) -> [UInt8] {
        let total = UInt16(20 + payloadBytes)
        return [
            0x45, 0x00,
            UInt8(total >> 8), UInt8(truncatingIfNeeded: total),
            0x1C, 0x46,
            0x00, 0x00,
            ttl,
            protocolNumber,
            0x00, 0x00,
        ] + [192, 168, 1, 10] + [93, 184, 216, 34]
    }

    static func ipv6(nextHeader: UInt8, payloadBytes: Int, hopLimit: UInt8 = 57) -> [UInt8] {
        let length = UInt16(payloadBytes)
        return [
            0x60, 0x00, 0x00, 0x00,
            UInt8(length >> 8), UInt8(truncatingIfNeeded: length),
            nextHeader,
            hopLimit,
        ]
            + [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
            + [0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42]
    }

    static func tcp(
        sequence: UInt32 = 1000,
        acknowledgement: UInt32 = 2000,
        window: UInt16 = 65535,
        flags: UInt8 = 0x10,
        options: [UInt8] = []
    ) -> [UInt8] {
        // The data offset counts whole words, so options are padded out with no-ops.
        var padded = options
        while padded.count % 4 != 0 { padded.append(0x01) }
        let headerWords = UInt8((20 + padded.count) / 4)
        func be32(_ value: UInt32) -> [UInt8] {
            [
                UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
                UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value),
            ]
        }
        return [0xC8, 0x22, 0x01, 0xBB]
            + be32(sequence) + be32(acknowledgement)
            + [
                headerWords << 4,
                flags,
                UInt8(window >> 8), UInt8(truncatingIfNeeded: window),
                0x00, 0x00,
                0x00, 0x00,
            ] + padded
    }

    static func timestampOption(value: UInt32, echo: UInt32) -> [UInt8] {
        func be32(_ v: UInt32) -> [UInt8] {
            [
                UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16),
                UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v),
            ]
        }
        return [8, 10] + be32(value) + be32(echo)
    }

    static func sackOption(blocks: Int) -> [UInt8] {
        [5, UInt8(2 + blocks * 8)] + Array(repeating: 0, count: blocks * 8)
    }

    static func mssOption(_ size: UInt16) -> [UInt8] {
        [2, 4, UInt8(size >> 8), UInt8(truncatingIfNeeded: size)]
    }

    static func windowScaleOption(_ shift: UInt8) -> [UInt8] { [3, 3, shift] }
}

@Suite("Packet facts for measurement")
struct PacketMeasurementTests {

    @Test("The capture timestamp is carried through untouched")
    func timestampSurvives() throws {
        let moment = Date(timeIntervalSince1970: 1_700_000_000.123456)
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 20)
            + Measured.tcp()
        let packet = try #require(
            expectSuccess(
                bytes.withUnsafeBytes {
                    PacketParser.parse(
                        $0, linkLayer: .ethernet, wireBytes: UInt32(bytes.count),
                        timestamp: moment
                    )
                }
            )
        )
        #expect(packet.timestamp == moment)
    }

    @Test("Sequence, acknowledgement and window are read")
    func tcpScalars() throws {
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 20)
            + Measured.tcp(sequence: 0xDEAD_BEEF, acknowledgement: 0x0BAD_F00D, window: 501)
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp?.sequence == 0xDEAD_BEEF)
        #expect(packet.tcp?.acknowledgement == 0x0BAD_F00D)
        #expect(packet.tcp?.window == 501)
        #expect(packet.hopLimit == 64)
    }

    /// The measurement this whole layer rests on. An Ethernet frame shorter than 60 bytes
    /// is padded, so a bare ACK arrives with six bytes of nothing attached. Counting the
    /// frame length would read those as data, and a zero-length segment counted as data is
    /// then indistinguishable from a retransmission of ground already covered.
    @Test("Ethernet padding does not turn a bare ACK into a data segment")
    func paddingIsNotPayload() throws {
        var bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 20)
            + Measured.tcp(flags: 0x10)
        #expect(bytes.count == 54)
        bytes += Array(repeating: 0, count: 6)  // the NIC's padding to the 60-byte minimum

        let packet = try #require(
            expectSuccess(parse(bytes, linkLayer: .ethernet, wireBytes: 60))
        )
        #expect(packet.transportPayloadLength == 0)
    }

    @Test("Segment length comes from the IP header, not from what was captured")
    func segmentLengthFromHeader() throws {
        let payload = Array(repeating: UInt8(0x41), count: 100)
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 120)
            + Measured.tcp() + payload
        // Captured short, as every full-MTU packet is at Beholder's snaplen.
        let truncated = Array(bytes.prefix(60))
        let packet = try #require(
            expectSuccess(parse(truncated, linkLayer: .ethernet, wireBytes: UInt32(bytes.count)))
        )
        #expect(packet.transportPayloadLength == 100)
        #expect(packet.payloadCapturedLength < 100)
    }

    @Test("IPv6 segment length comes from the payload length field")
    func ipv6SegmentLength() throws {
        let payload = Array(repeating: UInt8(0x42), count: 10)
        let bytes =
            Fixture.ethernetIPv6 + Measured.ipv6(nextHeader: 6, payloadBytes: 30)
            + Measured.tcp() + payload
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.transportPayloadLength == 10)
        #expect(packet.hopLimit == 57)
    }

    @Test("The timestamp option is read from both directions of the echo")
    func timestampOption() throws {
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 32)
            + Measured.tcp(options: Measured.timestampOption(value: 111_222, echo: 333_444))
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp?.timestampValue == 111_222)
        #expect(packet.tcp?.timestampEcho == 333_444)
    }

    @Test("Selective-acknowledgement blocks are counted")
    func sackBlocks() throws {
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 40)
            + Measured.tcp(options: Measured.sackOption(blocks: 2))
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp?.sackBlockCount == 2)
    }

    @Test("Maximum segment size and window scale are read from a SYN")
    func synOptions() throws {
        let options = Measured.mssOption(1460) + Measured.windowScaleOption(7)
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 28)
            + Measured.tcp(flags: 0x02, options: options)
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp?.maximumSegmentSize == 1460)
        #expect(packet.tcp?.windowScale == 7)
    }

    @Test("An unknown option is stepped over rather than stopping the walk")
    func unknownOptionIsSkipped() throws {
        let options = [UInt8(99), 4, 0, 0] + Measured.timestampOption(value: 7, echo: 8)
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 36)
            + Measured.tcp(options: options)
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp?.timestampValue == 7)
    }

    /// A length byte below two would leave the cursor where it was. The walk has to stop
    /// rather than spin, because the bytes come from whoever is on the far end.
    @Test("An option claiming an impossible length stops the walk instead of looping")
    func impossibleOptionLength() throws {
        let options: [UInt8] = [8, 0, 0, 0]  // kind 8, length 0
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 24)
            + Measured.tcp(options: options)
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp != nil)
        #expect(packet.tcp?.timestampValue == nil)
    }

    @Test("An option running past the header is refused, not read")
    func overlongOptionIsRefused() throws {
        let options: [UInt8] = [5, 40, 1, 1]  // SACK claiming 40 bytes inside 4
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 6, payloadBytes: 24)
            + Measured.tcp(options: options)
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp?.sackBlockCount == 0)
    }

    /// A fragmentation-needed unreachable is a path MTU black hole, which looks to the
    /// user like a connection that opens and then dies. Worth being able to name.
    @Test("ICMP type and code are read despite the protocol having no ports")
    func icmpDetail() throws {
        let icmp: [UInt8] = [3, 4, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC]
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 1, payloadBytes: 8) + icmp
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.transport == .icmp)
        #expect(packet.icmp?.type == 3)
        #expect(packet.icmp?.code == 4)
        #expect(packet.tcp == nil)
    }

    @Test("A UDP packet has no TCP detail")
    func udpHasNoTCPDetail() throws {
        let bytes =
            Fixture.ethernetIPv4 + Measured.ipv4(protocolNumber: 17, payloadBytes: 28)
            + Fixture.udp() + Array(repeating: UInt8(0), count: 20)
        let packet = try #require(expectSuccess(parse(bytes, linkLayer: .ethernet)))

        #expect(packet.tcp == nil)
        #expect(packet.transportPayloadLength == 20)
    }
}
