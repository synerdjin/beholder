import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!
private let server = IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!
private let localAddresses: Set<IPAddress> = [laptop]

private func packet(
    transport: TransportProtocol = .tcp,
    localPort: UInt16 = 51234,
    remotePort: UInt16
) -> ParsedPacket {
    ParsedPacket(
        transport: transport,
        source: laptop,
        destination: server,
        sourcePort: localPort,
        destinationPort: remotePort,
        tcpFlags: [],
        wireBytes: 1000,
        isFragment: false,
        payloadOffset: 0,
        payloadCapturedLength: 0
    )
}

private func read(
    _ bytes: [UInt8],
    transport: TransportProtocol = .tcp,
    remotePort: UInt16 = 51999
) -> ProtocolSniffer.Reading? {
    bytes.withUnsafeBytes { buffer in
        ProtocolSniffer.read(
            packet: packet(transport: transport, remotePort: remotePort),
            payload: buffer
        ).reading
    }
}

private func ascii(_ text: String) -> [UInt8] { Array(text.utf8) }

/// A minimal DNS response for `example.com` → 93.184.216.34, enough for the real parser.
private let dnsResponseBytes: [UInt8] = {
    var bytes: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
    bytes += [7] + ascii("example") + [3] + ascii("com") + [0]
    bytes += [0x00, 0x01, 0x00, 0x01]  // QTYPE A, QCLASS IN
    bytes += [0xC0, 0x0C]  // pointer back to the question name
    bytes += [0x00, 0x01, 0x00, 0x01]  // type A, class IN
    bytes += [0x00, 0x00, 0x01, 0x2C]  // TTL
    bytes += [0x00, 0x04, 93, 184, 216, 34]
    return bytes
}()

@Suite("Identifying what a connection is speaking")
struct ProtocolSnifferTests {

    // MARK: - Read from the bytes

    @Test("A TLS record header is read as encrypted, from the bytes")
    func tlsFromPayload() throws {
        // A handshake record on a port that means nothing, so only the bytes can be
        // responsible for the answer.
        let reading = try #require(read([0x16, 0x03, 0x01, 0x02, 0x00], remotePort: 51999))
        #expect(reading.security == .encrypted)
        #expect(reading.protocolName == "TLS")
        #expect(reading.evidence == .payload)
    }

    @Test("Mid-stream TLS application data still identifies the connection")
    func tlsApplicationData() throws {
        // Capture routinely starts after a handshake is over, so recognising only 0x16
        // would leave every long-lived connection permanently unidentified.
        let reading = try #require(read([0x17, 0x03, 0x03, 0x01, 0x00]))
        #expect(reading.security == .encrypted)
        #expect(reading.protocolName == "TLS")
    }

    @Test("An HTTP request line is read as cleartext, from the bytes")
    func httpFromPayload() throws {
        let reading = try #require(read(ascii("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")))
        #expect(reading.security == .cleartext)
        #expect(reading.protocolName == "HTTP")
        #expect(reading.evidence == .payload)
    }

    @Test("An HTTP response is recognised as well as a request")
    func httpResponse() throws {
        let reading = try #require(read(ascii("HTTP/1.1 200 OK\r\n")))
        #expect(reading.protocolName == "HTTP")
        #expect(reading.security == .cleartext)
    }

    @Test("An SSH banner is read as encrypted")
    func sshBanner() throws {
        let reading = try #require(read(ascii("SSH-2.0-OpenSSH_9.6\r\n"), remotePort: 2222))
        #expect(reading.security == .encrypted)
        #expect(reading.protocolName == "SSH")
        #expect(reading.evidence == .payload)
    }

    @Test("A mail greeting is cleartext, and the port supplies only the name")
    func smtpGreeting() throws {
        let reading = try #require(read(ascii("220 mail.example.com ESMTP\r\n"), remotePort: 25))
        #expect(reading.security == .cleartext)
        #expect(reading.protocolName == "SMTP")
        #expect(reading.evidence == .payload)
    }

    @Test("A DNS response on port 53 is read as cleartext")
    func dnsResponse() throws {
        let reading = try #require(read(dnsResponseBytes, transport: .udp, remotePort: 53))
        #expect(reading.security == .cleartext)
        #expect(reading.protocolName == "DNS")
        #expect(reading.evidence == .payload)
    }

    /// Recognising a packet as DNS *is* parsing it, and that parse is not cheap — it walks
    /// the question section and every answer record, follows compression pointers, and
    /// allocates a hostname. Handing the answer back is what keeps `PayloadInspector` from
    /// doing the identical work a second time on the same buffer, inside the capture
    /// callback. An earlier version parsed every DNS response on the machine twice.
    @Test("Identifying a packet as DNS hands back the answer it had to parse anyway")
    func dnsAnswerRidesAlong() throws {
        let findings = dnsResponseBytes.withUnsafeBytes { buffer in
            ProtocolSniffer.read(
                packet: packet(transport: .udp, remotePort: 53),
                payload: buffer
            )
        }
        let answer = try #require(findings.dnsAnswer)
        #expect(answer.name == "example.com")
        #expect(answer.addresses.count == 1)
    }

    @Test("A packet that is not DNS carries no answer")
    func noAnswerForNonDNS() {
        let findings = [UInt8]("GET / HTTP/1.1\r\n".utf8).withUnsafeBytes { buffer in
            ProtocolSniffer.read(packet: packet(remotePort: 80), payload: buffer)
        }
        #expect(findings.dnsAnswer == nil)
        #expect(findings.reading?.protocolName == "HTTP")
    }

    /// A DNS transaction ID is random, so its first byte sets both top bits about a
    /// quarter of the time — which is exactly the QUIC long-header pattern. Checking QUIC
    /// before settling the DNS port would report a steady trickle of ordinary lookups as
    /// encrypted QUIC, which is the reassuring direction to be wrong in.
    @Test("A DNS query with a QUIC-shaped transaction ID is not called QUIC")
    func dnsQueryIsNotMistakenForQUIC() throws {
        var query: [UInt8] = [0xC5, 0xA3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        query += [7] + ascii("example") + [3] + ascii("com") + [0]
        query += [0x00, 0x01, 0x00, 0x01]

        let reading = try #require(read(query, transport: .udp, remotePort: 53))
        #expect(reading.protocolName != "QUIC")
        #expect(reading.security == .cleartext, "port 53 carries plain DNS")
    }

    @Test("A QUIC long header on an ordinary port is read as encrypted")
    func quicLongHeader() throws {
        let reading = try #require(
            read([0xC3, 0x00, 0x00, 0x00, 0x01, 0x08], transport: .udp, remotePort: 443)
        )
        #expect(reading.security == .encrypted)
        #expect(reading.protocolName == "QUIC")
        #expect(reading.evidence == .payload)
    }

    // MARK: - The honesty rule

    /// The regression this whole design exists around. Bytes that match nothing look
    /// exactly like ciphertext, and calling them encrypted would tell the user something
    /// that was never observed — in the direction that reassures.
    @Test("Unrecognised high-entropy bytes are unknown, never encrypted")
    func unknownIsNotEncrypted() throws {
        // WireGuard on its usual port: genuinely encrypted, but nothing here can prove it.
        let noise: [UInt8] = [0x04, 0x9F, 0x2B, 0xE1, 0x77, 0x30, 0xCC, 0x1A, 0x5D, 0x88]
        let reading = try #require(read(noise, transport: .udp, remotePort: 51820))
        #expect(reading.security == .unknown)
        #expect(reading.protocolName == nil)
        #expect(reading.evidence == .port)
    }

    @Test("A truncated TLS record is unknown rather than a crash or a guess")
    func truncatedTLSRecord() throws {
        // One byte: the content type is there and nothing else. Claiming TLS from that
        // would match any binary payload whose first byte happens to be 0x16.
        let reading = try #require(read([0x16], remotePort: 51999))
        #expect(reading.security == .unknown)
    }

    @Test("An empty payload falls back to the port rather than failing")
    func emptyPayload() throws {
        // Pure ACKs carry nothing, and there are a great many of them; a connection must
        // not lose its classification because one arrived.
        let reading = try #require(read([], remotePort: 80))
        #expect(reading.security == .cleartext)
        #expect(reading.evidence == .port)
    }

    @Test("A protocol with no ports has no connection to characterise")
    func icmpHasNoReading() {
        let reading = read([0x08, 0x00], transport: .icmp, remotePort: 0)
        #expect(reading == nil)
    }

    // MARK: - Ports

    @Test("Port 443 with nothing readable is encrypted, but only by inference")
    func port443IsAGuess() throws {
        let reading = try #require(read([0x00, 0x01, 0x02, 0x03], remotePort: 443))
        #expect(reading.security == .encrypted)
        #expect(reading.evidence == .port)
        #expect(reading.isProof == false)
        #expect(reading.protocolName == nil, "the port names no protocol")
    }

    @Test("A database port defaults to cleartext, since its default configuration is")
    func databasePort() throws {
        let reading = try #require(read([0x00, 0x00], remotePort: 5432))
        #expect(reading.security == .cleartext)
        #expect(reading.evidence == .port)
    }

    /// The service port is the lower of the pair. It has to be decided without knowing
    /// which end is local, because this runs before the flow key is normalised.
    @Test("The service port is found whichever end it is on")
    func servicePortFromEitherEnd() throws {
        let inbound = ParsedPacket(
            transport: .tcp, source: server, destination: laptop,
            sourcePort: 80, destinationPort: 51234, tcpFlags: [],
            wireBytes: 100, isFragment: false, payloadOffset: 0, payloadCapturedLength: 0
        )
        let bytes: [UInt8] = [0x00]
        let reading = try #require(
            bytes.withUnsafeBytes { ProtocolSniffer.read(packet: inbound, payload: $0).reading }
        )
        #expect(reading.security == .cleartext)
    }
}

@Suite("How a security reading is allowed to change")
struct SecurityLadderTests {

    private func table(withHTTPOn key: FlowKey) -> FlowTable {
        let table = FlowTable()
        let first = ParsedPacket(
            transport: .tcp, source: laptop, destination: server,
            sourcePort: key.localPort, destinationPort: key.remotePort, tcpFlags: [],
            wireBytes: 100, isFragment: false, payloadOffset: 0, payloadCapturedLength: 0
        )
        table.record(first, interfaceName: "en0", localAddresses: localAddresses)
        return table
    }

    private func key(remotePort: UInt16) -> FlowKey {
        FlowKey(
            transport: .tcp, local: laptop, localPort: 51234,
            remote: server, remotePort: remotePort
        )
    }

    /// Every packet after the first of an HTTP conversation looks like nothing in
    /// particular. Without the ladder, the reading taken from the request line would be
    /// replaced a millisecond later by a port guess, and the display would flicker between
    /// "this is HTTP" and "no idea" for the life of the connection.
    @Test("A port guess cannot overwrite something read from the bytes")
    func portDoesNotOverwritePayload() throws {
        let flowKey = key(remotePort: 8080)
        let table = self.table(withHTTPOn: flowKey)

        table.applyReading(
            .init(security: .cleartext, protocolName: "HTTP", evidence: .payload),
            for: flowKey
        )
        table.applyReading(
            .init(security: .unknown, protocolName: nil, evidence: .port),
            for: flowKey
        )

        let flow = try #require(table.activeFlows().first)
        #expect(flow.security?.protocolName == "HTTP")
        #expect(flow.security?.evidence == .payload)
    }

    /// Once bytes have gone past in the clear, they went past in the clear. A STARTTLS
    /// session therefore stays reported as cleartext — and, as a side effect, a few bytes
    /// of binary in an HTTP body that happen to open like a TLS record cannot flip the
    /// connection to "encrypted" and reassure the user about traffic already read.
    @Test("Proven cleartext is not undone by a later encrypted reading")
    func cleartextIsSticky() throws {
        let flowKey = key(remotePort: 25)
        let table = self.table(withHTTPOn: flowKey)

        table.applyReading(
            .init(security: .cleartext, protocolName: "SMTP", evidence: .payload),
            for: flowKey
        )
        table.applyReading(
            .init(security: .encrypted, protocolName: "TLS", evidence: .payload),
            for: flowKey
        )

        let flow = try #require(table.activeFlows().first)
        #expect(flow.security?.security == .cleartext)
    }

    @Test("A payload reading replaces an earlier port guess")
    func payloadUpgradesPort() throws {
        let flowKey = key(remotePort: 443)
        let table = self.table(withHTTPOn: flowKey)

        table.applyReading(
            .init(security: .encrypted, protocolName: nil, evidence: .port),
            for: flowKey
        )
        // Plaintext HTTP on 443: the exact case that makes reading payload worth doing,
        // and the one a port-only classifier reports as safe.
        table.applyReading(
            .init(security: .cleartext, protocolName: "HTTP", evidence: .payload),
            for: flowKey
        )

        let flow = try #require(table.activeFlows().first)
        #expect(flow.security?.security == .cleartext)
        #expect(flow.security?.protocolName == "HTTP")
    }

    @Test("A reading for a flow that does not exist is ignored rather than creating one")
    func unknownKeyIsIgnored() {
        let table = FlowTable()
        table.applyReading(
            .init(security: .cleartext, protocolName: "HTTP", evidence: .payload),
            for: key(remotePort: 80)
        )
        #expect(table.count == 0)
    }
}
