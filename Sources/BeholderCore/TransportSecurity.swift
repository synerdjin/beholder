import Foundation

/// Whether a conversation's contents are protected from anyone on the path.
///
/// The three cases are deliberately asymmetric in how much they claim:
///
/// - `cleartext` is **proof**. Something in the bytes was read and understood — an HTTP
///   request line, a DNS question, an SMTP greeting. If it can be parsed here it can be
///   parsed by anyone else carrying the packet.
/// - `encrypted` is an **inference**. A TLS record header or an SSH banner says a
///   handshake happened, not that it succeeded or that the peer was verified.
/// - `unknown` is the honest answer for everything else.
///
/// The asymmetry is the whole point. Bytes that match nothing look exactly like ciphertext
/// and it is tempting to call them encrypted, but "I could not parse this" is not evidence
/// of protection — it is the absence of evidence either way. A tool that reports
/// `encrypted` for an unrecognised binary protocol has told its user something it never
/// observed, and told it in the reassuring direction, which is the worst way to be wrong.
public enum TransportSecurity: String, Codable, Sendable, Hashable, CaseIterable {
    /// Nothing recognisable was read. Not a claim that the traffic is unprotected, and
    /// emphatically not a claim that it is protected.
    case unknown
    /// A plaintext application protocol was read out of the payload, or the port is one
    /// that carries a protocol with no transport security at all.
    case cleartext
    /// A transport-security handshake was observed, or the port is one that carries it.
    case encrypted
}

/// Identifies the application protocol on a connection, and therefore whether it protects
/// what it carries.
///
/// Runs on the capture queue inside the pcap callback, under the same lifetime contract as
/// `PayloadInspector`: the buffer dies when the callback returns, so every check reads
/// bytes and returns owned values, and none of it defers work.
public enum ProtocolSniffer {
    /// What a reading rests on, weakest first.
    ///
    /// Ordered for the same reason `NameSource` is: a later, weaker observation must not
    /// overwrite a stronger earlier one. Every packet of an HTTP conversation after the
    /// first looks like nothing in particular, and without this ladder the `.payload`
    /// reading from the request line would be replaced by a `.port` guess a millisecond
    /// later — or worse, by `unknown`.
    public enum Evidence: Sendable, Hashable, Comparable, CaseIterable {
        /// The port number is one conventionally used by a known protocol. A guess:
        /// anything can listen anywhere, and on a developer's machine frequently does.
        case port
        /// A protocol marker was read out of the bytes themselves. Proof of what the
        /// connection is speaking.
        case payload

        private var rank: Int {
            switch self {
            case .port: return 0
            case .payload: return 1
            }
        }

        public static func < (lhs: Evidence, rhs: Evidence) -> Bool {
            lhs.rank < rhs.rank
        }
    }

    public struct Reading: Sendable, Hashable {
        public let security: TransportSecurity
        /// The protocol's common name — "HTTP", "TLS", "SSH", "DNS". Nil when the security
        /// is known from the port but the protocol itself was never confirmed.
        public let protocolName: String?
        public let evidence: Evidence

        public init(security: TransportSecurity, protocolName: String?, evidence: Evidence) {
            self.security = security
            self.protocolName = protocolName
            self.evidence = evidence
        }

        /// True when this rests on bytes that were actually read.
        public var isProof: Bool { evidence == .payload }
    }

    /// Everything one pass over a payload established.
    ///
    /// The DNS answer rides along because identifying a packet as DNS *is* parsing it, and
    /// the parse is not cheap — it walks the question section and every answer record,
    /// following compression pointers and allocating a hostname. Returning it means
    /// `PayloadInspector` never parses the same response a second time to learn the name.
    public struct Findings: Sendable {
        public var reading: Reading?
        public var dnsAnswer: DNSMessage.Answer?
    }

    /// Reads a packet's payload, falling back to its ports.
    ///
    /// `reading` is nil only for protocols with no ports at all (ICMP and friends), where
    /// there is no connection to characterise.
    public static func read(
        packet: ParsedPacket,
        payload: UnsafeRawBufferPointer
    ) -> Findings {
        guard packet.transport.hasPorts else { return Findings() }

        var findings = readPayload(packet: packet, payload: payload)
        if findings.reading == nil {
            findings.reading = readPorts(packet: packet)
        }
        return findings
    }

    /// Ports carrying DNS. Shared with `PayloadInspector`, which decides whether to look
    /// for a name in the same packet — two copies of this list would let classification
    /// and naming silently disagree about what counts as DNS.
    public static let dnsPorts: Set<UInt16> = [53, 5353]

    // MARK: - Payload signatures

    /// Checks the byte signatures, cheapest and most common first.
    ///
    /// Order matters for cost, not correctness: TLS is the overwhelming majority of a real
    /// machine's traffic and its check is three byte comparisons, so putting it first means
    /// almost every packet leaves this function having touched three bytes. `FlowMonitor`
    /// relies on that — it uses a `.payload`-backed `encrypted` reading as the gate that
    /// keeps payload copying off the hot path.
    ///
    /// Note the limit of that claim: a TLS record can be 16 KB while a segment is ~1.4 KB,
    /// so most segments of a bulk transfer are record *continuations* and match nothing
    /// here. Every prefix below is therefore a `static let` byte array rather than a
    /// `String` converted per call — those packets walk the whole list, and at line rate
    /// that was thousands of transient allocations a second on the capture queue.
    static func readPayload(
        packet: ParsedPacket,
        payload: UnsafeRawBufferPointer
    ) -> Findings {
        var findings = Findings()
        guard !payload.isEmpty else { return findings }

        func proven(_ security: TransportSecurity, _ name: String) -> Findings {
            var result = findings
            result.reading = Reading(security: security, protocolName: name, evidence: .payload)
            return result
        }

        if packet.transport == .tcp {
            if isTLSRecord(payload) { return proven(.encrypted, "TLS") }
            if sshPrefixes.contains(where: { starts(payload, with: $0) }) {
                return proven(.encrypted, "SSH")
            }
            if httpPrefixes.contains(where: { starts(payload, with: $0) }) {
                return proven(.cleartext, "HTTP")
            }
            if let name = textualGreeting(payload, packet: packet) {
                return proven(.cleartext, name)
            }
            return findings
        }

        // UDP. DNS is settled first, and by port rather than by signature, because a DNS
        // transaction ID is random: its top two bits are set about a quarter of the time,
        // which is exactly the QUIC long-header pattern. Checking QUIC first would have
        // reported a steady trickle of ordinary lookups as encrypted QUIC — the reassuring
        // direction to be wrong in, and therefore the one worth designing out.
        if dnsPorts.contains(packet.sourcePort) || dnsPorts.contains(packet.destinationPort) {
            // Only a response parses. A query falls through to the port conventions, which
            // reach the same conclusion by a weaker route.
            guard let answer = DNSMessage.parseResponse(payload) else { return findings }
            findings.dnsAnswer = answer
            return proven(.cleartext, "DNS")
        }
        if isQUICLongHeader(payload) { return proven(.encrypted, "QUIC") }
        if isDTLS(payload) { return proven(.encrypted, "DTLS") }
        return findings
    }

    /// A TLS record header: one of the four content types, then a two-byte version whose
    /// major is 3.
    ///
    /// Both the handshake and the application-data types are accepted, because capture
    /// frequently starts in the middle of a connection and the handshake is long gone. The
    /// version check is what keeps this from matching arbitrary binary data that happens
    /// to open with 0x16 — TLS 1.3 still writes a legacy 0x0301/0x0303 here for
    /// middlebox compatibility, so the major byte is reliably 3.
    private static func isTLSRecord(_ payload: UnsafeRawBufferPointer) -> Bool {
        payload.count >= 3 && payload[1] == 0x03 && payload[2] <= 0x04
            && (0x14...0x17).contains(payload[0])
    }

    /// A QUIC long header: high bit set (long form), next bit set (fixed bit), followed by
    /// a four-byte version. Version 0 is a version-negotiation packet and still QUIC.
    ///
    /// The fixed bit is what separates this from ordinary binary noise; without it, any
    /// UDP payload whose first byte happens to be high would be claimed as QUIC.
    private static func isQUICLongHeader(_ payload: UnsafeRawBufferPointer) -> Bool {
        guard payload.count >= 5 else { return false }
        return (payload[0] & 0xC0) == 0xC0
    }

    /// A DTLS record: the TLS content types, but with a version of 0xFE (1's complement of
    /// the TLS numbering).
    private static func isDTLS(_ payload: UnsafeRawBufferPointer) -> Bool {
        guard payload.count >= 3, payload[1] == 0xFE else { return false }
        return (0x14...0x17).contains(payload[0])
    }

    /// What an HTTP/1.x message can begin with: a status line, or a request line opening
    /// with one of these methods.
    ///
    /// Public because the app's header reader matches the same set on the decoded text. One
    /// list, so a protocol the daemon claims to recognise and one the reader will render
    /// cannot drift apart — the first divergence would show up only as headers mysteriously
    /// not rendering for one method, against live traffic.
    public static let httpStartTokens = [
        "HTTP/1.", "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ",
        "TRACE ", "CONNECT ",
    ]

    /// The same tokens as bytes, converted once.
    ///
    /// Matching is anchored at offset zero on purpose. Searching for "HTTP/1." anywhere in
    /// the buffer would match the body of an HTML page describing HTTP, and match it on a
    /// TLS connection this had already correctly declined.
    private static let httpPrefixes: [[UInt8]] = httpStartTokens.map { Array($0.utf8) }

    private static let sshPrefixes: [[UInt8]] = [Array("SSH-2.0".utf8), Array("SSH-1.".utf8)]
    private static let popPrefixes: [[UInt8]] = [Array("+OK".utf8), Array("-ERR".utf8)]
    private static let imapPrefixes: [[UInt8]] = [Array("* OK".utf8), Array("* BYE".utf8)]

    /// The mail and file-transfer family, which all open with a human-readable greeting.
    ///
    /// The shapes are distinctive enough to be worth trusting — a three-digit code
    /// followed by a space or hyphen (SMTP, FTP, NNTP), `+OK`/`-ERR` (POP3), or a tagged
    /// `* OK` (IMAP) — but they do not say *which* of those protocols it is, so the port
    /// picks the name. That is a guess sitting inside a proof: the security is read from
    /// the bytes, only the label comes from the port.
    private static func textualGreeting(
        _ payload: UnsafeRawBufferPointer,
        packet: ParsedPacket
    ) -> String? {
        let looksLikeGreeting: Bool
        if payload.count >= 4,
            isDigit(payload[0]), isDigit(payload[1]), isDigit(payload[2]),
            payload[3] == UInt8(ascii: " ") || payload[3] == UInt8(ascii: "-")
        {
            looksLikeGreeting = true
        } else if popPrefixes.contains(where: { starts(payload, with: $0) }) {
            looksLikeGreeting = true
        } else if imapPrefixes.contains(where: { starts(payload, with: $0) }) {
            looksLikeGreeting = true
        } else {
            looksLikeGreeting = false
        }
        guard looksLikeGreeting else { return nil }

        switch lowerPort(of: packet) {
        case 21: return "FTP"
        case 23: return "Telnet"
        case 25, 587: return "SMTP"
        case 110: return "POP3"
        case 119: return "NNTP"
        case 143: return "IMAP"
        default: return "Plain text"
        }
    }

    // MARK: - Port conventions

    /// Ports whose protocol has transport security built in.
    static let encryptedPorts: Set<UInt16> = [
        22,  // SSH
        443,  // HTTPS / QUIC
        465,  // SMTPS
        563,  // NNTPS
        636,  // LDAPS
        853,  // DNS over TLS
        993,  // IMAPS
        995,  // POP3S
        5061,  // SIP over TLS
        8443,  // HTTPS, alternate
    ]

    /// Ports whose protocol carries no transport security of its own.
    ///
    /// Database ports are here because their default configuration is unencrypted, which
    /// is the fact worth surfacing; a TLS-wrapped session on one of them will be corrected
    /// to `encrypted` the moment a record header is read, since `.payload` outranks
    /// `.port`.
    static let cleartextPorts: Set<UInt16> = [
        21,  // FTP control
        23,  // Telnet
        25,  // SMTP
        53,  // DNS
        69,  // TFTP
        80,  // HTTP
        110,  // POP3
        119,  // NNTP
        143,  // IMAP
        161,  // SNMP
        389,  // LDAP
        548,  // AFP
        1883,  // MQTT
        3306,  // MySQL
        5353,  // Multicast DNS
        5432,  // PostgreSQL
        5672,  // AMQP
        6379,  // Redis
        8080,  // HTTP, alternate
        8086,  // InfluxDB
        9200,  // Elasticsearch
        11211,  // memcached
    ]

    private static func readPorts(packet: ParsedPacket) -> Reading? {
        let port = lowerPort(of: packet)
        if encryptedPorts.contains(port) {
            return Reading(security: .encrypted, protocolName: nil, evidence: .port)
        }
        if cleartextPorts.contains(port) {
            return Reading(security: .cleartext, protocolName: nil, evidence: .port)
        }
        return Reading(security: .unknown, protocolName: nil, evidence: .port)
    }

    /// The service port of a connection: the lower of the two.
    ///
    /// One end is an ephemeral client port allocated from 49152 upward and carries no
    /// meaning; the other is the service. Taking the lower of the pair finds the service
    /// without needing to know which end is local, which matters because this runs before
    /// the flow key has been normalised.
    private static func lowerPort(of packet: ParsedPacket) -> UInt16 {
        min(packet.sourcePort, packet.destinationPort)
    }

    // MARK: - Byte helpers

    private static func isDigit(_ byte: UInt8) -> Bool {
        byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")
    }

    /// Takes bytes rather than a `String` deliberately: converting a literal per call put
    /// a heap allocation on the packet path for every prefix tried.
    private static func starts(_ payload: UnsafeRawBufferPointer, with bytes: [UInt8]) -> Bool {
        guard payload.count >= bytes.count else { return false }
        for index in bytes.indices where payload[index] != bytes[index] {
            return false
        }
        return true
    }
}
