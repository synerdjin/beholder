import Foundation
import Testing

@testable import BeholderCore

// MARK: - DNS fixtures

/// Encodes a DNS name as length-prefixed labels.
private func encodeName(_ name: String) -> [UInt8] {
    var bytes: [UInt8] = []
    for label in name.split(separator: ".") {
        bytes.append(UInt8(label.utf8.count))
        bytes.append(contentsOf: Array(label.utf8))
    }
    bytes.append(0)
    return bytes
}

private func dnsResponse(
    question: String,
    answers: [(name: [UInt8], type: UInt16, ttl: UInt32, data: [UInt8])],
    responseCode: UInt8 = 0
) -> [UInt8] {
    var bytes: [UInt8] = [
        0x12, 0x34,  // transaction id
        0x81, 0x80 | responseCode,  // response, recursion, rcode
    ]
    bytes += [0x00, 0x01]  // one question
    bytes += [UInt8(answers.count >> 8), UInt8(truncatingIfNeeded: answers.count)]
    bytes += [0x00, 0x00, 0x00, 0x00]  // no authority or additional records

    bytes += encodeName(question)
    bytes += [0x00, 0x01, 0x00, 0x01]  // QTYPE A, QCLASS IN

    for answer in answers {
        bytes += answer.name
        bytes += [UInt8(answer.type >> 8), UInt8(truncatingIfNeeded: answer.type)]
        bytes += [0x00, 0x01]  // class IN
        bytes += [
            UInt8(answer.ttl >> 24), UInt8(truncatingIfNeeded: answer.ttl >> 16),
            UInt8(truncatingIfNeeded: answer.ttl >> 8), UInt8(truncatingIfNeeded: answer.ttl),
        ]
        bytes += [UInt8(answer.data.count >> 8), UInt8(truncatingIfNeeded: answer.data.count)]
        bytes += answer.data
    }
    return bytes
}

/// A compression pointer to the question name, which sits at offset 12.
private let pointerToQuestion: [UInt8] = [0xC0, 0x0C]

private func parseDNS(_ bytes: [UInt8]) -> DNSMessage.Answer? {
    bytes.withUnsafeBytes { DNSMessage.parseResponse($0) }
}

@Suite("DNS parsing")
struct DNSMessageTests {

    @Test("An A record answer yields the queried name and address")
    func simpleAnswer() throws {
        let bytes = dnsResponse(
            question: "example.com",
            answers: [(pointerToQuestion, 1, 300, [93, 184, 216, 34])]
        )
        let answer = try #require(parseDNS(bytes))

        #expect(answer.name == "example.com")
        #expect(answer.addresses.count == 1)
        #expect(answer.addresses[0].description == "93.184.216.34")
        #expect(answer.timeToLive == 300)
    }

    @Test("Multiple A records are all collected")
    func multipleAddresses() throws {
        let bytes = dnsResponse(
            question: "cdn.example.com",
            answers: [
                (pointerToQuestion, 1, 60, [1, 2, 3, 4]),
                (pointerToQuestion, 1, 30, [5, 6, 7, 8]),
            ]
        )
        let answer = try #require(parseDNS(bytes))

        #expect(answer.addresses.count == 2)
        // The shortest lifetime governs, so a stale entry is never served.
        #expect(answer.timeToLive == 30)
    }

    @Test("AAAA records are parsed")
    func ipv6Answer() throws {
        let address: [UInt8] = [0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42]
        let bytes = dnsResponse(
            question: "example.com",
            answers: [(pointerToQuestion, 28, 120, address)]
        )
        let answer = try #require(parseDNS(bytes))

        #expect(answer.addresses.count == 1)
        #expect(answer.addresses[0].family == .v6)
        #expect(answer.addresses[0].description == "2606:2800::42")
    }

    /// After a CNAME chain the address record is owned by some CDN alias. The name worth
    /// showing is the one that was asked for.
    @Test("A CNAME chain still reports the queried name")
    func cnameChainUsesQueriedName() throws {
        let bytes = dnsResponse(
            question: "www.example.com",
            answers: [
                (pointerToQuestion, 5, 300, encodeName("edge.cdn.net")),
                (encodeName("edge.cdn.net"), 1, 300, [10, 20, 30, 40]),
            ]
        )
        let answer = try #require(parseDNS(bytes))

        #expect(answer.name == "www.example.com")
        #expect(answer.addresses.count == 1)
        #expect(answer.addresses[0].description == "10.20.30.40")
    }

    @Test("Queries, errors and empty answers are rejected")
    func nonAnswersAreRejected() {
        // A query rather than a response.
        var query = dnsResponse(
            question: "example.com",
            answers: [(pointerToQuestion, 1, 300, [1, 2, 3, 4])]
        )
        query[2] = 0x01  // clear the QR bit
        #expect(parseDNS(query) == nil)

        // NXDOMAIN.
        let failure = dnsResponse(
            question: "nope.example.com",
            answers: [(pointerToQuestion, 1, 300, [1, 2, 3, 4])],
            responseCode: 3
        )
        #expect(parseDNS(failure) == nil)

        // A response whose only record carries no address.
        let cnameOnly = dnsResponse(
            question: "www.example.com",
            answers: [(pointerToQuestion, 5, 300, encodeName("edge.cdn.net"))]
        )
        #expect(parseDNS(cnameOnly) == nil)
    }

    /// These parsers read data straight off the network, so malformed input must fail
    /// rather than read out of bounds.
    @Test("Malformed and truncated messages are refused without crashing")
    func malformedInputIsSafe() {
        #expect(parseDNS([]) == nil)
        #expect(parseDNS([0x12, 0x34, 0x81, 0x80]) == nil)

        let valid = dnsResponse(
            question: "example.com",
            answers: [(pointerToQuestion, 1, 300, [93, 184, 216, 34])]
        )
        // Every truncation of a valid message must be handled.
        for length in 0..<valid.count {
            _ = parseDNS(Array(valid.prefix(length)))
        }

        // A compression pointer that loops back on itself must terminate.
        var looping: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01]
        looping += [0x00, 0x00, 0x00, 0x00]
        looping += [0xC0, 0x0C]  // at offset 12, pointing at offset 12
        #expect(parseDNS(looping) == nil)
    }
}

// MARK: - TLS

private func clientHello(serverName: String?, includeExtensions: Bool = true) -> [UInt8] {
    var handshake: [UInt8] = []
    handshake += [0x03, 0x03]  // client version
    handshake += [UInt8](repeating: 0xAB, count: 32)  // random
    handshake += [0x00]  // no session id
    handshake += [0x00, 0x02, 0x13, 0x01]  // one cipher suite
    handshake += [0x01, 0x00]  // one compression method

    if includeExtensions {
        var extensions: [UInt8] = []
        if let serverName {
            let name = Array(serverName.utf8)
            var entry: [UInt8] = [0x00]  // host_name
            entry += [UInt8(name.count >> 8), UInt8(truncatingIfNeeded: name.count)]
            entry += name
            var list: [UInt8] = [UInt8(entry.count >> 8), UInt8(truncatingIfNeeded: entry.count)]
            list += entry
            extensions += [0x00, 0x00]  // server_name extension
            extensions += [UInt8(list.count >> 8), UInt8(truncatingIfNeeded: list.count)]
            extensions += list
        }
        // A supported_versions extension, so SNI is never the only one present.
        extensions += [0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]

        handshake += [
            UInt8(extensions.count >> 8), UInt8(truncatingIfNeeded: extensions.count),
        ]
        handshake += extensions
    }

    var body: [UInt8] = [0x01]  // client_hello
    body += [
        UInt8(handshake.count >> 16),
        UInt8(truncatingIfNeeded: handshake.count >> 8),
        UInt8(truncatingIfNeeded: handshake.count),
    ]
    body += handshake

    var record: [UInt8] = [0x16, 0x03, 0x01]
    record += [UInt8(body.count >> 8), UInt8(truncatingIfNeeded: body.count)]
    record += body
    return record
}

private func parseSNI(_ bytes: [UInt8]) -> String? {
    bytes.withUnsafeBytes { TLSClientHello.serverName(in: $0) }
}

@Suite("TLS ClientHello")
struct TLSClientHelloTests {

    @Test("SNI is extracted from a ClientHello")
    func extractsServerName() {
        #expect(parseSNI(clientHello(serverName: "www.example.com")) == "www.example.com")
    }

    @Test("A ClientHello without SNI yields nothing")
    func noServerName() {
        #expect(parseSNI(clientHello(serverName: nil)) == nil)
        #expect(parseSNI(clientHello(serverName: nil, includeExtensions: false)) == nil)
    }

    @Test("Non-handshake records are ignored")
    func ignoresOtherRecords() {
        var applicationData = clientHello(serverName: "www.example.com")
        applicationData[0] = 0x17  // application_data
        #expect(parseSNI(applicationData) == nil)
        #expect(parseSNI([]) == nil)
        #expect(parseSNI([0x16, 0x03]) == nil)
    }

    /// A snaplen cut can land anywhere. Every prefix must fail cleanly rather than read
    /// past the buffer.
    @Test("Truncated handshakes are refused without crashing")
    func truncationIsSafe() {
        let full = clientHello(serverName: "www.example.com")
        for length in 0..<full.count {
            _ = parseSNI(Array(full.prefix(length)))
        }

        // Cut before the extensions block begins: the name cannot be known yet.
        #expect(parseSNI(Array(full.prefix(45))) == nil)

        // A name is only ever reported in full. Any prefix that yields one must yield
        // exactly the right one — a half-read hostname would be worse than none.
        for length in 0...full.count {
            if let name = parseSNI(Array(full.prefix(length))) {
                #expect(name == "www.example.com", "truncated at \(length) bytes")
            }
        }
    }
}

// MARK: - Cache

@Suite("Name resolution cache")
struct NameResolutionCacheTests {

    private func answer(
        _ name: String, _ address: [UInt8], ttl: UInt32 = 300
    ) -> DNSMessage.Answer {
        DNSMessage.Answer(
            name: name,
            addresses: [IPAddress(networkOrderBytes: address, family: .v4)!],
            timeToLive: ttl
        )
    }

    @Test("A recorded answer resolves its address")
    func recordsAndResolves() throws {
        let cache = NameResolutionCache()
        let address = try #require(IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4))
        cache.record(answer("example.com", [93, 184, 216, 34]))

        #expect(cache.name(for: address) == "example.com")
    }

    /// A short TTL governs when a resolver must re-query; it should not blank the name
    /// out of the display while the connection is still open, nor lose it overnight now
    /// that the cache is carried between runs.
    @Test("Names outlive short DNS time-to-live values")
    func shortTTLIsExtended() throws {
        let cache = NameResolutionCache()
        let now = Date()
        let address = try #require(IPAddress(networkOrderBytes: [1, 2, 3, 4], family: .v4))
        cache.record(answer("brief.example.com", [1, 2, 3, 4], ttl: 5), at: now)

        #expect(cache.name(for: address, at: now.addingTimeInterval(60)) == "brief.example.com")
        // Still there after a few hours, so a run the next morning starts warm.
        #expect(
            cache.name(for: address, at: now.addingTimeInterval(4 * 3600)) == "brief.example.com"
        )
        // But not indefinitely: an address can be reassigned.
        #expect(cache.name(for: address, at: now.addingTimeInterval(48 * 3600)) == nil)
    }

    @Test("Expired entries are dropped")
    func expiry() throws {
        let cache = NameResolutionCache()
        let now = Date()
        let address = try #require(IPAddress(networkOrderBytes: [1, 2, 3, 4], family: .v4))
        cache.record(answer("example.com", [1, 2, 3, 4], ttl: 60), at: now)

        #expect(cache.expire(at: now.addingTimeInterval(30)) == 0)
        #expect(cache.expire(at: now.addingTimeInterval(200_000)) == 1)
        #expect(cache.name(for: address, at: now.addingTimeInterval(200_000)) == nil)
    }

    /// One address commonly serves many aliases; the shorter name is the recognisable one.
    @Test("The shorter name wins for a shared address")
    func shorterNameWins() throws {
        let cache = NameResolutionCache()
        let address = try #require(IPAddress(networkOrderBytes: [1, 2, 3, 4], family: .v4))

        cache.record(answer("a-very-long-cdn-alias.example.com", [1, 2, 3, 4]))
        cache.record(answer("example.com", [1, 2, 3, 4]))
        #expect(cache.name(for: address) == "example.com")

        cache.record(answer("another-long-alias.example.com", [1, 2, 3, 4]))
        #expect(cache.name(for: address) == "example.com")
    }

    /// The `.apple-dns.net` and `apple-relay.*` names here were all observed on a live
    /// machine; an earlier version matched only `mask*.icloud.com` and missed every one.
    @Test(
        "Private Relay ingress and egress are recognised",
        arguments: [
            ("mask.icloud.com", EndpointKind.privateRelay),
            ("mask-h2.icloud.com", EndpointKind.privateRelay),
            ("mask-api.icloud.com", EndpointKind.privateRelay),
            ("mask.apple-dns.net", EndpointKind.privateRelay),
            ("mask-h2.apple-dns.net", EndpointKind.privateRelay),
            ("apple-relay.fastly-edge.com", EndpointKind.privateRelay),
            ("apple-relay.cloudflare.com", EndpointKind.privateRelay),
            ("usw.apple-relay.fastly-edge.com", EndpointKind.privateRelay),
            ("www.icloud.com", EndpointKind.ordinary),
            ("example.com", EndpointKind.ordinary),
            ("mask.example.com", EndpointKind.ordinary),
            ("notapple-relay.example.com", EndpointKind.ordinary),
        ]
    )
    func privateRelayClassification(hostName: String, expected: EndpointKind) {
        #expect(NameResolutionCache.classify(hostName: hostName) == expected)
    }

    @Test("An unknown hostname classifies as ordinary")
    func nilHostName() {
        #expect(NameResolutionCache.classify(hostName: nil) == .ordinary)
    }
}
