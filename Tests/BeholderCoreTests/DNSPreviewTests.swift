import Foundation
import Testing

@testable import BeholderCore

/// Real bytes: the opening of an mDNS announcement this machine sent to 224.0.0.251:5353,
/// carrying an AirPlay service record. Cut where the excerpt cut it, mid-TXT, because that
/// truncation is the ordinary case and the thing most likely to be got wrong.
private let airplayAnnouncement: [UInt8] = [
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x12,
        0x00, 0x00, 0x00, 0x05, 0x14, 0x47, 0x65, 0x6e,
        0x65, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x4d, 0x61,
        0x63, 0x42, 0x6f, 0x6f, 0x6b, 0x20, 0x41, 0x69,
        0x72, 0x08, 0x5f, 0x61, 0x69, 0x72, 0x70, 0x6c,
        0x61, 0x79, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x10,
        0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x01, 0x6d,
        0x05, 0x61, 0x63, 0x74, 0x3d, 0x32, 0x05, 0x61,
        0x63, 0x6c, 0x3d, 0x30, 0x1a, 0x64, 0x65, 0x76,
        0x69, 0x63, 0x65, 0x69, 0x64, 0x3d, 0x33, 0x32,
        0x3a, 0x42, 0x34, 0x3a, 0x31, 0x41, 0x3a, 0x34,
        0x41, 0x3a, 0x39, 0x41, 0x3a, 0x46, 0x44, 0x14,
        0x66, 0x65, 0x78, 0x3d, 0x31, 0x63, 0x39, 0x2f,
        0x53, 0x74, 0x35, 0x50, 0x46, 0x7a, 0x67, 0x32,
        0x49, 0x59, 0x78, 0x41, 0x1e, 0x66, 0x65, 0x61,
        0x74, 0x75, 0x72, 0x65, 0x73, 0x3d, 0x30, 0x78,
        0x34, 0x41, 0x37, 0x46, 0x43, 0x46, 0x44, 0x35,
        0x2c, 0x30, 0x78, 0x33, 0x38, 0x31, 0x37, 0x34,
        0x46, 0x44, 0x45, 0x07, 0x72, 0x73, 0x66, 0x3d,
        0x30, 0x78, 0x38, 0x0b, 0x66, 0x6c, 0x61, 0x67,
        0x73, 0x3d, 0x30, 0x78, 0x32, 0x30, 0x34, 0x28,
        0x67, 0x69, 0x64, 0x3d, 0x37, 0x31, 0x39, 0x42,
        0x42, 0x34, 0x35, 0x34, 0x2d, 0x34, 0x42, 0x39,
        0x37, 0x2d, 0x34, 0x30, 0x41, 0x42, 0x2d, 0x42,
        0x37, 0x33, 0x32, 0x2d, 0x36, 0x34, 0x46, 0x45,
        0x35, 0x45, 0x30, 0x42, 0x34, 0x42, 0x41, 0x33,
        0x05, 0x69, 0x67, 0x6c, 0x3d, 0x30, 0x06, 0x67,
        0x63, 0x67, 0x6c, 0x3d, 0x30, 0x0e, 0x6d, 0x6f,
        0x64, 0x65, 0x6c, 0x3d, 0x4d, 0x61, 0x63, 0x31,
        0x36, 0x2c, 0x31, 0x33, 0x04, 0x61, 0x74, 0x3d,
        0x34, 0x0d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x76,
        0x65, 0x72, 0x73, 0x3d, 0x31, 0x2e, 0x31, 0x27,
        0x70, 0x69, 0x3d, 0x63, 0x63, 0x30, 0x63, 0x66,
        0x36, 0x66, 0x65, 0x2d, 0x36, 0x62, 0x63, 0x66,
        0x2d, 0x34, 0x38, 0x39, 0x30, 0x2d, 0x38, 0x63,
        0x63, 0x32, 0x2d, 0x33, 0x63, 0x37, 0x30, 0x65,
        0x66, 0x32, 0x62, 0x35, 0x30, 0x38, 0x35,
]

@Suite("Reading a DNS message")
struct DNSPreviewTests {

    @Test("An mDNS announcement is decoded into its service record")
    func airplayService() throws {
        let messages = DNSPreview.parse(airplayAnnouncement)
        let message = try #require(messages.first)

        #expect(message.isResponse)
        #expect(message.isAuthoritative)
        #expect(message.declaredCounts.questions == 0, "an announcement asks nothing")
        #expect(message.declaredCounts.answers == 18)
        #expect(message.declaredCounts.additionals == 5)

        let record = try #require(message.records.first)
        #expect(record.name == "Gene\u{2019}s MacBook Air._airplay._tcp.local")
        #expect(record.type == "TXT")
        #expect(record.timeToLive == 4500)
        #expect(record.isCacheFlush, "mDNS reuses the top class bit to mean replace")
        #expect(record.values.contains("deviceid=32:B4:1A:4A:9A:FD"))
        #expect(record.values.contains("model=Mac16,13"))
    }

    /// `DNSMessage.parseResponse` declines this message — no question section, no address
    /// records — which is why the preview needed its own walk rather than a wrapper.
    @Test("An announcement the resolver parser declines is still readable here")
    func announcementIsNotAnAnswer() {
        let answer = airplayAnnouncement.withUnsafeBytes { DNSMessage.parseResponse($0) }
        #expect(answer == nil)
        #expect(!DNSPreview.parse(airplayAnnouncement).isEmpty)
    }

    /// The caveat has to travel with the data: one record of twenty-three, shown without
    /// saying so, reads as a machine that announced one thing.
    @Test("A record cut short by the excerpt is reported, and said to be cut short")
    func truncationIsAdmitted() throws {
        let message = try #require(DNSPreview.parse(airplayAnnouncement).first)
        let record = try #require(message.records.first)

        #expect(record.isTruncated, "the TXT rdata runs past the end of the excerpt")
        #expect(message.isIncomplete)
        #expect(message.records.count < message.declaredCounts.recordTotal)
        #expect(!record.values.isEmpty, "the strings that did arrive are the readable part")
    }

    @Test("A query is decoded with its question")
    func query() throws {
        var bytes: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        bytes += [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]
        bytes += [0x00, 0x01, 0x00, 0x01]  // QTYPE A, QCLASS IN

        let message = try #require(DNSPreview.parse(bytes).first)
        #expect(!message.isResponse)
        #expect(message.questions.first?.name == "example.com")
        #expect(message.questions.first?.type == "A")
        #expect(!message.isIncomplete)
    }

    /// Datagrams are appended to an excerpt end to end, and a compression pointer is an
    /// offset from the start of *its own* message. Parsing the pair as one stream resolves
    /// the second message's pointers against the first one's bytes — which does not fail,
    /// it silently produces the wrong names.
    @Test("Concatenated datagrams are parsed separately, so pointers stay message-relative")
    func concatenatedDatagrams() throws {
        var one: [UInt8] = [0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        one += [4] + Array("host".utf8) + [5] + Array("local".utf8) + [0]
        one += [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 10, 0, 0, 5]

        // A second datagram whose answer name is a pointer to offset 12 — its own header
        // length, and a completely different name from the one at offset 12 of the first.
        var two: [UInt8] = [0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        two += [7] + Array("printer".utf8) + [5] + Array("local".utf8) + [0]
        two += [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 10, 0, 0, 6]
        two += [0xC0, 0x0C]  // a pointer back to "printer.local", message-relative

        let messages = DNSPreview.parse(one + two)
        #expect(messages.count == 2)
        #expect(messages.first?.records.first?.name == "host.local")
        #expect(messages.first?.records.first?.values == ["10.0.0.5"])
        #expect(messages.last?.records.first?.name == "printer.local")
        #expect(messages.last?.records.first?.values == ["10.0.0.6"])
    }

    /// The same rule the protocol sniffer follows: what cannot be read is reported as
    /// unread, never guessed at.
    @Test("An unreadable record type is reported as a byte count, not a guess")
    func unknownRecordType() throws {
        var bytes: [UInt8] = [0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        bytes += [4] + Array("host".utf8) + [5] + Array("local".utf8) + [0]
        bytes += [0x00, 0x63, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x03, 1, 2, 3]

        let record = try #require(DNSPreview.parse(bytes).first?.records.first)
        #expect(record.type == "TYPE99", "numbered, because inventing a name would be worse")
        #expect(record.values == ["3 bytes"])
    }

    /// The parse is offered to every excerpt, the way `HTTPPreview.parse` is, so declining
    /// what is not a DNS message is load-bearing rather than tidy.
    @Test("Payload that is not DNS is declined rather than rendered as a message")
    func notDNS() {
        #expect(DNSPreview.parse(Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)).isEmpty)
        // A WireGuard keepalive: four bytes of header that could be read as a DNS id and
        // flags, and nothing behind them that walks.
        #expect(DNSPreview.parse([4, 0, 0, 0] + (4..<32).map { UInt8($0) }).isEmpty)
        #expect(DNSPreview.parse([0x00, 0x00, 0x84]).isEmpty, "shorter than a header")
    }
}
