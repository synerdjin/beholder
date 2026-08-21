import Foundation
import Testing

@testable import BeholderCore

@Suite("Probe results")
struct ProbeStoreTests {

    private func temporary() -> String {
        NSTemporaryDirectory() + "beholder-probe-\(UUID().uuidString)/history.sqlite"
    }

    /// Silence is a measurement, not a gap. A missing row would be indistinguishable from
    /// the prober being switched off, which is the exact confusion probing exists to end.
    @Test("A probe that got no answer is recorded, not skipped")
    func silenceIsRecorded() throws {
        let path = temporary()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let store = try FlowStore(path: path)
        defer { store.close() }

        let now = Date()
        try store.recordProbes([
            ProbeResult(at: now, interface: "en0", target: "1.1.1.1", kind: .anchor, rttMs: 14),
            ProbeResult(
                at: now.addingTimeInterval(1), interface: "en0", target: "8.8.8.8",
                kind: .anchor, rttMs: nil
            ),
        ])

        let results = try store.probes(
            since: now.addingTimeInterval(-60), until: now.addingTimeInterval(60)
        )
        #expect(results.count == 2)
        #expect(results.contains { $0.rttMs == nil })
    }

    /// The comparison passive capture cannot make: a clean first hop with bad anchors puts
    /// the trouble beyond the router.
    @Test("A clean gateway with slow anchors points upstream of the router")
    func upstreamReading() throws {
        let path = temporary()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let store = try FlowStore(path: path)
        defer { store.close() }

        let now = Date()
        var probes: [ProbeResult] = []
        for step in 0..<20 {
            let at = now.addingTimeInterval(Double(step))
            probes.append(
                ProbeResult(at: at, interface: "en0", target: "192.168.1.1", kind: .gateway, rttMs: 2)
            )
            probes.append(
                ProbeResult(
                    at: at.addingTimeInterval(0.1), interface: "en0", target: "1.1.1.1",
                    kind: .anchor, rttMs: 400
                )
            )
        }
        try store.recordProbes(probes)

        let summary = try #require(
            try store.probeSummary(
                since: now.addingTimeInterval(-60), until: now.addingTimeInterval(600)
            )
        )
        #expect(try #require(summary.reading).contains("upstream of your router"))
    }

    @Test("A slow first hop points at your own network, before the ISP")
    func localReading() throws {
        let path = temporary()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let store = try FlowStore(path: path)
        defer { store.close() }

        let now = Date()
        var probes: [ProbeResult] = []
        for step in 0..<20 {
            let at = now.addingTimeInterval(Double(step))
            probes.append(
                ProbeResult(
                    at: at, interface: "en0", target: "192.168.1.1", kind: .gateway, rttMs: 180
                )
            )
            probes.append(
                ProbeResult(
                    at: at.addingTimeInterval(0.1), interface: "en0", target: "1.1.1.1",
                    kind: .anchor, rttMs: 400
                )
            )
        }
        try store.recordProbes(probes)

        let summary = try #require(
            try store.probeSummary(
                since: now.addingTimeInterval(-60), until: now.addingTimeInterval(600)
            )
        )
        #expect(try #require(summary.reading).contains("your own network"))
    }

    /// With only one half measured there is nothing to compare, and a reading would be an
    /// invention rather than a conclusion.
    @Test("Anchors without a gateway yield no reading")
    func noGatewayNoReading() throws {
        let path = temporary()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let store = try FlowStore(path: path)
        defer { store.close() }

        let now = Date()
        try store.recordProbes([
            ProbeResult(at: now, interface: "utun8", target: "1.1.1.1", kind: .anchor, rttMs: 30)
        ])

        let summary = try #require(
            try store.probeSummary(
                since: now.addingTimeInterval(-60), until: now.addingTimeInterval(60)
            )
        )
        #expect(summary.reading == nil)
    }
}

@Suite("ICMP echo messages")
struct ICMPEchoTests {

    /// A wrong checksum is dropped without a word, so the failure would look exactly like
    /// an unreachable network — the very finding the prober exists to report. Pinned
    /// against a hand-computed value rather than against itself.
    @Test("The checksum matches a hand-computed value")
    func knownChecksum() {
        // Type 8, code 0, checksum 0, identifier 0x1234, sequence 0x0001.
        // Words: 0x0800 + 0x0000 + 0x1234 + 0x0001 = 0x1A35; complement = 0xE5CA.
        let bytes: [UInt8] = [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]
        #expect(ICMPEcho.checksum(bytes) == 0xE5CA)
    }

    /// The defining property: a message carrying its own checksum sums to zero.
    @Test("A request carries a checksum that validates")
    func requestValidates() {
        let packet = ICMPEcho.request(identifier: 0x1234, sequence: 7)
        #expect(packet.count == 8)
        #expect(packet[0] == 8)
        #expect(ICMPEcho.checksum(packet) == 0)
    }

    @Test("An odd-length message still checksums")
    func oddLength() {
        #expect(ICMPEcho.checksum([0x01, 0x02, 0x03]) != 0)
    }

    @Test("The sequence number round-trips through a request")
    func sequenceIsPlaced() {
        let packet = ICMPEcho.request(identifier: 1, sequence: 0xBEEF)
        #expect(ICMPEcho.replySequence(in: [0, 0] + packet.dropFirst(2), count: 8) == 0xBEEF)
    }

    /// Observed on macOS: an unprivileged ICMP socket hands back the message with no IP
    /// header at all. Assuming the other shape would read the wrong two bytes and match
    /// nothing, forever, in silence.
    @Test("A reply with no IP header is read")
    func bareReply() {
        let reply: [UInt8] = [0, 0, 0xF7, 0xFF, 0x12, 0x34, 0x00, 0x2A]
        #expect(ICMPEcho.replySequence(in: reply, count: reply.count) == 42)
    }

    @Test("A reply behind an IPv4 header is read")
    func headeredReply() {
        let header: [UInt8] = [0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 1, 1, 1, 1, 10, 0, 0, 1]
        let reply = header + [0, 0, 0xF7, 0xFF, 0x12, 0x34, 0x00, 0x2A]
        #expect(ICMPEcho.replySequence(in: reply, count: reply.count) == 42)
    }

    /// Everything that is not an echo reply has to be refused rather than read. An
    /// unreachable message quotes the packet that provoked it, so bytes six and seven hold
    /// part of *our own* request — a sequence number that would match, and turn a failure
    /// into a successful round trip.
    @Test("A message that is not an echo reply is refused")
    func nonReplyRefused() {
        let unreachable: [UInt8] = [3, 1, 0, 0, 0, 0, 0, 42]
        #expect(ICMPEcho.replySequence(in: unreachable, count: unreachable.count) == nil)
        #expect(ICMPEcho.replySequence(in: [], count: 0) == nil)
        #expect(ICMPEcho.replySequence(in: [0, 0, 0], count: 3) == nil)
    }
}
