import Foundation
import Testing

@testable import BeholderCore

/// The wire protocol's version stayed at 1 when payload reading landed, on the grounds
/// that every field it added is optional and therefore compatible in both directions.
/// That is a claim about decoding, so it is tested rather than asserted.
///
/// If any of these fail, the fix is not to loosen the test — it is to bump
/// `WireProtocol.version`, which is what the version number is for.
@Suite("Old and new ends of the socket still understand each other")
struct WireCompatibilityTests {

    /// JSON from a daemon built before any of this existed: no `security` on a flow, no
    /// `cleartextExcerpts` on the snapshot. A current app must read it without complaint.
    private let snapshotFromAnOlderDaemon = """
        {
          "version": 1,
          "generatedAt": 1750000000,
          "startedAt": 1749999940,
          "interfaces": ["utun8"],
          "statistics": {
            "flowCount": 1, "processCount": 1, "outgoingCount": 1, "incomingCount": 0,
            "undeterminedDirectionCount": 0, "unattributedCount": 0,
            "unattributableCount": 0, "namedFlowCount": 1, "cachedNameCount": 0,
            "privateRelayFlowCount": 0, "evictedFlowCount": 0,
            "totalBytesOut": 100, "totalBytesIn": 200,
            "packetsCaptured": 3, "packetsDropped": 0,
            "warnings": [], "interfaceTransitions": []
          },
          "flows": [{
            "id": "TCP|10.5.0.2:51234|93.184.216.34:443",
            "transport": "TCP",
            "localAddress": "10.5.0.2", "localPort": 51234,
            "remoteAddress": "93.184.216.34", "remotePort": 443,
            "hostName": "example.com", "hostNameIsProof": true, "isPrivateRelay": false,
            "bytesOut": 100, "bytesIn": 200, "packetsOut": 2, "packetsIn": 1,
            "firstSeen": 1749999950, "lastSeen": 1750000000,
            "initiationIsCertain": true
          }]
        }
        """

    @Test("A snapshot from a daemon that knows nothing of payload reading still decodes")
    func olderSnapshotDecodes() throws {
        let snapshot = try FlowSnapshot.decoder()
            .decode(FlowSnapshot.self, from: Data(snapshotFromAnOlderDaemon.utf8))

        #expect(snapshot.flows.count == 1)
        #expect(snapshot.statistics.flowCount == 1)
        #expect(snapshot.cleartextExcerpts == nil, "nil means nothing is reading payload")

        let flow = try #require(snapshot.flows.first)
        #expect(flow.security == nil)
        #expect(flow.protocolName == nil)
        #expect(flow.securityIsProof == nil)
        #expect(!flow.isUnprotected, "no reading is not a claim of exposure")
    }

    @Test("New statistics fields default rather than failing to decode")
    func olderStatisticsDecode() throws {
        let snapshot = try FlowSnapshot.decoder()
            .decode(FlowSnapshot.self, from: Data(snapshotFromAnOlderDaemon.utf8))
        #expect(snapshot.statistics.cleartextFlowCount == 0)
        #expect(snapshot.statistics.unknownSecurityFlowCount == 0)
        #expect(snapshot.statistics.encryptedFlowCount == 0)
    }

    /// `WireStatistics.init(from:)` is a hand-maintained list of every field, which is what
    /// makes absent keys decode to their defaults. The risk that buys is an omission: add a
    /// counter, forget the matching line, and the daemon sends a number every reader shows
    /// as zero — silently, forever. Distinct values here mean any omission fails this test
    /// at the moment it is made.
    @Test("Every statistic survives a round trip, so no field can be left out of the decoder")
    func everyStatisticRoundTrips() throws {
        var original = WireStatistics()
        original.flowCount = 1
        original.processCount = 2
        original.outgoingCount = 3
        original.incomingCount = 4
        original.undeterminedDirectionCount = 5
        original.unattributedCount = 6
        original.unattributableCount = 7
        original.namedFlowCount = 8
        original.cachedNameCount = 9
        original.privateRelayFlowCount = 10
        original.evictedFlowCount = 11
        original.cleartextFlowCount = 12
        original.unknownSecurityFlowCount = 13
        original.encryptedFlowCount = 14
        original.totalBytesOut = 15
        original.totalBytesIn = 16
        original.packetsCaptured = 17
        original.packetsDropped = 18
        original.measuredFlowCount = 19
        original.measuredByteShare = 0.20
        original.medianRttMs = 21.5
        original.minRttMs = 22.5
        original.retransmitRateOut = 0.23
        original.retransmitRateIn = 0.24
        original.unmeasurableFlowCount = 25
        original.unmeasurableBytes = 26
        original.connectionAttempts = 27
        original.connectionTimeouts = 28
        original.connectionRefusals = 29
        original.discardedRttSamples = 30
        original.segmentOffloadFlowCount = 31
        original.warnings = ["a warning"]
        original.interfaceTransitions = ["en0 → utun8"]

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(WireStatistics.self, from: encoded)
        #expect(decoded == original)

        // A field missing from the decoder would round-trip as its default, so the guard is
        // only real if no field's true value equals its default.
        let defaults = WireStatistics()
        #expect(decoded.flowCount != defaults.flowCount)
        #expect(decoded.warnings != defaults.warnings)
    }

    @Test("A snapshot carrying payload survives a round trip")
    func excerptRoundTrip() throws {
        let request = Data("GET /login?token=hunter2 HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        let original = FlowSnapshot(
            generatedAt: Date(timeIntervalSince1970: 1_750_000_000),
            startedAt: Date(timeIntervalSince1970: 1_749_999_940),
            interfaces: ["en0"],
            flows: [],
            statistics: WireStatistics(),
            cleartextExcerpts: [
                WireExcerpt(
                    id: "TCP|10.5.0.2:51234|93.184.216.34:80",
                    sent: request,
                    received: nil,
                    sentObserved: 900_000,
                    receivedObserved: 0
                )
            ]
        )

        let encoded = try FlowSnapshot.encoder().encode(original)
        let decoded = try FlowSnapshot.decoder().decode(FlowSnapshot.self, from: encoded)

        let excerpt = try #require(decoded.cleartextExcerpts?.first)
        #expect(excerpt.sent == request)
        #expect(excerpt.received == nil)
        #expect(excerpt.isTruncated, "900 KB was sent and 46 bytes were kept")
        #expect(excerpt.sentCaptured == request.count)
    }

    /// The socket's framing is one snapshot per line, so a payload that could contain a
    /// newline byte would corrupt the stream. `Data` encodes as base64, which cannot.
    @Test("Payload containing newlines cannot break the line framing")
    func payloadCannotBreakFraming() throws {
        let awkward = Data([0x0A, 0x0D, 0x0A, 0x22, 0x5C, 0x00, 0xFF])
        let snapshot = FlowSnapshot(
            generatedAt: Date(timeIntervalSince1970: 1),
            startedAt: Date(timeIntervalSince1970: 0),
            interfaces: [],
            flows: [],
            statistics: WireStatistics(),
            cleartextExcerpts: [
                WireExcerpt(
                    id: "x", sent: awkward, received: nil,
                    sentObserved: 7, receivedObserved: 0
                )
            ]
        )

        let encoded = try FlowSnapshot.encoder().encode(snapshot)
        #expect(!encoded.contains(0x0A), "a newline here would truncate the message")

        let decoded = try FlowSnapshot.decoder().decode(FlowSnapshot.self, from: encoded)
        #expect(decoded.cleartextExcerpts?.first?.sent == awkward)
    }

    /// Nil and empty must stay distinguishable through encoding, because the app uses that
    /// difference to tell "nothing is reading payload" from "reading, and there was
    /// nothing to read".
    @Test("An empty excerpt list is not encoded as an absent one")
    func emptyIsNotNil() throws {
        let reading = FlowSnapshot(
            generatedAt: Date(timeIntervalSince1970: 1), startedAt: Date(timeIntervalSince1970: 0),
            interfaces: [], flows: [], statistics: WireStatistics(), cleartextExcerpts: []
        )
        let notReading = FlowSnapshot(
            generatedAt: Date(timeIntervalSince1970: 1), startedAt: Date(timeIntervalSince1970: 0),
            interfaces: [], flows: [], statistics: WireStatistics()
        )

        let decodedReading = try FlowSnapshot.decoder()
            .decode(FlowSnapshot.self, from: try FlowSnapshot.encoder().encode(reading))
        let decodedNot = try FlowSnapshot.decoder()
            .decode(FlowSnapshot.self, from: try FlowSnapshot.encoder().encode(notReading))

        #expect(decodedReading.cleartextExcerpts?.isEmpty == true)
        #expect(decodedNot.cleartextExcerpts == nil)
    }

    @Test("A flow read as cleartext reports itself as unprotected; an encrypted one does not")
    func unprotectedReflectsTheReading() {
        func flow(_ security: TransportSecurity?) -> WireFlow {
            WireFlow(
                id: "x", processName: nil, processPath: nil, pid: nil,
                transport: "TCP", localAddress: "10.5.0.2", localPort: 1,
                remoteAddress: "93.184.216.34", remotePort: 80,
                hostName: nil, hostNameIsProof: false, isPrivateRelay: false,
                bytesOut: 0, bytesIn: 0, packetsOut: 0, packetsIn: 0,
                tcpState: nil, firstSeen: Date(), lastSeen: Date(),
                location: nil, classification: nil, networkOperator: nil,
                isOutgoing: true, initiationIsCertain: true,
                security: security, protocolName: nil, securityIsProof: nil
            )
        }

        #expect(flow(.cleartext).isUnprotected)
        // Unknown counts as unprotected for the purpose of "show me what is exposed",
        // while still being labelled as unknown everywhere it is displayed.
        #expect(flow(.unknown).isUnprotected)
        #expect(!flow(.encrypted).isUnprotected)
        #expect(!flow(nil).isUnprotected)
    }
}

// MARK: - Quality fields

/// The quality fields were added without raising `WireProtocol.version`, on the same
/// grounds as payload reading before them: every one is optional. The claim needs the same
/// test, plus one the earlier fields did not need — that absent decodes as *nil* and not as
/// zero. For a latency figure the two say opposite things, and a reader shown 0 ms would
/// conclude the network was perfect when in fact nothing measured it.
@Suite("Quality fields cross the socket without a version bump")
struct WireQualityCompatibilityTests {

    private let snapshotWithoutQuality = """
        {
          "version": 1,
          "generatedAt": 1750000000,
          "startedAt": 1749999940,
          "interfaces": ["en0"],
          "statistics": {
            "flowCount": 1, "totalBytesOut": 100, "totalBytesIn": 200,
            "warnings": [], "interfaceTransitions": []
          },
          "flows": [{
            "id": "TCP|10.5.0.2:51234|93.184.216.34:443",
            "transport": "TCP",
            "localAddress": "10.5.0.2", "localPort": 51234,
            "remoteAddress": "93.184.216.34", "remotePort": 443,
            "hostNameIsProof": false, "isPrivateRelay": false,
            "bytesOut": 100, "bytesIn": 200, "packetsOut": 2, "packetsIn": 1,
            "firstSeen": 1749999950, "lastSeen": 1750000000,
            "initiationIsCertain": true
          }]
        }
        """

    @Test("A daemon that measures nothing reports absence, not zero")
    func absentQualityIsNil() throws {
        let snapshot = try FlowSnapshot.decoder()
            .decode(FlowSnapshot.self, from: Data(snapshotWithoutQuality.utf8))

        #expect(snapshot.statistics.measuredByteShare == nil)
        #expect(snapshot.statistics.medianRttMs == nil)
        #expect(snapshot.statistics.retransmitRateOut == nil)
        #expect(snapshot.statistics.connectionTimeouts == nil)

        let flow = try #require(snapshot.flows.first)
        #expect(flow.rttMs == nil)
        #expect(flow.rttMinMs == nil)
        #expect(flow.retransmitsOut == nil)
        #expect(!flow.isMeasured)
    }

    @Test("Every quality field on a flow survives a round trip")
    func flowQualityRoundTrips() throws {
        var flow = Flow(
            key: FlowKey(
                transport: .tcp,
                local: IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!,
                localPort: 51234,
                remote: IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!,
                remotePort: 443
            ),
            interfaceName: "en0",
            at: Date(timeIntervalSince1970: 1_750_000_000)
        )

        // A handshake and one round trip, so the measurement is genuinely populated
        // rather than assembled by hand.
        let syn = measuredSegment(at: 0, flags: [.syn], timestampValue: 10)
        let synAck = measuredSegment(at: 0.020, flags: [.syn, .ack], timestampValue: 90,
            timestampEcho: 10)
        flow.record(syn, direction: .outbound, at: syn.timestamp, measuringQuality: true)
        flow.record(synAck, direction: .inbound, at: synAck.timestamp, measuringQuality: true)

        let wire = flow.wireRepresentation(measuringQuality: true)
        let encoded = try FlowSnapshot.encoder().encode(wire)
        let decoded = try FlowSnapshot.decoder().decode(WireFlow.self, from: encoded)

        #expect(decoded.rttSource == "handshake")
        // The handshake sample is 20 ms, and it is what the smoothed figure starts from.
        #expect(abs(try #require(decoded.rttMs) - 20) < 0.01)
        #expect(abs(try #require(decoded.rttMinMs) - 20) < 0.01)
        #expect(decoded.retransmitsOut == 0)
        #expect(decoded.isMeasured)
    }

    /// The default is not measuring, so a caller that forgets to say so publishes absence
    /// rather than a page of zeros claiming a flawless connection.
    @Test("A flow rendered without measuring reports nothing rather than zeroes")
    func unmeasuredFlowPublishesNothing() {
        let flow = Flow(
            key: FlowKey(
                transport: .tcp,
                local: IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!,
                localPort: 51234,
                remote: IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!,
                remotePort: 443
            ),
            interfaceName: "en0",
            at: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let wire = flow.wireRepresentation()

        #expect(wire.rttMs == nil)
        #expect(wire.rttMinMs == nil)
        #expect(wire.retransmitsOut == nil)
    }
}

private func measuredSegment(
    at seconds: TimeInterval,
    flags: TCPFlags,
    timestampValue: UInt32? = nil,
    timestampEcho: UInt32? = nil
) -> ParsedPacket {
    ParsedPacket(
        transport: .tcp,
        source: IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!,
        destination: IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!,
        sourcePort: 51234,
        destinationPort: 443,
        tcpFlags: flags,
        wireBytes: 74,
        isFragment: false,
        payloadOffset: 74,
        payloadCapturedLength: 0,
        timestamp: Date(timeIntervalSince1970: 1_750_000_000 + seconds),
        transportPayloadLength: 0,
        hopLimit: 57,
        tcp: TCPDetail(
            sequence: 1000,
            acknowledgement: 0,
            window: 65535,
            timestampValue: timestampValue,
            timestampEcho: timestampEcho
        )
    )
}
