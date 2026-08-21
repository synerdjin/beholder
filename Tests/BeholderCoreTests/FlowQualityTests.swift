import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!
private let server = IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!

/// A TCP segment built directly, so a test can state the one field it is about.
private func segment(
    at seconds: TimeInterval,
    sequence: UInt32 = 0,
    acknowledgement: UInt32 = 0,
    window: UInt16 = 65535,
    flags: TCPFlags = [.ack],
    payload: Int = 0,
    timestampValue: UInt32? = nil,
    timestampEcho: UInt32? = nil,
    sackBlocks: UInt8 = 0,
    hopLimit: UInt8 = 64
) -> ParsedPacket {
    ParsedPacket(
        transport: .tcp,
        source: laptop,
        destination: server,
        sourcePort: 51234,
        destinationPort: 443,
        tcpFlags: flags,
        wireBytes: UInt32(54 + payload),
        isFragment: false,
        payloadOffset: 54,
        payloadCapturedLength: payload,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000 + seconds),
        transportPayloadLength: payload,
        hopLimit: hopLimit,
        tcp: TCPDetail(
            sequence: sequence,
            acknowledgement: acknowledgement,
            window: window,
            timestampValue: timestampValue,
            timestampEcho: timestampEcho,
            sackBlockCount: sackBlocks
        )
    )
}

private func datagram(at seconds: TimeInterval, payload: Int = 200) -> ParsedPacket {
    ParsedPacket(
        transport: .udp,
        source: server,
        destination: laptop,
        sourcePort: 443,
        destinationPort: 51234,
        tcpFlags: [],
        wireBytes: UInt32(42 + payload),
        isFragment: false,
        payloadOffset: 42,
        payloadCapturedLength: payload,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000 + seconds),
        transportPayloadLength: payload
    )
}

private func icmp(type: UInt8, code: UInt8 = 0) -> ParsedPacket {
    ParsedPacket(
        transport: .icmp,
        source: server,
        destination: laptop,
        sourcePort: 0,
        destinationPort: 0,
        tcpFlags: [],
        wireBytes: 70,
        isFragment: false,
        payloadOffset: 34,
        payloadCapturedLength: 8,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000),
        transportPayloadLength: 8,
        hopLimit: 64,
        icmp: ICMPDetail(type: type, code: code)
    )
}

// MARK: - The estimator

@Suite("Round-trip estimation")
struct RTTEstimatorTests {

    /// RFC 6298's first-sample rule, which is a special case and not the smoothing.
    @Test("The first sample sets the estimate outright")
    func firstSample() {
        var estimator = RTTEstimator()
        let accepted = estimator.add(0.100)
        #expect(accepted)
        #expect(estimator.smoothed == 0.100)
        #expect(estimator.variation == 0.050)
        #expect(estimator.minimum == 0.100)
        #expect(estimator.sampleCount == 1)
    }

    @Test("Later samples follow RFC 6298's smoothing")
    func smoothing() throws {
        var estimator = RTTEstimator()
        estimator.add(0.100)
        estimator.add(0.200)

        // rttvar = 0.75 * 0.050 + 0.25 * |0.100 - 0.200| = 0.0625
        // srtt   = 0.875 * 0.100 + 0.125 * 0.200        = 0.1125
        let variation = try #require(estimator.variation as TimeInterval?)
        let smoothed = try #require(estimator.smoothed)
        #expect(abs(variation - 0.0625) < 1e-9)
        #expect(abs(smoothed - 0.1125) < 1e-9)
    }

    /// The minimum is the figure worth reasoning about, so it must track the floor rather
    /// than drift with the smoothing.
    @Test("The minimum holds the floor while the smoothed value wanders")
    func minimumHoldsFloor() throws {
        var estimator = RTTEstimator()
        for sample in [0.180, 0.012, 0.200, 0.250] { estimator.add(sample) }

        #expect(estimator.minimum == 0.012)
        #expect(try #require(estimator.smoothed) > 0.012)
    }

    /// A wall clock stepped by NTP produces intervals that are not round trips. Counted,
    /// because a silent discard makes a clock correction look like a quiet network.
    @Test("Impossible samples are refused and counted, not absorbed")
    func impossibleSamplesRefused() {
        var estimator = RTTEstimator()
        let negative = estimator.add(-0.5)
        let absurd = estimator.add(45)
        #expect(!negative)
        #expect(!absurd)
        #expect(estimator.sampleCount == 0)
        #expect(estimator.discardedCount == 2)
        #expect(estimator.smoothed == nil)
    }
}

// MARK: - Round trip, three ways

@Suite("Flow round-trip measurement")
struct FlowQualityRoundTripTests {

    @Test("The handshake gives one clean sample")
    func handshake() throws {
        var quality = FlowQuality()
        quality.record(segment(at: 0, flags: [.syn]), direction: .outbound)
        quality.record(
            segment(at: 0.048, flags: [.syn, .ack]), direction: .inbound
        )

        let handshake = try #require(quality.handshakeRTT)
        #expect(abs(handshake - 0.048) < 1e-6)
        #expect(quality.rttSource == .handshake)
        #expect(quality.sawSynAck)
    }

    /// The cleanest sample turning into the most misleading one. A retransmitted SYN is
    /// answered a full retransmission timeout later, and reporting that as latency would
    /// claim a second of network delay on a healthy path.
    @Test("A retransmitted SYN gives up the handshake sample rather than reporting the timeout")
    func retransmittedSYNIsNotASample() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, flags: [.syn]), direction: .outbound)
        quality.record(segment(at: 1.0, flags: [.syn]), direction: .outbound)
        quality.record(segment(at: 1.03, flags: [.syn, .ack]), direction: .inbound)

        #expect(quality.sawSynAck)
        #expect(quality.handshakeRTT == nil)
        #expect(quality.rtt.sampleCount == 0)
    }

    /// The opening SYN is deliberately not armed: its echo comes back in the SYN-ACK, and
    /// the handshake already measures that round trip. Sampling it here as well would
    /// weigh the first round trip of every connection twice.
    @Test("The opening SYN does not also produce a timestamp sample")
    func synIsNotDoubleCounted() {
        var quality = FlowQuality()
        quality.record(
            segment(at: 0, flags: [.syn], timestampValue: 10), direction: .outbound
        )
        quality.record(
            segment(at: 0.020, flags: [.syn, .ack], timestampValue: 90, timestampEcho: 10),
            direction: .inbound
        )

        #expect(quality.rtt.sampleCount == 1)
        #expect(quality.rttSource == .handshake)
    }

    @Test("The timestamp echo gives a sample per round trip")
    func timestampEcho() throws {
        var quality = FlowQuality()
        quality.record(
            segment(at: 0, sequence: 1000, payload: 100, timestampValue: 500),
            direction: .outbound
        )
        quality.record(
            segment(at: 0.020, acknowledgement: 1100, timestampValue: 900, timestampEcho: 500),
            direction: .inbound
        )

        #expect(quality.rtt.sampleCount == 1)
        #expect(abs(try #require(quality.rtt.minimum) - 0.020) < 1e-6)
        #expect(quality.rttSource == .timestampOption)
    }

    /// One outstanding sample at a time is the whole memory budget of this estimator.
    @Test("Only one sample is outstanding at a time")
    func oneOutstandingSample() {
        var quality = FlowQuality()
        quality.record(
            segment(at: 0, sequence: 1000, payload: 100, timestampValue: 500),
            direction: .outbound
        )
        quality.record(
            segment(at: 0.005, sequence: 1100, payload: 100, timestampValue: 501),
            direction: .outbound
        )
        quality.record(
            segment(at: 0.020, timestampValue: 900, timestampEcho: 501), direction: .inbound
        )

        #expect(quality.rtt.sampleCount == 1)
    }

    @Test("Without the timestamp option the acknowledgement is timed instead")
    func acknowledgementFallback() throws {
        var quality = FlowQuality()
        quality.record(
            segment(at: 0, sequence: 1000, payload: 100), direction: .outbound
        )
        quality.record(
            segment(at: 0.030, acknowledgement: 1100), direction: .inbound
        )

        #expect(quality.rtt.sampleCount == 1)
        #expect(abs(try #require(quality.rtt.minimum) - 0.030) < 1e-6)
        #expect(quality.rttSource == .acknowledgement)
    }

    /// Karn's algorithm. The acknowledgement does not say which copy it answers, so there
    /// is no sample here — only the appearance of one.
    @Test("A retransmitted segment yields no acknowledgement sample")
    func karnsAlgorithm() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, sequence: 1000, payload: 100), direction: .outbound)
        quality.record(segment(at: 0.5, sequence: 1000, payload: 100), direction: .outbound)
        quality.record(segment(at: 0.6, acknowledgement: 1100), direction: .inbound)

        #expect(quality.rtt.sampleCount == 0)
        #expect(quality.retransmitsOut == 1)
    }

    /// An offer is not an agreement. Treating it as one would switch off the fallback for
    /// connections that never negotiated the option, leaving them with no figure at all.
    @Test("A timestamp option offered but not answered still allows the fallback")
    func oneSidedTimestampOfferDoesNotDisableFallback() {
        var quality = FlowQuality()
        quality.record(
            segment(at: 0, sequence: 1000, payload: 100, timestampValue: 500),
            direction: .outbound
        )
        quality.record(segment(at: 0.030, acknowledgement: 1100), direction: .inbound)

        #expect(!quality.usesTimestampOption)
        #expect(quality.rtt.sampleCount == 1)
        #expect(quality.rttSource == .acknowledgement)
    }

    @Test("Queueing delay is the gap between the typical round trip and the floor")
    func queueingDelay() throws {
        var quality = FlowQuality()
        quality.record(segment(at: 0, timestampValue: 1), direction: .outbound)
        quality.record(segment(at: 0.010, timestampEcho: 1), direction: .inbound)
        for step in 1...20 {
            let base = 1.0 * Double(step)
            quality.record(
                segment(at: base, timestampValue: UInt32(step + 1)), direction: .outbound
            )
            quality.record(
                segment(at: base + 0.200, timestampEcho: UInt32(step + 1)), direction: .inbound
            )
        }

        let delay = try #require(quality.queueingDelay)
        #expect(delay > 0.1)
        #expect(abs(try #require(quality.rtt.minimum) - 0.010) < 1e-6)
    }
}

// MARK: - Loss

@Suite("Flow loss measurement")
struct FlowQualityLossTests {

    @Test("A later timestamp on old ground proves a retransmission")
    func provenRetransmission() {
        var quality = FlowQuality()
        // Both directions carrying timestamps, so the option counts as negotiated.
        quality.record(
            segment(at: 0, sequence: 1000, payload: 100, timestampValue: 10),
            direction: .outbound
        )
        quality.record(
            segment(at: 0.01, acknowledgement: 1000, timestampValue: 90, timestampEcho: 10),
            direction: .inbound
        )
        quality.record(
            segment(at: 0.5, sequence: 1000, payload: 100, timestampValue: 60),
            direction: .outbound
        )

        #expect(quality.retransmitsOut == 1)
        #expect(quality.reordersOut == 0)
        #expect(quality.retransmitsAreProven)
    }

    /// Not loss. A segment the network delivered late is a different fact from one the
    /// sender had to repeat, and filing it as loss would overstate the path's failures.
    @Test("An earlier timestamp on old ground is reordering, not loss")
    func reorderingIsNotLoss() {
        var quality = FlowQuality()
        quality.record(
            segment(at: 0, sequence: 1100, payload: 100, timestampValue: 60),
            direction: .outbound
        )
        quality.record(
            segment(at: 0.01, acknowledgement: 1100, timestampValue: 90, timestampEcho: 60),
            direction: .inbound
        )
        quality.record(
            segment(at: 0.02, sequence: 1000, payload: 100, timestampValue: 10),
            direction: .outbound
        )

        #expect(quality.reordersOut == 1)
        #expect(quality.retransmitsOut == 0)
    }

    /// Without the option the two are genuinely indistinguishable, and the count says so
    /// rather than picking the more alarming reading.
    @Test("Without timestamps a repeat is counted but not claimed as proof")
    func ambiguousRepeatIsNotProof() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, sequence: 1000, payload: 100), direction: .outbound)
        quality.record(segment(at: 0.5, sequence: 1000, payload: 100), direction: .outbound)

        #expect(quality.retransmitsOut == 1)
        #expect(!quality.retransmitsAreProven)
    }

    /// The test that justifies serial arithmetic existing. A sequence space that has just
    /// wrapped makes an old segment look like the highest one ever seen under a plain
    /// comparison, and the whole loss figure silently inverts.
    @Test("Sequence numbers that have wrapped are still ordered correctly")
    func sequenceWrap() {
        var quality = FlowQuality()
        // Ends at 36, having wrapped past 2^32.
        quality.record(
            segment(at: 0, sequence: 0xFFFF_FFC0, payload: 100), direction: .outbound
        )
        // Sits *before* the wrap, so it covers ground already seen — even though its raw
        // value is enormous next to 36.
        quality.record(
            segment(at: 0.1, sequence: 0xFFFF_FF00, payload: 64), direction: .outbound
        )

        #expect(quality.retransmitsOut == 1)
    }

    @Test("Three identical acknowledgements are one loss signal, not three")
    func duplicateAcknowledgementRuns() {
        var quality = FlowQuality()
        for step in 0..<5 {
            quality.record(
                segment(at: 0.01 * Double(step), acknowledgement: 5000), direction: .inbound
            )
        }
        #expect(quality.duplicateAckEventsIn == 1)
    }

    @Test("A changed window breaks the duplicate-acknowledgement run")
    func windowChangeBreaksRun() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, acknowledgement: 5000, window: 100), direction: .inbound)
        quality.record(segment(at: 0.01, acknowledgement: 5000, window: 100), direction: .inbound)
        quality.record(segment(at: 0.02, acknowledgement: 5000, window: 200), direction: .inbound)
        quality.record(segment(at: 0.03, acknowledgement: 5000, window: 200), direction: .inbound)

        #expect(quality.duplicateAckEventsIn == 0)
    }

    /// A stalled receiver is an application problem. Counting it as loss would raise an
    /// alarm about the network on the strength of a program that stopped reading.
    @Test("A zero window is counted apart from loss")
    func zeroWindowIsNotLoss() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, acknowledgement: 1, window: 0), direction: .inbound)

        #expect(quality.zeroWindowEvents == 1)
        #expect(quality.retransmitsIn == 0)
        #expect(quality.retransmitsOut == 0)
    }

    @Test("Selective-acknowledgement blocks are accumulated as corroboration")
    func sackBlocks() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, acknowledgement: 1, sackBlocks: 2), direction: .inbound)
        quality.record(segment(at: 0.01, acknowledgement: 1, sackBlocks: 1), direction: .inbound)

        #expect(quality.sackBlocksSeen == 3)
    }

    /// Coalesced segments are not segments, and a rate computed over them is not a rate.
    @Test("Segment offload is noticed rather than quietly skewing the counts")
    func offloadIsNoticed() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, sequence: 1, payload: 32000), direction: .inbound)

        #expect(quality.sawSegmentOffload)
    }
}

// MARK: - Everything else

@Suite("Flow path observations")
struct FlowQualityPathTests {

    @Test("Hop counts are guessed from the conventional starting values")
    func hopCounts() {
        #expect(FlowQuality.hopsTravelled(observedHopLimit: 57) == 7)
        #expect(FlowQuality.hopsTravelled(observedHopLimit: 64) == 0)
        #expect(FlowQuality.hopsTravelled(observedHopLimit: 120) == 8)
        #expect(FlowQuality.hopsTravelled(observedHopLimit: 250) == 5)
    }

    @Test("Unreachable and time-exceeded count as path errors; an echo does not")
    func icmpErrors() {
        var quality = FlowQuality()
        quality.record(icmp(type: 3, code: 4), direction: .inbound)
        quality.record(icmp(type: 11), direction: .inbound)
        quality.record(icmp(type: 0), direction: .inbound)  // echo reply

        #expect(quality.icmpErrors == 2)
    }

    /// The QUIC hole, stated as a test. A UDP conversation yields no round trip at all,
    /// and everything downstream has to publish how much of the traffic that covers.
    @Test("A UDP conversation is not measurable")
    func udpIsNotMeasurable() {
        var quality = FlowQuality()
        for step in 0..<20 {
            quality.record(datagram(at: 0.02 * Double(step)), direction: .inbound)
        }

        #expect(!quality.isMeasurable)
        #expect(quality.rtt.sampleCount == 0)
    }

    @Test("Arrival spacing needs enough samples before it means anything")
    func arrivalSpacingNeedsSamples() {
        var quality = FlowQuality()
        for step in 0..<5 {
            quality.record(datagram(at: 0.02 * Double(step)), direction: .inbound)
        }
        #expect(!quality.arrivalSpacingIsMeaningful)

        for step in 5..<40 {
            // Deliberately uneven, so the estimate has something to find.
            let jitter = step.isMultiple(of: 2) ? 0.005 : 0.030
            quality.record(datagram(at: 0.02 * Double(step) + jitter), direction: .inbound)
        }
        #expect(quality.arrivalSpacingIsMeaningful)
        #expect(quality.arrivalSpacingVariation > 0)
    }

    @Test("Segments are counted per direction")
    func segmentsPerDirection() {
        var quality = FlowQuality()
        quality.record(segment(at: 0, sequence: 1, payload: 100), direction: .outbound)
        quality.record(segment(at: 0.01, sequence: 101, payload: 100), direction: .outbound)
        quality.record(segment(at: 0.02, acknowledgement: 201), direction: .inbound)

        #expect(quality.segmentsOut == 2)
        #expect(quality.segmentsIn == 1)
        #expect(quality.sequenceConsumingSegmentsOut == 2)
        #expect(quality.sequenceConsumingSegmentsIn == 0)
    }
}

@Suite("One rule for a connection that went unanswered")
struct ConnectionTimeoutRuleTests {

    /// Built by recording real segments rather than by setting flags, so the fixture and
    /// the daemon reach the same state by the same route.
    private func attempt(
        at start: Date,
        synAck: Bool = false,
        reset: Bool = false,
        outbound: Bool = true
    ) -> Flow {
        var flow = Flow(
            key: FlowKey(
                transport: .tcp,
                local: laptop,
                localPort: 51234,
                remote: server,
                remotePort: 443
            ),
            interfaceName: "en0",
            at: start
        )
        let syn = segment(at: 0, flags: [.syn])
        flow.record(
            syn, direction: outbound ? .outbound : .inbound, at: start, measuringQuality: true)
        if synAck {
            flow.record(
                segment(at: 0.02, flags: [.syn, .ack]), direction: .inbound,
                at: start.addingTimeInterval(0.02), measuringQuality: true)
        }
        if reset {
            flow.record(
                segment(at: 0.02, flags: [.rst]), direction: .inbound,
                at: start.addingTimeInterval(0.02), measuringQuality: true)
        }
        return flow
    }

    /// The daemon and the live summary both have to decide this, and were deciding it in
    /// two places — one of them inside an executable no test could reach.
    @Test("An unanswered attempt past the grace period has timed out")
    func unansweredTimesOut() {
        let start = Date(timeIntervalSince1970: 1_750_000_000)
        let flow = attempt(at: start)
        #expect(!flow.connectionTimedOut(at: start.addingTimeInterval(1)), "still within grace")
        #expect(flow.connectionTimedOut(at: start.addingTimeInterval(30)))
    }

    /// Answered, just not welcomed. A closed port is not the network failing, and folding
    /// the two together would blame the path for the far end's decision.
    @Test("A refusal is not a timeout, and neither is an answered handshake")
    func answeredIsNotATimeout() {
        let start = Date(timeIntervalSince1970: 1_750_000_000)
        let later = start.addingTimeInterval(30)
        #expect(!attempt(at: start, synAck: true).connectionTimedOut(at: later))
        #expect(!attempt(at: start, reset: true).connectionTimedOut(at: later))
    }

    /// An inbound connection's fate is the far end's business and says nothing about the
    /// path out of here.
    @Test("Only connections this machine opened count")
    func inboundIsNotCounted() {
        let start = Date(timeIntervalSince1970: 1_750_000_000)
        #expect(
            !attempt(at: start, outbound: false)
                .connectionTimedOut(at: start.addingTimeInterval(30))
        )
    }
}
