import Foundation

// MARK: - Serial number arithmetic

/// RFC 1982 comparison, for the two TCP fields that wrap.
///
/// Sequence numbers wrap at 2^32, and on a fast connection that is minutes away, not
/// years: a gigabit link exhausts the space in about thirty seconds. A plain `<` gets
/// every comparison wrong across the wrap, and the symptom would not be a crash but a
/// burst of retransmissions that never happened — which is worse, because it looks like
/// an answer. Timestamp option values wrap the same way and are compared the same way.
@inline(__always)
func serialIsAfter(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
    Int32(bitPattern: lhs &- rhs) > 0
}

@inline(__always)
func serialIsAtOrAfter(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
    Int32(bitPattern: lhs &- rhs) >= 0
}

// MARK: - Round-trip time

/// Where a round-trip sample came from, weakest evidence first.
///
/// Ordered by how much the number can be trusted, not by how it reads. An
/// acknowledgement-derived sample is contaminated by the peer's delayed-ACK timer, which
/// on macOS and most servers can add up to 40 ms of the peer's idleness to what is
/// reported as network latency. The handshake is clean but happens once. The timestamp
/// echo is clean *and* continuous, so it wins.
public enum RTTSource: Int, Comparable, Sendable, Codable {
    case acknowledgement = 0
    case handshake = 1
    case timestampOption = 2

    public static func < (lhs: RTTSource, rhs: RTTSource) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var name: String {
        switch self {
        case .acknowledgement: return "ack"
        case .handshake: return "handshake"
        case .timestampOption: return "tcp timestamps"
        }
    }
}

/// RFC 6298's smoothed round-trip time, plus the two order statistics that matter.
///
/// `minimum` is the number to reason about, and the UI says so. The mean and the smoothed
/// value both carry whatever delay the far end added before answering; the minimum over
/// many samples is the closest a passive observer gets to the path's actual propagation
/// delay. How far the rest sits above that minimum is congestion — see the bufferbloat
/// reading, which is exactly that gap measured against concurrent throughput.
public struct RTTEstimator: Sendable, Equatable {
    public private(set) var smoothed: TimeInterval?
    /// RFC 6298's RTTVAR. This is the jitter figure for a TCP conversation.
    public private(set) var variation: TimeInterval = 0
    public private(set) var minimum: TimeInterval?
    public private(set) var sampleCount: UInt32 = 0

    /// Samples rejected as impossible, counted rather than dropped in silence.
    ///
    /// Capture timestamps come from a wall clock that NTP can step underneath us, which
    /// produces negative and absurd intervals. Discarding them quietly would make a clock
    /// correction look like a quiet, healthy network.
    public private(set) var discardedCount: UInt32 = 0

    /// The widest interval still worth believing is a round trip. Beyond this it is a
    /// clock step, or a sample armed on a connection that then went silent for a minute.
    public static let plausibleCeiling: TimeInterval = 10

    public init() {}

    @discardableResult
    public mutating func add(_ sample: TimeInterval) -> Bool {
        guard sample >= 0, sample <= Self.plausibleCeiling else {
            discardedCount &+= 1
            return false
        }

        if let previous = smoothed {
            variation = 0.75 * variation + 0.25 * abs(previous - sample)
            smoothed = 0.875 * previous + 0.125 * sample
        } else {
            // RFC 6298's first-sample rule: nothing to smooth against yet.
            smoothed = sample
            variation = sample / 2
        }
        minimum = Swift.min(minimum ?? sample, sample)
        sampleCount &+= 1
        return true
    }
}

// MARK: - What one packet contributed

/// What a single packet added to the measurement.
///
/// Exists so the per-minute time series can be built by *pushing* each sample as it is
/// taken, rather than by sampling the running totals on a timer and subtracting.
/// Subtracting works for counters but not for round trips: the estimator holds a smoothed
/// value and a minimum, not the samples that produced them, so a tick that saw the count
/// rise by nine would have nothing but the smoothed value to attribute nine times over.
/// Pushing also puts every sample in the minute it actually happened in, which is the
/// whole point of a time series meant to answer "was it bad at eight on Tuesday".
public struct QualityEvent: Sendable, Equatable {
    /// A round-trip sample taken from this packet, in seconds.
    public var rttSample: TimeInterval?
    /// Whether that sample was the handshake's — kept apart because it is the cleanest
    /// one a connection ever produces, and the baseline is built from it.
    public var isHandshakeSample = false

    public var segmentsOut = 0
    public var segmentsIn = 0
    public var retransmitsOut = 0
    public var retransmitsIn = 0

    public var bytesOut: UInt64 = 0
    public var bytesIn: UInt64 = 0

    /// Whether the flow this packet belongs to had yielded a round trip by the time the
    /// packet arrived.
    ///
    /// Decides which side of the coverage figure its bytes fall on. The first packet or
    /// two of a TCP connection are filed as unmeasured because the handshake has not
    /// completed yet, which understates coverage very slightly — the safe direction.
    public var flowIsMeasured = false

    /// An outbound SYN: this machine trying to open a connection.
    public var isConnectionAttempt = false

    public init() {}

    public var isEmpty: Bool {
        rttSample == nil && segmentsOut == 0 && segmentsIn == 0 && bytesOut == 0
            && bytesIn == 0 && !isConnectionAttempt
    }
}

// MARK: - Per-direction sequence bookkeeping

/// One direction's view of the sequence space.
///
/// Kept per direction because the two answer different questions. Data of ours that had
/// to be sent again means loss on the way out (or a lost acknowledgement coming back);
/// data of theirs sent again means loss on the way in. Folding the two together would
/// throw away the only part of this that points anywhere.
struct DirectionQuality: Sendable, Equatable {
    var highestSequenceEnd: UInt32?
    /// The timestamp option carried by whichever segment set `highestSequenceEnd`. This
    /// is what tells a genuine retransmission from a segment that merely arrived late.
    var highestTimestampValue: UInt32?

    var lastAcknowledgement: UInt32?
    var lastWindow: UInt16?
    var duplicateAckRun: UInt8 = 0

    var segments: UInt64 = 0
    /// Segments that consumed sequence space — data, plus SYN and FIN, which each take one.
    var sequenceConsumingSegments: UInt64 = 0
    /// Covered ground already seen, and a timestamp option proved it was sent later.
    var provenRetransmits: UInt64 = 0
    /// Covered ground already seen, and a timestamp option proved it was sent earlier:
    /// the network reordered it. Not loss, and counted apart from it.
    var reorders: UInt64 = 0
    /// Covered ground already seen on a connection with no timestamp option, where a
    /// retransmission and a late arrival cannot be told apart.
    var ambiguousRetransmits: UInt64 = 0
    /// Runs of three or more identical acknowledgements — what triggers fast retransmit.
    var duplicateAckEvents: UInt64 = 0
    var zeroWindows: UInt64 = 0
}

// MARK: - Flow quality

/// Everything measurable about how one conversation's packets travelled.
///
/// Confined to the flow queue with the rest of `Flow`, O(1) per packet, and allocation
/// free: this runs on every packet the machine sends or receives.
///
/// Roughly 300 bytes per flow, so about 2.5 MB at `FlowTable.maximumFlows`. That is the
/// budget it is written to; anything here that wanted an array would blow it.
public struct FlowQuality: Sendable, Equatable {

    // MARK: Round trip

    public private(set) var rtt = RTTEstimator()
    public private(set) var rttSource: RTTSource?
    /// The handshake's own sample, kept apart because it is the cleanest one available:
    /// no application is involved in answering a SYN, so nothing can delay it but the
    /// path. It is the figure the ISP baseline is built from.
    public private(set) var handshakeRTT: TimeInterval?

    // At most one sample is outstanding at a time. That is O(1) in memory and yields
    // roughly one sample per round trip, which is exactly the rate worth having — a
    // sample per packet would only measure the same path a thousand times a second.
    private var armedTimestampValue: UInt32?
    private var armedTimestampAt: Date?
    private var armedSequenceEnd: UInt32?
    private var armedSequenceAt: Date?
    private var armedSequenceWasRetransmitted = false
    private var synAt: Date?
    private var synWasRetransmitted = false

    // MARK: Loss

    private var outbound = DirectionQuality()
    private var inbound = DirectionQuality()

    public private(set) var sackBlocksSeen: UInt64 = 0

    private var sawTimestampOutbound = false
    private var sawTimestampInbound = false

    /// Whether this connection actually negotiated RFC 7323 timestamps.
    ///
    /// Both directions, not either: a SYN may offer the option and be answered by a peer
    /// that does not support it, after which neither end sends one again. Taking the offer
    /// as agreement would switch off the acknowledgement-based fallback for exactly the
    /// connections that need it, and leave them with no round-trip figure at all.
    ///
    /// Also decides whether the retransmission counts below are proof or inference, and is
    /// published alongside them as such.
    public var usesTimestampOption: Bool { sawTimestampOutbound && sawTimestampInbound }

    // MARK: Outcome

    public private(set) var sawSynAck = false
    public private(set) var sawReset = false
    public private(set) var icmpErrors: UInt32 = 0

    // MARK: Arrival spacing

    /// Variation in the gap between inbound packets, smoothed the way RFC 3550 smooths
    /// its jitter estimate.
    ///
    /// Deliberately *not* called RFC 3550 jitter, which measures transit time and needs
    /// the sender's clock. Nothing on the wire carries that here, so this measures how
    /// evenly packets arrived and nothing more. For a call or a video stream — constant
    /// rate by nature — that is the useful figure. For a bulk transfer it is noise, which
    /// is why `arrivalSpacingIsMeaningful` gates it rather than the UI showing it always.
    public private(set) var arrivalSpacingVariation: TimeInterval = 0
    public private(set) var arrivalSpacingSamples: UInt32 = 0
    private var lastInboundArrival: Date?
    private var lastInboundGap: TimeInterval?

    // MARK: Path

    public private(set) var hopCount: UInt8?

    /// Set when a segment arrives larger than any real MTU, which means the interface
    /// coalesced several before handing them over.
    ///
    /// macOS does this by default on `en0`. It matters because segment counts and
    /// retransmission detection both assume a segment is a segment; under coalescing they
    /// are counting something else, and the counters say so rather than reading low.
    public private(set) var sawSegmentOffload = false

    /// Larger than any Ethernet MTU including jumbo frames, so nothing legitimate trips it.
    static let offloadThreshold = 9000

    public init() {}

    // MARK: - Recording

    /// Folds one packet into the measurement.
    ///
    /// Takes the parsed packet rather than a `PacketObservation` deliberately.
    /// `PayloadInspector.inspect` returns nothing for a packet with an empty payload, and
    /// a pure acknowledgement has exactly that — while being precisely where the
    /// round-trip and duplicate-acknowledgement signal lives. Routing this through the
    /// observation path would silently discard most of what there is to measure.
    @discardableResult
    public mutating func record(_ packet: ParsedPacket, direction: FlowDirection) -> QualityEvent {
        let now = packet.timestamp
        var event = QualityEvent()
        switch direction {
        case .outbound: event.bytesOut = UInt64(packet.wireBytes)
        case .inbound: event.bytesIn = UInt64(packet.wireBytes)
        }

        switch packet.transport {
        case .tcp:
            recordTCP(packet, direction: direction, at: now, into: &event)
        case .udp:
            recordArrivalSpacing(direction: direction, at: now)
        case .icmp, .icmpv6:
            recordICMP(packet)
        default:
            break
        }

        // Only inbound: our own hop limit is whatever this machine set, and says nothing
        // about the path.
        if direction == .inbound, packet.hopLimit > 0, hopCount == nil {
            hopCount = Self.hopsTravelled(observedHopLimit: packet.hopLimit)
        }

        event.flowIsMeasured = rtt.sampleCount > 0
        return event
    }

    private mutating func recordTCP(
        _ packet: ParsedPacket,
        direction: FlowDirection,
        at now: Date,
        into event: inout QualityEvent
    ) {
        guard let tcp = packet.tcp else { return }
        let flags = packet.tcpFlags
        let payloadLength = packet.transportPayloadLength

        if payloadLength >= Self.offloadThreshold { sawSegmentOffload = true }
        if tcp.timestampValue != nil {
            if direction == .outbound { sawTimestampOutbound = true } else {
                sawTimestampInbound = true
            }
        }
        sackBlocksSeen &+= UInt64(tcp.sackBlockCount)
        if flags.contains(.rst) { sawReset = true }

        if direction == .outbound { event.segmentsOut = 1 } else { event.segmentsIn = 1 }
        if flags.isConnectionOpen, direction == .outbound, synAt == nil {
            event.isConnectionAttempt = true
        }

        recordHandshake(flags: flags, direction: direction, at: now, into: &event)
        recordTimestampRoundTrip(tcp, flags: flags, direction: direction, at: now, into: &event)
        let wasResent = recordSequenceSpace(
            tcp, flags: flags, payloadLength: payloadLength, direction: direction
        )
        if wasResent {
            if direction == .outbound { event.retransmitsOut = 1 } else { event.retransmitsIn = 1 }
        }
        recordAcknowledgementRoundTrip(
            tcp, flags: flags, payloadLength: payloadLength, direction: direction,
            wasResent: wasResent, at: now, into: &event
        )
    }

    private mutating func recordHandshake(
        flags: TCPFlags,
        direction: FlowDirection,
        at now: Date,
        into event: inout QualityEvent
    ) {
        if flags.isConnectionOpen, direction == .outbound {
            if synAt == nil {
                synAt = now
            } else {
                // A second SYN makes the handshake ambiguous in exactly the way Karn's
                // algorithm describes: the answer that eventually comes back does not say
                // which SYN it answers. Restarting the clock would report the first
                // retransmission timeout — a whole second, by convention — as the
                // network's latency, and that is the flow's cleanest sample being turned
                // into its most misleading one. Give the sample up instead.
                synWasRetransmitted = true
            }
        }
        guard flags.contains(.syn), flags.contains(.ack), direction == .inbound else { return }
        sawSynAck = true
        guard handshakeRTT == nil, !synWasRetransmitted, let sent = synAt else { return }

        let sample = now.timeIntervalSince(sent)
        if rtt.add(sample) {
            handshakeRTT = sample
            raise(.handshake)
            event.rttSample = sample
            event.isHandshakeSample = true
        }
    }

    private mutating func recordTimestampRoundTrip(
        _ tcp: TCPDetail,
        flags: TCPFlags,
        direction: FlowDirection,
        at now: Date,
        into event: inout QualityEvent
    ) {
        // Never arm on the opening SYN. Its timestamp comes back in the SYN-ACK, which is
        // the very round trip the handshake already measures — arming here would sample
        // the first round trip of every connection twice, counting it once as evidence
        // and once again as weight in the smoothing.
        if direction == .outbound, !flags.isConnectionOpen, let value = tcp.timestampValue {
            // An echo that never came must not block sampling forever. Abandoning the
            // armed sample is right where extending it would be wrong: the interval is no
            // longer a round trip once it has outlived the connection's own timeouts.
            if let armedAt = armedTimestampAt,
                now.timeIntervalSince(armedAt) > RTTEstimator.plausibleCeiling
            {
                armedTimestampValue = nil
                armedTimestampAt = nil
            }
            if armedTimestampValue == nil {
                armedTimestampValue = value
                armedTimestampAt = now
            }
        }

        guard direction == .inbound,
            let echo = tcp.timestampEcho,
            let armed = armedTimestampValue,
            let armedAt = armedTimestampAt,
            serialIsAtOrAfter(echo, armed)
        else { return }

        let sample = now.timeIntervalSince(armedAt)
        if rtt.add(sample) {
            raise(.timestampOption)
            event.rttSample = sample
        }
        armedTimestampValue = nil
        armedTimestampAt = nil
    }

    /// Returns whether this segment covered sequence space already seen, which the
    /// acknowledgement-based estimator needs in order to obey Karn's algorithm.
    @discardableResult
    private mutating func recordSequenceSpace(
        _ tcp: TCPDetail,
        flags: TCPFlags,
        payloadLength: Int,
        direction: FlowDirection
    ) -> Bool {
        var coveredOldGround = false
        var state = direction == .outbound ? outbound : inbound
        state.segments &+= 1

        // SYN and FIN each occupy one sequence number even carrying no data, which is why
        // a handshake advances the space at all.
        let occupied =
            payloadLength + (flags.contains(.syn) ? 1 : 0) + (flags.contains(.fin) ? 1 : 0)

        if occupied > 0 {
            state.sequenceConsumingSegments &+= 1
            let end = tcp.sequence &+ UInt32(truncatingIfNeeded: occupied)

            if let highest = state.highestSequenceEnd {
                if serialIsAfter(end, highest) {
                    state.highestSequenceEnd = end
                    state.highestTimestampValue = tcp.timestampValue
                } else {
                    coveredOldGround = true
                    // Ground already covered. Either it was sent a second time, or this
                    // is the first copy arriving out of order.
                    if let sent = tcp.timestampValue, let highest = state.highestTimestampValue {
                        if serialIsAfter(sent, highest) {
                            state.provenRetransmits &+= 1
                        } else {
                            state.reorders &+= 1
                        }
                    } else {
                        state.ambiguousRetransmits &+= 1
                    }

                    // Karn's algorithm. Once anything has been sent twice, an
                    // acknowledgement no longer says which copy it answers, so the
                    // outstanding sample is spoiled. Spoiling it on any outbound resend
                    // rather than only on an overlapping one errs towards discarding,
                    // which is the safe direction: a missing sample costs nothing, a
                    // wrong one is reported as latency.
                    if direction == .outbound, armedSequenceEnd != nil {
                        armedSequenceWasRetransmitted = true
                    }
                }
            } else {
                state.highestSequenceEnd = end
                state.highestTimestampValue = tcp.timestampValue
            }
        }

        // A duplicate acknowledgement carries no data, repeats the previous acknowledgement
        // and leaves the window alone. One of them is ordinary; three in a row is what
        // makes a sender retransmit, so runs are what get counted.
        if occupied == 0, flags.contains(.ack), !flags.contains(.rst),
            let previous = state.lastAcknowledgement,
            previous == tcp.acknowledgement,
            state.lastWindow == tcp.window
        {
            if state.duplicateAckRun < .max { state.duplicateAckRun &+= 1 }
            if state.duplicateAckRun == 3 { state.duplicateAckEvents &+= 1 }
        } else {
            state.duplicateAckRun = 0
        }

        if flags.contains(.ack) {
            state.lastAcknowledgement = tcp.acknowledgement
            state.lastWindow = tcp.window
        }

        // A zero window is a receiver that has stopped reading. Counted, but kept well
        // away from the loss figures: it is an application stalling, not a network fault,
        // and filing it as loss would raise an alarm about the wrong machine entirely.
        if tcp.window == 0, !flags.contains(.rst), !flags.contains(.syn) {
            state.zeroWindows &+= 1
        }

        if direction == .outbound { outbound = state } else { inbound = state }
        return coveredOldGround
    }

    /// The fallback round trip: time from sending data to seeing it acknowledged.
    ///
    /// Only used where the timestamp option is absent. Where it is present it is strictly
    /// better, and feeding delayed-acknowledgement-inflated samples into the same
    /// estimator would drag the smoothed value up in exchange for nothing.
    private mutating func recordAcknowledgementRoundTrip(
        _ tcp: TCPDetail,
        flags: TCPFlags,
        payloadLength: Int,
        direction: FlowDirection,
        wasResent: Bool,
        at now: Date,
        into event: inout QualityEvent
    ) {
        guard !usesTimestampOption else { return }

        if direction == .outbound {
            // An acknowledgement that never came must not block sampling forever.
            if let armedAt = armedSequenceAt,
                now.timeIntervalSince(armedAt) > RTTEstimator.plausibleCeiling
            {
                armedSequenceEnd = nil
                armedSequenceAt = nil
                armedSequenceWasRetransmitted = false
            }

            // Karn's algorithm again, at the other end: a segment that is itself a
            // repeat cannot start a measurement, because the acknowledgement it earns
            // will not say which copy it answers.
            let occupied =
                payloadLength + (flags.contains(.syn) ? 1 : 0) + (flags.contains(.fin) ? 1 : 0)
            if occupied > 0, !wasResent, armedSequenceEnd == nil {
                armedSequenceEnd = tcp.sequence &+ UInt32(truncatingIfNeeded: occupied)
                armedSequenceAt = now
                armedSequenceWasRetransmitted = false
            }
            return
        }

        guard flags.contains(.ack),
            let armed = armedSequenceEnd,
            let armedAt = armedSequenceAt,
            serialIsAtOrAfter(tcp.acknowledgement, armed)
        else { return }

        let sample = now.timeIntervalSince(armedAt)
        if !armedSequenceWasRetransmitted, rtt.add(sample) {
            raise(.acknowledgement)
            event.rttSample = sample
        }
        armedSequenceEnd = nil
        armedSequenceAt = nil
        armedSequenceWasRetransmitted = false
    }

    private mutating func recordArrivalSpacing(direction: FlowDirection, at now: Date) {
        guard direction == .inbound else { return }
        guard let previousArrival = lastInboundArrival else {
            lastInboundArrival = now
            return
        }
        lastInboundArrival = now

        let gap = now.timeIntervalSince(previousArrival)
        guard gap >= 0, gap <= RTTEstimator.plausibleCeiling else { return }
        guard let previousGap = lastInboundGap else {
            lastInboundGap = gap
            return
        }
        lastInboundGap = gap

        arrivalSpacingVariation += (abs(gap - previousGap) - arrivalSpacingVariation) / 16
        arrivalSpacingSamples &+= 1
    }

    private mutating func recordICMP(_ packet: ParsedPacket) {
        guard let icmp = packet.icmp else { return }
        // Unreachable and time-exceeded mean the path gave up. Echo traffic is neither an
        // error nor evidence of one, and is not counted here.
        switch (packet.transport, icmp.type) {
        case (.icmp, 3), (.icmp, 11), (.icmpv6, 1), (.icmpv6, 3):
            icmpErrors &+= 1
        default:
            break
        }
    }

    private mutating func raise(_ source: RTTSource) {
        if let current = rttSource, current >= source { return }
        rttSource = source
    }

    /// Distance travelled, guessed from the hop limit that arrived.
    ///
    /// Senders start at one of a few conventional values, so the distance is the gap up to
    /// the next one. It is a guess: a host starting somewhere unusual, or a path longer
    /// than the gap, both read wrong. Shown as an estimate and never used for a verdict.
    static func hopsTravelled(observedHopLimit: UInt8) -> UInt8? {
        for initial in [UInt8(64), 128, 255] where observedHopLimit <= initial {
            return initial - observedHopLimit
        }
        return nil
    }

    // MARK: - Reading

    public var segmentsOut: UInt64 { outbound.segments }
    public var segmentsIn: UInt64 { inbound.segments }

    /// Segments that covered ground already seen, on the way out and on the way in.
    ///
    /// Whether this is proof or inference depends on `retransmitsAreProven`: without the
    /// timestamp option a resent segment and a reordered one look identical, and both land
    /// here. The count travels with that flag everywhere it is published, the same way a
    /// hostname travels with whether it was proof.
    public var retransmitsOut: UInt64 {
        outbound.provenRetransmits + outbound.ambiguousRetransmits
    }
    public var retransmitsIn: UInt64 {
        inbound.provenRetransmits + inbound.ambiguousRetransmits
    }
    public var retransmitsAreProven: Bool { usesTimestampOption }

    /// Segments the network delivered late rather than the sender repeating. Only ever
    /// non-zero where the timestamp option made the distinction possible.
    public var reordersOut: UInt64 { outbound.reorders }
    public var reordersIn: UInt64 { inbound.reorders }

    public var duplicateAckEventsOut: UInt64 { outbound.duplicateAckEvents }
    public var duplicateAckEventsIn: UInt64 { inbound.duplicateAckEvents }
    public var zeroWindowEvents: UInt64 { outbound.zeroWindows + inbound.zeroWindows }

    public var sequenceConsumingSegmentsOut: UInt64 { outbound.sequenceConsumingSegments }
    public var sequenceConsumingSegmentsIn: UInt64 { inbound.sequenceConsumingSegments }

    /// Whether anything here rests on measurement rather than on absence.
    ///
    /// False for QUIC and every other UDP conversation. That is not a small exception:
    /// HTTP/3 carries a large and growing share of browser traffic and offers a passive
    /// observer no sequence numbers, no acknowledgements and no round trips whatsoever.
    /// Every total built from these flows publishes what share of bytes it could see.
    public var isMeasurable: Bool { rtt.sampleCount > 0 }

    /// Whether the arrival-spacing figure means anything for this flow.
    ///
    /// Wants enough samples to have smoothed, and is only ever offered for UDP, where
    /// there is no round-trip figure to prefer.
    public var arrivalSpacingIsMeaningful: Bool { arrivalSpacingSamples >= 16 }

    /// How far the typical round trip sits above this path's own floor.
    ///
    /// The bufferbloat reading. A path whose minimum is 12 ms and whose smoothed value is
    /// 180 ms under load is not a slow path; it is a full buffer somewhere, usually the
    /// router at the end of the street. Meaningless without both figures, hence optional.
    public var queueingDelay: TimeInterval? {
        guard let smoothed = rtt.smoothed, let minimum = rtt.minimum else { return nil }
        return Swift.max(0, smoothed - minimum)
    }
}

// MARK: - Aggregation

/// The quality reading across a set of flows at one moment.
///
/// Every ratio here is optional and every one of them carries its own denominator,
/// because the denominators differ: the round-trip figures cover only flows that yielded a
/// sample, while the retransmission rates cover every TCP segment seen. Publishing them as
/// bare numbers would invite them to be read as covering the same traffic.
public struct QualitySummary: Sendable, Equatable {
    /// Flows a round trip could be measured on, and flows where it could not.
    public var measuredFlowCount = 0
    public var unmeasurableFlowCount = 0
    public var measuredBytes: UInt64 = 0
    public var unmeasurableBytes: UInt64 = 0

    public var medianRTT: TimeInterval?
    public var minimumRTT: TimeInterval?

    public var segmentsOut: UInt64 = 0
    public var segmentsIn: UInt64 = 0
    public var retransmitsOut: UInt64 = 0
    public var retransmitsIn: UInt64 = 0

    public var connectionAttempts = 0
    public var connectionTimeouts = 0
    public var connectionRefusals = 0

    public var discardedSamples: UInt64 = 0
    public var segmentOffloadFlowCount = 0

    public init() {}

    /// What share of the bytes moved could be measured at all.
    ///
    /// The figure every latency number here has to be read against. HTTP/3 runs over QUIC,
    /// which is UDP: no sequence numbers, no acknowledgements, no round trips. On a
    /// machine that mostly browses, this can honestly be well under half.
    public var measuredByteShare: Double? {
        let total = measuredBytes + unmeasurableBytes
        guard total > 0 else { return nil }
        return Double(measuredBytes) / Double(total)
    }

    /// Repeats as a share of segments sent. Nil rather than zero when nothing was sent,
    /// because a rate over no segments is not zero, it is unknown.
    public var retransmitRateOut: Double? {
        guard segmentsOut > 0 else { return nil }
        return Double(retransmitsOut) / Double(segmentsOut)
    }

    public var retransmitRateIn: Double? {
        guard segmentsIn > 0 else { return nil }
        return Double(retransmitsIn) / Double(segmentsIn)
    }

    /// How long a connection attempt is given before its silence counts as a failure.
    ///
    /// TCP's own initial retransmission timeout is a second, and it retries; anything
    /// still unanswered after five has not been answered. Shorter than this and every
    /// connection opened in the last instant would be reported as a failure, which would
    /// make a busy machine look like a broken one.
    public static let handshakeGrace: TimeInterval = 5


    /// Folds a set of flows into one reading.
    ///
    /// `now` decides which unanswered connections have waited long enough to count as
    /// failures, and is passed rather than read so the result is a function of its inputs.
    public static func summarise(_ flows: [Flow], at now: Date) -> QualitySummary {
        var summary = QualitySummary()
        var smoothedSamples: [TimeInterval] = []

        for flow in flows {
            // Beholder's own probes are not evidence about anyone's network but Beholder's.
            if flow.isSelfOriginated { continue }
            let quality = flow.quality

            if quality.isMeasurable {
                summary.measuredFlowCount += 1
                summary.measuredBytes += flow.totalBytes
                if let smoothed = quality.rtt.smoothed { smoothedSamples.append(smoothed) }
                if let minimum = quality.rtt.minimum {
                    summary.minimumRTT = Swift.min(summary.minimumRTT ?? minimum, minimum)
                }
            } else {
                summary.unmeasurableFlowCount += 1
                summary.unmeasurableBytes += flow.totalBytes
            }

            summary.segmentsOut += quality.segmentsOut
            summary.segmentsIn += quality.segmentsIn
            summary.retransmitsOut += quality.retransmitsOut
            summary.retransmitsIn += quality.retransmitsIn
            summary.discardedSamples += UInt64(quality.rtt.discardedCount)
            if quality.sawSegmentOffload { summary.segmentOffloadFlowCount += 1 }

            // Only connections this machine opened. An inbound connection's fate is the
            // far end's business and says nothing about the path out.
            guard flow.key.transport == .tcp, flow.initiationIsCertain,
                flow.initiatedLocally == true
            else { continue }
            summary.connectionAttempts += 1

            if quality.sawSynAck { continue }
            if quality.sawReset {
                // Answered, just not welcomed. The far end declining is not the network
                // failing, and folding the two together would blame the path for a closed
                // port.
                summary.connectionRefusals += 1
            } else if flow.connectionTimedOut(at: now) {
                summary.connectionTimeouts += 1
            }
        }

        summary.medianRTT = smoothedSamples.median
        return summary
    }
}

extension Flow {
    /// Whether this is a connection this machine opened that has gone unanswered long
    /// enough to count as failed.
    ///
    /// One rule, in Core, because two things decide it: the live summary above, and the
    /// per-minute series the daemon persists. They were deciding it separately, and the
    /// daemon's copy sat in an executable no test can reach — so the two could drift
    /// without anything failing.
    public func connectionTimedOut(at now: Date) -> Bool {
        guard key.transport == .tcp, initiationIsCertain, initiatedLocally == true,
            !quality.sawSynAck, !quality.sawReset
        else { return false }
        return now.timeIntervalSince(firstSeen) > QualitySummary.handshakeGrace
    }
}
