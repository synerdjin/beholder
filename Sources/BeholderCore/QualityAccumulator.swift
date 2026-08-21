import Foundation

// MARK: - Grouping the far end

extension Flow {
    /// The fallback when no autonomous system is known: the address's prefix.
    ///
    /// A /24 or a /48, not the address itself. Addresses within a prefix are almost always
    /// the same operator and the same path, and grouping by bare address would produce a
    /// new group for every host contacted — which, with the group cap below, means
    /// everything falls into the overflow bucket and the time series says nothing. This
    /// matters most on a machine with no ASN database installed, where it is the only
    /// grouping there is.
    /// Read off the address's own storage rather than through `networkOrderBytes`, which
    /// heap-allocates a fresh array on every call, and with hand-written hex rather than
    /// `String(format:)`, which is a varargs trip through Foundation's formatter. This runs
    /// once per new flow on the flow queue — during a page load or a port scan, thousands
    /// of times a second.
    public static func addressGroup(for address: IPAddress) -> String {
        switch address.family {
        case .v4:
            let value = address.low
            return "\((value >> 24) & 0xFF).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).0/24"
        case .v6:
            let prefix = address.high
            return hexGroup(prefix >> 48) + ":" + hexGroup(prefix >> 32) + ":"
                + hexGroup(prefix >> 16) + "::/48"
        }
    }

    private static let hexDigits = Array("0123456789abcdef")

    /// One IPv6 group: lowercase hex, leading zeros suppressed, as the address is written.
    private static func hexGroup(_ value: UInt64) -> String {
        let group = value & 0xFFFF
        guard group > 0 else { return "0" }

        var digits = ""
        var started = false
        for shift in stride(from: 12, through: 0, by: -4) {
            let nibble = Int((group >> UInt64(shift)) & 0xF)
            if nibble != 0 { started = true }
            if started { digits.append(hexDigits[nibble]) }
        }
        return digits
    }
}

// MARK: - Round-trip distribution

/// A fixed log-scale histogram of round-trip times.
///
/// Four buckets to a doubling, starting at 0.1 ms: sixty-four of them reach about 6.5
/// seconds, which spans everything from a loopback reply to a connection that has all but
/// given up. Fixed size and mergeable, so a minute's distribution costs the same whether
/// it saw ten samples or ten million — the alternative, keeping the samples, is unbounded
/// in exactly the situation that matters most.
///
/// The cost is resolution: a percentile read back from this is accurate to about a fifth
/// of its own value. That is why the *minimum* is stored exactly and separately wherever
/// this is used. The minimum is the figure the ISP analysis reasons about, and blurring it
/// by a fifth would blur the baseline everything else is measured against.
public struct RTTHistogram: Sendable, Equatable {
    public static let bucketCount = 64
    public static let bucketsPerOctave = 4.0
    public static let floorMilliseconds = 0.1

    private var counts = [UInt32](repeating: 0, count: bucketCount)
    public private(set) var total: UInt32 = 0

    public init() {}

    static func index(forMilliseconds milliseconds: Double) -> Int {
        guard milliseconds > floorMilliseconds else { return 0 }
        let octaves = log2(milliseconds / floorMilliseconds)
        return Swift.min(bucketCount - 1, Swift.max(0, Int(octaves * bucketsPerOctave)))
    }

    /// The value a bucket stands for: its geometric middle, which is the right centre for
    /// a scale whose buckets grow by a constant ratio.
    static func representativeMilliseconds(ofBucket index: Int) -> Double {
        floorMilliseconds * pow(2, (Double(index) + 0.5) / bucketsPerOctave)
    }

    public mutating func add(milliseconds: Double) {
        counts[Self.index(forMilliseconds: milliseconds)] &+= 1
        total &+= 1
    }

    public mutating func merge(_ other: RTTHistogram) {
        for index in 0..<Self.bucketCount { counts[index] &+= other.counts[index] }
        total &+= other.total
    }

    /// The value below which the given share of samples fall, in milliseconds.
    ///
    /// Nil when there is nothing to ask about. A percentile over an empty set is not zero.
    public func percentile(_ fraction: Double) -> Double? {
        guard total > 0 else { return nil }
        let target = Swift.max(1, Int((Double(total) * fraction).rounded(.up)))
        var seen = 0
        for index in 0..<Self.bucketCount {
            seen += Int(counts[index])
            if seen >= target { return Self.representativeMilliseconds(ofBucket: index) }
        }
        return Self.representativeMilliseconds(ofBucket: Self.bucketCount - 1)
    }
}

extension Array where Element == Double {
    /// The middle value once sorted, or nil when there is nothing to ask about.
    ///
    /// One implementation, beside `RTTHistogram.percentile` which owns the same decision.
    /// Six of these existed — in `FlowQuality`, twice in `ReliabilityReport`, in
    /// `FlowStoreQuality`, in `MCPTools` and in the app's history chart — each with its own
    /// empty-versus-nil guard, in a feature whose entire premise is that the two differ.
    /// The daemon and the window could have disagreed about the same statistic without
    /// anything failing.
    public var median: Double? {
        guard !isEmpty else { return nil }
        return sorted()[count / 2]
    }
}

// MARK: - Per-minute buckets

/// One minute of measurement for one interface and one destination network.
public struct QualityBucket: Sendable, Equatable {
    public var histogram = RTTHistogram()
    /// Kept exactly rather than read off the histogram, because this is the baseline the
    /// whole ISP analysis is measured against and the histogram is only good to a fifth.
    public var rttMinimum: TimeInterval?

    public var handshakeSamples: UInt32 = 0
    public var handshakeMinimum: TimeInterval?

    public var segmentsOut: UInt64 = 0
    public var segmentsIn: UInt64 = 0
    public var retransmitsOut: UInt64 = 0
    public var retransmitsIn: UInt64 = 0

    public var bytesOut: UInt64 = 0
    public var bytesIn: UInt64 = 0
    /// Bytes that moved on connections a round trip could be read from, and bytes that
    /// moved on connections where it could not. The second is mostly QUIC.
    public var measuredBytes: UInt64 = 0
    public var unmeasurableBytes: UInt64 = 0

    public var connectionAttempts: UInt32 = 0

    /// Distinct conversations that contributed to this minute.
    public private(set) var flowKeys: Set<FlowKey> = []

    /// The last conversation counted, so a run of packets from one flow costs a comparison
    /// rather than a hash and an insert. Traffic arrives in runs — a download is thousands
    /// of consecutive packets from the same flow — so this skips nearly every insert.
    private var lastFlow: FlowKey?

    public init() {}

    public var rttSamples: UInt32 { histogram.total }
    public var flowCount: Int { flowKeys.count }

    /// Folds one packet's measurement in.
    ///
    /// A method on the bucket rather than a block in the accumulator so the whole update
    /// happens through one subscript access. Reading the bucket out into a `var` and
    /// writing it back left the dictionary holding the original the whole time, so the
    /// histogram's counts array and the flow-key set were both non-uniquely referenced and
    /// the first write to each deep-copied its buffer — per packet, on `flowQueue`, which
    /// is the cost this file's own doc comment says fixed-size buckets exist to avoid.
    mutating func record(_ event: QualityEvent, flow: FlowKey) {
        if let sample = event.rttSample {
            histogram.add(milliseconds: sample * 1000)
            rttMinimum = Swift.min(rttMinimum ?? sample, sample)
            if event.isHandshakeSample {
                handshakeSamples &+= 1
                handshakeMinimum = Swift.min(handshakeMinimum ?? sample, sample)
            }
        }
        segmentsOut &+= UInt64(event.segmentsOut)
        segmentsIn &+= UInt64(event.segmentsIn)
        retransmitsOut &+= UInt64(event.retransmitsOut)
        retransmitsIn &+= UInt64(event.retransmitsIn)
        bytesOut &+= event.bytesOut
        bytesIn &+= event.bytesIn
        if event.flowIsMeasured {
            measuredBytes &+= event.bytesOut &+ event.bytesIn
        } else {
            unmeasurableBytes &+= event.bytesOut &+ event.bytesIn
        }
        if event.isConnectionAttempt { connectionAttempts &+= 1 }
        if lastFlow != flow {
            flowKeys.insert(flow)
            lastFlow = flow
        }
    }
}

/// Accumulates measurement into per-minute buckets, ready to be written out.
///
/// Attribution is to the minute the packet arrived in, not the minute the row was written.
/// The distinction is the entire reason this exists rather than reusing the `rollups`
/// table: that one keys on the minute a flow *retired*, so a download running from eight
/// until midnight lands wholly in the midnight bucket. For a chart meant to answer "was it
/// bad at eight on Tuesday" that is not an approximation, it is the wrong answer.
///
/// Confined to one queue, like the flow table it is fed from.
public final class QualityAccumulator {

    public struct Key: Hashable, Sendable {
        public let minute: Int64
        public let interface: String
        public let destinationGroup: String

        public init(minute: Int64, interface: String, destinationGroup: String) {
            self.minute = minute
            self.interface = interface
            self.destinationGroup = destinationGroup
        }
    }

    /// The most distinct networks any one minute may name before the rest are pooled.
    ///
    /// A port scan or a peer-to-peer client can touch thousands of networks in a minute,
    /// and a row for each would turn a time series into a log. Sixty-four is far more than
    /// the handful of large networks a normal minute's browsing touches.
    public static let maximumGroupsPerMinute = 64
    public static let overflowGroup = "(other)"

    private var buckets: [Key: QualityBucket] = [:]
    private var labels: [String: String] = [:]
    private var groupsSeen: [Int64: Set<String>] = [:]
    private var overflowedMinutes: Set<Int64> = []

    public init() {}

    public var bucketCount: Int { buckets.count }

    /// Whether any minute had to pool networks into the overflow group. Surfaced rather
    /// than silent, because a pooled minute cannot support a common-mode judgement.
    public func overflowed(minute: Int64) -> Bool { overflowedMinutes.contains(minute) }

    public static func minute(of timestamp: Date) -> Int64 {
        Int64(timestamp.timeIntervalSince1970 / 60)
    }

    /// The inverse. Paired with `minute(of:)` rather than spelled out at each call site,
    /// because the two have to agree about the epoch and a disagreement between them is
    /// invisible — rows simply land one bucket off, and nothing fails.
    public static func date(ofMinute minute: Int64) -> Date {
        Date(timeIntervalSince1970: Double(minute) * 60)
    }

    public func record(
        _ event: QualityEvent,
        flow: FlowKey,
        interface: String,
        group: String,
        label: String?,
        at timestamp: Date
    ) {
        guard !event.isEmpty else { return }
        let minute = Self.minute(of: timestamp)

        // Every mutation below goes through a subscript rather than through a local copy,
        // for the reason spelled out on `QualityBucket.record`: a copy out and a write back
        // deep-copies the collection's buffer on the first write, once per packet.
        var resolved = group
        if !groupsSeen[minute, default: []].contains(group) {
            if groupsSeen[minute]?.count ?? 0 >= Self.maximumGroupsPerMinute {
                resolved = Self.overflowGroup
                overflowedMinutes.insert(minute)
            } else {
                groupsSeen[minute, default: []].insert(group)
            }
        }
        if let label, resolved != Self.overflowGroup { labels[resolved] = label }

        let key = Key(minute: minute, interface: interface, destinationGroup: resolved)
        buckets[key, default: QualityBucket()].record(event, flow: flow)
    }

    public func label(for group: String) -> String? { labels[group] }

    /// Hands over every minute that has certainly finished.
    ///
    /// "Certainly" allows for packets still in flight between the capture queue and here:
    /// a minute is only closed once the clock has moved a whole minute past it, so a
    /// straggler cannot arrive after its row has been written and be silently dropped.
    public func drainClosedMinutes(now: Date) -> [(key: Key, bucket: QualityBucket)] {
        let cutoff = Self.minute(of: now) - 1
        return drain { $0.minute < cutoff }
    }

    /// Hands over everything, closed or not. For shutdown, where the alternative is losing
    /// the minute in progress.
    public func drainAll() -> [(key: Key, bucket: QualityBucket)] {
        drain { _ in true }
    }

    private func drain(_ include: (Key) -> Bool) -> [(key: Key, bucket: QualityBucket)] {
        var drained: [(key: Key, bucket: QualityBucket)] = []
        for (key, bucket) in buckets where include(key) {
            drained.append((key, bucket))
            buckets.removeValue(forKey: key)
        }
        let remaining = Set(buckets.keys.map(\.minute))
        groupsSeen = groupsSeen.filter { remaining.contains($0.key) }
        overflowedMinutes = overflowedMinutes.filter { remaining.contains($0) }
        return drained.sorted { $0.key.minute < $1.key.minute }
    }
}
