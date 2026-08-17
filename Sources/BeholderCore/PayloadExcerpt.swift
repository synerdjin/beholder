import Foundation

/// A copy of some of a packet's payload, taken while the pcap buffer was still alive.
///
/// This exists because `ParsedPacket` deliberately carries no bytes — only offsets into a
/// buffer that libpcap frees the instant the capture callback returns. Anything that wants
/// to look at payload later must own it, and this is that owned copy.
public struct PayloadExcerpt: Sendable, Equatable {
    public let direction: FlowDirection
    public let bytes: [UInt8]

    /// How much payload the packet actually carried, which is not `bytes.count`.
    ///
    /// `bytes` stops at `maximumBytesPerPacket`; this does not. Counting the copy instead
    /// would understate the conversation by exactly the amount that was too big to keep —
    /// so the coverage line would report "first 4 KB of 40 KB" for a connection that had
    /// moved 300 KB, which is the kind of undercount-presented-as-a-total this codebase
    /// refuses everywhere else.
    public let observedBytes: Int

    public init(direction: FlowDirection, bytes: [UInt8], observedBytes: Int? = nil) {
        self.direction = direction
        self.bytes = bytes
        self.observedBytes = observedBytes ?? bytes.count
    }

    /// The most any single packet contributes.
    ///
    /// Smaller than the raised snaplen on purpose: a full-MTU packet of a bulk transfer
    /// would otherwise fill a direction's whole budget in one go, and the opening bytes —
    /// the request line, the headers, the greeting — are what identify a conversation.
    public static let maximumBytesPerPacket = 2048

    /// Copies at most `maximumBytesPerPacket` out of a live capture buffer.
    ///
    /// Must be called synchronously inside the capture callback. Returns bytes rather than
    /// a whole `PayloadExcerpt` because the capture queue does not yet know which way the
    /// packet went: direction comes from `FlowKey` normalisation, which needs the set of
    /// local interface addresses, and that set is confined to the flow queue. So the bytes
    /// are copied here and labelled there.
    ///
    /// Returns nil rather than an empty array so callers can skip the queue hop entirely
    /// for the pure-ACK packets that make up much of a TCP conversation.
    public static func copy(from payload: UnsafeRawBufferPointer) -> [UInt8]? {
        guard !payload.isEmpty else { return nil }
        let count = min(payload.count, maximumBytesPerPacket)
        return Array(UnsafeRawBufferPointer(rebasing: payload[0..<count]))
    }
}

/// What has been kept for one connection, and how much of the whole it represents.
///
/// `captured` and `observed` are tracked separately because they diverge immediately and
/// permanently: the buffer stops at 4 KB while the conversation carries on. Showing the
/// first without the second would present a fragment as if it were the whole thing, which
/// is the failure this codebase repeatedly refuses — a total that does not say it is an
/// undercount is worse than no total.
public struct StoredExcerpt: Sendable, Equatable {
    public var sent: [UInt8] = []
    public var received: [UInt8] = []
    /// Payload bytes seen in each direction, including everything not kept.
    public var sentObserved: UInt64 = 0
    public var receivedObserved: UInt64 = 0

    public var isEmpty: Bool { sent.isEmpty && received.isEmpty }

    /// What this connection contributes to a snapshot's payload budget.
    public var byteCount: Int { sent.count + received.count }
}

/// Holds the opening bytes of unencrypted connections, in memory and nowhere else.
///
/// **Not thread-safe.** Confine it to one queue, as with `FlowTable` and `FlowStore`; in
/// the daemon that is `FlowMonitor.flowQueue`.
///
/// Everything about this type is bounded, because it is the one place in Beholder that
/// holds the contents of traffic rather than facts about it. Per-direction cap, flow count
/// cap, and prompt release when a connection retires. Nothing here is ever handed to
/// `FlowStore` or to the run transcript.
public final class PayloadExcerptStore {
    /// The opening bytes kept for each direction of each connection.
    ///
    /// 4 KB comfortably covers an HTTP request line plus its headers, a full mail
    /// greeting exchange, and the start of a response body — the part that says what a
    /// connection is for. Beyond that it is payload for payload's sake.
    public static let maximumBytesPerDirection = 4096

    /// How many connections are buffered at once. Reached only on a machine doing a great
    /// deal of unencrypted work; past it the least recently active connection is dropped.
    public static let maximumFlows = 64

    private var excerpts: [FlowKey: StoredExcerpt] = [:]
    /// Insertion-ordered keys, oldest first. A plain array rather than a linked list
    /// because it is bounded at 64 entries and only touched once per appended packet.
    private var order: [FlowKey] = []

    /// Connections dropped to stay within `maximumFlows`, so the count can be reported
    /// rather than the loss being silent.
    public private(set) var evictedFlowCount: UInt64 = 0

    public init() {}

    public var count: Int { excerpts.count }

    /// Adds what was seen in one packet, keeping only what fits.
    ///
    /// **Must be called for every packet of a buffered flow, including once the buffer is
    /// full.** The observed counter keeps rising after the bytes stop being kept, and that
    /// difference is the entire basis for telling a reader it is looking at a fragment.
    /// Skipping the call to save work freezes the count and turns "first 4 KB of 900 KB"
    /// into "first 4 KB of 8 KB" — a caveat that quietly stops being true.
    public func append(_ excerpt: PayloadExcerpt, for key: FlowKey) {
        if excerpts[key] == nil {
            evictIfNeeded(making: 1)
            order.append(key)
        } else {
            // Recency is last-active, not first-seen: a busy long-lived connection must not
            // be evicted in favour of a burst of one-packet flows.
            touch(key)
        }

        var stored = excerpts[key] ?? StoredExcerpt()
        let limit = Self.maximumBytesPerDirection
        switch excerpt.direction {
        case .outbound:
            stored.sentObserved += UInt64(excerpt.observedBytes)
            let room = limit - stored.sent.count
            if room > 0 {
                stored.sent.append(contentsOf: excerpt.bytes.prefix(room))
            }
        case .inbound:
            stored.receivedObserved += UInt64(excerpt.observedBytes)
            let room = limit - stored.received.count
            if room > 0 {
                stored.received.append(contentsOf: excerpt.bytes.prefix(room))
            }
        }
        excerpts[key] = stored
    }

    public func excerpt(for key: FlowKey) -> StoredExcerpt? {
        excerpts[key]
    }

    /// The buffered payload in wire form, within a byte budget.
    ///
    /// Biggest first, on the reasoning that a connection which has moved more unencrypted
    /// data is the one worth seeing; the count of what would not fit is returned so the
    /// caller can say so rather than quietly showing less.
    ///
    /// Lives here rather than in the daemon because it is the only per-snapshot bound on
    /// the one structure that holds the contents of traffic. In an executable target no
    /// test could reach it, and an inverted sort or an off-by-one in the budget would be
    /// silent.
    public func publishable(budget: Int) -> (excerpts: [WireExcerpt], dropped: Int) {
        // Ties broken on the id, not left to the dictionary. Swift seeds its hashing per
        // process, so an unstable order would silently change *which* equal-sized flows
        // survive the budget from one snapshot to the next, and payload would appear and
        // disappear in the view for no reason the user could see.
        let candidates = excerpts
            .filter { !$0.value.isEmpty }
            .sorted {
                $0.value.byteCount != $1.value.byteCount
                    ? $0.value.byteCount > $1.value.byteCount
                    : $0.key.wireID < $1.key.wireID
            }

        var published: [WireExcerpt] = []
        var remaining = budget
        var dropped = 0
        for (key, stored) in candidates {
            guard stored.byteCount <= remaining else {
                dropped += 1
                continue
            }
            remaining -= stored.byteCount
            published.append(
                WireExcerpt(
                    id: key.wireID,
                    sent: stored.sent.isEmpty ? nil : Data(stored.sent),
                    received: stored.received.isEmpty ? nil : Data(stored.received),
                    sentObserved: stored.sentObserved,
                    receivedObserved: stored.receivedObserved
                )
            )
        }
        return (published, dropped)
    }

    /// Releases a connection's bytes. Called when a flow retires, so a finished
    /// conversation stops being held in memory rather than waiting for eviction pressure.
    public func forget(_ key: FlowKey) {
        guard excerpts.removeValue(forKey: key) != nil else { return }
        order.removeAll { $0 == key }
    }

    // MARK: - Bounds

    private func touch(_ key: FlowKey) {
        guard let index = order.firstIndex(of: key) else { return }
        order.remove(at: index)
        order.append(key)
    }

    private func evictIfNeeded(making room: Int) {
        while excerpts.count + room > Self.maximumFlows, let oldest = order.first {
            order.removeFirst()
            excerpts.removeValue(forKey: oldest)
            evictedFlowCount += 1
        }
    }
}
