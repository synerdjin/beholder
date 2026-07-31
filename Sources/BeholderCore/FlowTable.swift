import Foundation

/// Aggregates captured packets into conversations.
///
/// Not thread-safe by design — the capture engine already serialises packets onto one
/// queue, and adding a lock per packet would cost more than it protects. Callers must
/// confine a table to a single queue.
public final class FlowTable {
    public struct Configuration: Sendable {
        /// How long a TCP flow may sit idle before being retired. Generous, because a
        /// long-lived idle connection (an IMAP or WebSocket keepalive) is still a real
        /// connection the user expects to see listed.
        public var tcpIdleTimeout: TimeInterval = 300
        /// Shorter for a torn-down connection: once FIN or RST is seen there is nothing
        /// more coming.
        public var closedIdleTimeout: TimeInterval = 30
        /// UDP has no lifecycle, so idleness is all there is to go on.
        public var udpIdleTimeout: TimeInterval = 60
        /// Upper bound on live flows, so a port scan or a flood cannot grow the table
        /// without limit. The least recently active flows are evicted first.
        public var maximumFlows = 8192

        public init() {}
    }

    public private(set) var configuration: Configuration
    private var flows: [FlowKey: Flow] = [:]

    /// Flows retired since the last drain, kept so a consumer can persist them.
    private var retired: [Flow] = []

    /// Counts flows dropped by the size cap. Surfaced rather than silent, because a
    /// non-zero value means the picture being shown is incomplete.
    public private(set) var evictedFlowCount: UInt64 = 0

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    public var count: Int { flows.count }

    /// Folds one captured packet into the table.
    ///
    /// `isNew` lets the caller react the instant a conversation appears. That matters for
    /// short-lived sockets — a DNS query and its answer can be over in under a
    /// millisecond — where waiting for the next scheduled attribution poll means the
    /// socket is already gone.
    @discardableResult
    public func record(
        _ packet: ParsedPacket,
        interfaceName: String,
        localAddresses: Set<IPAddress>,
        at timestamp: Date = Date()
    ) -> (key: FlowKey, isNew: Bool) {
        let (key, direction) = FlowKey.make(from: packet, localAddresses: localAddresses)

        let isNew = flows[key] == nil
        if isNew {
            flows[key] = Flow(key: key, interfaceName: interfaceName, at: timestamp)
        }
        flows[key]?.record(
            direction: direction,
            wireBytes: packet.wireBytes,
            tcpFlags: packet.tcpFlags,
            at: timestamp
        )
        return (key, isNew)
    }

    /// Applies an ownership lookup to every flow that still lacks one.
    ///
    /// Already-attributed flows are left alone: the socket that produced them may since
    /// have closed and had its port reused, and overwriting a good answer with a newer
    /// wrong one is worse than not updating at all.
    public func attribute(
        _ resolve: (FlowKey) -> (owner: ProcessOwner, tcpState: TCPState?)?
    ) {
        for (key, flow) in flows where flow.owner == nil {
            guard let resolution = resolve(key) else { continue }
            flows[key]?.owner = resolution.owner
            flows[key]?.tcpState = resolution.tcpState
        }
    }

    /// Refreshes TCP state on flows that already have an owner, so the display can show a
    /// connection moving to CLOSE_WAIT without re-attributing it.
    public func refreshState(_ resolve: (FlowKey) -> TCPState?) {
        for (key, flow) in flows where flow.owner != nil {
            if let state = resolve(key) {
                flows[key]?.tcpState = state
            }
        }
    }

    /// Whether any flow is still waiting to be attributed. Drives the adaptive poll rate:
    /// there is no point walking every process's file descriptors when nothing is
    /// unresolved.
    public var hasUnattributedFlows: Bool {
        flows.values.contains { $0.owner == nil }
    }

    /// Retires idle flows and enforces the size cap. Returns the flows removed.
    @discardableResult
    public func expire(at now: Date = Date()) -> [Flow] {
        var removed: [Flow] = []

        for (key, flow) in flows {
            let timeout: TimeInterval
            if flow.isClosing {
                timeout = configuration.closedIdleTimeout
            } else if flow.key.transport == .tcp {
                timeout = configuration.tcpIdleTimeout
            } else {
                timeout = configuration.udpIdleTimeout
            }

            if now.timeIntervalSince(flow.lastSeen) > timeout {
                removed.append(flow)
                flows.removeValue(forKey: key)
            }
        }

        if flows.count > configuration.maximumFlows {
            let excess = flows.count - configuration.maximumFlows
            let oldest = flows.values
                .sorted { $0.lastSeen < $1.lastSeen }
                .prefix(excess)
            for flow in oldest {
                flows.removeValue(forKey: flow.key)
                removed.append(flow)
            }
            evictedFlowCount += UInt64(excess)
        }

        retired.append(contentsOf: removed)
        return removed
    }

    /// Hands over retired flows and clears the backlog, for persistence.
    public func drainRetired() -> [Flow] {
        defer { retired.removeAll(keepingCapacity: true) }
        return retired
    }

    public func activeFlows() -> [Flow] {
        Array(flows.values)
    }

    /// Live flows grouped by owning process, each group sorted by traffic volume.
    /// Flows with no known owner are collected under a nil key rather than hidden.
    public func flowsByProcess() -> [(owner: ProcessOwner?, flows: [Flow], totalBytes: UInt64)] {
        var groups: [ProcessOwner?: [Flow]] = [:]
        for flow in flows.values {
            groups[flow.owner, default: []].append(flow)
        }

        return groups
            .map { owner, flows in
                (
                    owner: owner,
                    flows: flows.sorted { $0.totalBytes > $1.totalBytes },
                    totalBytes: flows.reduce(0) { $0 + $1.totalBytes }
                )
            }
            .sorted { $0.totalBytes > $1.totalBytes }
    }
}
