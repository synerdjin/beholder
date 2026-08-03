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

    /// Records the hostname a specific connection asked for, from its own ClientHello.
    ///
    /// SNI is direct evidence for this flow, so it replaces any name previously guessed
    /// from DNS.
    public func setServerName(_ name: String, for key: FlowKey) {
        guard flows[key] != nil else { return }
        flows[key]?.hostName = name
        flows[key]?.hostNameSource = .serverNameIndication
    }

    /// Fills in hostnames for flows that do not already have better evidence. Applied to
    /// every flow each pass, because a DNS answer often arrives after the connection it
    /// was looking up has already started.
    ///
    /// The lookup returns the source alongside the name. An earlier version stamped every
    /// name as `.dns` regardless of where it came from, which made reverse-lookup results
    /// invisible in the statistics and, worse, presented a PTR guess with the same
    /// confidence as an observed DNS answer.
    public func applyNames(_ lookup: (IPAddress) -> (name: String, source: NameSource)?) {
        for (key, flow) in flows {
            guard let resolved = lookup(flow.key.remote) else { continue }
            // Never downgrade: a name read from this connection's own handshake outranks
            // anything inferred from an address.
            if let existing = flow.hostNameSource, existing >= resolved.source { continue }
            flows[key]?.hostName = resolved.name
            flows[key]?.hostNameSource = resolved.source
        }
    }

    /// Fills in locations for flows that do not have one yet. Cheap to call repeatedly:
    /// the geolocation cache absorbs the repeats, and a flow is only asked about once.
    public func applyLocations(_ lookup: (IPAddress) -> GeoLocation?) {
        for (key, flow) in flows where flow.location == nil {
            if let location = lookup(flow.key.remote) {
                flows[key]?.location = location
            }
        }
    }

    /// Identifies the operator behind each named flow. Re-applied when a name changes,
    /// since a flow only becomes classifiable once it has a hostname.
    public func applyClassifications(_ classify: (String) -> HostClassification) {
        for (key, flow) in flows {
            guard let hostName = flow.hostName else { continue }
            if flow.classification != nil, flow.classification?.matchedDomain != nil {
                continue
            }
            let result = classify(hostName)
            flows[key]?.classification = result.isEmpty ? nil : result
        }
    }

    /// Names the network behind each remote address. Unlike naming and classification
    /// this needs no hostname, so it reaches the addresses nothing else can identify.
    public func applyNetworkOperators(_ lookup: (IPAddress) -> NetworkOperator?) {
        for (key, flow) in flows where flow.networkOperator == nil {
            if let operatorInfo = lookup(flow.key.remote) {
                flows[key]?.networkOperator = operatorInfo
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
