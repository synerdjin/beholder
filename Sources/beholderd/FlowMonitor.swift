import BeholderCore
import Darwin
import Dispatch
import Foundation

/// Joins captured packets to the processes that own them.
///
/// Three pieces of work run on three different schedules, deliberately kept apart:
///
/// - Packets arrive on the capture queue and are folded into the flow table.
/// - Attribution walks every process's file descriptors, which takes tens of
///   milliseconds. It runs on its own queue so it can never stall capture, and its
///   result is handed to the flow queue to apply.
/// - Interface addresses refresh slowly, since they only change when a link comes up or
///   a VPN connects.
final class FlowMonitor: @unchecked Sendable {
    private let flowQueue = DispatchQueue(label: "com.beholder.flows")
    private let attributionQueue = DispatchQueue(label: "com.beholder.attribution", qos: .utility)

    // Confined to flowQueue.
    private let table = FlowTable()
    private let names = NameResolutionCache()
    /// Nil when no geolocation database is installed, which is a normal state — it is
    /// large, separately licensed, and fetched deliberately.
    private let geography = GeoIPDatabase.loadFromStandardPaths()
    private var localAddresses: Set<IPAddress>
    private var recentlyDeparted: [ConnectionKey: (entry: SocketEntry, departedAt: Date)] = [:]
    private var previousConnections: [ConnectionKey: SocketEntry] = [:]
    private var lastAttributionAt = Date.distantPast
    private var lastOnDemandRequestAt = Date.distantPast
    private var attributionPasses: UInt64 = 0
    private var onDemandPasses: UInt64 = 0

    private var attributionTimer: DispatchSourceTimer?
    private var addressTimer: DispatchSourceTimer?

    /// How long a closed socket stays available for attribution after it disappears from
    /// the socket table. Packets for a connection often arrive just after the socket has
    /// gone, and without this window those flows would be permanently unattributed.
    private static let departedRetention: TimeInterval = 30

    /// Poll fast while anything is unattributed, and idle back when the table is clean.
    /// The fast rate is what catches short-lived connections; the slow rate is what keeps
    /// a walk of ~1000 processes off the CPU when there is nothing to resolve.
    private static let fastPollInterval: TimeInterval = 0.1
    private static let idlePollInterval: TimeInterval = 1.0

    /// Minimum gap between attribution passes triggered by a brand-new flow. Each pass
    /// walks every process's file descriptors, so this bounds the cost when a burst of
    /// connections opens at once — a page load can create dozens in a few milliseconds.
    private static let onDemandMinimumGap: TimeInterval = 0.025

    init() {
        self.localAddresses = LocalAddresses.current()
    }

    /// The handler to give `CaptureEngine`.
    ///
    /// Hostname extraction happens *here*, synchronously, before anything is dispatched
    /// elsewhere. The payload buffer belongs to libpcap and dies the moment this returns,
    /// so the observation is turned into owned values first and only those cross onto the
    /// flow queue.
    func packetHandler() -> PacketSink {
        { [weak self] packet, payload, interfaceName in
            guard let self else { return }
            let observation = PayloadInspector.inspect(packet: packet, payload: payload)

            self.flowQueue.async {
                let result = self.table.record(
                    packet,
                    interfaceName: interfaceName,
                    localAddresses: self.localAddresses
                )
                if let observation {
                    self.apply(observation, to: result.key)
                }
                if result.isNew {
                    self.requestImmediateAttribution()
                }
            }
        }
    }

    /// Runs on flowQueue.
    private func apply(_ observation: NameObservation, to key: FlowKey) {
        switch observation {
        case .serverName(let name):
            table.setServerName(name, for: key)
        case .dnsAnswer(let answer):
            names.record(answer)
            // A DNS answer usually arrives just before the connection it enables, so
            // pushing names out immediately is what makes the very first flow to a host
            // show a name rather than an address.
            table.applyNames { self.names.name(for: $0) }
        }
    }

    /// Runs on flowQueue. Asks for an attribution pass right now, because a socket that
    /// has only just started sending may not survive until the next scheduled poll.
    private func requestImmediateAttribution() {
        let now = Date()
        guard now.timeIntervalSince(lastOnDemandRequestAt) >= Self.onDemandMinimumGap
        else { return }
        lastOnDemandRequestAt = now
        attributionQueue.async { [weak self] in
            guard let self else { return }
            let snapshot = Attributor.snapshot()
            self.flowQueue.async {
                self.onDemandPasses += 1
                self.apply(snapshot, at: Date())
            }
        }
    }

    func start() {
        let attribution = DispatchSource.makeTimerSource(queue: attributionQueue)
        attribution.schedule(
            deadline: .now() + 0.2,
            repeating: Self.fastPollInterval,
            leeway: .milliseconds(20)
        )
        attribution.setEventHandler { [weak self] in self?.attributionTick() }
        attributionTimer = attribution
        attribution.resume()

        let addresses = DispatchSource.makeTimerSource(queue: attributionQueue)
        addresses.schedule(deadline: .now() + 10, repeating: 10, leeway: .seconds(2))
        addresses.setEventHandler { [weak self] in
            guard let self else { return }
            let current = LocalAddresses.current()
            self.flowQueue.async { self.localAddresses = current }
        }
        addressTimer = addresses
        addresses.resume()
    }

    func stop() {
        attributionTimer?.cancel()
        attributionTimer = nil
        addressTimer?.cancel()
        addressTimer = nil
    }

    /// Re-reads the machine's interface addresses at once.
    ///
    /// Called when the route moves, because the local address changes with it. Waiting
    /// for the periodic refresh would leave every new flow keyed against a stale address
    /// set, and `FlowKey` decides direction by asking which end is local — so inbound and
    /// outbound would be reported backwards until the next tick.
    func refreshLocalAddresses() {
        let current = LocalAddresses.current()
        flowQueue.async { self.localAddresses = current }
    }

    // MARK: - Attribution

    /// Runs on attributionQueue.
    private func attributionTick() {
        let now = Date()
        let (needsFastPoll, sinceLastPass) = flowQueue.sync {
            (table.hasUnattributedFlows, now.timeIntervalSince(lastAttributionAt))
        }

        // Nothing unresolved and the idle interval has not elapsed: skip the expensive
        // walk entirely.
        guard needsFastPoll || sinceLastPass >= Self.idlePollInterval else { return }

        let snapshot = Attributor.snapshot()
        flowQueue.async { self.apply(snapshot, at: now) }
    }

    /// Runs on flowQueue.
    private func apply(_ snapshot: SocketSnapshot, at now: Date) {
        lastAttributionAt = now
        attributionPasses += 1

        // Sockets that were present last pass and are gone now stay usable briefly, so a
        // packet that arrives just after teardown can still be named.
        for (key, entry) in previousConnections where snapshot.connections[key] == nil {
            recentlyDeparted[key] = (entry, now)
        }
        recentlyDeparted = recentlyDeparted.filter {
            now.timeIntervalSince($0.value.departedAt) < Self.departedRetention
        }
        previousConnections = snapshot.connections

        table.attribute { key in
            resolve(key, in: snapshot).map { (owner: $0.owner, tcpState: $0.tcpState) }
        }
        table.refreshState { key in resolve(key, in: snapshot)?.tcpState }
        table.applyNames { self.names.name(for: $0, at: now) }
        if let geography {
            table.applyLocations { geography.location(for: $0) }
        }
        table.expire(at: now)
        names.expire(at: now)
    }

    /// Runs on flowQueue.
    private func resolve(
        _ key: FlowKey,
        in snapshot: SocketSnapshot
    ) -> (owner: ProcessOwner, tcpState: TCPState?)? {
        guard key.transport == .tcp || key.transport == .udp else { return nil }
        let isTCP = key.transport == .tcp

        let connectionKey = ConnectionKey(
            isTCP: isTCP,
            local: key.local,
            localPort: key.localPort,
            remote: key.remote,
            remotePort: key.remotePort
        )

        // Best evidence first: a live socket for this exact conversation.
        if let entry = snapshot.connections[connectionKey], entry.carriesTraffic {
            return (entry.owner, entry.tcpState)
        }
        // Then one that existed moments ago.
        if let departed = recentlyDeparted[connectionKey] {
            return (departed.entry.owner, departed.entry.tcpState)
        }
        // Last resort: something holding this local port, which is all that is knowable
        // for unconnected UDP.
        if let entry = snapshot.localPorts[LocalPortKey(isTCP: isTCP, port: key.localPort)],
            entry.carriesTraffic
        {
            return (entry.owner, entry.tcpState)
        }
        return nil
    }

    // MARK: - Read access

    struct Summary: Sendable {
        var flows: [Flow]
        var flowCount: Int
        /// Flows that could have been attributed but were not — the real miss rate.
        var unattributedCount: Int
        /// Flows with no ports (ICMP and friends), which have no socket to match against
        /// at all. Counting these as failures would overstate the miss rate and imply a
        /// problem that no amount of polling can fix.
        var unattributableCount: Int
        var processCount: Int
        var totalBytesOut: UInt64
        var totalBytesIn: UInt64
        var evictedFlowCount: UInt64
        var attributionPasses: UInt64
        var onDemandPasses: UInt64
        var namedFlowCount: Int
        var cachedNameCount: Int
        var privateRelayFlowCount: Int
        var outgoingCount: Int
        var incomingCount: Int
        var undeterminedDirectionCount: Int
    }

    /// Builds the published form of the current state.
    func wireSnapshot(
        startedAt: Date,
        interfaces: [String],
        packetsCaptured: UInt64,
        packetsDropped: UInt64,
        transitions: [String]
    ) -> FlowSnapshot {
        let current = summary()

        var statistics = WireStatistics()
        statistics.flowCount = current.flowCount
        statistics.processCount = current.processCount
        statistics.unattributedCount = current.unattributedCount
        statistics.unattributableCount = current.unattributableCount
        statistics.namedFlowCount = current.namedFlowCount
        statistics.cachedNameCount = current.cachedNameCount
        statistics.privateRelayFlowCount = current.privateRelayFlowCount
        statistics.outgoingCount = current.outgoingCount
        statistics.incomingCount = current.incomingCount
        statistics.undeterminedDirectionCount = current.undeterminedDirectionCount
        statistics.evictedFlowCount = current.evictedFlowCount
        statistics.totalBytesOut = current.totalBytesOut
        statistics.totalBytesIn = current.totalBytesIn
        statistics.packetsCaptured = packetsCaptured
        statistics.packetsDropped = packetsDropped
        statistics.interfaceTransitions = transitions
        statistics.warnings = ProxyDetection.findLikelyProxies(in: current.flows)
            .map(\.advice)

        return FlowSnapshot(
            generatedAt: Date(),
            startedAt: startedAt,
            interfaces: interfaces,
            flows: current.flows.map { $0.wireRepresentation() },
            statistics: statistics
        )
    }

    func summary() -> Summary {
        flowQueue.sync {
            let flows = table.activeFlows()
            var owners = Set<ProcessOwner>()
            var unattributed = 0
            var unattributable = 0
            var named = 0
            var privateRelay = 0
            var outgoing = 0
            var accepted = 0
            var undetermined = 0
            var out: UInt64 = 0
            var incoming: UInt64 = 0

            for flow in flows {
                if let owner = flow.owner {
                    owners.insert(owner)
                } else if flow.key.transport.hasPorts {
                    unattributed += 1
                } else {
                    unattributable += 1
                }
                switch flow.direction {
                case .outgoing: outgoing += 1
                case .incoming: accepted += 1
                case .undetermined: undetermined += 1
                }
                if flow.hostName != nil { named += 1 }
                if NameResolutionCache.classify(hostName: flow.hostName) == .privateRelay {
                    privateRelay += 1
                }
                out += flow.bytesOut
                incoming += flow.bytesIn
            }

            return Summary(
                flows: flows,
                flowCount: flows.count,
                unattributedCount: unattributed,
                unattributableCount: unattributable,
                processCount: owners.count,
                totalBytesOut: out,
                totalBytesIn: incoming,
                evictedFlowCount: table.evictedFlowCount,
                attributionPasses: attributionPasses,
                onDemandPasses: onDemandPasses,
                namedFlowCount: named,
                cachedNameCount: names.count,
                privateRelayFlowCount: privateRelay,
                outgoingCount: outgoing,
                incomingCount: accepted,
                undeterminedDirectionCount: undetermined
            )
        }
    }
}
