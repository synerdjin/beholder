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
    /// Note for later: `ParsedPacket.payloadOffset` points into pcap's buffer, which is
    /// only valid for the duration of the capture callback. Anything that needs the
    /// payload — TLS SNI, DNS answers — must extract it synchronously inside the
    /// callback and pass the result by value, not read it from here.
    func packetHandler() -> @Sendable (ParsedPacket, String) -> Void {
        { [weak self] packet, interfaceName in
            guard let self else { return }
            self.flowQueue.async {
                let result = self.table.record(
                    packet,
                    interfaceName: interfaceName,
                    localAddresses: self.localAddresses
                )
                if result.isNew {
                    self.requestImmediateAttribution()
                }
            }
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
        table.expire(at: now)
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
        var unattributedCount: Int
        var processCount: Int
        var totalBytesOut: UInt64
        var totalBytesIn: UInt64
        var evictedFlowCount: UInt64
        var attributionPasses: UInt64
        var onDemandPasses: UInt64
    }

    func summary() -> Summary {
        flowQueue.sync {
            let flows = table.activeFlows()
            var owners = Set<ProcessOwner>()
            var unattributed = 0
            var out: UInt64 = 0
            var incoming: UInt64 = 0

            for flow in flows {
                if let owner = flow.owner {
                    owners.insert(owner)
                } else {
                    unattributed += 1
                }
                out += flow.bytesOut
                incoming += flow.bytesIn
            }

            return Summary(
                flows: flows,
                flowCount: flows.count,
                unattributedCount: unattributed,
                processCount: owners.count,
                totalBytesOut: out,
                totalBytesIn: incoming,
                evictedFlowCount: table.evictedFlowCount,
                attributionPasses: attributionPasses,
                onDemandPasses: onDemandPasses
            )
        }
    }
}
