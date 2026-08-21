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
    private let table: FlowTable
    private let names = NameResolutionCache()
    /// The opening bytes of unencrypted connections. Nil unless `--read-cleartext` was
    /// given, which is what keeps the default run exactly as it always was: no payload is
    /// copied, so none can be published, logged or stored.
    private let excerpts: PayloadExcerptStore?
    /// Nil when no geolocation database is installed, which is a normal state — it is
    /// large, separately licensed, and fetched deliberately.
    private let geography = GeoIPDatabase.loadFromStandardPaths()
    /// Names the network behind an address, which works where hostnames do not.
    private let networks = ASNDatabase.loadFromStandardPaths()
    private var reverseResolver: ReverseResolver?
    /// Nil when no tracker index is installed. Fetched deliberately, like geolocation,
    /// because its data carries a NonCommercial licence.
    private let trackers = TrackerDatabase.loadFromStandardPaths()
    /// Nil when history is disabled or the database could not be opened. Losing history
    /// is a nuisance; refusing to capture over it would be worse.
    private var store: FlowStore?
    /// Per-minute measurement waiting to be written. Nil when nothing is measuring.
    private let qualityBuckets: QualityAccumulator?
    private var qualityTimer: DispatchSourceTimer?
    /// Connection attempts already counted as failures, so a flow looked at on several
    /// enrichment passes before it retires is not blamed once per pass.
    ///
    /// Culled when a flow retires. The daemon runs for weeks, so anything keyed by flow
    /// and never emptied is a slow leak rather than a bounded cache.
    private var reportedTimeouts: Set<FlowKey> = []
    private var lastPrunedAt = Date.distantPast
    private(set) var flowsPersisted: UInt64 = 0

    /// Where learned names are kept between runs, resolved centrally alongside the
    /// history database so the two cannot drift apart.
    static var nameCacheURL: URL {
        URL(fileURLWithPath: BeholderPaths.nameCache())
    }
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

    /// The addresses the prober is currently echoing, so its own packets can be recognised
    /// when pcap hands them straight back.
    ///
    /// flowQueue-confined, and refreshed every round rather than read once: the gateway is
    /// one of the targets and it moves the moment a VPN comes up.
    private var probeTargets: Set<IPAddress> = []

    /// The prober, when there is one.
    ///
    /// Held here rather than in `main()` for two reasons: `dispatchMain()` never returns,
    /// so a local would be free to be released while the process carried on running and
    /// silently stopped probing; and it has to be cancelled before the store is closed, or
    /// a round in flight would write to a closed database.
    private var prober: Prober?

    func attach(prober: Prober) {
        self.prober = prober
        let targets = Set(prober.currentTargets().map(\.address))
        flowQueue.async { self.probeTargets = targets }
        prober.start()
    }

    init(readCleartext: Bool = false, measureQuality: Bool = true) {
        self.localAddresses = LocalAddresses.current()
        self.excerpts = readCleartext ? PayloadExcerptStore() : nil
        // Read once here rather than through the optional on every packet: the capture
        // callback runs on its own queue and must not touch flowQueue-confined state.
        self.isReadingCleartext = readCleartext
        self.isMeasuringQuality = measureQuality
        self.table = FlowTable(measuresQuality: measureQuality)
        self.qualityBuckets = measureQuality ? QualityAccumulator() : nil
    }

    /// Whether payload copying is on. Immutable after init, so the capture queue may read
    /// it without synchronisation — unlike `excerpts`, which belongs to flowQueue.
    private let isReadingCleartext: Bool

    /// Whether per-flow quality is being measured.
    ///
    /// Unlike payload reading this is on by default, and the asymmetry is the point.
    /// Reading cleartext touches the *contents* of traffic, so it is opt-in and announced.
    /// Measuring quality reads only header fields the kernel has already handed over,
    /// learns nothing about what anyone is doing, and costs a few hundred bytes a flow.
    /// More to the point, it has to be running when the trouble happens: a switch you flip
    /// after the connection went bad has nothing to tell you about the connection going
    /// bad.
    private let isMeasuringQuality: Bool

    /// The handler to give `CaptureEngine`.
    ///
    /// Payload inspection happens *here*, synchronously, before anything is dispatched
    /// elsewhere. The payload buffer belongs to libpcap and dies the moment this returns,
    /// so the observation is turned into owned values first and only those cross onto the
    /// flow queue.
    ///
    /// That is also why a payload excerpt arrives unlabelled: which way the packet went is
    /// decided by `FlowKey` normalisation against the local address set, which belongs to
    /// the flow queue. The bytes are copied here and given a direction there.
    func packetHandler() -> PacketSink {
        { [weak self] packet, payload, interfaceName in
            guard let self else { return }
            let observation = PayloadInspector.inspect(
                packet: packet,
                payload: payload,
                capturePayload: self.isReadingCleartext
            )

            self.flowQueue.async {
                let result = self.table.record(
                    packet,
                    interfaceName: interfaceName,
                    localAddresses: self.localAddresses,
                    at: packet.timestamp
                )
                if let observation {
                    self.apply(observation, to: result.key, direction: result.direction)
                }
                // Marked once, when the flow first appears, so every later reader — the
                // series, the live summary, the history table — can leave it out by asking
                // the flow rather than by repeating this test.
                if result.isNew, self.isOwnTraffic(result.key) {
                    self.table.markSelfOriginated(result.key)
                }
                if let event = result.quality, let buckets = self.qualityBuckets,
                    !result.isSelfOriginated
                {
                    // Attributed to the minute the packet arrived in, using the capture
                    // timestamp rather than the clock now — the difference is the whole
                    // point of a series meant to answer "was it bad at eight on Tuesday".
                    buckets.record(
                        event,
                        flow: result.key,
                        interface: interfaceName,
                        group: result.destinationGroup,
                        label: result.destinationLabel,
                        at: packet.timestamp
                    )
                }
                if result.isNew {
                    self.requestImmediateAttribution()
                }
            }
        }
    }

    /// Whether a flow is this daemon's own doing. Runs on flowQueue.
    ///
    /// Probes are real packets and pcap captures them like any other, so without this the
    /// prober would appear in its own measurements — inflating the byte totals and, worse,
    /// contributing round trips to the very series it exists to keep honest.
    ///
    /// Recognised by target rather than by a capture filter. A filter on the probe
    /// addresses would also hide genuine traffic to them, which on anycast resolvers is
    /// exactly the DNS this machine does all day.
    ///
    /// This used to ask the flow table for the owning PID and compare it with our own,
    /// which could never be true: `Attributor.owner` begins `guard packet.transport
    /// .hasPorts`, and ICMP has no ports, so a probe flow never acquires an owner at all.
    /// The exclusion the design notes promise was therefore not happening. The prober is
    /// the only thing that knows which echoes are its own, so it says so directly.
    private func isOwnTraffic(_ key: FlowKey) -> Bool {
        guard !probeTargets.isEmpty, key.transport == .icmp else { return false }
        return probeTargets.contains(key.remote)
    }

    /// Runs on flowQueue.
    private func apply(
        _ observation: PacketObservation,
        to key: FlowKey,
        direction: FlowDirection
    ) {
        if let reading = observation.reading {
            table.applyReading(reading, for: key)
        }
        if let bytes = observation.excerptBytes, let excerpts {
            // Called for every packet, including once the buffer for this flow is full.
            // The store discards the bytes at that point but keeps counting them, and that
            // count is what the reader shows as "first 4 KB of 900 KB". Skipping the call
            // to save the work would freeze the total and make the caveat wrong.
            excerpts.append(
                PayloadExcerpt(
                    direction: direction,
                    bytes: bytes,
                    observedBytes: observation.payloadBytesSeen
                ),
                for: key
            )
        }
        switch observation.name {
        case .serverName(let name):
            table.setServerName(name, for: key)
        case .dnsAnswer(let answer):
            names.record(answer)
            // A DNS answer usually arrives just before the connection it enables, so
            // pushing names out immediately is what makes the very first flow to a host
            // show a name rather than an address.
            table.applyNames { self.names.resolved(for: $0) }
            classifyNamedFlows()
        case nil:
            break
        }
    }

    /// Runs on flowQueue. A flow only becomes classifiable once it has a name, so this
    /// follows every naming pass rather than running on its own schedule.
    private func classifyNamedFlows() {
        guard let trackers else { return }
        table.applyClassifications { trackers.classify(hostName: $0) }
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

    /// Names learned in earlier runs, and how many were reloaded.
    private(set) var restoredNameCount = 0

    /// Opens the history database. Called before `start()`; a failure is reported and
    /// capture continues without history.
    func openStore(at path: String) -> Result<String, Error> {
        do {
            let opened = try FlowStore(path: path)
            flowQueue.sync { self.store = opened }
            return .success(opened.path)
        } catch {
            return .failure(error)
        }
    }

    func start() {
        // A warm start matters: macOS caches DNS for hours, so a fresh capture sees very
        // few lookups and would otherwise relearn everything from scratch.
        let restored = names.load(from: Self.nameCacheURL)
        flowQueue.async { self.restoredNameCount = restored }

        let resolver = ReverseResolver { [weak self] address, name in
            guard let self else { return }
            self.flowQueue.async {
                // PTR records are long-lived and rarely change; a day is generous without
                // being permanent.
                self.names.adopt(
                    name: name,
                    for: address,
                    expiresAt: Date().addingTimeInterval(86400),
                    source: .reverseLookup
                )
                self.table.applyNames { self.names.resolved(for: $0) }
                self.classifyNamedFlows()
            }
        }
        reverseResolver = resolver

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

        // The per-minute series is flushed on its own timer rather than when flows retire.
        // The existing `rollups` table does the latter and shows why not to: it keys on the
        // minute a flow *ended*, so a download running from eight until midnight lands
        // wholly in the midnight bucket, and a chart of the evening shows nothing.
        if qualityBuckets != nil {
            let quality = DispatchSource.makeTimerSource(queue: flowQueue)
            quality.schedule(deadline: .now() + 60, repeating: 60, leeway: .seconds(5))
            quality.setEventHandler { [weak self] in self?.flushQuality(at: Date()) }
            qualityTimer = quality
            quality.resume()
        }
    }

    /// Writes out every minute that has certainly finished. Runs on flowQueue.
    private func flushQuality(at now: Date, closedOnly: Bool = true) {
        guard let qualityBuckets, let store else { return }
        let drained =
            closedOnly ? qualityBuckets.drainClosedMinutes(now: now) : qualityBuckets.drainAll()
        guard !drained.isEmpty else { return }

        let rows = drained.map { qualityBuckets.row(for: $0.key, $0.bucket) }
        do {
            try store.recordQuality(rows)
        } catch {
            if storeErrorReported == false {
                storeErrorReported = true
                FileHandle.standardError.write(
                    Data("beholderd: cannot write quality history: \(error)\n".utf8)
                )
            }
        }
    }

    /// Files connections that were opened and never answered against the minute they were
    /// *attempted* in, not the minute we gave up on them.
    ///
    /// Runs on flowQueue during the enrichment pass, so a failure is noticed while it is
    /// still recent. Writing straight to the store rather than into the accumulator is
    /// deliberate: the attempt's minute may already have been flushed, and the row upsert
    /// is what lets a late fact join a minute already on disk.
    private func recordConnectionTimeouts(at now: Date) {
        guard isMeasuringQuality, let store else { return }

        var rows: [QualityMinute] = []
        // The predicate itself lives on `Flow` in Core, shared with `QualitySummary`, so
        // the live reading and the persisted series cannot disagree about what a timeout
        // is. What stays here is only the once-per-flow bookkeeping and the write.
        table.forEachActive { flow in
            guard !flow.isSelfOriginated,
                flow.connectionTimedOut(at: now),
                !reportedTimeouts.contains(flow.key)
            else { return }

            reportedTimeouts.insert(flow.key)
            rows.append(
                QualityMinute(
                    minute: QualityAccumulator.minute(of: flow.firstSeen),
                    interface: flow.interfaceName,
                    destinationGroup: flow.destinationGroupKey,
                    destinationLabel: flow.destinationGroupLabel,
                    connectionTimeouts: 1
                )
            )
        }
        guard !rows.isEmpty else { return }
        _ = try? store.recordQuality(rows)
    }

    func stop() {
        // First, so no round in flight can write to a store that is about to close.
        prober?.stop()
        prober = nil
        attributionTimer?.cancel()
        attributionTimer = nil
        addressTimer?.cancel()
        addressTimer = nil
        qualityTimer?.cancel()
        qualityTimer = nil
        saveNameCache()
        // Anything still live at shutdown never retired, so it would otherwise be lost.
        flowQueue.sync {
            guard let store else { return }
            // The minute in progress included, since the alternative is losing it.
            flushQuality(at: Date(), closedOnly: false)
            let remaining = table.activeFlows() + table.drainRetired()
            _ = try? store.record(remaining)
            store.close()
        }
    }

    /// Files a round of probe results. Hops onto flowQueue, which owns the store.
    func recordProbes(_ results: [ProbeResult]) {
        flowQueue.async {
            // Unioned rather than replaced: a round that got no reply from a target still
            // sent to it, and those packets are still ours. The set stays small — three
            // fixed anchors and however many gateways this machine has seen.
            for result in results {
                if let address = IPAddress(text: result.target) {
                    self.probeTargets.insert(address)
                }
            }
            guard let store = self.store else { return }
            _ = try? store.recordProbes(results)
        }
    }

    /// Hands the learned names to the next run.
    @discardableResult
    func saveNameCache() -> Int {
        flowQueue.sync {
            let entries = names.persistableEntries()
            _ = names.save(to: Self.nameCacheURL)
            // The daemon runs as root, so the file would otherwise be unreadable to the
            // user it is about — the same problem the transcript has.
            let environment = ProcessInfo.processInfo.environment
            if let uidText = environment["SUDO_UID"], let uid = uid_t(uidText),
                let gidText = environment["SUDO_GID"], let gid = gid_t(gidText)
            {
                let path = Self.nameCacheURL.path
                chown(path, uid, gid)
                chown(Self.nameCacheURL.deletingLastPathComponent().path, uid, gid)
            }
            return entries.count
        }
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
        table.applyNames { self.names.resolved(for: $0, at: now) }
        classifyNamedFlows()
        if let geography {
            table.applyLocations { geography.location(for: $0) }
        }
        if let networks {
            table.applyNetworkOperators { networks.lookup($0) }
        }

        // Ask about anything still nameless. Cheapest source first means this only ever
        // sees what SNI and observed DNS could not account for.
        if let reverseResolver {
            table.forEachActive { flow in
                guard flow.hostName == nil, flow.key.remote.isGloballyRoutable else { return }
                reverseResolver.request(flow.key.remote)
            }
        }

        recordConnectionTimeouts(at: now)
        let expired = table.expire(at: now)
        // Release payload as soon as a conversation is over, rather than waiting for
        // eviction pressure. This is the one structure in Beholder holding the contents of
        // traffic, so it should hold as little of it, for as short a time, as it can.
        if let excerpts {
            for flow in expired { excerpts.forget(flow.key) }
        }
        if !reportedTimeouts.isEmpty {
            for flow in expired { reportedTimeouts.remove(flow.key) }
        }
        persistRetiredFlows(at: now)
        names.expire(at: now)
    }

    /// Runs on flowQueue. Hands retired flows to the database.
    ///
    /// Retirement is the right moment: a flow is only complete once it has stopped, and
    /// writing it earlier would mean rewriting it as its counters grew.
    private func persistRetiredFlows(at now: Date) {
        guard let store else { return }
        // Probes are excluded here too, not only from the series. A history table that
        // recorded Beholder's own echoes would answer "what did this machine talk to on
        // Tuesday" with Beholder.
        let retired = table.drainRetired().filter { !$0.isSelfOriginated }
        if !retired.isEmpty {
            do {
                try store.record(retired)
                flowsPersisted += UInt64(retired.count)
            } catch {
                // Reported once per run rather than per batch; a failing database should
                // not drown the terminal or stop capture.
                if storeErrorReported == false {
                    storeErrorReported = true
                    FileHandle.standardError.write(
                        Data("beholderd: cannot write history: \(error)\n".utf8)
                    )
                }
            }
        }

        // Hourly is often enough for a retention policy measured in days, and keeps a
        // delete off the hot path.
        if now.timeIntervalSince(lastPrunedAt) > 3600 {
            lastPrunedAt = now
            _ = try? store.prune(now: now)
            _ = try? store.pruneQuality(now: now)
        }
    }

    private var storeErrorReported = false

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
        /// Named flows split by evidence, so a coverage figure can be read for what it is.
        var namedBySNI: Int
        var namedByDNS: Int
        var namedByReverseLookup: Int
        var restoredNameCount: Int
        var reverseLookupsAttempted: Int
        var reverseLookupsSucceeded: Int
        /// Connections by what is known about their protection. Kept apart rather than
        /// summed into "unencrypted", because `cleartext` was read off the wire and
        /// `unknown` is the absence of a reading — reporting them as one figure would
        /// claim observations that were never made.
        var cleartextFlowCount: Int
        var unknownSecurityFlowCount: Int
        var encryptedFlowCount: Int
        /// Nil when measurement is off, so the published statistics can distinguish
        /// "nothing was measuring" from "measured, and found nothing".
        var quality: QualitySummary?
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
        statistics.cleartextFlowCount = current.cleartextFlowCount
        statistics.unknownSecurityFlowCount = current.unknownSecurityFlowCount
        statistics.encryptedFlowCount = current.encryptedFlowCount

        var qualityWarnings: [String] = []
        if let quality = current.quality {
            statistics.measuredFlowCount = quality.measuredFlowCount
            statistics.unmeasurableFlowCount = quality.unmeasurableFlowCount
            statistics.unmeasurableBytes = quality.unmeasurableBytes
            statistics.measuredByteShare = quality.measuredByteShare
            statistics.medianRttMs = quality.medianRTT.map { $0 * 1000 }
            statistics.minRttMs = quality.minimumRTT.map { $0 * 1000 }
            statistics.retransmitRateOut = quality.retransmitRateOut
            statistics.retransmitRateIn = quality.retransmitRateIn
            statistics.connectionAttempts = quality.connectionAttempts
            statistics.connectionTimeouts = quality.connectionTimeouts
            statistics.connectionRefusals = quality.connectionRefusals
            statistics.discardedRttSamples = quality.discardedSamples
            statistics.segmentOffloadFlowCount = quality.segmentOffloadFlowCount

            // A latency figure covering a minority of the traffic is a different object
            // from one covering nearly all of it, and the difference is invisible in the
            // number itself. Said out loud rather than left to be inferred from a ratio
            // the reader would have to go looking for.
            if let share = quality.measuredByteShare, share < 0.5, quality.measuredFlowCount > 0 {
                qualityWarnings.append(
                    "Latency and loss below cover \(Int((share * 100).rounded()))% of the "
                        + "bytes moved. The rest is QUIC or other UDP traffic, which carries "
                        + "no round trips a passive observer can read."
                )
            }
            if quality.segmentOffloadFlowCount > 0 {
                let count = quality.segmentOffloadFlowCount
                qualityWarnings.append(
                    "\(pluralised(Int(count), "connection")) arrived with segments coalesced "
                        + "by the interface, so their segment and retransmission counts are "
                        + "undercounts."
                )
            }
        }
        // Assigned first and appended to after, rather than the other way round. These two
        // caveats were being appended to `warnings` and then thrown away wholesale by this
        // assignment, so neither had ever reached a screen — which is the failure the
        // "caveats travel with the data" rule exists to prevent, arriving by way of a line
        // of code rather than a decision.
        statistics.warnings =
            ProxyDetection.findLikelyProxies(in: current.flows).map(\.advice) + qualityWarnings

        let payload = publishableExcerpts()
        if payload.dropped > 0 {
            statistics.warnings.append(
                """
                Payload for \(payload.dropped) unencrypted \
                \(agreeing(payload.dropped, "connection is", "connections are")) not shown: \
                this snapshot reached its \
                \(WireProtocol.maximumExcerptBytesPerSnapshot / 1024) KB payload limit.
                """
            )
        }
        if payload.evicted > 0 {
            statistics.warnings.append(
                """
                Payload for \(payload.evicted) earlier \
                \(agreeing(payload.evicted, "connection was", "connections were")) released to \
                stay within the \(PayloadExcerptStore.maximumFlows)-connection buffer.
                """
            )
        }

        return FlowSnapshot(
            generatedAt: Date(),
            startedAt: startedAt,
            interfaces: interfaces,
            flows: current.flows.map { $0.wireRepresentation(measuringQuality: isMeasuringQuality) },
            statistics: statistics,
            cleartextExcerpts: payload.excerpts
        )
    }

    /// Collects buffered payload for publication.
    ///
    /// Returns nil excerpts — not an empty array — when payload reading is off, because
    /// the client distinguishes the two: nil is "nothing is reading payload", empty is
    /// "reading, and there was nothing to read". Collapsing them would show the same blank
    /// list for a daemon that was never asked to look and one that looked and found
    /// nothing.
    ///
    /// The selection itself lives in `PayloadExcerptStore.publishable(budget:)`, in Core,
    /// where a test can reach it — this is the one per-snapshot bound on the structure
    /// holding traffic contents, and an inverted sort or an off-by-one budget would
    /// otherwise be silent. All that is left here is the hop onto the flow queue.
    private func publishableExcerpts()
        -> (excerpts: [WireExcerpt]?, dropped: Int, evicted: UInt64)
    {
        guard isReadingCleartext else { return (nil, 0, 0) }
        return flowQueue.sync {
            guard let excerpts else { return (nil, 0, 0) }
            let selected = excerpts.publishable(
                budget: WireProtocol.maximumExcerptBytesPerSnapshot
            )
            return (selected.excerpts, selected.dropped, excerpts.evictedFlowCount)
        }
    }

    func summary() -> Summary {
        // Read outside the flow queue: the resolver has its own.
        // Labels on the fallback, or the tuple loses them and `.attempted` stops existing.
        let reverseStatistics =
            reverseResolver?.statistics ?? (attempted: 0, succeeded: 0, failed: 0)
        return flowQueue.sync {
            let flows = table.activeFlows()
            var owners = Set<ProcessOwner>()
            var unattributed = 0
            var unattributable = 0
            var named = 0
            var bySNI = 0
            var byDNS = 0
            var byReverse = 0
            var privateRelay = 0
            var outgoing = 0
            var accepted = 0
            var undetermined = 0
            var out: UInt64 = 0
            var incoming: UInt64 = 0
            var cleartext = 0
            var unknownSecurity = 0
            var encrypted = 0

            for flow in flows {
                switch flow.security?.security {
                case .cleartext: cleartext += 1
                case .encrypted: encrypted += 1
                case .unknown: unknownSecurity += 1
                // No ports, so no connection to characterise. Counted nowhere rather than
                // swept into "unknown", which would imply something was looked at.
                case nil: break
                }
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
                if flow.hostName != nil {
                    named += 1
                    switch flow.hostNameSource {
                    case .serverNameIndication: bySNI += 1
                    case .dns: byDNS += 1
                    case .reverseLookup: byReverse += 1
                    case nil: break
                    }
                }
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
                undeterminedDirectionCount: undetermined,
                namedBySNI: bySNI,
                namedByDNS: byDNS,
                namedByReverseLookup: byReverse,
                restoredNameCount: restoredNameCount,
                reverseLookupsAttempted: reverseStatistics.attempted,
                reverseLookupsSucceeded: reverseStatistics.succeeded,
                cleartextFlowCount: cleartext,
                unknownSecurityFlowCount: unknownSecurity,
                encryptedFlowCount: encrypted,
                quality: isMeasuringQuality
                    ? QualitySummary.summarise(flows, at: Date()) : nil
            )
        }
    }
}
