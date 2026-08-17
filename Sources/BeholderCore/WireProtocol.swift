import Foundation

/// What the daemon publishes and the app consumes.
///
/// The plan called for XPC. XPC to a root daemon requires registering it as a
/// LaunchDaemon under `/Library/LaunchDaemons`, which is a persistent system change and
/// realistically wants a signing identity to be pleasant. A Unix domain socket carrying
/// newline-delimited JSON needs neither, so the app works today and the daemon stays
/// something you start and stop by hand.
///
/// The socket is created 0600 and owned by the user who invoked sudo, for the same
/// reason the transcript is: this is a list of everywhere the machine has been.
public enum WireProtocol {
    /// Default socket path. Under `/var/run` because that is where runtime sockets
    /// belong, and because a root daemon can always create it there.
    public static let defaultSocketPath = "/var/run/beholder.sock"

    /// Bumped when the shape below changes incompatibly, so an old app talking to a new
    /// daemon fails with a clear message rather than decoding into nonsense.
    ///
    /// Payload reading did *not* bump it, and deliberately so. Every field it added is
    /// `Optional`, which Swift's synthesised decoding tolerates being absent, so an old
    /// app reading a new daemon ignores the new keys and a new app reading an old daemon
    /// sees nil. Bumping would have broken working pairs to announce a change neither end
    /// can be hurt by. The rule remains: bump on an *incompatible* change, and adding an
    /// optional is not one.
    public static let version = 1

    /// The most excerpt payload one snapshot will carry, across all connections.
    ///
    /// The store is already bounded at 64 flows × 4 KB × 2 directions, so the true worst
    /// case is 512 KB per second on a machine doing nothing but unencrypted work. That is
    /// survivable over a local Unix socket but pointless, and this cap keeps the common
    /// case — a handful of cleartext connections, a few KB — from ever being able to
    /// surprise anyone. When it bites, the snapshot says so in `statistics.warnings`.
    public static let maximumExcerptBytesPerSnapshot = 256 * 1024
}

public struct WireFlow: Codable, Sendable, Identifiable, Hashable {
    /// Stable across snapshots, so the UI can animate a row rather than replacing it.
    public let id: String

    public let processName: String?
    public let processPath: String?
    public let pid: Int32?

    public let transport: String
    public let localAddress: String
    public let localPort: UInt16
    public let remoteAddress: String
    public let remotePort: UInt16

    public let hostName: String?
    /// True when the name came from this connection's own ClientHello, which is proof.
    /// False means it was inferred from a DNS answer, which is only a good guess.
    public let hostNameIsProof: Bool
    public let isPrivateRelay: Bool

    public let bytesOut: UInt64
    public let bytesIn: UInt64
    public let packetsOut: UInt64
    public let packetsIn: UInt64

    public let tcpState: String?
    public let firstSeen: Date
    public let lastSeen: Date

    /// Where the far end is, when a geolocation database is installed.
    public let location: GeoLocation?
    /// Who operates the far end, when a tracker database recognises it.
    public let classification: HostClassification?
    /// The network announcing the remote address, when an ASN database is installed.
    public let networkOperator: NetworkOperator?
    /// True when this machine opened the connection. Nil when nothing has been observed
    /// yet, which in practice never reaches a client.
    public let isOutgoing: Bool?
    /// True when `isOutgoing` came from watching the opening handshake rather than being
    /// inferred from which direction moved first.
    public let initiationIsCertain: Bool

    /// Whether this conversation is protected. Nil for protocols with no ports, where
    /// there is no connection to characterise, and when talking to a daemon that predates
    /// the field.
    public let security: TransportSecurity?
    /// The application protocol, when one was identified. Nil when the security reading
    /// came from the port alone.
    public let protocolName: String?
    /// True when the security reading was read out of the payload rather than guessed from
    /// the port — the same one-bit flattening of provenance that `hostNameIsProof` does.
    /// Nil, rather than false, when no reading exists at all, so "unprotected by
    /// inference" is never mistaken for "unprotected, observed".
    public let securityIsProof: Bool?

    public var totalBytes: UInt64 { bytesOut + bytesIn }

    /// True when this connection is not known to be protected — either read as cleartext,
    /// or unrecognised. The two are kept distinct in `security`; this is the union, which
    /// is what a "show me what is exposed" list wants.
    public var isUnprotected: Bool {
        guard let security else { return false }
        return security != .encrypted
    }

    /// What to show for the far end: the hostname when known, the address otherwise.
    /// Never blank — the address is true even when the name is not known.
    public var remoteDescription: String {
        hostName ?? remoteAddress
    }

    /// Whether anything at all is known about the far end beyond its address.
    ///
    /// Three independent sources feed this, and any one of them counts: a hostname, the
    /// company a tracker database attributes it to, or the network announcing it. What is
    /// left over is the genuinely opaque set — an address, a port, and nothing else — and
    /// that is the set worth looking at.
    ///
    /// Deliberately broader than "recognised by the tracker database". Since the ASN
    /// lookup landed, almost nothing is in that database and almost everything has an
    /// operator, so filtering on tracker recognition alone kept practically every flow
    /// and looked like it was doing nothing at all.
    public var isIdentified: Bool {
        hostName != nil || classification?.owner != nil || networkOperator != nil
    }

    public init(
        id: String, processName: String?, processPath: String?, pid: Int32?,
        transport: String, localAddress: String, localPort: UInt16,
        remoteAddress: String, remotePort: UInt16,
        hostName: String?, hostNameIsProof: Bool, isPrivateRelay: Bool,
        bytesOut: UInt64, bytesIn: UInt64, packetsOut: UInt64, packetsIn: UInt64,
        tcpState: String?, firstSeen: Date, lastSeen: Date,
        location: GeoLocation?, classification: HostClassification?,
        networkOperator: NetworkOperator?,
        isOutgoing: Bool?, initiationIsCertain: Bool,
        security: TransportSecurity? = nil,
        protocolName: String? = nil,
        securityIsProof: Bool? = nil
    ) {
        self.security = security
        self.protocolName = protocolName
        self.securityIsProof = securityIsProof
        self.location = location
        self.classification = classification
        self.networkOperator = networkOperator
        self.isOutgoing = isOutgoing
        self.initiationIsCertain = initiationIsCertain
        self.id = id
        self.processName = processName
        self.processPath = processPath
        self.pid = pid
        self.transport = transport
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.hostName = hostName
        self.hostNameIsProof = hostNameIsProof
        self.isPrivateRelay = isPrivateRelay
        self.bytesOut = bytesOut
        self.bytesIn = bytesIn
        self.packetsOut = packetsOut
        self.packetsIn = packetsIn
        self.tcpState = tcpState
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

/// The opening bytes of one unencrypted connection.
///
/// Sent only when the daemon was started with `--read-cleartext`; otherwise
/// `FlowSnapshot.cleartextExcerpts` is absent entirely. The daemon pushes these rather
/// than answering requests for them, because the socket is strictly read-only — an
/// unauthenticated reader must never be able to make the daemon do anything, and "send me
/// the payload of flow X" would be exactly that.
///
/// `Data` encodes as base64 in JSON, which contains no newline and so cannot break the
/// newline framing the socket depends on.
public struct WireExcerpt: Codable, Sendable, Hashable, Identifiable {
    /// The `WireFlow.id` this belongs to.
    public let id: String
    public let sent: Data?
    public let received: Data?
    /// Payload bytes seen in each direction, including those not kept. Compare against the
    /// lengths of `sent` and `received` to know how much of the conversation this is.
    public let sentObserved: UInt64
    public let receivedObserved: UInt64

    public init(
        id: String, sent: Data?, received: Data?,
        sentObserved: UInt64, receivedObserved: UInt64
    ) {
        self.id = id
        self.sent = sent
        self.received = received
        self.sentObserved = sentObserved
        self.receivedObserved = receivedObserved
    }

    public var sentCaptured: Int { sent?.count ?? 0 }
    public var receivedCaptured: Int { received?.count ?? 0 }

    /// True when either direction carried more than was kept.
    public var isTruncated: Bool {
        sentObserved > UInt64(sentCaptured) || receivedObserved > UInt64(receivedCaptured)
    }
}

/// Counts and caveats. The caveats travel with the data deliberately: a UI that shows
/// totals without saying they are an undercount is worse than one that shows nothing.
public struct WireStatistics: Codable, Sendable, Hashable {
    public var flowCount = 0
    public var processCount = 0
    /// Connections this machine opened, and connections it accepted. Reported separately
    /// because "something on my laptop reached out" and "something reached in" are very
    /// different facts, and a single total hides which happened.
    public var outgoingCount = 0
    public var incomingCount = 0
    /// Connections whose initiator could not be established. Reported rather than folded
    /// into either side, so neither number claims more than was observed.
    public var undeterminedDirectionCount = 0
    public var unattributedCount = 0
    public var unattributableCount = 0
    public var namedFlowCount = 0
    public var cachedNameCount = 0
    public var privateRelayFlowCount = 0
    public var evictedFlowCount: UInt64 = 0

    /// Connections read as speaking a plaintext protocol, and connections nothing could
    /// identify. Counted apart because they claim very different things: the first is an
    /// observation, the second is the absence of one. Folding them into a single
    /// "unencrypted" figure would let a machine full of unrecognised binary protocols
    /// report an alarming number it never actually established.
    public var cleartextFlowCount = 0
    public var unknownSecurityFlowCount = 0
    public var encryptedFlowCount = 0

    public var totalBytesOut: UInt64 = 0
    public var totalBytesIn: UInt64 = 0

    public var packetsCaptured: UInt64 = 0
    public var packetsDropped: UInt64 = 0

    /// Human-readable warnings — transparent proxies, and anything else that makes the
    /// per-process numbers misleading.
    public var warnings: [String] = []
    /// Interface changes seen during the run, most recent last.
    public var interfaceTransitions: [String] = []

    public init() {}

    public var attributableCount: Int { flowCount - unattributableCount }
    public var attributedCount: Int { attributableCount - unattributedCount }

    /// Decoded field by field, each falling back to its default when absent.
    ///
    /// This is not boilerplate for its own sake. Swift's synthesised decoding ignores
    /// property defaults entirely — a `var x = 0` still fails to decode when the key is
    /// missing — so every counter added here would otherwise be an *incompatible* change
    /// requiring a version bump, for a field no old reader cares about and no new reader
    /// needs. Written out once, this type extends freely, which is the property its
    /// all-defaults declaration was always meant to have.
    ///
    /// It is not a licence to change meaning silently: renaming or repurposing a field
    /// still breaks readers, and still needs `WireProtocol.version` raised.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        func int(_ key: CodingKeys) throws -> Int {
            try container.decodeIfPresent(Int.self, forKey: key) ?? 0
        }
        func count(_ key: CodingKeys) throws -> UInt64 {
            try container.decodeIfPresent(UInt64.self, forKey: key) ?? 0
        }
        func strings(_ key: CodingKeys) throws -> [String] {
            try container.decodeIfPresent([String].self, forKey: key) ?? []
        }

        flowCount = try int(.flowCount)
        processCount = try int(.processCount)
        outgoingCount = try int(.outgoingCount)
        incomingCount = try int(.incomingCount)
        undeterminedDirectionCount = try int(.undeterminedDirectionCount)
        unattributedCount = try int(.unattributedCount)
        unattributableCount = try int(.unattributableCount)
        namedFlowCount = try int(.namedFlowCount)
        cachedNameCount = try int(.cachedNameCount)
        privateRelayFlowCount = try int(.privateRelayFlowCount)
        evictedFlowCount = try count(.evictedFlowCount)
        cleartextFlowCount = try int(.cleartextFlowCount)
        unknownSecurityFlowCount = try int(.unknownSecurityFlowCount)
        encryptedFlowCount = try int(.encryptedFlowCount)
        totalBytesOut = try count(.totalBytesOut)
        totalBytesIn = try count(.totalBytesIn)
        packetsCaptured = try count(.packetsCaptured)
        packetsDropped = try count(.packetsDropped)
        warnings = try strings(.warnings)
        interfaceTransitions = try strings(.interfaceTransitions)
    }
}

public struct FlowSnapshot: Codable, Sendable {
    public let version: Int
    public let generatedAt: Date
    public let startedAt: Date
    public let interfaces: [String]
    public let flows: [WireFlow]
    public let statistics: WireStatistics

    /// The opening bytes of unencrypted connections, when the daemon was started with
    /// `--read-cleartext`.
    ///
    /// Three states, and the difference between the last two is the point: **nil** means
    /// the daemon is not reading payload at all, **empty** means it is and has found
    /// nothing to read. A client that collapsed those would show the same blank list for
    /// "not watching" and "watched, saw nothing" — the exact ambiguity this project makes
    /// a rule of avoiding.
    public let cleartextExcerpts: [WireExcerpt]?

    public init(
        version: Int = WireProtocol.version,
        generatedAt: Date,
        startedAt: Date,
        interfaces: [String],
        flows: [WireFlow],
        statistics: WireStatistics,
        cleartextExcerpts: [WireExcerpt]? = nil
    ) {
        self.cleartextExcerpts = cleartextExcerpts
        self.version = version
        self.generatedAt = generatedAt
        self.startedAt = startedAt
        self.interfaces = interfaces
        self.flows = flows
        self.statistics = statistics
    }

    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}

extension FlowKey {
    /// The identifier a flow carries on the wire.
    ///
    /// Lives on the key because that is all it depends on, and because two things need it:
    /// `wireRepresentation()` and the payload excerpts, which are published separately and
    /// have to name the same connection. Deriving it twice from a format string in two
    /// places would mean excerpts silently stopping matching flows the moment either
    /// changed.
    public var wireID: String {
        "\(transport.name)|\(local):\(localPort)|\(remote):\(remotePort)"
    }
}

extension Flow {
    /// Builds the wire form of a flow.
    public func wireRepresentation() -> WireFlow {
        let relay = NameResolutionCache.classify(hostName: hostName) == .privateRelay
        return WireFlow(
            id: key.wireID,
            processName: owner?.name,
            processPath: owner?.path,
            pid: owner?.pid,
            transport: key.transport.name,
            localAddress: key.local.description,
            localPort: key.localPort,
            remoteAddress: key.remote.description,
            remotePort: key.remotePort,
            hostName: hostName,
            hostNameIsProof: hostNameSource == .serverNameIndication,
            isPrivateRelay: relay,
            bytesOut: bytesOut,
            bytesIn: bytesIn,
            packetsOut: packetsOut,
            packetsIn: packetsIn,
            tcpState: tcpState.map(String.init(describing:)),
            firstSeen: firstSeen,
            lastSeen: lastSeen,
            location: location,
            classification: classification,
            networkOperator: networkOperator,
            isOutgoing: {
                switch direction {
                case .outgoing: return true
                case .incoming: return false
                case .undetermined: return nil
                }
            }(),
            initiationIsCertain: initiationIsCertain,
            security: security?.security,
            protocolName: security?.protocolName,
            securityIsProof: security.map(\.isProof)
        )
    }
}
