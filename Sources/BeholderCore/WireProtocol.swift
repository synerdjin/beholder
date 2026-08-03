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
    public static let version = 1
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

    /// True when this machine opened the connection. Nil when nothing has been observed
    /// yet, which in practice never reaches a client.
    public let isOutgoing: Bool?
    /// True when `isOutgoing` came from watching the opening handshake rather than being
    /// inferred from which direction moved first.
    public let initiationIsCertain: Bool

    public var totalBytes: UInt64 { bytesOut + bytesIn }

    /// What to show for the far end: the hostname when known, the address otherwise.
    /// Never blank — the address is true even when the name is not known.
    public var remoteDescription: String {
        hostName ?? remoteAddress
    }

    public init(
        id: String, processName: String?, processPath: String?, pid: Int32?,
        transport: String, localAddress: String, localPort: UInt16,
        remoteAddress: String, remotePort: UInt16,
        hostName: String?, hostNameIsProof: Bool, isPrivateRelay: Bool,
        bytesOut: UInt64, bytesIn: UInt64, packetsOut: UInt64, packetsIn: UInt64,
        tcpState: String?, firstSeen: Date, lastSeen: Date,
        isOutgoing: Bool?, initiationIsCertain: Bool
    ) {
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
}

public struct FlowSnapshot: Codable, Sendable {
    public let version: Int
    public let generatedAt: Date
    public let startedAt: Date
    public let interfaces: [String]
    public let flows: [WireFlow]
    public let statistics: WireStatistics

    public init(
        version: Int = WireProtocol.version,
        generatedAt: Date,
        startedAt: Date,
        interfaces: [String],
        flows: [WireFlow],
        statistics: WireStatistics
    ) {
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

extension Flow {
    /// Builds the wire form of a flow.
    public func wireRepresentation() -> WireFlow {
        let relay = NameResolutionCache.classify(hostName: hostName) == .privateRelay
        return WireFlow(
            id: "\(key.transport.name)|\(key.local):\(key.localPort)|\(key.remote):\(key.remotePort)",
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
            isOutgoing: {
                switch direction {
                case .outgoing: return true
                case .incoming: return false
                case .undetermined: return nil
                }
            }(),
            initiationIsCertain: initiationIsCertain
        )
    }
}
