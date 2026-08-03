import Foundation

/// Which way a packet moved relative to this machine.
public enum FlowDirection: Sendable, Hashable {
    case outbound
    case inbound
}

/// Identifies one conversation, normalised so that both directions of the same
/// conversation produce the same key.
///
/// Normalisation is the whole point: a captured packet is just a source and a
/// destination, and without deciding which end is "us" the table would hold two
/// half-conversations per connection and be unable to say whether traffic went up or
/// down — the first thing anyone looks at.
public struct FlowKey: Hashable, Sendable {
    public let transport: TransportProtocol
    public let local: IPAddress
    public let localPort: UInt16
    public let remote: IPAddress
    public let remotePort: UInt16

    public init(
        transport: TransportProtocol,
        local: IPAddress,
        localPort: UInt16,
        remote: IPAddress,
        remotePort: UInt16
    ) {
        self.transport = transport
        self.local = local
        self.localPort = localPort
        self.remote = remote
        self.remotePort = remotePort
    }

    /// Derives the key and direction for a captured packet.
    ///
    /// When exactly one end is a local interface address the answer is unambiguous. Both
    /// ends are local for loopback traffic, and neither is when an interface address has
    /// not been refreshed yet — in both cases we fall back to treating the higher port as
    /// the local one, since ephemeral client ports are high and service ports are low.
    /// The fallback only has to be *consistent* to keep both directions on one key; being
    /// occasionally backwards costs a mislabelled direction, not a lost flow.
    public static func make(
        from packet: ParsedPacket,
        localAddresses: Set<IPAddress>
    ) -> (key: FlowKey, direction: FlowDirection) {
        let sourceIsLocal = localAddresses.contains(packet.source)
        let destinationIsLocal = localAddresses.contains(packet.destination)

        let sourceIsTheLocalEnd: Bool
        switch (sourceIsLocal, destinationIsLocal) {
        case (true, false):
            sourceIsTheLocalEnd = true
        case (false, true):
            sourceIsTheLocalEnd = false
        default:
            if packet.sourcePort != packet.destinationPort {
                sourceIsTheLocalEnd = packet.sourcePort > packet.destinationPort
            } else {
                // Identical ports: fall back to address ordering, purely for determinism.
                sourceIsTheLocalEnd =
                    packet.source.comparisonKey >= packet.destination.comparisonKey
            }
        }

        let key = sourceIsTheLocalEnd
            ? FlowKey(
                transport: packet.transport,
                local: packet.source, localPort: packet.sourcePort,
                remote: packet.destination, remotePort: packet.destinationPort
            )
            : FlowKey(
                transport: packet.transport,
                local: packet.destination, localPort: packet.destinationPort,
                remote: packet.source, remotePort: packet.sourcePort
            )

        return (key, sourceIsTheLocalEnd ? .outbound : .inbound)
    }
}

/// One conversation and everything observed about it.
public struct Flow: Sendable {
    public let key: FlowKey

    public var bytesOut: UInt64 = 0
    public var bytesIn: UInt64 = 0
    public var packetsOut: UInt64 = 0
    public var packetsIn: UInt64 = 0

    public var firstSeen: Date
    public var lastSeen: Date

    /// The union of every TCP flag seen, which is how the table knows a connection was
    /// opened (SYN) or torn down (FIN/RST) without tracking full TCP state.
    public var tcpFlagsSeen: TCPFlags = []

    /// The interface the traffic was captured on. A flow can legitimately appear on more
    /// than one (a tunnel and the physical interface beneath it); this records the first.
    public var interfaceName: String

    /// Nil until the attributor identifies the socket's owner, and it may stay nil for
    /// connections too short-lived to catch. Displayed as unknown rather than dropped.
    public var owner: ProcessOwner?
    public var tcpState: TCPState?

    /// The hostname this connection asked for, and how that was established.
    ///
    /// SNI outranks DNS: it names the host for *this* connection, whereas a DNS answer
    /// only says some name once resolved to this address, and one address commonly
    /// serves many names.
    public var hostName: String?
    public var hostNameSource: NameSource?

    /// Whether this machine opened the connection, rather than accepting one.
    ///
    /// Nil only before the first packet is recorded. Determining it from port numbers
    /// would be a guess — plenty of services live on high ports — so it comes from
    /// observed direction instead.
    public private(set) var initiatedLocally: Bool?

    /// True when the answer came from watching the opening SYN, which is proof. False
    /// means it was inferred from whichever direction moved first, which is right for
    /// UDP and for TCP connections that were already open when capture started, but is
    /// an inference rather than an observation.
    public private(set) var initiationIsCertain = false

    public init(key: FlowKey, interfaceName: String, at timestamp: Date) {
        self.key = key
        self.interfaceName = interfaceName
        self.firstSeen = timestamp
        self.lastSeen = timestamp
    }

    public var totalBytes: UInt64 { bytesOut + bytesIn }
    public var totalPackets: UInt64 { packetsOut + packetsIn }

    /// True once a FIN or RST has been seen, meaning the conversation is winding down.
    public var isClosing: Bool {
        tcpFlagsSeen.isConnectionClose
    }

    public mutating func record(
        direction: FlowDirection,
        wireBytes: UInt32,
        tcpFlags: TCPFlags,
        at timestamp: Date
    ) {
        switch direction {
        case .outbound:
            bytesOut += UInt64(wireBytes)
            packetsOut += 1
        case .inbound:
            bytesIn += UInt64(wireBytes)
            packetsIn += 1
        }

        // Whoever moved first is presumed to have started it.
        if initiatedLocally == nil {
            initiatedLocally = direction == .outbound
        }
        // A SYN with no ACK *is* the connection opening, so its direction settles the
        // question and outranks the presumption above. Only the first one counts: a
        // retransmitted SYN says nothing new, and a SYN-ACK travels the other way.
        if tcpFlags.isConnectionOpen, !initiationIsCertain {
            initiatedLocally = direction == .outbound
            initiationIsCertain = true
        }

        tcpFlagsSeen.formUnion(tcpFlags)
        lastSeen = timestamp
    }
}

extension IPAddress {
    /// A stable ordering used only to break ties deterministically.
    var comparisonKey: (UInt8, UInt64, UInt64) {
        (family.rawValue, high, low)
    }
}
