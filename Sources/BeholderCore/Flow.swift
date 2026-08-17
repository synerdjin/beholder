import Foundation

/// Which way a packet moved relative to this machine.
public enum FlowDirection: Sendable, Hashable {
    case outbound
    case inbound
}

/// Who opened a connection.
public enum ConnectionDirection: Sendable, Hashable {
    /// This machine reached out.
    case outgoing
    /// Something reached in.
    case incoming
    /// Not determinable from what was observed. Reported as such rather than guessed:
    /// claiming an inbound connection that never happened is alarming in a way that
    /// saying "unknown" is not.
    case undetermined
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

    /// Where the far end is, from the local geolocation database. Nil when no database
    /// is installed, or when the address is not one it can place.
    public var location: GeoLocation?

    /// Who operates the far end, and what its name suggests it is for. Requires a
    /// hostname, so this stays nil for flows that were never named.
    public var classification: HostClassification?

    /// The network announcing the remote address. Needs no hostname, so this is often
    /// the only identification available for an address nothing else can name.
    public var networkOperator: NetworkOperator?

    /// Whether this conversation protects what it carries, and what that rests on.
    ///
    /// Nil for ICMP and anything else without ports, where there is no connection to
    /// characterise. Updated through `FlowTable.applyReading`, which honours the evidence
    /// ladder so a port guess on a later packet cannot undo something read from the bytes.
    public var security: ProtocolSniffer.Reading?

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

    /// macOS allocates ephemeral client ports from here upward
    /// (`net.inet.ip.portrange.first`). A socket bound below it is nearly always a
    /// service rather than a client.
    public static let ephemeralPortFloor: UInt16 = 49152

    /// The best available reading of who opened this connection.
    ///
    /// Watching the SYN settles it. Failing that, port allocation is the next best
    /// evidence: an ephemeral local port talking to a service port is a connection this
    /// machine made.
    ///
    /// Note what is deliberately *not* used here — which side sent the first packet
    /// Beholder happened to see. For a connection already established when capture
    /// started, that is decided by whichever end spoke next, which is a coin flip. An
    /// earlier version used it and duly reported seven inbound connections to a laptop
    /// behind a VPN, every one of them an outgoing connection misread.
    public var direction: ConnectionDirection {
        if initiationIsCertain {
            return initiatedLocally == true ? .outgoing : .incoming
        }
        let localIsEphemeral = key.localPort >= Self.ephemeralPortFloor
        let remoteIsEphemeral = key.remotePort >= Self.ephemeralPortFloor
        if localIsEphemeral != remoteIsEphemeral {
            return localIsEphemeral ? .outgoing : .incoming
        }
        // Both ends ephemeral, or both privileged: loopback pairs and peer-to-peer
        // traffic land here, and there is nothing left to reason from.
        return .undetermined
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

    /// Takes on a security reading, if it is allowed to replace what is already known.
    ///
    /// Never downgrades, for the same reason a hostname does not: every packet after the
    /// first of an HTTP conversation looks like nothing in particular, so a reading taken
    /// from the request line would otherwise be replaced a millisecond later by a port
    /// guess — or by `unknown`, which would make the display flicker between "this is
    /// HTTP" and "no idea" for the life of the connection.
    ///
    /// Proven cleartext is also sticky: once bytes have been read off this connection in
    /// the clear, they were in the clear, and nothing later can make that untrue. A
    /// STARTTLS session therefore stays reported as cleartext, which is the accurate thing
    /// to say about a conversation that began unprotected. It also closes a false positive
    /// that would otherwise run the wrong way — a few bytes of binary in an HTTP body can
    /// happen to open like a TLS record header, and without this the connection would flip
    /// to "encrypted" mid-stream and reassure the user about traffic it had just watched
    /// go past in plain text.
    public mutating func adopt(_ reading: ProtocolSniffer.Reading) {
        if let current = security {
            if current.evidence > reading.evidence { return }
            let provenCleartext = current.evidence == .payload && current.security == .cleartext
            if provenCleartext, reading.security != .cleartext { return }
        }
        security = reading
    }
}

extension IPAddress {
    /// A stable ordering used only to break ties deterministically.
    var comparisonKey: (UInt8, UInt64, UInt64) {
        (family.rawValue, high, low)
    }
}
