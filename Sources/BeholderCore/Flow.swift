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

    /// How this conversation's packets travelled: round trips, repeats, arrival spacing.
    ///
    /// Always present but only filled in when measurement is on. An untouched value reads
    /// as "nothing measured", which is the same thing an unmeasurable conversation reads
    /// as — and both are published as absence rather than as zero, because a zero here
    /// would be indistinguishable from a perfect connection.
    public var quality = FlowQuality()

    /// How this conversation's far end is grouped in the per-minute time series.
    ///
    /// The autonomous system when one is known, because that is the unit of *independent
    /// network*. The whole ISP question turns on being able to say "three networks sharing
    /// nothing but my uplink all slowed at once", and grouping by hostname or by address
    /// would defeat it: a hundred addresses behind one CDN are one network, and counting
    /// them as a hundred would make a single CDN's bad afternoon look like everything
    /// failing together.
    ///
    /// Stored rather than computed because it is read on every packet, and building
    /// "AS15169" afresh each time would put a string allocation on the hot path. Updated
    /// when the network operator is learned, which happens once per flow.
    public private(set) var destinationGroupKey: String

    /// The human-readable name for that group.
    ///
    /// Computed, unlike the key. The hot-path argument above is about `"AS15169"`, which
    /// really is built per packet if it is not stored; the label is a plain copy of a
    /// `String?` the flow already holds, so storing it bought a redundant field per flow
    /// and an invariant between two fields that could drift.
    public var destinationGroupLabel: String? { networkOperator?.organization }

    /// True when Beholder itself sent this traffic — which today means `--probe`.
    ///
    /// A property of the flow rather than a test applied at one call site, because the
    /// exclusion has to hold everywhere the flow is read: the per-minute series, the live
    /// summary, and the history table. Set once, when the flow is first seen.
    public var isSelfOriginated = false

    public init(key: FlowKey, interfaceName: String, at timestamp: Date) {
        self.key = key
        self.interfaceName = interfaceName
        self.firstSeen = timestamp
        self.lastSeen = timestamp
        self.destinationGroupKey = Flow.addressGroup(for: key.remote)
    }

    /// Adopts the network operator, and with it the grouping the time series uses.
    ///
    /// The two move together so a flow cannot end up filed under its address prefix while
    /// claiming to know which network it is talking to.
    public mutating func adoptNetworkOperator(_ network: NetworkOperator) {
        networkOperator = network
        destinationGroupKey = "AS\(network.number)"
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

    /// Folds a captured packet in, counting it and — when asked — measuring it.
    ///
    /// The two are kept separate below because counting must never be optional: the byte
    /// totals are the thing Beholder exists to be right about, and they are computed the
    /// same way whether or not anything is measuring quality.
    @discardableResult
    public mutating func record(
        _ packet: ParsedPacket,
        direction: FlowDirection,
        at timestamp: Date,
        measuringQuality: Bool
    ) -> QualityEvent? {
        record(
            direction: direction,
            wireBytes: packet.wireBytes,
            tcpFlags: packet.tcpFlags,
            at: timestamp
        )
        guard measuringQuality else { return nil }
        return quality.record(packet, direction: direction)
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
