import Foundation

/// Something learned about a name by watching traffic.
public enum NameObservation: Sendable, Equatable {
    /// A DNS response mapping a queried name onto addresses.
    case dnsAnswer(DNSMessage.Answer)
    /// A TLS ClientHello naming the host this particular connection wants.
    case serverName(String)
}

/// How a hostname was established, weakest evidence first.
public enum NameSource: String, Sendable, Equatable, Comparable, CaseIterable {
    /// A PTR record for the address. The weakest source: PTR names describe
    /// infrastructure rather than service, so a Google address resolves to something
    /// like `lga25s71-in-f14.1e100.net` rather than to anything a person asked for.
    /// Still worth having — it names the operator, which is often the useful part.
    case reverseLookup
    /// Inferred from a DNS answer seen earlier. An address can host many names, so this
    /// is a good guess rather than proof.
    case dns
    /// Read from this connection's own ClientHello. Proof, for this flow specifically.
    case serverNameIndication

    private var rank: Int {
        switch self {
        case .reverseLookup: return 0
        case .dns: return 1
        case .serverNameIndication: return 2
        }
    }

    public static func < (lhs: NameSource, rhs: NameSource) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// What kind of endpoint an address turned out to be.
public enum EndpointKind: Sendable, Equatable {
    case ordinary
    /// An iCloud Private Relay ingress. Traffic through it is end-to-end encrypted to
    /// Apple, so the real destination is deliberately unknowable from this machine.
    case privateRelay
}

/// Remembers which names map to which addresses, from DNS answers seen on the wire.
///
/// Not thread-safe; confine to one queue, as with `FlowTable`.
public final class NameResolutionCache {
    struct Entry {
        var name: String
        var expiresAt: Date
        var source: NameSource
    }

    private var entries: [IPAddress: Entry] = [:]

    /// Exposed for persistence, which lives in an extension.
    var entriesForPersistence: [IPAddress: Entry] { entries }

    /// Stores a name directly. Used when reloading from disk and by reverse lookups;
    /// observed DNS goes through `record(_:at:)`.
    public func adopt(
        name: String, for address: IPAddress, expiresAt: Date, source: NameSource
    ) {
        // Better evidence wins; equal evidence prefers the shorter, more recognisable name.
        if let existing = entries[address], existing.expiresAt > Date() {
            if existing.source > source { return }
            if existing.source == source, existing.name.count <= name.count { return }
        }
        entries[address] = Entry(name: name, expiresAt: expiresAt, source: source)
    }

    /// Whether this address already has a name, so a reverse lookup can be skipped.
    public func hasName(for address: IPAddress, at now: Date = Date()) -> Bool {
        guard let entry = entries[address] else { return false }
        return entry.expiresAt > now
    }

    public func source(for address: IPAddress) -> NameSource? {
        entries[address]?.source
    }

    /// DNS time-to-live governs when a resolver must ask again — it is not a statement
    /// about how long a name remains *useful for display*. A 30-second TTL on a
    /// long-lived connection would otherwise blank out the hostname mid-flow, which is
    /// worse than showing a name that is slightly stale.
    private static let minimumRetention: TimeInterval = 600
    private static let maximumRetention: TimeInterval = 86400

    /// Bounds memory on a machine doing a lot of DNS.
    private static let maximumEntries = 16384

    public init() {}

    public var count: Int { entries.count }

    public func record(_ answer: DNSMessage.Answer, at now: Date = Date()) {
        let retention = min(
            max(TimeInterval(answer.timeToLive), Self.minimumRetention),
            Self.maximumRetention
        )
        let expiry = now.addingTimeInterval(retention)

        for address in answer.addresses {
            // Prefer the shortest name for an address. CDNs resolve many long aliases to
            // one address, and the shorter name is almost always the recognisable one.
            if let existing = entries[address],
                existing.expiresAt > now,
                existing.source == .dns,
                existing.name.count <= answer.name.count
            {
                entries[address]?.expiresAt = expiry
                continue
            }
            adopt(name: answer.name, for: address, expiresAt: expiry, source: .dns)
        }

        if entries.count > Self.maximumEntries {
            expire(at: now)
        }
    }

    public func name(for address: IPAddress, at now: Date = Date()) -> String? {
        resolved(for: address, at: now)?.name
    }

    /// The name and the evidence behind it, so callers can record provenance rather than
    /// assuming it.
    public func resolved(
        for address: IPAddress, at now: Date = Date()
    ) -> (name: String, source: NameSource)? {
        guard let entry = entries[address], entry.expiresAt > now else { return nil }
        return (entry.name, entry.source)
    }

    @discardableResult
    public func expire(at now: Date = Date()) -> Int {
        let before = entries.count
        entries = entries.filter { $0.value.expiresAt > now }

        // If everything is still live and we are over the cap, drop the soonest to
        // expire. Silently unbounded growth is not an option for a long-running daemon.
        if entries.count > Self.maximumEntries {
            let survivors = entries
                .sorted { $0.value.expiresAt > $1.value.expiresAt }
                .prefix(Self.maximumEntries)
            entries = Dictionary(uniqueKeysWithValues: survivors.map { ($0.key, $0.value) })
        }
        return before - entries.count
    }

    /// Classifies an endpoint from its hostname.
    ///
    /// Worth labelling explicitly: under Private Relay the real destination is
    /// unknowable from this machine by design, and showing a bare Apple address invites
    /// the user to think Beholder is broken.
    ///
    /// Recognising it needs more than one pattern. Observed on a live machine:
    /// `mask.apple-dns.net` and `mask-h2.apple-dns.net` for the ingress, and
    /// `apple-relay.fastly-edge.com` / `apple-relay.cloudflare.com` for the egress
    /// partners that carry the second hop. An earlier version matched only
    /// `mask*.icloud.com` and missed every one of them.
    public static func classify(hostName: String?) -> EndpointKind {
        guard let hostName else { return .ordinary }
        let name = hostName.lowercased()

        // Ingress: mask… on either of Apple's two relay domains.
        if name.hasPrefix("mask") {
            if name.hasSuffix(".icloud.com") || name.hasSuffix(".apple-dns.net") {
                return .privateRelay
            }
        }
        // Egress partners, which Apple names explicitly.
        if name.hasPrefix("apple-relay.") || name.contains(".apple-relay.") {
            return .privateRelay
        }
        return .ordinary
    }
}

/// Pulls hostnames out of packet payloads.
///
/// **Lifetime contract:** the payload buffer belongs to libpcap and is valid only for the
/// duration of the capture callback. Everything here must therefore run synchronously,
/// inside that callback, and return owned values. Deferring the work to another queue
/// would read freed memory.
public enum PayloadInspector {
    public static func inspect(
        packet: ParsedPacket,
        payload: UnsafeRawBufferPointer
    ) -> NameObservation? {
        guard !payload.isEmpty else { return nil }

        switch packet.transport {
        case .udp:
            // Ordinary DNS, multicast DNS, and Apple's local resolver port.
            let dnsPorts: Set<UInt16> = [53, 5353]
            guard
                dnsPorts.contains(packet.sourcePort)
                    || dnsPorts.contains(packet.destinationPort)
            else { return nil }
            return DNSMessage.parseResponse(payload).map(NameObservation.dnsAnswer)

        case .tcp:
            // DNS over TCP is length-prefixed; the ClientHello is not. Only the latter is
            // worth chasing, since large DNS answers over TCP are rare on a client.
            guard let name = TLSClientHello.serverName(in: payload) else { return nil }
            return .serverName(name)

        default:
            return nil
        }
    }
}
