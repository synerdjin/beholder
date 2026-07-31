import Foundation

/// Something learned about a name by watching traffic.
public enum NameObservation: Sendable, Equatable {
    /// A DNS response mapping a queried name onto addresses.
    case dnsAnswer(DNSMessage.Answer)
    /// A TLS ClientHello naming the host this particular connection wants.
    case serverName(String)
}

/// How a hostname was established, best evidence first.
public enum NameSource: Sendable, Equatable, Comparable {
    /// Inferred from a DNS answer seen earlier. An address can host many names, so this
    /// is a good guess rather than proof.
    case dns
    /// Read from this connection's own ClientHello. Proof, for this flow specifically.
    case serverNameIndication

    public static func < (lhs: NameSource, rhs: NameSource) -> Bool {
        lhs == .dns && rhs == .serverNameIndication
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
    private struct Entry {
        var name: String
        var expiresAt: Date
    }

    private var entries: [IPAddress: Entry] = [:]

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
                existing.name.count <= answer.name.count
            {
                entries[address]?.expiresAt = expiry
                continue
            }
            entries[address] = Entry(name: answer.name, expiresAt: expiry)
        }

        if entries.count > Self.maximumEntries {
            expire(at: now)
        }
    }

    public func name(for address: IPAddress, at now: Date = Date()) -> String? {
        guard let entry = entries[address], entry.expiresAt > now else { return nil }
        return entry.name
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
    /// iCloud Private Relay bootstraps through `mask.icloud.com` / `mask-h2.icloud.com`,
    /// and that lookup happens in the clear, so watching DNS is enough to recognise the
    /// ingress. Worth labelling explicitly: under Private Relay, Safari's real
    /// destinations are unknowable from this machine by design, and showing a bare Apple
    /// address invites the user to think Beholder is broken.
    public static func classify(hostName: String?) -> EndpointKind {
        guard let hostName else { return .ordinary }
        let lowercased = hostName.lowercased()
        guard lowercased.hasSuffix(".icloud.com") || lowercased == "icloud.com" else {
            return .ordinary
        }
        return lowercased.hasPrefix("mask") ? .privateRelay : .ordinary
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
