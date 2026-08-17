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
    ///
    /// The floor is six hours rather than ten minutes because the cache is now carried
    /// between runs. At ten minutes an overnight gap expired almost everything: a run the
    /// next morning reloaded nine names having saved over two hundred, so the warm start
    /// helped within a session and not at all across days. Six hours is a deliberate
    /// trade — an address may be reassigned in that window, which is why DNS-derived
    /// names are always marked as inferred rather than shown as fact.
    private static let minimumRetention: TimeInterval = 6 * 3600
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

/// Everything one packet's payload had to say, as owned values.
///
/// A single struct rather than three separate passes over the same bytes: the buffer is
/// only alive once, and walking it three times would cost three times as much on the
/// hottest path in the program.
public struct PacketObservation: Sendable {
    /// A hostname learned from a ClientHello or a DNS answer.
    public var name: NameObservation?
    /// What protocol this is and whether it protects its contents.
    public var reading: ProtocolSniffer.Reading?
    /// A copy of the opening bytes, unlabelled: which direction they went is only known
    /// once the flow key has been normalised, which happens on another queue. Only ever
    /// non-nil when payload reading was asked for.
    public var excerptBytes: [UInt8]?
    /// How much payload the packet carried, which is more than `excerptBytes` holds once a
    /// packet exceeds the per-packet copy limit. Carried separately so the store can keep
    /// an honest running total of a conversation's size.
    public var payloadBytesSeen = 0

    public var isEmpty: Bool { name == nil && reading == nil && excerptBytes == nil }
}

/// Pulls hostnames, protocol identity and — when asked — payload bytes out of packets.
///
/// **Lifetime contract:** the payload buffer belongs to libpcap and is valid only for the
/// duration of the capture callback. Everything here must therefore run synchronously,
/// inside that callback, and return owned values. Deferring the work to another queue
/// would read freed memory.
public enum PayloadInspector {
    /// Reads one packet.
    ///
    /// `capturePayload` is the `--read-cleartext` flag reaching the hot path. When it is
    /// false — the default, and every run that has ever existed before this — no bytes are
    /// copied and behaviour is exactly what it was: names, and nothing else.
    public static func inspect(
        packet: ParsedPacket,
        payload: UnsafeRawBufferPointer,
        capturePayload: Bool
    ) -> PacketObservation? {
        guard !payload.isEmpty else { return nil }

        var observation = PacketObservation()
        let findings = ProtocolSniffer.read(packet: packet, payload: payload)
        observation.reading = findings.reading

        switch packet.transport {
        case .udp:
            // Recognising a packet as DNS *is* parsing it, so the sniffer already did the
            // work — question section, answer records, compression pointers and all. Taking
            // the answer it hands back is what keeps this to one pass over the buffer.
            observation.name = findings.dnsAnswer.map(NameObservation.dnsAnswer)

        case .tcp:
            // DNS over TCP is length-prefixed; the ClientHello is not. Only the latter is
            // worth chasing, since large DNS answers over TCP are rare on a client.
            if let name = TLSClientHello.serverName(in: payload) {
                observation.name = .serverName(name)
            }

        default:
            break
        }

        if capturePayload, shouldCopy(observation.reading) {
            observation.excerptBytes = PayloadExcerpt.copy(from: payload)
            observation.payloadBytesSeen = payload.count
        }

        return observation.isEmpty ? nil : observation
    }

    /// The gate that keeps payload copying off the hot path.
    ///
    /// A packet is copied unless it was *read* as encrypted. That is a three-byte
    /// comparison for TLS, which is the overwhelming majority of a real machine's traffic,
    /// so almost nothing is copied on a normal system.
    ///
    /// Note what does *not* exempt a packet: an `encrypted` reading resting only on the
    /// port. Port 443 is the internet's junk drawer, and skipping its payload would mean
    /// the one thing worth catching — something plaintext on a port that promises
    /// otherwise — is the one thing never looked at.
    ///
    /// A nil reading means the protocol has no ports at all — ICMP and friends. Those are
    /// not copied: with no ports there is no connection to characterise, so `security`
    /// stays nil, and the Cleartext view has nothing it could show. Copying them anyway
    /// spent the bounded 64-flow buffer and the per-snapshot byte budget on payload that
    /// could never be displayed, evicting the cleartext connections the buffer is for.
    private static func shouldCopy(_ reading: ProtocolSniffer.Reading?) -> Bool {
        guard let reading else { return false }
        return !(reading.security == .encrypted && reading.evidence == .payload)
    }
}
