import CBeholderShim

/// A compact, hashable IPv4 or IPv6 address.
///
/// Stored as two 64-bit host-order integers rather than a byte array so that flow-table
/// keys hash and compare without touching the heap — this type is on the hot path for
/// every captured packet.
public struct IPAddress: Hashable, Sendable, CustomStringConvertible {
    public enum Family: UInt8, Sendable, Hashable {
        case v4 = 4
        case v6 = 6
    }

    public let family: Family

    /// Host-order numeric value. For IPv4, `high` is 0 and the address occupies the low
    /// 32 bits of `low`. For IPv6, `high` is the first 8 bytes and `low` the last 8.
    @usableFromInline let high: UInt64
    @usableFromInline let low: UInt64

    @inlinable
    init(family: Family, high: UInt64, low: UInt64) {
        self.family = family
        self.high = high
        self.low = low
    }

    /// Builds an IPv4 address from the 4 bytes as they appear in a packet.
    @inlinable
    public init(v4NetworkOrder raw: UInt32) {
        self.init(family: .v4, high: 0, low: UInt64(UInt32(bigEndian: raw)))
    }

    /// Builds an IPv6 address from 16 bytes as they appear in a packet.
    /// The caller must guarantee 16 readable bytes at `pointer`.
    @inlinable
    public init(v6NetworkOrderBytes pointer: UnsafeRawPointer) {
        self.init(
            family: .v6,
            high: UInt64(bigEndian: pointer.loadUnaligned(as: UInt64.self)),
            low: UInt64(bigEndian: pointer.loadUnaligned(fromByteOffset: 8, as: UInt64.self))
        )
    }

    /// Builds an address from a raw byte buffer: 4 bytes for IPv4, 16 for IPv6.
    public init?(networkOrderBytes bytes: [UInt8], family: Family) {
        switch family {
        case .v4:
            guard bytes.count >= 4 else { return nil }
            let value = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
                | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
            self.init(family: .v4, high: 0, low: UInt64(value))
        case .v6:
            guard bytes.count >= 16 else { return nil }
            var high: UInt64 = 0
            var low: UInt64 = 0
            for index in 0..<8 { high = high << 8 | UInt64(bytes[index]) }
            for index in 8..<16 { low = low << 8 | UInt64(bytes[index]) }
            self.init(family: .v6, high: high, low: low)
        }
    }

    /// The address as network-order bytes: 4 for IPv4, 16 for IPv6.
    public var networkOrderBytes: [UInt8] {
        switch family {
        case .v4:
            let value = UInt32(truncatingIfNeeded: low)
            return [
                UInt8(truncatingIfNeeded: value >> 24),
                UInt8(truncatingIfNeeded: value >> 16),
                UInt8(truncatingIfNeeded: value >> 8),
                UInt8(truncatingIfNeeded: value),
            ]
        case .v6:
            var out = [UInt8]()
            out.reserveCapacity(16)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: high >> UInt64(shift)))
            }
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: low >> UInt64(shift)))
            }
            return out
        }
    }

    public var description: String {
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let addressFamily = family == .v4 ? AF_INET : AF_INET6
        let bytes = networkOrderBytes
        let rendered = bytes.withUnsafeBytes { source in
            inet_ntop(addressFamily, source.baseAddress, &text, socklen_t(INET6_ADDRSTRLEN))
        }
        return rendered == nil ? "<invalid>" : String(nullTerminated: text)
    }

    /// Parses a textual address. Accepts both families; returns nil for anything else.
    public init?(text: String) {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            self.init(v4NetworkOrder: v4.s_addr)
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            guard let parsed = IPAddress(networkOrderBytes: bytes, family: .v6) else {
                return nil
            }
            self = parsed
            return
        }
        return nil
    }

    /// Renders an address with its port.
    ///
    /// IPv6 addresses must be bracketed, because they contain colons themselves:
    /// `2607:f8b0:4020:c0b::64:443` is genuinely ambiguous about where the address ends
    /// and the port begins, while `[2607:f8b0:4020:c0b::64]:443` is not.
    public func endpoint(port: UInt16) -> String {
        family == .v6 ? "[\(self)]:\(port)" : "\(self):\(port)"
    }

    /// True for addresses that never leave the machine or the local network. Used to
    /// separate "my laptop talked to the internet" from LAN and loopback chatter.
    public var isLoopback: Bool {
        switch family {
        case .v4: return UInt32(truncatingIfNeeded: low) >> 24 == 127
        case .v6: return high == 0 && low == 1
        }
    }

    public var isLinkLocal: Bool {
        switch family {
        case .v4: return UInt32(truncatingIfNeeded: low) >> 16 == 0xA9FE  // 169.254/16
        // fe80::/10 — the top ten bits are 1111111010, i.e. 0x3FA.
        case .v6: return high >> 54 == 0x3FA
        }
    }

    public var isPrivate: Bool {
        switch family {
        case .v4:
            let value = UInt32(truncatingIfNeeded: low)
            if value >> 24 == 10 { return true }                    // 10/8
            if value >> 20 == 0xAC1 { return true }                 // 172.16/12
            if value >> 16 == 0xC0A8 { return true }                // 192.168/16
            // 100.64/10, RFC 6598 shared address space. Carrier NAT uses it, and so does
            // this machine's VPN for its internal resolver. It is not routable on the
            // public internet, so geolocating or reverse-resolving it is wasted work.
            if value >> 22 == 0x191 { return true }
            return false
        case .v6:
            return high >> 57 == 0x7E                               // fc00::/7
        }
    }

    /// True when the peer is outside this machine and its local network — the traffic a
    /// user actually cares to see on a map.
    public var isGloballyRoutable: Bool {
        !isLoopback && !isLinkLocal && !isPrivate && !isMulticast
    }

    /// The address with every bit below `prefixLength` cleared.
    ///
    /// Used to canonicalise a network before it becomes a pf table entry, so that
    /// `192.168.1.5/24` and `192.168.1.0/24` are one entry rather than two spellings of it.
    /// Without that, a reload would compute a difference against what pf already holds and
    /// add and remove the same network forever.
    ///
    /// Swift's shift operators are non-masking, so a shift of the full width yields zero
    /// rather than the undefined behaviour the C equivalent would have here — which is what
    /// makes the `/0` case fall out without a special case.
    public func masked(prefixLength: UInt8) -> IPAddress {
        switch family {
        case .v4:
            guard prefixLength < 32 else { return self }
            let mask = (~UInt64(0) << (32 - UInt64(prefixLength))) & 0xFFFF_FFFF
            return IPAddress(family: .v4, high: 0, low: low & mask)
        case .v6:
            guard prefixLength < 128 else { return self }
            if prefixLength >= 64 {
                let mask = ~UInt64(0) << (128 - UInt64(prefixLength))
                return IPAddress(family: .v6, high: high, low: low & mask)
            }
            let mask = ~UInt64(0) << (64 - UInt64(prefixLength))
            return IPAddress(family: .v6, high: high & mask, low: 0)
        }
    }

    public var isMulticast: Bool {
        switch family {
        case .v4: return UInt32(truncatingIfNeeded: low) >> 28 == 0xE     // 224/4
        case .v6: return high >> 56 == 0xFF                               // ff00::/8
        }
    }
}
