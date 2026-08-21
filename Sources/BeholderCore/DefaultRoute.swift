import CBeholderShim
import Darwin

/// The interface currently carrying the default route.
public struct DefaultRoute: Sendable, Equatable, CustomStringConvertible {
    public let interfaceName: String
    public let interfaceIndex: UInt32
    public let family: IPAddress.Family

    /// The next hop, when there is one with an address.
    ///
    /// Nil for a point-to-point link — a `utun` tunnel's next hop is the interface itself,
    /// expressed as a link-level address with no IP in it. That absence is meaningful
    /// rather than a failure: it is precisely the case where there is no local router to
    /// time separately, and so no way to tell "my Wi-Fi" from "my uplink".
    public let gateway: IPAddress?

    public init(
        interfaceName: String,
        interfaceIndex: UInt32,
        family: IPAddress.Family,
        gateway: IPAddress? = nil
    ) {
        self.interfaceName = interfaceName
        self.interfaceIndex = interfaceIndex
        self.family = family
        self.gateway = gateway
    }

    public var description: String {
        let hop = gateway.map { " via \($0)" } ?? ""
        return "\(interfaceName) (index \(interfaceIndex), IPv\(family.rawValue))\(hop)"
    }
}

/// Discovers which interface traffic actually leaves by.
///
/// This is not cosmetic. With a VPN up, the default route runs through a `utun`
/// interface and capturing the physical `en0` would show nothing but encrypted tunnel
/// packets — technically "traffic", but useless for telling the user which process
/// talked to whom. Beholder must follow the route, and the route moves whenever the VPN
/// connects or drops.
///
/// Uses an `RTM_GET` request on a routing socket, which returns the route the kernel
/// would actually *select* — the same thing `route -n get default` reports. Dumping the
/// whole table instead would show every candidate default route (physical and VPN both)
/// with no reliable way to tell which one wins.
public enum RouteLookup {
    public static func defaultRoute(family: IPAddress.Family = .v4) -> DefaultRoute? {
        let routeSocket = socket(PF_ROUTE, SOCK_RAW, 0)
        guard routeSocket >= 0 else { return nil }
        defer { close(routeSocket) }

        // Never block the caller indefinitely if the kernel has nothing to say.
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(
            routeSocket, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, socklen_t(MemoryLayout<timeval>.stride)
        )

        let sequence: Int32 = 1
        guard let request = makeRouteRequest(family: family, sequence: sequence) else {
            return nil
        }

        let written = request.withUnsafeBytes { bytes in
            write(routeSocket, bytes.baseAddress, bytes.count)
        }
        guard written == request.count else { return nil }

        // The routing socket is a broadcast channel — other processes' route messages
        // arrive here too. Read until we see the reply carrying our own sequence and pid.
        var response = [UInt8](repeating: 0, count: 4096)
        for _ in 0..<32 {
            let count = read(routeSocket, &response, response.count)
            guard count >= MemoryLayout<rt_msghdr>.stride else { return nil }

            let header = response.withUnsafeBytes {
                $0.loadUnaligned(as: rt_msghdr.self)
            }
            guard header.rtm_seq == sequence, header.rtm_pid == getpid() else {
                continue
            }

            let index = UInt32(header.rtm_index)
            var nameBuffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            guard if_indextoname(index, &nameBuffer) != nil else { return nil }

            return DefaultRoute(
                interfaceName: String(nullTerminated: nameBuffer),
                interfaceIndex: index,
                family: family,
                gateway: gateway(in: response, count: count, header: header)
            )
        }
        return nil
    }

    /// Pulls the next hop out of an `RTM_GET` reply.
    ///
    /// The addresses follow the header packed one after another, present only when their
    /// bit is set in `rtm_addrs` and always in bit order, each padded up to a multiple of
    /// four bytes. There is no length prefix and no way to seek: the gateway can only be
    /// reached by walking everything before it, which is why this is a loop rather than an
    /// offset.
    private static func gateway(
        in response: [UInt8], count: Int, header: rt_msghdr
    ) -> IPAddress? {
        var cursor = MemoryLayout<rt_msghdr>.stride
        var bit: Int32 = 1

        while bit <= RTA_GATEWAY, cursor < count {
            guard header.rtm_addrs & bit != 0 else {
                bit <<= 1
                continue
            }

            let length = Int(response[cursor])
            let family = Int32(response[cursor + 1])
            // A zero length still consumes a full word — the padding is what advances the
            // cursor, and treating it as zero would spin here forever.
            let step = length == 0 ? 4 : (length + 3) & ~3
            guard cursor + max(length, 1) <= count else { return nil }

            if bit == RTA_GATEWAY {
                return response.withUnsafeBytes { bytes -> IPAddress? in
                    guard let base = bytes.baseAddress?.advanced(by: cursor) else { return nil }
                    switch family {
                    case AF_INET where length >= MemoryLayout<sockaddr_in>.stride:
                        let address = base.loadUnaligned(as: sockaddr_in.self)
                        return IPAddress(v4NetworkOrder: address.sin_addr.s_addr)
                    case AF_INET6 where length >= MemoryLayout<sockaddr_in6>.stride:
                        var address = base.loadUnaligned(as: sockaddr_in6.self)
                        return withUnsafeBytes(of: &address.sin6_addr) {
                            IPAddress(v6NetworkOrderBytes: $0.baseAddress!)
                        }
                    default:
                        // AF_LINK, most often: a point-to-point interface whose next hop is
                        // the interface itself. There is no address to probe.
                        return nil
                    }
                }
            }

            cursor += step
            bit <<= 1
        }
        return nil
    }

    /// Builds an `RTM_GET` message asking for the route to the wildcard destination,
    /// which is by definition the default route.
    private static func makeRouteRequest(family: IPAddress.Family, sequence: Int32) -> [UInt8]? {
        let headerSize = MemoryLayout<rt_msghdr>.stride
        let addressSize = family == .v4
            ? MemoryLayout<sockaddr_in>.stride
            : MemoryLayout<sockaddr_in6>.stride
        let totalSize = headerSize + addressSize
        guard totalSize <= UInt16.max else { return nil }

        var message = [UInt8](repeating: 0, count: totalSize)

        var header = rt_msghdr()
        header.rtm_msglen = UInt16(totalSize)
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_flags = RTF_UP | RTF_GATEWAY
        header.rtm_addrs = RTA_DST
        header.rtm_seq = sequence
        header.rtm_pid = 0

        message.withUnsafeMutableBytes { destination in
            withUnsafeBytes(of: header) { source in
                destination.baseAddress!.copyMemory(
                    from: source.baseAddress!, byteCount: headerSize
                )
            }

            // An all-zero address of the right family is the wildcard destination.
            // Only the length and family fields need to be set.
            switch family {
            case .v4:
                var address = sockaddr_in()
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.stride)
                address.sin_family = sa_family_t(AF_INET)
                withUnsafeBytes(of: address) { source in
                    destination.baseAddress!.advanced(by: headerSize)
                        .copyMemory(from: source.baseAddress!, byteCount: addressSize)
                }
            case .v6:
                var address = sockaddr_in6()
                address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.stride)
                address.sin6_family = sa_family_t(AF_INET6)
                withUnsafeBytes(of: address) { source in
                    destination.baseAddress!.advanced(by: headerSize)
                        .copyMemory(from: source.baseAddress!, byteCount: addressSize)
                }
            }
        }

        return message
    }
}
