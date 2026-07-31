import Darwin

/// The set of addresses assigned to this machine's interfaces.
///
/// Needed to decide which end of a captured packet is "us", which in turn decides whether
/// a packet counts as inbound or outbound. Without this, a flow table can aggregate
/// traffic but cannot say which direction it moved — the first thing anyone looks at.
public enum LocalAddresses {
    public static func current() -> Set<IPAddress> {
        var addresses = Set<IPAddress>()

        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return addresses }
        defer { freeifaddrs(head) }

        var cursor = head
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let socketAddress = entry.pointee.ifa_addr else { continue }

            switch Int32(socketAddress.pointee.sa_family) {
            case AF_INET:
                let inet = UnsafeRawPointer(socketAddress)
                    .assumingMemoryBound(to: sockaddr_in.self)
                addresses.insert(IPAddress(v4NetworkOrder: inet.pointee.sin_addr.s_addr))

            case AF_INET6:
                let inet6 = UnsafeRawPointer(socketAddress)
                    .assumingMemoryBound(to: sockaddr_in6.self)
                withUnsafeBytes(of: inet6.pointee.sin6_addr) { raw in
                    if let base = raw.baseAddress {
                        addresses.insert(IPAddress(v6NetworkOrderBytes: base))
                    }
                }

            default:
                continue
            }
        }
        return addresses
    }
}
