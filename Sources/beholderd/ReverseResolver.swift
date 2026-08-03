import BeholderCore
import Darwin
import Dispatch
import Foundation

/// Asks the system resolver for the name behind an address.
///
/// The weakest of the three naming sources and the only one that generates traffic of its
/// own, so it is used last and sparingly: only for addresses nothing else has named.
///
/// Three constraints shape this. `getnameinfo` blocks, sometimes for seconds, so it must
/// never run anywhere near the capture path. A machine talking to hundreds of hosts would
/// otherwise issue hundreds of simultaneous lookups, so concurrency is capped. And every
/// address is attempted at most once per run — including failures, since an address with
/// no PTR record will not grow one while Beholder watches.
final class ReverseResolver: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.beholder.reverse", qos: .background)
    private let group = DispatchQueue(
        label: "com.beholder.reverse.workers", qos: .background, attributes: .concurrent
    )
    private let inFlight = DispatchSemaphore(value: 4)
    private let onResolved: @Sendable (IPAddress, String) -> Void

    // Confined to `queue`.
    private var attempted = Set<IPAddress>()
    private var pending = 0
    private(set) var succeeded = 0
    private(set) var failed = 0

    /// Beholder's own lookups become DNS packets that Beholder then captures. That is not
    /// a runaway loop — the resolver's own address gets named once and never asked about
    /// again — but resolving the resolver is pointless work, so it is skipped.
    private var excluded = Set<IPAddress>()

    init(onResolved: @escaping @Sendable (IPAddress, String) -> Void) {
        self.onResolved = onResolved
    }

    /// Marks addresses that should never be looked up, such as the DNS servers whose
    /// answers Beholder is already reading.
    func exclude(_ addresses: Set<IPAddress>) {
        queue.async { self.excluded.formUnion(addresses) }
    }

    func request(_ address: IPAddress) {
        queue.async { [self] in
            guard address.isGloballyRoutable,
                !excluded.contains(address),
                !attempted.contains(address),
                pending < 64
            else { return }

            attempted.insert(address)
            pending += 1

            group.async { [self] in
                inFlight.wait()
                let name = Self.lookup(address)
                inFlight.signal()

                queue.async {
                    self.pending -= 1
                    if let name {
                        self.succeeded += 1
                        self.onResolved(address, name)
                    } else {
                        self.failed += 1
                    }
                }
            }
        }
    }

    var statistics: (attempted: Int, succeeded: Int, failed: Int) {
        queue.sync { (attempted.count, succeeded, failed) }
    }

    /// Blocking. Only ever called on a worker.
    private static func lookup(_ address: IPAddress) -> String? {
        var storage = sockaddr_storage()
        var length: socklen_t = 0
        let bytes = address.networkOrderBytes

        switch address.family {
        case .v4:
            var inet = sockaddr_in()
            inet.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            inet.sin_family = sa_family_t(AF_INET)
            inet.sin_addr.s_addr = bytes.withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self)
            }
            withUnsafeBytes(of: inet) { source in
                withUnsafeMutableBytes(of: &storage) { destination in
                    destination.copyMemory(from: source)
                }
            }
            length = socklen_t(MemoryLayout<sockaddr_in>.size)

        case .v6:
            var inet6 = sockaddr_in6()
            inet6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            inet6.sin6_family = sa_family_t(AF_INET6)
            withUnsafeMutableBytes(of: &inet6.sin6_addr) { $0.copyBytes(from: bytes) }
            withUnsafeBytes(of: inet6) { source in
                withUnsafeMutableBytes(of: &storage) { destination in
                    destination.copyMemory(from: source)
                }
            }
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = withUnsafeBytes(of: &storage) { raw -> Int32 in
            guard let base = raw.baseAddress else { return EAI_FAIL }
            return getnameinfo(
                base.assumingMemoryBound(to: sockaddr.self), length,
                &host, socklen_t(NI_MAXHOST),
                nil, 0,
                // Fail rather than hand back the numeric form, which would be a "name"
                // identical to the address and therefore worse than nothing.
                NI_NAMEREQD
            )
        }
        guard result == 0 else { return nil }

        let name = String(nullTerminated: host)
        return name.isEmpty ? nil : name
    }
}
