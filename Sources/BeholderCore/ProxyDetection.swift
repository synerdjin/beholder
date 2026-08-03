import Foundation

/// Recognises when a single process is fronting other applications' traffic.
///
/// A transparent proxy — a `NETransparentProxyProvider` system extension such as
/// NordVPN's Threat Protection, or a corporate inspection agent — intercepts an
/// application's connection and re-originates it from its own socket. The kernel then
/// truthfully reports that socket as belonging to the proxy, and the application that
/// actually wanted the connection never appears on the wire at all.
///
/// This is a hard limit of packet capture, not a bug that better polling can fix: the
/// application's socket never reaches the network output path, so there is nothing to
/// capture. Only a socket-layer filter (`NEFilterDataProvider`, which needs the Apple
/// entitlement Beholder deliberately does without) observes the original flow.
///
/// Since the limit cannot be removed, it must at least be *visible*. Reporting "NordVPN
/// used 20 MB" when the user actually browsed the web is worse than saying nothing —
/// it is confidently wrong in a way the user cannot detect.
public enum ProxyDetection {

    public struct Finding: Sendable {
        public let owner: ProcessOwner
        public let flowCount: Int
        public let distinctRemoteHosts: Int
        public let shareOfFlows: Double
        public let bytes: UInt64
        /// Always true: a finding is only raised for system-level components. Kept
        /// explicit because it is the load-bearing part of the judgement.
        public let isSystemExtension: Bool

        public var advice: String {
            """
            \(owner.name) owns \(flowCount) flows (\(Int(shareOfFlows * 100))% of \
            application traffic) to \(distinctRemoteHosts) different hosts, and runs as a \
            system extension or privileged helper. It is almost certainly a transparent \
            proxy re-originating other applications' connections, which means the \
            processes that actually made these requests cannot be identified from \
            captured packets. Disable that extension's filtering to see real \
            per-application attribution.
            """
        }
    }

    /// A process must hold at least this share of all flows, and reach at least this many
    /// distinct hosts, before it looks like a proxy rather than a busy application.
    /// A browser talks to many hosts but rarely dominates the whole table; a proxy does
    /// both at once.
    static let flowShareThreshold = 0.30
    static let distinctHostThreshold = 8

    /// Ports belonging to network infrastructure rather than to anything a user opened.
    ///
    /// Excluding these is what separates a proxy from a resolver. `mDNSResponder` talks
    /// to every DNS server and multicast group on the network and can easily own a third
    /// of all flows — but it is resolving names, not carrying anybody's payload. An
    /// earlier version flagged it as a transparent proxy, which is precisely the
    /// false positive that teaches a user to ignore the warning.
    static let infrastructurePorts: Set<UInt16> = [
        53,  // DNS
        5353,  // multicast DNS
        853,  // DNS over TLS
        67, 68,  // DHCP
        123,  // NTP
        137, 138, 139,  // NetBIOS
        1900,  // SSDP
        5355,  // LLMNR
    ]

    /// Flows that a transparent proxy would plausibly be carrying on someone's behalf:
    /// out to the internet, on a port an application would actually use.
    static func proxyCandidateFlows(_ flows: [Flow]) -> [Flow] {
        flows.filter { flow in
            flow.owner != nil
                && flow.key.remote.isGloballyRoutable
                && !infrastructurePorts.contains(flow.key.remotePort)
                && flow.key.transport.hasPorts
        }
    }

    public static func findLikelyProxies(in flows: [Flow]) -> [Finding] {
        let attributed = proxyCandidateFlows(flows)
        guard attributed.count >= 20 else { return [] }

        var flowsByOwner: [ProcessOwner: [Flow]] = [:]
        for flow in attributed {
            guard let owner = flow.owner else { continue }
            flowsByOwner[owner, default: []].append(flow)
        }

        return flowsByOwner.compactMap { owner, ownedFlows -> Finding? in
            // A system-level component fronting traffic is the load-bearing signal, and
            // it is required rather than merely weighted.
            //
            // Volume alone cannot distinguish a proxy from a browser: both talk to many
            // hosts, and on a quiet machine a browser is trivially the majority of
            // application traffic. Warning about Safari every session would train the
            // user to ignore the warning, which costs more than the rare userspace proxy
            // this misses — and a userspace proxy is one the user configured and knows
            // about, whereas a system extension quietly rewriting attribution is exactly
            // the case worth flagging.
            guard looksLikeSystemExtension(owner.path) else { return nil }

            let hosts = Set(ownedFlows.map(\.key.remote))
            let share = Double(ownedFlows.count) / Double(attributed.count)

            guard share >= flowShareThreshold, hosts.count >= distinctHostThreshold else {
                return nil
            }
            return Finding(
                owner: owner,
                flowCount: ownedFlows.count,
                distinctRemoteHosts: hosts.count,
                shareOfFlows: share,
                bytes: ownedFlows.reduce(0) { $0 + $1.totalBytes },
                isSystemExtension: looksLikeSystemExtension(owner.path)
            )
        }
        .sorted { $0.flowCount > $1.flowCount }
    }

    /// Whether a path belongs to a system-level component rather than a user application.
    /// A macOS transparent proxy has to be one of these — `NETransparentProxyProvider`
    /// runs in a system extension, and the older approach used a privileged helper.
    static func looksLikeSystemExtension(_ path: String) -> Bool {
        path.contains(".systemextension/")
            || path.hasPrefix("/Library/SystemExtensions/")
            || path.contains(".appex/")
            || path.hasPrefix("/Library/PrivilegedHelperTools/")
    }
}
