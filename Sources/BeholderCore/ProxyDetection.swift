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
        /// True when the executable lives in a system-extension bundle, which makes a
        /// proxy interpretation much more likely than a merely chatty application.
        public let isSystemExtension: Bool

        public var advice: String {
            let name = owner.name
            if isSystemExtension {
                return """
                    \(name) owns \(flowCount) flows (\(Int(shareOfFlows * 100))% of all \
                    traffic) to \(distinctRemoteHosts) different hosts, and runs as a \
                    system extension. It is almost certainly a transparent proxy \
                    re-originating other applications' connections, which means the \
                    processes that actually made these requests cannot be identified \
                    from captured packets. Disable that extension's filtering to see \
                    real per-application attribution.
                    """
            }
            return """
                \(name) owns \(flowCount) flows (\(Int(shareOfFlows * 100))% of all \
                traffic) to \(distinctRemoteHosts) different hosts. If it is a proxy, \
                the applications behind it cannot be identified from captured packets.
                """
        }
    }

    /// A process must hold at least this share of all flows, and reach at least this many
    /// distinct hosts, before it looks like a proxy rather than a busy application.
    /// A browser talks to many hosts but rarely dominates the whole table; a proxy does
    /// both at once.
    static let flowShareThreshold = 0.30
    static let distinctHostThreshold = 8

    public static func findLikelyProxies(in flows: [Flow]) -> [Finding] {
        let attributed = flows.filter { $0.owner != nil }
        guard attributed.count >= 20 else { return [] }

        var flowsByOwner: [ProcessOwner: [Flow]] = [:]
        for flow in attributed {
            guard let owner = flow.owner else { continue }
            flowsByOwner[owner, default: []].append(flow)
        }

        return flowsByOwner.compactMap { owner, ownedFlows -> Finding? in
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

    static func looksLikeSystemExtension(_ path: String) -> Bool {
        path.contains(".systemextension/")
            || path.hasPrefix("/Library/SystemExtensions/")
            || path.contains(".appex/")
    }
}
