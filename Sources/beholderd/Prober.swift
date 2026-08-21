import BeholderCore
import CBeholderShim
import Darwin
import Dispatch
import Foundation

/// The one part of Beholder that sends.
///
/// Everything else here observes: it watches traffic somebody else asked for and draws
/// conclusions from it. That is enough for almost every question, and it is deliberately
/// not enough for two:
///
/// - **Was the connection working while nobody was using it?** Passively, an outage at four
///   in the morning is indistinguishable from being asleep. Only something that asks a
///   question every thirty seconds can tell those apart.
/// - **Is it my Wi-Fi or my ISP?** Loss on the local radio and loss upstream of the router
///   look identical from the far end of a path that runs through both. Timing the first hop
///   *separately* is the only way to split them, and no ordinary traffic goes only that far.
///
/// So this exists, and it is off by default, and it says so loudly when it is on. The
/// README's claim that Beholder observes and never blocks stays true — nothing here alters
/// anyone else's traffic — but "never sends" would not be true with `--probe`, and the
/// banner says exactly that rather than letting the distinction go unnoticed.
final class Prober: @unchecked Sendable {

    struct Target {
        let address: IPAddress
        let kind: ProbeResult.Kind
    }

    /// Anycast resolvers, chosen because they answer ICMP, are run by three unrelated
    /// organisations, and will still exist in a year — a yardstick is only useful if it
    /// does not move.
    static let defaultAnchors = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    /// How long to wait for a reply before recording silence. Anything past this is not a
    /// slow network so much as an absent one, and recording it as latency would be worse
    /// than recording it as loss.
    private static let replyTimeout: TimeInterval = 1.0

    private let queue = DispatchQueue(label: "com.beholder.probe", qos: .utility)
    private let interval: TimeInterval
    private let anchors: [IPAddress]
    private let record: @Sendable ([ProbeResult]) -> Void

    private var timer: DispatchSourceTimer?
    private var sequence: UInt16 = 0
    private var reportedFailure = false

    init(
        interval: TimeInterval,
        anchors: [String],
        record: @escaping @Sendable ([ProbeResult]) -> Void
    ) {
        self.interval = interval
        self.anchors = anchors.compactMap { IPAddress(text: $0) }
        self.record = record
    }

    /// The targets as they stand now, for the startup banner. The gateway is resolved
    /// afresh on every round, since it moves when a VPN comes up.
    func currentTargets() -> [Target] {
        var targets: [Target] = []
        if let route = RouteLookup.defaultRoute(), let gateway = route.gateway {
            targets.append(Target(address: gateway, kind: .gateway))
        }
        targets.append(contentsOf: anchors.map { Target(address: $0, kind: .anchor) })
        return targets
    }

    func start() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: interval, leeway: .seconds(1))
        timer.setEventHandler { [weak self] in self?.round() }
        self.timer = timer
        timer.resume()
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    private func round() {
        let route = RouteLookup.defaultRoute()
        let interface = route?.interfaceName ?? "?"

        var targets: [Target] = []
        if let gateway = route?.gateway {
            targets.append(Target(address: gateway, kind: .gateway))
        }
        targets.append(contentsOf: anchors.map { Target(address: $0, kind: .anchor) })
        guard !targets.isEmpty else { return }

        var results: [ProbeResult] = []
        for target in targets {
            sequence &+= 1
            let outcome = echo(to: target.address, sequence: sequence)
            switch outcome {
            case .replied(let seconds):
                results.append(
                    ProbeResult(
                        at: Date(), interface: interface,
                        target: target.address.description, kind: target.kind,
                        rttMs: seconds * 1000
                    )
                )
            case .silent:
                // Recorded, not skipped. Silence is the measurement in an outage, and a
                // gap in the series would be indistinguishable from the prober being off.
                results.append(
                    ProbeResult(
                        at: Date(), interface: interface,
                        target: target.address.description, kind: target.kind, rttMs: nil
                    )
                )
            case .unavailable(let reason):
                // Reported once rather than every thirty seconds, and never quietly
                // downgraded to a TCP probe: opening a connection to a stranger's port is
                // a more intrusive thing to do on someone's behalf than an echo request,
                // and doing it as a silent fallback would be doing it without being asked.
                if !reportedFailure {
                    reportedFailure = true
                    FileHandle.standardError.write(
                        Data(
                            """
                            beholderd: cannot send probes (\(reason)). ICMP is probably \
                            filtered here. Passive measurement continues; the gateway \
                            comparison will not be available.\n
                            """.utf8
                        )
                    )
                }
                return
            }
        }
        record(results)
    }

    private enum Outcome {
        case replied(TimeInterval)
        case silent
        case unavailable(String)
    }

    /// One echo request, and the wait for its answer.
    ///
    /// `SOCK_DGRAM` rather than `SOCK_RAW`, which needs no privilege — the daemon has it
    /// anyway, but a component that does not need root should not take it. The kernel may
    /// rewrite the identifier on this socket, so replies are matched on the sequence number
    /// alone, which it leaves alone.
    private func echo(to address: IPAddress, sequence: UInt16) -> Outcome {
        guard address.family == .v4 else {
            // IPv6 needs ICMPv6 and a different message type. Not attempted rather than
            // half-attempted: a probe that silently never works would read as an outage.
            return .silent
        }

        let handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard handle >= 0 else { return .unavailable("socket: \(String(cString: strerror(errno)))") }
        defer { close(handle) }

        var timeout = timeval(
            tv_sec: Int(Self.replyTimeout),
            tv_usec: Int32((Self.replyTimeout - Double(Int(Self.replyTimeout))) * 1_000_000)
        )
        setsockopt(
            handle, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.stride)
        )

        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.stride)
        destination.sin_family = sa_family_t(AF_INET)
        let bytes = address.networkOrderBytes
        guard bytes.count >= 4 else { return .silent }
        destination.sin_addr.s_addr = bytes.withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self)
        }

        var request = ICMPEcho.request(
            identifier: UInt16(truncatingIfNeeded: getpid()), sequence: sequence
        )
        let sentAt = Date()
        let sent = request.withUnsafeMutableBytes { payload -> Int in
            withUnsafePointer(to: &destination) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    sendto(
                        handle, payload.baseAddress, payload.count, 0,
                        socketAddress, socklen_t(MemoryLayout<sockaddr_in>.stride)
                    )
                }
            }
        }
        guard sent == request.count else {
            return .unavailable("sendto: \(String(cString: strerror(errno)))")
        }

        // Replies to other sockets can arrive here too, so read until ours turns up or the
        // window closes.
        var response = [UInt8](repeating: 0, count: 1024)
        while Date().timeIntervalSince(sentAt) < Self.replyTimeout {
            let count = recv(handle, &response, response.count, 0)
            guard count > 0 else { break }
            guard let echoed = ICMPEcho.replySequence(in: response, count: count) else { continue }
            if echoed == sequence { return .replied(Date().timeIntervalSince(sentAt)) }
        }
        return .silent
    }

}
