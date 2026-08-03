import BeholderCore
import Darwin
import Dispatch
import Foundation
import Network

/// Keeps capture pointed at whichever interface traffic is actually leaving by.
///
/// Without this, Beholder resolves the default route once at startup and never looks
/// again. Connect a VPN and the route moves to a `utun`; drop it and the route returns to
/// `en0`. In either case capture carries on reading an interface nothing uses any more,
/// reporting a confident, well-formatted zero. Silently going blind is the worst failure
/// available to a monitoring tool, because nothing about the output says anything is
/// wrong.
///
/// Changes are detected two ways on purpose. `NWPathMonitor` reports them promptly, and a
/// slow poll catches anything it does not consider a "path" change — a route metric
/// shifting between two live interfaces, for instance. Every transition is recorded and
/// shown, so a reconnect is visible in the output rather than inferred from a gap.
final class InterfaceSupervisor: @unchecked Sendable {

    struct Transition: Sendable {
        let at: Date
        let from: String?
        let to: String?
        let succeeded: Bool
        let detail: String?

        var summary: String {
            let origin = from ?? "nothing"
            let destination = to ?? "no default route"
            let outcome = succeeded ? "" : "  — FAILED: \(detail ?? "unknown error")"
            return "\(formatTimestamp(at))  capture moved \(origin) → \(destination)\(outcome)"
        }
    }

    private let engine: CaptureEngine
    /// Interfaces that stay captured regardless of routing, such as `lo0`.
    private let pinned: Set<String>
    private let onChange: @Sendable () -> Void
    private let queue = DispatchQueue(label: "com.beholder.interfaces")

    private var pathMonitor: NWPathMonitor?
    private var backstopTimer: DispatchSourceTimer?

    // Confined to queue.
    private var followed: String?
    private var transitions: [Transition] = []
    private var failureAlreadyNoted: String?

    private static let backstopInterval: TimeInterval = 5

    init(
        engine: CaptureEngine,
        pinned: [String],
        initiallyFollowing: String?,
        onChange: @escaping @Sendable () -> Void
    ) {
        self.engine = engine
        self.pinned = Set(pinned)
        self.followed = initiallyFollowing
        self.onChange = onChange
    }

    func start() {
        let monitor = NWPathMonitor()
        // Updates are delivered on `queue`, which is where reconcile() must run, so no
        // further hop is needed.
        monitor.pathUpdateHandler = { [weak self] _ in
            guard let self else { return }
            self.reconcile()
        }
        monitor.start(queue: queue)
        pathMonitor = monitor

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + Self.backstopInterval,
            repeating: Self.backstopInterval,
            leeway: .seconds(1)
        )
        timer.setEventHandler { [weak self] in self?.reconcile() }
        backstopTimer = timer
        timer.resume()
    }

    func stop() {
        pathMonitor?.cancel()
        pathMonitor = nil
        backstopTimer?.cancel()
        backstopTimer = nil
    }

    func recordedTransitions() -> [Transition] {
        queue.sync { transitions }
    }

    /// Runs on queue.
    private func reconcile() {
        let desired = RouteLookup.defaultRoute()?.interfaceName
        guard desired != followed else {
            failureAlreadyNoted = nil
            return
        }

        let previous = followed

        // Give up the old interface unless something else wants it kept.
        if let previous, !pinned.contains(previous) {
            engine.stop(interface: previous)
        }

        guard let desired else {
            // The machine has no default route at all — mid-reconnect, or the link is
            // down. Record it and wait; the next tick will pick the route back up.
            followed = nil
            record(Transition(at: Date(), from: previous, to: nil, succeeded: true, detail: nil))
            onChange()
            return
        }

        do {
            try engine.start(interface: desired)
            followed = desired
            failureAlreadyNoted = nil
            record(
                Transition(at: Date(), from: previous, to: desired, succeeded: true, detail: nil)
            )
            onChange()
        } catch {
            // Leave `followed` unchanged so the next tick retries. An interface can exist
            // in the routing table a moment before it is ready to capture.
            let description = (error as? CaptureError)?.description ?? "\(error)"
            if failureAlreadyNoted != desired {
                failureAlreadyNoted = desired
                record(
                    Transition(
                        at: Date(), from: previous, to: desired,
                        succeeded: false, detail: description
                    )
                )
            }
        }
    }

    /// Runs on queue. Keeps only the recent history; this is a display aid, not a log.
    private func record(_ transition: Transition) {
        transitions.append(transition)
        if transitions.count > 20 {
            transitions.removeFirst(transitions.count - 20)
        }
    }
}
