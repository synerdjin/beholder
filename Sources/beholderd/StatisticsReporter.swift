import BeholderCore
import Darwin
import Dispatch
import Foundation

/// Prints per-interface capture statistics once a second, and handles shutdown.
///
/// This state deliberately lives in a class rather than as top-level variables in a
/// `main.swift`. Swift 6 treats top-level variables as `@MainActor`-isolated, so a
/// dispatch-source handler touching them from a background queue trips
/// `swift_task_checkIsolated` and traps at runtime — which is exactly what an earlier
/// version of this file did on the timer's first tick. Confining the state to this
/// object's own queue removes the isolation question entirely.
///
/// `@unchecked Sendable` is the honest annotation: the invariant is queue confinement.
final class StatisticsReporter: @unchecked Sendable {
    private let engine: CaptureEngine
    private let queue = DispatchQueue(label: "com.beholder.report")

    private var timer: DispatchSourceTimer?
    private var signalSources: [DispatchSourceSignal] = []

    // Everything below is confined to `queue`.
    private var previousCounters: [String: CaptureCounters] = [:]
    private var previousTimestamp = Date()
    private var ticksRemaining: Int?

    init(engine: CaptureEngine) {
        self.engine = engine
    }

    /// Starts reporting. `stopAfterTicks` bounds the run, used by `--self-test`.
    func start(stopAfterTicks: Int? = nil) {
        queue.async { [self] in
            ticksRemaining = stopAfterTicks
            previousTimestamp = Date()
        }

        print(
            Column.left("INTERFACE", 12) + Column.right("PKTS/S", 10)
                + Column.right("BYTES/S", 14) + Column.right("TOTAL", 14)
                + Column.right("PARSED", 12) + Column.right("NON-IP", 10)
                + Column.right("DROPPED", 10)
        )

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1.0)
        timer.setEventHandler { [weak self] in self?.tick() }
        self.timer = timer
        timer.resume()
    }

    func installSignalHandlers() {
        for number in [SIGINT, SIGTERM] {
            // The dispatch source only sees the signal if the default action is disabled.
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { [weak self] in self?.shutDown() }
            source.resume()
            signalSources.append(source)
        }
    }

    // MARK: - Queue-confined work

    private func tick() {
        let now = Date()
        let elapsed = now.timeIntervalSince(previousTimestamp)
        previousTimestamp = now
        guard elapsed > 0 else { return }

        for statistics in engine.statistics() {
            let current = statistics.counters
            let previous = previousCounters[statistics.interfaceName] ?? CaptureCounters()
            previousCounters[statistics.interfaceName] = current

            let packetRate = Double(current.packets - previous.packets) / elapsed
            let byteRate = Double(current.wireBytes - previous.wireBytes) / elapsed

            print(
                Column.left(statistics.interfaceName, 12)
                    + Column.right(String(format: "%.0f", packetRate), 10)
                    + Column.right(formatBytes(byteRate) + "/s", 14)
                    + Column.right(formatBytes(Double(current.wireBytes)), 14)
                    + Column.right(current.parsed, 12)
                    + Column.right(current.nonIP, 10)
                    + Column.right(statistics.kernelDropped, 10)
            )
        }

        if let remaining = ticksRemaining {
            ticksRemaining = remaining - 1
            if remaining - 1 <= 0 {
                print("")
                print("Self-test complete: the reporting loop ran without an isolation fault.")
                engine.stopAll()
                exit(0)
            }
        }
    }

    private func shutDown() {
        print("\nStopping.")
        for statistics in engine.statistics() {
            let counters = statistics.counters
            print(
                """
                \(statistics.interfaceName): \(counters.packets) packets, \
                \(formatBytes(Double(counters.wireBytes))) on the wire, \
                \(counters.parsed) parsed, \(counters.nonIP) non-IP, \
                \(counters.truncatedHeaders) truncated, \
                \(counters.otherFailures) other failures, \
                \(statistics.kernelDropped) dropped by the kernel
                """
            )
        }
        engine.stopAll()
        exit(0)
    }
}
