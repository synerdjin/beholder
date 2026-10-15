import BeholderCore
import Foundation
import Observation

/// Reads the recent probe summary that the Overview needs to tell a problem at home from
/// one upstream.
///
/// Probe results are not on the live socket — the daemon records them to the history
/// database, as it does every other measurement worth keeping — so this opens the database
/// read-only, the same way `QualityModel` does, rather than widening the wire contract for
/// a figure that changes every thirty seconds at most.
@MainActor
@Observable
final class HealthModel {

    /// The window the probe figures cover. Long enough to hold a few dozen probes at the
    /// default thirty-second interval, short enough that a router fixed ten minutes ago
    /// stops being blamed soon after.
    static let probeWindow: TimeInterval = 15 * 60

    /// Nil when no probe ran in the window, which is the ordinary state: `--probe` is off
    /// unless asked for, because it is the only part of Beholder that sends anything.
    private(set) var probes: ProbeSummary?

    private let queue = DispatchQueue(label: "com.beholder.health", qos: .utility)
    private var started = false

    /// Starts refreshing every thirty seconds, matching the prober's default interval. Safe
    /// to call more than once; the menu bar and the window both ask.
    func start() {
        guard !started else { return }
        started = true
        Task { [weak self] in
            while !Task.isCancelled {
                await self?.reload()
                try? await Task.sleep(for: .seconds(30))
            }
        }
    }

    func reload() async {
        let window = Self.probeWindow
        let outcome = await HistoryReading.read(on: queue) { store in
            let until = Date()
            return try store.probeSummary(since: until.addingTimeInterval(-window), until: until)
        }
        switch outcome {
        case .success(let summary): probes = summary
        // No database yet, or one this build cannot read: either way there is nothing to
        // say about probes, and the Overview offers to start them.
        case .failure: probes = nil
        }
    }
}
