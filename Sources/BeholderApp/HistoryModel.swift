import BeholderCore
import Foundation
import Observation

/// Reads the history database for the History tab.
///
/// The app opens SQLite directly rather than asking the daemon for it. The database is
/// owned by you and the app runs as you, so no privilege is involved — and history is
/// worth looking at precisely when capture is *not* running, which a daemon round-trip
/// could not serve. Opened read-only, so a viewer can never alter what was recorded.
@MainActor
@Observable
final class HistoryModel {

    typealias Range = HistoryReading.Range
    typealias State = HistoryReading.State
    static let ranges: [Range] = Range.allCases

    private(set) var state: State = .idle
    private(set) var totals: [ProcessTotal] = []
    private(set) var flows: [HistoricalFlow] = []
    private(set) var coverage: (earliest: Date, latest: Date)?

    var range: Range = .day { didSet { reload() } }
    var searchText = "" { didSet { scheduleReload() } }

    /// Queries run off the main thread — a month of history is a real query, and a
    /// spinning window would be worse than a slow one.
    private let queue = DispatchQueue(label: "com.beholder.history", qos: .userInitiated)
    private var pendingReload: Task<Void, Never>?

    nonisolated static let flowLimit = 500

    func reload() {
        state = .loading
        let range = self.range
        let search = searchText.isEmpty ? nil : searchText

        Task { [weak self] in
            let result = await Self.query(range: range, search: search, on: self?.queue)
            guard let self else { return }
            switch result {
            case .success(let loaded):
                self.totals = loaded.totals
                self.flows = loaded.flows
                self.coverage = loaded.coverage
                self.state = .loaded
            case .failure(let message):
                self.totals = []
                self.flows = []
                self.coverage = nil
                self.state = .unavailable(message)
            }
        }
    }

    /// Typing should not fire a query per keystroke against a month of rows.
    private func scheduleReload() {
        pendingReload?.cancel()
        pendingReload = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            self?.reload()
        }
    }

    private struct Loaded {
        let totals: [ProcessTotal]
        let flows: [HistoricalFlow]
        let coverage: (earliest: Date, latest: Date)?
    }

    private static func query(
        range: Range, search: String?, on queue: DispatchQueue?
    ) async -> HistoryReading.Outcome<Loaded> {
        await HistoryReading.read(on: queue) { store in
            let since = Date().addingTimeInterval(-range.duration)
            return Loaded(
                totals: try store.processTotals(since: since),
                flows: try store.flows(since: since, matching: search, limit: flowLimit),
                coverage: try store.coverage()
            )
        }
    }

    var totalBytesOut: UInt64 { totals.reduce(0) { $0 + $1.bytesOut } }
    var totalBytesIn: UInt64 { totals.reduce(0) { $0 + $1.bytesIn } }

    /// Whether the window asked for reaches further back than anything recorded. Saying
    /// so is what stops a short history reading as a quiet month.
    var windowExceedsCoverage: Bool {
        HistoryReading.windowExceedsCoverage(earliest: coverage?.earliest, range: range)
    }
}
