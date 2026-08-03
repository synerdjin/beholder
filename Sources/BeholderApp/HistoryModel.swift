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

    enum Range: String, CaseIterable, Identifiable {
        case hour = "Last hour"
        case day = "Last 24 hours"
        case week = "Last 7 days"
        case month = "Last 30 days"

        var id: String { rawValue }

        var duration: TimeInterval {
            switch self {
            case .hour: return 3600
            case .day: return 86400
            case .week: return 7 * 86400
            case .month: return 30 * 86400
            }
        }
    }

    enum State: Equatable {
        case idle
        case loading
        case loaded
        case unavailable(String)
    }

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

    /// A plain two-case outcome rather than `Result`, whose failure type must be an
    /// `Error` — here the failure is a sentence for the user, not a thrown condition.
    private enum Outcome {
        case success(Loaded)
        case failure(String)
    }

    private static func query(
        range: Range, search: String?, on queue: DispatchQueue?
    ) async -> Outcome {
        guard let queue else { return .failure("Not ready.") }

        return await withCheckedContinuation { continuation in
            queue.async {
                let path = BeholderPaths.historyDatabase()
                guard FileManager.default.fileExists(atPath: path) else {
                    // Not an error. Capture writes history as connections finish, so an
                    // absent database simply means nothing has been recorded yet.
                    continuation.resume(returning: .failure("No history has been recorded yet."))
                    return
                }

                do {
                    let store = try FlowStore(path: path, readOnly: true)
                    defer { store.close() }

                    let since = Date().addingTimeInterval(-range.duration)
                    let loaded = Loaded(
                        totals: try store.processTotals(since: since),
                        flows: try store.flows(
                            since: since, matching: search, limit: flowLimit
                        ),
                        coverage: try store.coverage()
                    )
                    continuation.resume(returning: .success(loaded))
                } catch {
                    continuation.resume(returning: .failure("\(error)"))
                }
            }
        }
    }

    var totalBytesOut: UInt64 { totals.reduce(0) { $0 + $1.bytesOut } }
    var totalBytesIn: UInt64 { totals.reduce(0) { $0 + $1.bytesIn } }

    /// Whether the window asked for reaches further back than anything recorded. Saying
    /// so is what stops a short history reading as a quiet month.
    var windowExceedsCoverage: Bool {
        guard let coverage else { return false }
        return coverage.earliest > Date().addingTimeInterval(-range.duration)
    }
}
