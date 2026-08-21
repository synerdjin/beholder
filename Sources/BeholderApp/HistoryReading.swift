import BeholderCore
import Foundation

/// What the two read-only history readers share.
///
/// `HistoryModel` and `QualityModel` both open the same database read-only, off the main
/// thread, over the same set of windows, and both have to answer the same question about
/// whether the window asked for reaches further back than anything recorded. They were two
/// near-verbatim copies of that scaffolding, comments included but reworded — which meant
/// the reasoning documented on one of them was unattached to the other, and a fix to either
/// was a fix to half the app.
enum HistoryReading {

    /// The windows a reader offers.
    ///
    /// One list rather than two overlapping ones: `QualityModel` omitted `.hour` because a
    /// per-minute series needs more than an hour to say anything, so that stays a choice
    /// each reader makes about which cases to *offer* rather than a second enum.
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

    /// Deliberately not `Result`. The failure side is a sentence for the reader, not an
    /// `Error` anything catches or switches on, and typing it as one invited a `throws`
    /// chain through code whose only response to failure is to print it.
    enum Outcome<Value> {
        case success(Value)
        case failure(String)
    }

    /// Runs a read against the history database on `queue`, or explains why it could not.
    ///
    /// The store is opened read-only and closed on every path, so a viewer can never alter
    /// what the daemon recorded — and an absent database is not an error: capture writes
    /// history as connections finish, so its absence simply means nothing has finished yet.
    static func read<Value: Sendable>(
        on queue: DispatchQueue?,
        _ body: @escaping @Sendable (FlowStore) throws -> Value
    ) async -> Outcome<Value> {
        guard let queue else { return .failure("Not ready.") }

        return await withCheckedContinuation { continuation in
            queue.async {
                let path = BeholderPaths.historyDatabase()
                guard FileManager.default.fileExists(atPath: path) else {
                    continuation.resume(returning: .failure("No history has been recorded yet."))
                    return
                }
                do {
                    let store = try FlowStore(path: path, readOnly: true)
                    defer { store.close() }
                    continuation.resume(returning: .success(try body(store)))
                } catch {
                    continuation.resume(returning: .failure("\(error)"))
                }
            }
        }
    }

    /// Whether the window asked for reaches further back than anything recorded.
    ///
    /// Saying so is what stops two days of history reading as a quiet month — the same
    /// rule as "every report states the window it actually covers", applied to a window
    /// the reader chose rather than one the data defined.
    static func windowExceedsCoverage(earliest: Date?, range: Range) -> Bool {
        guard let earliest else { return false }
        return earliest > Date().addingTimeInterval(-range.duration)
    }
}
