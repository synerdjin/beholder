import BeholderCore
import Foundation
import Observation

/// Reads the per-minute quality series for the Quality tab's long view.
///
/// Opens the database directly and read-only, for the same reasons `HistoryModel` does:
/// the file is yours, no privilege is involved, and the long view is worth having exactly
/// when capture is *not* running.
@MainActor
@Observable
final class QualityModel {

    /// The windows this reader offers. A per-minute series needs more than an hour to say
    /// anything, so `.hour` is left out of the choices rather than out of the type.
    typealias Range = HistoryReading.Range
    typealias State = HistoryReading.State
    static let ranges: [Range] = [.day, .week, .month]

    private(set) var state: State = .idle
    private(set) var rows: [QualityMinute] = []
    private(set) var report: Reliability.Report?
    private(set) var coverage: (earliest: Date, latest: Date, minutes: Int)?
    /// The chart's points, collapsed once per load on the query queue rather than once per
    /// redraw in a view body. `rows` only changes when a load finishes, so recomputing the
    /// month-wide grouping on every frame was pure repetition — on the main thread.
    private(set) var series: [Reliability.Point] = []

    var range: Range = .week { didSet { reload() } }
    /// Nil means every interface pooled. Choosing one is how a VPN tunnel's measurements
    /// are separated from the link underneath, which is the difference between measuring
    /// your ISP and measuring your VPN provider.
    var interface: String? { didSet { reload() } }

    /// The interfaces to choose between, which is exactly what the report already carries.
    /// Kept as a view onto it rather than as a third copy of the same array.
    var availableInterfaces: [(name: String, bytes: UInt64)] { report?.interfaces ?? [] }

    private let queue = DispatchQueue(label: "com.beholder.quality", qos: .userInitiated)

    func reload() {
        state = .loading
        let range = self.range
        let interface = self.interface

        Task { [weak self] in
            let result = await Self.query(range: range, interface: interface, on: self?.queue)
            guard let self else { return }
            switch result {
            case .success(let loaded):
                self.rows = loaded.rows
                self.report = loaded.report
                self.coverage = loaded.coverage
                self.series = loaded.series
                self.state = .loaded
            case .failure(let message):
                self.rows = []
                self.report = nil
                self.coverage = nil
                self.series = []
                self.state = .unavailable(message)
            }
        }
    }

    private struct Loaded {
        let rows: [QualityMinute]
        let report: Reliability.Report
        let coverage: (earliest: Date, latest: Date, minutes: Int)?
        let series: [Reliability.Point]
    }

    private static func query(
        range: Range, interface: String?, on queue: DispatchQueue?
    ) async -> HistoryReading.Outcome<Loaded> {
        await HistoryReading.read(on: queue) { store in
                    let until = Date()
                    let since = until.addingTimeInterval(-range.duration)
                    let rows = try store.qualityMinutes(
                        since: since, until: until, interface: interface
                    )
                    let interfaces = try store.qualityInterfaces(since: since, until: until)
                    let report = Reliability.report(
                        rows: rows,
                        interfaces: interfaces,
                        start: since,
                        end: until
                    )
                    return Loaded(
                        rows: rows,
                        report: report,
                        coverage: try store.qualityCoverage(),
                        series: Reliability.series(rows: rows)
                    )
        }
    }

    /// Whether the window asked for reaches further back than anything recorded. Saying so
    /// is what stops two days of history reading as a quiet month.
    var windowExceedsCoverage: Bool {
        HistoryReading.windowExceedsCoverage(earliest: coverage?.earliest, range: range)
    }
}
