import Foundation
import Testing

@testable import BeholderCore

private let base: Int64 = 28_000_000

private func row(
    minute: Int64,
    group: String,
    minMs: Double?,
    p50: Double? = nil,
    samples: Int = 20,
    segmentsOut: UInt64 = 1000,
    retransmitsOut: UInt64 = 0,
    bytes: UInt64 = 10_000,
    timeouts: Int = 0,
    interface: String = "en0"
) -> QualityMinute {
    QualityMinute(
        minute: minute,
        interface: interface,
        destinationGroup: group,
        destinationLabel: nil,
        rttSamples: samples,
        rttMinMs: minMs,
        rttP50Ms: p50 ?? minMs.map { $0 * 1.2 },
        rttP95Ms: nil,
        segmentsOut: segmentsOut,
        retransmitsOut: retransmitsOut,
        bytesIn: bytes,
        measuredBytes: bytes,
        connectionTimeouts: timeouts
    )
}

/// A week of steady behaviour for three networks, which is the ordinary case every
/// judgement below has to not fire on.
private func steadyRows(minutes: Int = 200) -> [QualityMinute] {
    var rows: [QualityMinute] = []
    for step in 0..<minutes {
        rows.append(row(minute: base + Int64(step), group: "AS1", minMs: 20))
        rows.append(row(minute: base + Int64(step), group: "AS2", minMs: 35))
        rows.append(row(minute: base + Int64(step), group: "AS3", minMs: 12))
    }
    return rows
}

@Suite("Baselines")
struct ReliabilityBaselineTests {

    /// The floor is a low percentile, not the outright minimum. One freakishly fast sample
    /// would otherwise set a bar nothing could clear, and every minute after it would read
    /// as degraded.
    @Test("One unusually fast minute does not become the baseline")
    func baselineResistsAnOutlier() throws {
        var rows = steadyRows(minutes: 100).filter { $0.destinationGroup == "AS1" }
        rows.append(row(minute: base + 500, group: "AS1", minMs: 0.4))

        let baseline = try #require(Reliability.baselines(from: rows)["AS1"])
        #expect(baseline.floorMs > 1)
    }

    /// A minute with two samples in it says nothing about a network, and must not be
    /// allowed to say something anyway.
    @Test("Minutes with too few samples are excluded from the baseline")
    func sampleFloorExcludes() {
        let thin = (0..<50).map {
            row(minute: base + Int64($0), group: "AS1", minMs: 500, samples: 2)
        }
        #expect(Reliability.baselines(from: thin).isEmpty)
    }
}

@Suite("Common-mode degradation")
struct ReliabilityDegradationTests {

    @Test("A steady week produces no degraded minutes at all")
    func steadyIsQuiet() {
        let rows = steadyRows()
        let degraded = Reliability.degradedMinutes(
            from: rows, baselines: Reliability.baselines(from: rows)
        )
        #expect(degraded.isEmpty)
    }

    /// One CDN having a bad afternoon is that CDN's problem. The whole point of grouping by
    /// autonomous system is that this must not read as the uplink failing.
    @Test("A single slow network is not blamed on the uplink")
    func oneSlowNetworkIsNotCommonMode() throws {
        var rows = steadyRows()
        rows.append(row(minute: base + 900, group: "AS1", minMs: 400))
        rows.append(row(minute: base + 900, group: "AS2", minMs: 35))
        rows.append(row(minute: base + 900, group: "AS3", minMs: 12))

        let degraded = Reliability.degradedMinutes(
            from: rows, baselines: Reliability.baselines(from: rows)
        )
        let minute = try #require(degraded.first { $0.minute == base + 900 })
        #expect(minute.groups == ["AS1"])
        #expect(!minute.isCommonMode)
    }

    /// Three networks that share nothing but the uplink do not slow together by chance.
    @Test("Three networks slowing together implicates the shared path")
    func threeNetworksIsCommonMode() throws {
        var rows = steadyRows()
        for group in ["AS1", "AS2", "AS3"] {
            rows.append(row(minute: base + 900, group: group, minMs: 400))
        }

        let degraded = Reliability.degradedMinutes(
            from: rows, baselines: Reliability.baselines(from: rows)
        )
        let minute = try #require(degraded.first { $0.minute == base + 900 })
        #expect(minute.groups.count == 3)
        #expect(minute.isCommonMode)
    }

    /// A CDN four milliseconds away going to six is not a fault, and a purely
    /// proportional test would call it one every single time.
    @Test("A near path is judged against an absolute floor, not only a ratio")
    func nearPathsUseTheAbsoluteFloor() {
        var rows: [QualityMinute] = []
        for step in 0..<100 { rows.append(row(minute: base + Int64(step), group: "AS1", minMs: 4)) }
        rows.append(row(minute: base + 500, group: "AS1", minMs: 8))

        let degraded = Reliability.degradedMinutes(
            from: rows, baselines: Reliability.baselines(from: rows)
        )
        #expect(degraded.isEmpty)
    }

    @Test("A sustained retransmission rate counts as degradation on its own")
    func lossAloneDegrades() throws {
        var rows = steadyRows()
        rows.append(
            row(
                minute: base + 900, group: "AS1", minMs: 20,
                segmentsOut: 5000, retransmitsOut: 400
            )
        )

        let degraded = Reliability.degradedMinutes(
            from: rows, baselines: Reliability.baselines(from: rows)
        )
        #expect(degraded.contains { $0.minute == base + 900 && $0.groups.contains("AS1") })
    }
}

@Suite("The reliability verdict")
struct ReliabilityVerdictTests {

    private let window = (
        start: Date(timeIntervalSince1970: Double(base) * 60),
        end: Date(timeIntervalSince1970: Double(base + 1000) * 60)
    )

    @Test("An empty window says so rather than reporting a healthy network")
    func emptyWindowIsAmbiguous() {
        let report = Reliability.report(
            rows: [], interfaces: [], start: window.start, end: window.end
        )
        #expect(report.verdict.contains("nothing was watching"))
        #expect(report.minutesObserved == 0)
    }

    /// Fewer than three independent networks and the trick does not work. Saying so is the
    /// only honest option; offering a verdict anyway would be the tempting one.
    @Test("Too few networks to compare yields no verdict, and says why")
    func tooFewNetworks() {
        let rows = (0..<50).map { row(minute: base + Int64($0), group: "AS1", minMs: 20) }
        let report = Reliability.report(
            rows: rows, interfaces: [("en0", 1000)], start: window.start, end: window.end
        )
        #expect(report.verdict.contains("no verdict is offered"))
    }

    @Test("A common-mode stretch is named as being on this side of the internet")
    func commonModeVerdict() {
        var rows = steadyRows()
        for group in ["AS1", "AS2", "AS3"] {
            rows.append(row(minute: base + 900, group: group, minMs: 400))
        }
        let report = Reliability.report(
            rows: rows, interfaces: [("en0", 1000)], start: window.start, end: window.end
        )

        #expect(report.commonModeMinutes == 1)
        #expect(report.verdict.contains("your side of the internet"))
        // Never claims to know which of the three, because it cannot.
        #expect(report.verdict.contains("cannot tell those three apart"))
    }

    /// The caveat that invalidates everything else if it goes unsaid.
    @Test("Measuring over a VPN tunnel is stated plainly")
    func vpnCaveat() {
        let rows = steadyRows(minutes: 20).map { row in
            var copy = row
            copy.interface = "utun8"
            return copy
        }
        let report = Reliability.report(
            rows: rows, interfaces: [("utun8", 5000), ("en0", 10)],
            start: window.start, end: window.end
        )
        #expect(report.caveats.contains { $0.contains("not your ISP") })
    }

    @Test("Every report carries the idleness caveat, however good the numbers")
    func idlenessCaveatAlwaysTravels() {
        let rows = steadyRows()
        let report = Reliability.report(
            rows: rows, interfaces: [("en0", 1000)], start: window.start, end: window.end
        )
        #expect(report.caveats.contains { $0.contains("nobody asked anything") })
        #expect(!report.verdict.contains("down"))
    }

    @Test("Unanswered connections are reported as failures, never as an outage")
    func failuresAreNotOutages() {
        var rows = steadyRows()
        rows.append(row(minute: base + 900, group: "AS1", minMs: 20, timeouts: 3))
        rows.append(row(minute: base + 901, group: "AS2", minMs: 35, timeouts: 2))

        let report = Reliability.report(
            rows: rows, interfaces: [("en0", 1000)], start: window.start, end: window.end
        )
        #expect(report.failures.count == 1)
        #expect(report.failures.first?.timeouts == 5)
        #expect(report.verdict.contains("no answer at all"))
        #expect(!report.verdict.lowercased().contains("outage"))
    }
}

@Suite("Bufferbloat")
struct BufferbloatTests {

    /// Latency that climbs under load and settles when idle. The reading a speed test
    /// cannot give, and the one most likely to explain a connection that "feels slow".
    @Test("Latency rising with load is recognised as queueing")
    func inflationUnderLoad() throws {
        var rows: [QualityMinute] = []
        for step in 0..<30 {
            rows.append(
                row(minute: base + Int64(step), group: "AS1", minMs: 15, p50: 18, bytes: 5_000)
            )
        }
        for step in 30..<60 {
            rows.append(
                row(
                    minute: base + Int64(step), group: "AS1", minMs: 15, p50: 320,
                    bytes: 50_000_000
                )
            )
        }

        let reading = try #require(Reliability.bufferbloat(rows: rows))
        #expect(reading.inflationMs > 250)
        #expect(reading.isSignificant)
    }

    /// Without a real difference in load there is nothing to compare, and reporting a
    /// number anyway would be comparing an idle link against itself.
    @Test("A link that was never busy yields no reading")
    func noLoadNoReading() {
        let rows = (0..<40).map {
            row(minute: base + Int64($0), group: "AS1", minMs: 15, p50: 18, bytes: 5_000)
        }
        #expect(Reliability.bufferbloat(rows: rows) == nil)
    }
}

@Suite("Collapsing a series to one point per minute")
struct ReliabilitySeriesTests {

    /// The collapse is a median of per-network medians, which is a real choice about how
    /// independent networks combine — and it used to be made inside a SwiftUI view body,
    /// the one place in this project a test cannot reach.
    @Test("Networks in the same minute collapse to one floor and one typical value")
    func collapsesAcrossNetworks() throws {
        let rows = [
            row(minute: 100, group: "AS1", minMs: 10, p50: 12),
            row(minute: 100, group: "AS2", minMs: 30, p50: 40),
            row(minute: 100, group: "AS3", minMs: 20, p50: 50),
            row(minute: 101, group: "AS1", minMs: 15, p50: 18),
        ]

        let series = Reliability.series(rows: rows)
        #expect(series.count == 2)
        #expect(series[0].at < series[1].at, "sorted by time, whatever order the rows arrive")

        // The floor is the best anyone saw, not an average of the three.
        #expect(series[0].floorMs == 10)
        #expect(series[0].typicalMs == 40, "the middle of 12, 40 and 50")
        #expect(series[1].floorMs == 15)
    }

    /// Hourly rows carry a floor but no median, because a median cannot be summed. A point
    /// with no typical value has to say so rather than fall back to its floor, which would
    /// draw a flat line exactly where queueing should be visible.
    @Test("A minute with a floor but no median has no typical value")
    func typicalIsAbsentNotBorrowed() throws {
        let series = Reliability.series(rows: [row(minute: 100, group: "AS1", minMs: 10, p50: nil)])
        let point = try #require(series.first)
        #expect(point.floorMs == 10)
        #expect(point.typicalMs == 12, "p50 defaults to 1.2x the floor in this fixture")

        var coarse = row(minute: 200, group: "AS1", minMs: 25)
        coarse.rttP50Ms = nil
        let hourly = try #require(Reliability.series(rows: [coarse]).first)
        #expect(hourly.floorMs == 25)
        #expect(hourly.typicalMs == nil)
    }

    /// Nothing measured is not a fast minute, so it is left off the chart rather than
    /// plotted at zero.
    @Test("Minutes with nothing measured are dropped rather than plotted at zero")
    func unmeasuredMinutesAreDropped() {
        let rows = [
            row(minute: 100, group: "AS1", minMs: nil),
            row(minute: 101, group: "AS1", minMs: 10),
        ]
        #expect(Reliability.series(rows: rows).count == 1)
    }
}
