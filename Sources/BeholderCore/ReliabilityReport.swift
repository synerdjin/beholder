import Foundation

/// Whether the trouble was yours or theirs.
///
/// The question this whole feature exists to answer is "is my ISP any good", and the
/// honest answer needs a trick, because a round trip to a server measures the whole path
/// and not the part you pay for. The trick is **common mode**: when several networks that
/// share nothing except your uplink all slow down in the same minute, the thing they share
/// is the thing at fault. When one slows down alone, it is that one.
///
/// Everything below is a pure function of rows already on disk, so the verdict can be
/// tested without a network — which matters, because a verdict is the easiest thing here
/// to get quietly, confidently wrong.
public enum Reliability {

    /// One point per minute: the floor across every network, and the typical value.
    ///
    /// The same collapse `byHourOfDay` makes for hours and `qualityByDay` makes for days,
    /// and it is not a trivial one — the typical value is a median of per-network medians,
    /// which is a deliberate choice about how independent networks combine. It lived in a
    /// SwiftUI view, which made it the only one of the three no test could reach.
    ///
    /// Minutes with nothing measured are dropped rather than plotted at zero, for the
    /// reason that runs through all of this: nothing measured is not a fast connection.
    public static func series(rows: [QualityMinute]) -> [Point] {
        var byMinute: [Int64: (floor: Double?, medians: [Double])] = [:]
        for row in rows {
            guard let floor = row.rttMinMs else { continue }
            var entry = byMinute[row.minute] ?? (nil, [])
            entry.floor = Swift.min(entry.floor ?? floor, floor)
            if let median = row.rttP50Ms { entry.medians.append(median) }
            byMinute[row.minute] = entry
        }

        return byMinute
            .compactMap { minute, entry in
                guard let floor = entry.floor else { return nil }
                return Point(
                    at: QualityAccumulator.date(ofMinute: minute),
                    floorMs: floor,
                    typicalMs: entry.medians.median
                )
            }
            .sorted { $0.at < $1.at }
    }

    public struct Point: Sendable, Equatable {
        public let at: Date
        public let floorMs: Double
        /// Nil for a minute where a floor was measured but no median was — a coarse
        /// hourly row, or a minute with a single sample.
        public let typicalMs: Double?
    }

    // MARK: - Thresholds

    /// How many round trips a network must contribute in a minute before that minute is
    /// allowed to say anything about it.
    ///
    /// Below this the minimum is one or two samples and moves with the wind. A verdict
    /// built on it would be noise wearing a conclusion's clothes, so such minutes are
    /// reported as *insufficient* rather than as fine.
    public static let minimumSamplesPerMinute = 5

    /// A network counts as degraded when its floor for the minute rises above its own
    /// baseline by more than half again, or by 20 ms, whichever is larger.
    ///
    /// The absolute floor is there for near paths: a CDN 4 ms away goes to 6 ms on a
    /// perfectly healthy link, and a purely proportional test would call that a fault
    /// every time.
    public static let degradationFactor = 0.5
    public static let degradationFloorMs = 20.0

    /// How many independent networks must degrade together before the shared segment is
    /// implicated. Two can be coincidence — two CDNs sharing a transit provider is an
    /// ordinary arrangement. Three that share nothing but your uplink is the uplink.
    public static let commonModeGroups = 3

    /// A retransmission rate above this is treated as loss worth reporting.
    public static let retransmitThreshold = 0.02

    // MARK: - Baselines

    /// A network's own floor, against which its bad minutes are measured.
    public struct Baseline: Sendable, Equatable {
        public let group: String
        public let label: String?
        /// The tenth percentile of this network's per-minute minima. Not the outright
        /// minimum: one freakishly fast sample would set a floor nothing could live up to,
        /// and every minute after it would read as degraded.
        public let floorMs: Double
        public let minutes: Int
    }

    public static func baselines(from rows: [QualityMinute]) -> [String: Baseline] {
        var byGroup: [String: [Double]] = [:]
        var labels: [String: String] = [:]
        for row in rows {
            guard row.rttSamples >= minimumSamplesPerMinute, let floor = row.rttMinMs else {
                continue
            }
            byGroup[row.destinationGroup, default: []].append(floor)
            if let label = row.destinationLabel { labels[row.destinationGroup] = label }
        }

        return byGroup.mapValues { values in
            let sorted = values.sorted()
            let index = Swift.min(sorted.count - 1, Int(Double(sorted.count) * 0.1))
            return (sorted[index], sorted.count)
        }
        .reduce(into: [String: Baseline]()) { result, entry in
            result[entry.key] = Baseline(
                group: entry.key,
                label: labels[entry.key],
                floorMs: entry.value.0,
                minutes: entry.value.1
            )
        }
    }

    // MARK: - Degradation

    /// Which networks were having a bad minute, and why.
    public struct DegradedMinute: Sendable, Equatable {
        public let minute: Int64
        public let groups: [String]
        public var at: Date { QualityAccumulator.date(ofMinute: minute) }
        /// True once enough independent networks are involved that the fault is more
        /// likely to be on this side of the internet than on all of theirs at once.
        public var isCommonMode: Bool { groups.count >= commonModeGroups }
    }

    public static func degradedMinutes(
        from rows: [QualityMinute],
        baselines: [String: Baseline]
    ) -> [DegradedMinute] {
        var byMinute: [Int64: Set<String>] = [:]

        for row in rows {
            guard let baseline = baselines[row.destinationGroup] else { continue }
            guard row.rttSamples >= minimumSamplesPerMinute else { continue }

            var degraded = false
            if let floor = row.rttMinMs {
                let allowance = Swift.max(
                    baseline.floorMs * degradationFactor, degradationFloorMs
                )
                if floor > baseline.floorMs + allowance { degraded = true }
            }
            if let rate = row.retransmitRateOut, rate > retransmitThreshold, row.segmentsOut > 100
            {
                degraded = true
            }
            if degraded { byMinute[row.minute, default: []].insert(row.destinationGroup) }
        }

        return byMinute
            .map { DegradedMinute(minute: $0.key, groups: $0.value.sorted()) }
            .sorted { $0.minute < $1.minute }
    }

    // MARK: - Time of day

    /// One hour of the day, averaged across every day in the window. The classic shape of
    /// a contended residential link: fine all day, worse from seven.
    public struct HourReading: Sendable, Equatable {
        public let hour: Int
        public let floorMs: Double?
        public let typicalMs: Double?
        public let retransmitRateOut: Double?
        public let bytes: UInt64
        public let samples: Int
        public let degradedMinutes: Int
    }

    public static func byHourOfDay(
        rows: [QualityMinute],
        degraded: [DegradedMinute],
        calendar: Calendar = .current
    ) -> [HourReading] {
        var floors: [Int: Double] = [:]
        var typical: [Int: [Double]] = [:]
        var segmentsOut: [Int: UInt64] = [:]
        var retransmits: [Int: UInt64] = [:]
        var bytes: [Int: UInt64] = [:]
        var samples: [Int: Int] = [:]

        for row in rows {
            let hour = calendar.component(.hour, from: row.at)
            if let floor = row.rttMinMs, row.rttSamples >= minimumSamplesPerMinute {
                floors[hour] = Swift.min(floors[hour] ?? floor, floor)
            }
            if let median = row.rttP50Ms, row.rttSamples >= minimumSamplesPerMinute {
                typical[hour, default: []].append(median)
            }
            segmentsOut[hour, default: 0] += row.segmentsOut
            retransmits[hour, default: 0] += row.retransmitsOut
            bytes[hour, default: 0] += row.totalBytes
            samples[hour, default: 0] += row.rttSamples
        }

        var degradedPerHour: [Int: Int] = [:]
        for minute in degraded where minute.isCommonMode {
            let hour = calendar.component(.hour, from: minute.at)
            degradedPerHour[hour, default: 0] += 1
        }

        return (0..<24).map { hour in
            let sent = segmentsOut[hour] ?? 0
            return HourReading(
                hour: hour,
                floorMs: floors[hour],
                typicalMs: (typical[hour] ?? []).median,
                retransmitRateOut: sent > 0 ? Double(retransmits[hour] ?? 0) / Double(sent) : nil,
                bytes: bytes[hour] ?? 0,
                samples: samples[hour] ?? 0,
                degradedMinutes: degradedPerHour[hour] ?? 0
            )
        }
    }

    // MARK: - Bufferbloat

    /// Latency under load against latency at rest.
    ///
    /// Probably the most useful thing here for a home connection, and the one a speed test
    /// will never show: a link can hit its advertised rate and still feel broken because
    /// something between here and the exchange holds a fat buffer that fills under load.
    /// Beholder can see it because it has both numbers for the same minute.
    public struct BufferbloatReading: Sendable, Equatable {
        public let idleFloorMs: Double
        public let loadedTypicalMs: Double
        public let busyMinutes: Int
        public let idleMinutes: Int

        /// How much latency the load adds. The number to act on: a router doing fair
        /// queueing keeps this near zero.
        public var inflationMs: Double { Swift.max(0, loadedTypicalMs - idleFloorMs) }
        /// Enough to be felt in a call or a game, rather than merely measurable.
        public var isSignificant: Bool { inflationMs > 100 }
    }

    public static func bufferbloat(rows: [QualityMinute]) -> BufferbloatReading? {
        let usable = rows.filter { $0.rttSamples >= minimumSamplesPerMinute && $0.rttP50Ms != nil }
        guard usable.count >= 20 else { return nil }

        let byBytes = usable.sorted { $0.totalBytes < $1.totalBytes }
        let quartile = Swift.max(1, byBytes.count / 4)
        let idle = byBytes.prefix(quartile)
        let busy = byBytes.suffix(quartile)

        // A quiet minute and a busy one have to differ by enough for the comparison to
        // mean anything; otherwise this compares two samples of the same idle link.
        let idleBytes = idle.map(\.totalBytes).reduce(0, +) / UInt64(idle.count)
        let busyBytes = busy.map(\.totalBytes).reduce(0, +) / UInt64(busy.count)
        guard busyBytes > idleBytes * 4 else { return nil }

        let idleFloors = idle.compactMap(\.rttMinMs).sorted()
        let busyMedians = busy.compactMap(\.rttP50Ms)
        guard let floor = idleFloors.first, let loaded = busyMedians.median else { return nil }

        return BufferbloatReading(
            idleFloorMs: floor,
            loadedTypicalMs: loaded,
            busyMinutes: busy.count,
            idleMinutes: idle.count
        )
    }

    // MARK: - Connectivity failures

    /// A run of minutes in which connections were opened and never answered.
    ///
    /// Not an outage. An outage is what happens when nothing is being asked of the
    /// network, and from here that is indistinguishable from nobody asking. This is the
    /// thing that *can* honestly be said: connections were attempted, and they failed.
    public struct FailureWindow: Sendable, Equatable {
        public let start: Date
        public let end: Date
        public let timeouts: Int
        public let networks: Int
    }

    public static func failureWindows(rows: [QualityMinute]) -> [FailureWindow] {
        let failing = rows.filter { $0.connectionTimeouts > 0 }
        guard !failing.isEmpty else { return [] }

        var windows: [FailureWindow] = []
        var runStart: Int64?
        var runEnd: Int64 = 0
        var timeouts = 0
        var networks: Set<String> = []

        func close() {
            guard let start = runStart else { return }
            windows.append(
                FailureWindow(
                    start: Date(timeIntervalSince1970: Double(start) * 60),
                    end: Date(timeIntervalSince1970: Double(runEnd + 1) * 60),
                    timeouts: timeouts,
                    networks: networks.count
                )
            )
            runStart = nil
            timeouts = 0
            networks = []
        }

        for row in failing.sorted(by: { $0.minute < $1.minute }) {
            if let _ = runStart, row.minute <= runEnd + 1 {
                runEnd = Swift.max(runEnd, row.minute)
            } else {
                close()
                runStart = row.minute
                runEnd = row.minute
            }
            timeouts += row.connectionTimeouts
            networks.insert(row.destinationGroup)
        }
        close()
        return windows
    }

    // MARK: - The report

    public struct Report: Sendable {
        public let start: Date
        public let end: Date
        public let minutesObserved: Int
        public let baselines: [String: Baseline]
        public let degraded: [DegradedMinute]
        public let hours: [HourReading]
        public let bufferbloat: BufferbloatReading?
        public let failures: [FailureWindow]
        public let interfaces: [(name: String, bytes: UInt64)]
        public let measuredByteShare: Double?
        public let caveats: [String]
        public let verdict: String

        public var commonModeMinutes: Int { degraded.count { $0.isCommonMode } }
    }

    public static func report(
        rows: [QualityMinute],
        interfaces: [(name: String, bytes: UInt64)],
        start: Date,
        end: Date,
        calendar: Calendar = .current
    ) -> Report {
        let baselines = baselines(from: rows)
        let degraded = degradedMinutes(from: rows, baselines: baselines)
        let hours = byHourOfDay(rows: rows, degraded: degraded, calendar: calendar)
        let bloat = bufferbloat(rows: rows)
        let failures = failureWindows(rows: rows)
        let minutes = Set(rows.map(\.minute)).count

        let measured = rows.map(\.measuredBytes).reduce(UInt64(0), &+)
        let unmeasurable = rows.map(\.unmeasurableBytes).reduce(UInt64(0), &+)
        let share =
            (measured + unmeasurable) > 0
            ? Double(measured) / Double(measured + unmeasurable) : nil

        var caveats: [String] = []

        // The one that invalidates everything else if it goes unsaid.
        let tunnels = interfaces.filter { $0.name.hasPrefix("utun") || $0.name.hasPrefix("ipsec") }
        if let tunnel = tunnels.max(by: { $0.bytes < $1.bytes }) {
            let total = interfaces.map(\.bytes).reduce(UInt64(0), &+)
            let portion = total > 0 ? Double(tunnel.bytes) / Double(total) : 1
            caveats.append(
                """
                \(Int((portion * 100).rounded()))% of this was measured on \(tunnel.name), \
                a VPN tunnel. Those round trips are to the VPN's exit and back, so they \
                describe the tunnel — not the connection underneath it, and not your ISP.
                """
            )
        }
        if let share, share < 0.75 {
            caveats.append(
                """
                Latency and loss here cover \(Int((share * 100).rounded()))% of the bytes \
                moved. The rest is QUIC or other UDP traffic, which carries no round trips \
                a passive observer can read.
                """
            )
        }
        caveats.append(
            """
            Only paths actually used are measured, and only while they were being used. A \
            quiet stretch means nobody asked anything of the network — it is not evidence \
            that the network was working, and not evidence that it was not.
            """
        )
        if rows.contains(where: { $0.retransmitsOut > 0 }) {
            caveats.append(
                """
                What is counted is retransmissions, not dropped packets. From one end of a \
                connection a lost acknowledgement coming back looks exactly like data lost \
                on the way out, so this is a floor on loss rather than a measurement of it.
                """
            )
        }

        return Report(
            start: start,
            end: end,
            minutesObserved: minutes,
            baselines: baselines,
            degraded: degraded,
            hours: hours,
            bufferbloat: bloat,
            failures: failures,
            interfaces: interfaces,
            measuredByteShare: share,
            caveats: caveats,
            verdict: verdict(
                minutes: minutes,
                degraded: degraded,
                baselines: baselines,
                bufferbloat: bloat,
                failures: failures
            )
        )
    }

    /// The sentence a person actually reads.
    ///
    /// Written to be defensible rather than satisfying. It will not say the ISP was down,
    /// because passive capture cannot know that; it will not give a score, because a score
    /// throws away the caveats that make it mean anything.
    static func verdict(
        minutes: Int,
        degraded: [DegradedMinute],
        baselines: [String: Baseline],
        bufferbloat: BufferbloatReading?,
        failures: [FailureWindow]
    ) -> String {
        guard minutes > 0 else {
            return """
                Nothing was recorded in this window. That means either nothing was asked of \
                the network, or nothing was watching — and from here those look the same.
                """
        }
        guard baselines.count >= commonModeGroups else {
            return """
                \(pluralised(minutes, "minute")) of traffic, reaching \
                \(pluralised(baselines.count, "network")) often \
                enough to measure. Telling a problem on your side from a slow destination \
                needs at least \(commonModeGroups) independent networks to compare, so no \
                verdict is offered yet.
                """
        }

        let common = degraded.count { $0.isCommonMode }
        var lines: [String] = []

        if common == 0 {
            lines.append(
                """
                Across \(pluralised(minutes, "minute")) of traffic to \
                \(baselines.count) networks, no minute showed several independent networks \
                slowing together. Whatever went wrong in this window went wrong at one end \
                or the other, not on the path you share.
                """
            )
        } else {
            let portion = Double(common) / Double(minutes) * 100
            lines.append(
                """
                In \(common) of \(minutes) minutes — \(String(format: "%.1f", portion))% — \
                \(commonModeGroups) or more independent networks slowed at the same time. \
                Networks that share nothing but your uplink do not degrade together by \
                chance, so that points at something on your side of the internet: your \
                Wi-Fi, your router, or your ISP. Passive capture cannot tell those three \
                apart; --probe can, by timing your gateway separately.
                """
            )
        }

        if let bufferbloat, bufferbloat.isSignificant {
            lines.append(
                """
                Under load, the typical round trip rises to \
                \(Int(bufferbloat.loadedTypicalMs.rounded())) ms against a floor of \
                \(Int(bufferbloat.idleFloorMs.rounded())) ms — about \
                \(Int(bufferbloat.inflationMs.rounded())) ms of queueing. That is \
                bufferbloat, and it is why a connection can pass a speed test and still \
                feel bad on a call. It is usually fixed at the router, not by the ISP.
                """
            )
        }

        if !failures.isEmpty {
            let total = failures.map(\.timeouts).reduce(0, +)
            lines.append(
                """
                \(pluralised(total, "connection attempt")) in \
                \(pluralised(failures.count, "stretch", plural: "stretches")) got no \
                answer at all. That is direct evidence the path failed while it was being \
                used — distinct from a quiet period, which proves nothing either way.
                """
            )
        }

        return lines.joined(separator: "\n\n")
    }
}
