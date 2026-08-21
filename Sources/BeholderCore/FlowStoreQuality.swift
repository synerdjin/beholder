import CBeholderShim
import Foundation

// MARK: - Rows

/// One minute of measurement as it lives in the database.
public struct QualityMinute: Sendable, Equatable {
    public var minute: Int64
    public var interface: String
    public var destinationGroup: String
    public var destinationLabel: String?

    public var rttSamples: Int
    public var rttMinMs: Double?
    public var rttP50Ms: Double?
    public var rttP95Ms: Double?
    public var handshakeSamples: Int
    public var handshakeMinMs: Double?

    public var segmentsOut: UInt64
    public var segmentsIn: UInt64
    public var retransmitsOut: UInt64
    public var retransmitsIn: UInt64

    public var bytesOut: UInt64
    public var bytesIn: UInt64
    public var measuredBytes: UInt64
    public var unmeasurableBytes: UInt64

    public var flowCount: Int
    public var connectionAttempts: Int
    public var connectionTimeouts: Int

    public init(
        minute: Int64,
        interface: String,
        destinationGroup: String,
        destinationLabel: String? = nil,
        rttSamples: Int = 0,
        rttMinMs: Double? = nil,
        rttP50Ms: Double? = nil,
        rttP95Ms: Double? = nil,
        handshakeSamples: Int = 0,
        handshakeMinMs: Double? = nil,
        segmentsOut: UInt64 = 0,
        segmentsIn: UInt64 = 0,
        retransmitsOut: UInt64 = 0,
        retransmitsIn: UInt64 = 0,
        bytesOut: UInt64 = 0,
        bytesIn: UInt64 = 0,
        measuredBytes: UInt64 = 0,
        unmeasurableBytes: UInt64 = 0,
        flowCount: Int = 0,
        connectionAttempts: Int = 0,
        connectionTimeouts: Int = 0
    ) {
        self.minute = minute
        self.interface = interface
        self.destinationGroup = destinationGroup
        self.destinationLabel = destinationLabel
        self.rttSamples = rttSamples
        self.rttMinMs = rttMinMs
        self.rttP50Ms = rttP50Ms
        self.rttP95Ms = rttP95Ms
        self.handshakeSamples = handshakeSamples
        self.handshakeMinMs = handshakeMinMs
        self.segmentsOut = segmentsOut
        self.segmentsIn = segmentsIn
        self.retransmitsOut = retransmitsOut
        self.retransmitsIn = retransmitsIn
        self.bytesOut = bytesOut
        self.bytesIn = bytesIn
        self.measuredBytes = measuredBytes
        self.unmeasurableBytes = unmeasurableBytes
        self.flowCount = flowCount
        self.connectionAttempts = connectionAttempts
        self.connectionTimeouts = connectionTimeouts
    }

    public var at: Date { QualityAccumulator.date(ofMinute: minute) }

    /// Repeats as a share of segments sent. Nil, not zero, when nothing was sent.
    public var retransmitRateOut: Double? {
        segmentsOut > 0 ? Double(retransmitsOut) / Double(segmentsOut) : nil
    }
    public var retransmitRateIn: Double? {
        segmentsIn > 0 ? Double(retransmitsIn) / Double(segmentsIn) : nil
    }
    public var measuredByteShare: Double? {
        let total = measuredBytes + unmeasurableBytes
        return total > 0 ? Double(measuredBytes) / Double(total) : nil
    }
    public var totalBytes: UInt64 { bytesOut + bytesIn }
}

extension QualityAccumulator {
    /// Turns a drained bucket into the row that will be written.
    ///
    /// The percentiles are read off the histogram here rather than being carried further,
    /// since this is the last point at which the distribution still exists.
    public func row(for key: Key, _ bucket: QualityBucket) -> QualityMinute {
        QualityMinute(
            minute: key.minute,
            interface: key.interface,
            destinationGroup: key.destinationGroup,
            destinationLabel: label(for: key.destinationGroup),
            rttSamples: Int(bucket.rttSamples),
            rttMinMs: bucket.rttMinimum.map { $0 * 1000 },
            rttP50Ms: bucket.histogram.percentile(0.5),
            rttP95Ms: bucket.histogram.percentile(0.95),
            handshakeSamples: Int(bucket.handshakeSamples),
            handshakeMinMs: bucket.handshakeMinimum.map { $0 * 1000 },
            segmentsOut: bucket.segmentsOut,
            segmentsIn: bucket.segmentsIn,
            retransmitsOut: bucket.retransmitsOut,
            retransmitsIn: bucket.retransmitsIn,
            bytesOut: bucket.bytesOut,
            bytesIn: bucket.bytesIn,
            measuredBytes: bucket.measuredBytes,
            unmeasurableBytes: bucket.unmeasurableBytes,
            flowCount: bucket.flowCount,
            connectionAttempts: Int(bucket.connectionAttempts),
            connectionTimeouts: 0
        )
    }
}

// MARK: - Writing

extension FlowStore {

    /// Records a batch of per-minute measurements.
    ///
    /// An upsert, not an insert. A minute can legitimately be written twice: the
    /// accumulator writes it when the minute closes, and a connection that turns out to
    /// have timed out is attributed back to the minute it was *attempted* in, which may by
    /// then already be on disk. Counters add; the minimum takes the lower of the two.
    ///
    /// The percentiles are the one thing that cannot be merged — they came from a
    /// distribution that no longer exists — so the row with more samples behind it wins.
    /// In practice the two writers never both carry samples, so this arbitration is a
    /// safeguard rather than a routine approximation.
    @discardableResult
    public func recordQuality(_ rows: [QualityMinute]) throws -> Int {
        guard !rows.isEmpty, rawHandle != nil else { return 0 }

        let sql = """
            INSERT INTO quality_minutes (
                minute, interface, destination_group, destination_label,
                rtt_samples, rtt_min_ms, rtt_p50_ms, rtt_p95_ms,
                handshake_samples, handshake_min_ms,
                segments_out, segments_in, retransmits_out, retransmits_in,
                bytes_out, bytes_in, measured_bytes, unmeasurable_bytes,
                flow_count, connection_attempts, connection_timeouts
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(minute, interface, destination_group) DO UPDATE SET
                destination_label = COALESCE(excluded.destination_label, destination_label),
                rtt_min_ms = CASE
                    WHEN rtt_min_ms IS NULL THEN excluded.rtt_min_ms
                    WHEN excluded.rtt_min_ms IS NULL THEN rtt_min_ms
                    ELSE MIN(rtt_min_ms, excluded.rtt_min_ms) END,
                rtt_p50_ms = CASE
                    WHEN excluded.rtt_samples > rtt_samples THEN excluded.rtt_p50_ms
                    ELSE rtt_p50_ms END,
                rtt_p95_ms = CASE
                    WHEN excluded.rtt_samples > rtt_samples THEN excluded.rtt_p95_ms
                    ELSE rtt_p95_ms END,
                handshake_min_ms = CASE
                    WHEN handshake_min_ms IS NULL THEN excluded.handshake_min_ms
                    WHEN excluded.handshake_min_ms IS NULL THEN handshake_min_ms
                    ELSE MIN(handshake_min_ms, excluded.handshake_min_ms) END,
                rtt_samples = rtt_samples + excluded.rtt_samples,
                handshake_samples = handshake_samples + excluded.handshake_samples,
                segments_out = segments_out + excluded.segments_out,
                segments_in = segments_in + excluded.segments_in,
                retransmits_out = retransmits_out + excluded.retransmits_out,
                retransmits_in = retransmits_in + excluded.retransmits_in,
                bytes_out = bytes_out + excluded.bytes_out,
                bytes_in = bytes_in + excluded.bytes_in,
                measured_bytes = measured_bytes + excluded.measured_bytes,
                unmeasurable_bytes = unmeasurable_bytes + excluded.unmeasurable_bytes,
                flow_count = MAX(flow_count, excluded.flow_count),
                connection_attempts = connection_attempts + excluded.connection_attempts,
                connection_timeouts = connection_timeouts + excluded.connection_timeouts;
            """

        try execute("BEGIN IMMEDIATE;")
        do {
            try withStatement(sql) { statement in
                for row in rows {
                    sqlite3_reset(statement)
                    sqlite3_clear_bindings(statement)

                    var index: Int32 = 1
                    func bind(_ value: Int64) {
                        sqlite3_bind_int64(statement, index, value)
                        index += 1
                    }
                    func bind(_ value: Double?) {
                        if let value {
                            sqlite3_bind_double(statement, index, value)
                        } else {
                            sqlite3_bind_null(statement, index)
                        }
                        index += 1
                    }
                    func bind(_ value: String?) {
                        if let value {
                            bindText(statement, index, value)
                        } else {
                            sqlite3_bind_null(statement, index)
                        }
                        index += 1
                    }

                    bind(row.minute)
                    bind(row.interface)
                    bind(row.destinationGroup)
                    bind(row.destinationLabel)
                    bind(Int64(row.rttSamples))
                    bind(row.rttMinMs)
                    bind(row.rttP50Ms)
                    bind(row.rttP95Ms)
                    bind(Int64(row.handshakeSamples))
                    bind(row.handshakeMinMs)
                    bind(Int64(clamping: row.segmentsOut))
                    bind(Int64(clamping: row.segmentsIn))
                    bind(Int64(clamping: row.retransmitsOut))
                    bind(Int64(clamping: row.retransmitsIn))
                    bind(Int64(clamping: row.bytesOut))
                    bind(Int64(clamping: row.bytesIn))
                    bind(Int64(clamping: row.measuredBytes))
                    bind(Int64(clamping: row.unmeasurableBytes))
                    bind(Int64(row.flowCount))
                    bind(Int64(row.connectionAttempts))
                    bind(Int64(row.connectionTimeouts))

                    guard sqlite3_step(statement) == SQLITE_DONE else {
                        throw StoreError.statementFailed(lastErrorMessage)
                    }
            }
            }
            try execute("COMMIT;")
        } catch {
            try? execute("ROLLBACK;")
            throw error
        }
        return rows.count
    }

    /// Folds minutes older than the retention window into hours, then deletes them.
    ///
    /// Percentiles are deliberately not carried up. They came from a distribution that no
    /// longer exists, and a weighted average of two percentiles is not a percentile of
    /// anything. The minimum survives exactly, which is the figure the long view needs.
    @discardableResult
    public func pruneQuality(now: Date = Date()) throws -> Int {
        guard rawHandle != nil else { return 0 }
        let minuteCutoff = QualityAccumulator.minute(
            of: now.addingTimeInterval(-Double(retention.qualityMinuteDays) * 86400))
        let hourCutoff = Int64(
            now.addingTimeInterval(-Double(retention.qualityHourDays) * 86400)
                .timeIntervalSince1970 / 3600
        )
        let probeCutoff =
            now.addingTimeInterval(-Double(retention.probeDays) * 86400).timeIntervalSince1970

        try execute("BEGIN IMMEDIATE;")
        do {
            try execute(
                """
                INSERT INTO quality_hours (
                    hour, interface, destination_group, destination_label,
                    rtt_samples, rtt_min_ms, segments_out, segments_in,
                    retransmits_out, retransmits_in, bytes_out, bytes_in,
                    measured_bytes, unmeasurable_bytes,
                    connection_attempts, connection_timeouts
                )
                SELECT minute / 60, interface, destination_group, MIN(destination_label),
                       SUM(rtt_samples), MIN(rtt_min_ms), SUM(segments_out), SUM(segments_in),
                       SUM(retransmits_out), SUM(retransmits_in), SUM(bytes_out), SUM(bytes_in),
                       SUM(measured_bytes), SUM(unmeasurable_bytes),
                       SUM(connection_attempts), SUM(connection_timeouts)
                FROM quality_minutes WHERE minute < \(minuteCutoff)
                GROUP BY minute / 60, interface, destination_group
                ON CONFLICT(hour, interface, destination_group) DO UPDATE SET
                    rtt_samples = rtt_samples + excluded.rtt_samples,
                    rtt_min_ms = CASE
                        WHEN rtt_min_ms IS NULL THEN excluded.rtt_min_ms
                        WHEN excluded.rtt_min_ms IS NULL THEN rtt_min_ms
                        ELSE MIN(rtt_min_ms, excluded.rtt_min_ms) END,
                    segments_out = segments_out + excluded.segments_out,
                    segments_in = segments_in + excluded.segments_in,
                    retransmits_out = retransmits_out + excluded.retransmits_out,
                    retransmits_in = retransmits_in + excluded.retransmits_in,
                    bytes_out = bytes_out + excluded.bytes_out,
                    bytes_in = bytes_in + excluded.bytes_in,
                    measured_bytes = measured_bytes + excluded.measured_bytes,
                    unmeasurable_bytes = unmeasurable_bytes + excluded.unmeasurable_bytes,
                    connection_attempts = connection_attempts + excluded.connection_attempts,
                    connection_timeouts = connection_timeouts + excluded.connection_timeouts;
                """
            )
            try execute("DELETE FROM quality_minutes WHERE minute < \(minuteCutoff);")
            try execute("DELETE FROM quality_hours WHERE hour < \(hourCutoff);")
            try execute("DELETE FROM quality_probes WHERE at < \(probeCutoff);")
            try execute("COMMIT;")
        } catch {
            try? execute("ROLLBACK;")
            throw error
        }
        return Int(sqlite3_changes(rawHandle))
    }

}

// MARK: - Reading

extension FlowStore {

    /// Every per-minute row in a window, oldest first.
    public func qualityMinutes(
        since: Date,
        until: Date,
        interface: String? = nil
    ) throws -> [QualityMinute] {
        let first = QualityAccumulator.minute(of: since)
        let last = QualityAccumulator.minute(of: until)
        var sql = """
            SELECT minute, interface, destination_group, destination_label,
                   rtt_samples, rtt_min_ms, rtt_p50_ms, rtt_p95_ms,
                   handshake_samples, handshake_min_ms,
                   segments_out, segments_in, retransmits_out, retransmits_in,
                   bytes_out, bytes_in, measured_bytes, unmeasurable_bytes,
                   flow_count, connection_attempts, connection_timeouts
            FROM quality_minutes WHERE minute >= ? AND minute <= ?
            """
        if interface != nil { sql += " AND interface = ?" }
        sql += " ORDER BY minute ASC;"

        var rows: [QualityMinute] = []
        try withStatement(sql) { statement in
            sqlite3_bind_int64(statement, 1, first)
            sqlite3_bind_int64(statement, 2, last)
            if let interface {
                bindText(statement, 3, interface)
            }
            while sqlite3_step(statement) == SQLITE_ROW {
                rows.append(self.qualityMinute(from: statement))
            }
        }
        return rows
    }

    /// The interfaces that carry measurement in a window, busiest first.
    ///
    /// Wanted because a `utun` interface means the measurements describe a VPN tunnel
    /// rather than the connection underneath it, and no report should be shown without
    /// saying which it was.
    public func qualityInterfaces(since: Date, until: Date) throws -> [(String, UInt64)] {
        let first = QualityAccumulator.minute(of: since)
        let last = QualityAccumulator.minute(of: until)
        var rows: [(String, UInt64)] = []
        try withStatement(
            """
            SELECT interface, SUM(bytes_out + bytes_in) AS total
            FROM quality_minutes WHERE minute >= ? AND minute <= ?
            GROUP BY interface ORDER BY total DESC;
            """
        ) { statement in
            sqlite3_bind_int64(statement, 1, first)
            sqlite3_bind_int64(statement, 2, last)
            while sqlite3_step(statement) == SQLITE_ROW {
                rows.append((text(statement, 0) ?? "?", unsigned(statement, 1)))
            }
        }
        return rows
    }

    /// The coarse tier, for windows reaching back past the minute retention.
    ///
    /// Returned as `QualityMinute` rows keyed to the hour's first minute so every reader —
    /// `Reliability`, the groupers, the app — works on them unchanged. What the hour rollup
    /// does not carry is stated by its absence rather than by a zero: `rttP50Ms`, `rttP95Ms`
    /// and the handshake figures are nil, because a median cannot be summed and the rollup
    /// never kept one.
    ///
    /// Without this, `quality_hours` was written every hour, pruned on a 365-day schedule
    /// and read by nothing, so a request for ninety days answered with an empty stretch —
    /// indistinguishable from "nothing was watching", which is the one ambiguity every
    /// report here exists to prevent.
    public func qualityHours(
        since: Date,
        until: Date,
        interface: String? = nil
    ) throws -> [QualityMinute] {
        let first = Int64(since.timeIntervalSince1970 / 3600)
        let last = Int64(until.timeIntervalSince1970 / 3600)

        var sql = """
            SELECT hour, interface, destination_group, destination_label,
                   rtt_samples, rtt_min_ms, segments_out, segments_in,
                   retransmits_out, retransmits_in, bytes_out, bytes_in,
                   measured_bytes, unmeasurable_bytes,
                   connection_attempts, connection_timeouts
            FROM quality_hours WHERE hour >= ? AND hour <= ?
            """
        if interface != nil { sql += " AND interface = ?" }
        sql += " ORDER BY hour ASC;"

        var rows: [QualityMinute] = []
        try withStatement(sql) { statement in
            sqlite3_bind_int64(statement, 1, first)
            sqlite3_bind_int64(statement, 2, last)
            if let interface { bindText(statement, 3, interface) }
            while sqlite3_step(statement) == SQLITE_ROW {
                rows.append(
                    QualityMinute(
                        minute: sqlite3_column_int64(statement, 0) * 60,
                        interface: text(statement, 1) ?? "?",
                        destinationGroup: text(statement, 2) ?? "?",
                        destinationLabel: text(statement, 3),
                        rttSamples: Int(sqlite3_column_int64(statement, 4)),
                        rttMinMs: optionalDouble(statement, 5),
                        segmentsOut: unsigned(statement, 6),
                        segmentsIn: unsigned(statement, 7),
                        retransmitsOut: unsigned(statement, 8),
                        retransmitsIn: unsigned(statement, 9),
                        bytesOut: unsigned(statement, 10),
                        bytesIn: unsigned(statement, 11),
                        measuredBytes: unsigned(statement, 12),
                        unmeasurableBytes: unsigned(statement, 13),
                        connectionAttempts: Int(sqlite3_column_int64(statement, 14)),
                        connectionTimeouts: Int(sqlite3_column_int64(statement, 15))
                    )
                )
            }
        }
        return rows
    }

    /// The earliest minute the fine tier still holds, so a caller can tell where it has to
    /// fall back to hours.
    public func qualityMinuteHorizon() throws -> Date? {
        var horizon: Date?
        try withStatement("SELECT MIN(minute) FROM quality_minutes;") { statement in
            guard sqlite3_step(statement) == SQLITE_ROW,
                sqlite3_column_type(statement, 0) != SQLITE_NULL
            else { return }
            horizon = QualityAccumulator.date(ofMinute: sqlite3_column_int64(statement, 0))
        }
        return horizon
    }

    /// The window the quality series actually covers, which an empty result has to be read
    /// against: no rows in a window can mean a quiet network or a daemon that was not
    /// running, and only this tells them apart.
    public func qualityCoverage() throws -> (earliest: Date, latest: Date, minutes: Int)? {
        var result: (Date, Date, Int)?
        try withStatement(
            "SELECT MIN(minute), MAX(minute), COUNT(DISTINCT minute) FROM quality_minutes;"
        ) { statement in
            guard sqlite3_step(statement) == SQLITE_ROW,
                sqlite3_column_type(statement, 0) != SQLITE_NULL
            else { return }
            let first = sqlite3_column_int64(statement, 0)
            let last = sqlite3_column_int64(statement, 1)
            result = (
                QualityAccumulator.date(ofMinute: first),
                QualityAccumulator.date(ofMinute: last),
                Int(sqlite3_column_int64(statement, 2))
            )
        }
        return result
    }

    /// Reads one row, through the shared column helpers rather than local copies of them.
    ///
    /// The locals that used to sit here re-derived `unsigned`'s clamp without the comment
    /// explaining why it clamps rather than truncates, which is exactly how two readers of
    /// one table come to disagree about a negative count.
    private func qualityMinute(from statement: OpaquePointer?) -> QualityMinute {
        func double(_ column: Int32) -> Double? { optionalDouble(statement, column) }
        func string(_ column: Int32) -> String? { text(statement, column) }
        func count(_ column: Int32) -> UInt64 { unsigned(statement, column) }
        func integer(_ column: Int32) -> Int {
            Int(sqlite3_column_int64(statement, column))
        }

        return QualityMinute(
            minute: sqlite3_column_int64(statement, 0),
            interface: string(1) ?? "?",
            destinationGroup: string(2) ?? "?",
            destinationLabel: string(3),
            rttSamples: integer(4),
            rttMinMs: double(5),
            rttP50Ms: double(6),
            rttP95Ms: double(7),
            handshakeSamples: integer(8),
            handshakeMinMs: double(9),
            segmentsOut: count(10),
            segmentsIn: count(11),
            retransmitsOut: count(12),
            retransmitsIn: count(13),
            bytesOut: count(14),
            bytesIn: count(15),
            measuredBytes: count(16),
            unmeasurableBytes: count(17),
            flowCount: integer(18),
            connectionAttempts: integer(19),
            connectionTimeouts: integer(20)
        )
    }
}

// MARK: - Probes

/// One active measurement: what was asked, and what came back.
public struct ProbeResult: Sendable, Equatable {
    public enum Kind: String, Sendable {
        /// The next hop out of this machine. The only measurement that can separate the
        /// local link from everything beyond it.
        case gateway
        /// A fixed, distant address, used as a stable yardstick over months.
        case anchor
    }

    public let at: Date
    public let interface: String
    public let target: String
    public let kind: Kind
    /// Nil means no reply came back within the timeout, which is a result and not a gap.
    public let rttMs: Double?

    public init(at: Date, interface: String, target: String, kind: Kind, rttMs: Double?) {
        self.at = at
        self.interface = interface
        self.target = target
        self.kind = kind
        self.rttMs = rttMs
    }
}

extension FlowStore {

    @discardableResult
    public func recordProbes(_ probes: [ProbeResult]) throws -> Int {
        guard !probes.isEmpty, rawHandle != nil else { return 0 }

        let sql = """
            INSERT OR REPLACE INTO quality_probes (at, interface, target, kind, rtt_ms)
            VALUES (?,?,?,?,?);
            """
        try withStatement(sql) { statement in
            for probe in probes {
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
                sqlite3_bind_double(statement, 1, probe.at.timeIntervalSince1970)
                bindText(statement, 2, probe.interface)
                bindText(statement, 3, probe.target)
                bindText(statement, 4, probe.kind.rawValue)
                if let rtt = probe.rttMs {
                    sqlite3_bind_double(statement, 5, rtt)
                } else {
                    sqlite3_bind_null(statement, 5)
                }
                guard sqlite3_step(statement) == SQLITE_DONE else {
                    throw StoreError.statementFailed(lastErrorMessage)
                }
        }
        }
        return probes.count
    }

    public func probes(since: Date, until: Date) throws -> [ProbeResult] {
        var results: [ProbeResult] = []
        try withStatement(
            """
            SELECT at, interface, target, kind, rtt_ms FROM quality_probes
            WHERE at >= ? AND at <= ? ORDER BY at ASC;
            """
        ) { statement in
            sqlite3_bind_double(statement, 1, since.timeIntervalSince1970)
            sqlite3_bind_double(statement, 2, until.timeIntervalSince1970)
            while sqlite3_step(statement) == SQLITE_ROW {
                results.append(
                    ProbeResult(
                        at: Date(timeIntervalSince1970: sqlite3_column_double(statement, 0)),
                        interface: text(statement, 1) ?? "?",
                        target: text(statement, 2) ?? "?",
                        kind: ProbeResult.Kind(rawValue: text(statement, 3) ?? "") ?? .anchor,
                        rttMs: sqlite3_column_type(statement, 4) == SQLITE_NULL
                            ? nil : sqlite3_column_double(statement, 4)
                    )
                )
            }
        }
        return results
    }

    /// The gateway against the anchors, which is the one comparison passive capture cannot
    /// make and the entire reason probing exists.
    ///
    /// A clean gateway with bad anchors puts the trouble upstream of your router. A bad
    /// gateway puts it on your own Wi-Fi or cable. Nothing in the passive measurements can
    /// tell those apart, because both look identical from the far end of the path.
    public func probeSummary(since: Date, until: Date) throws -> ProbeSummary? {
        let results = try probes(since: since, until: until)
        guard !results.isEmpty else { return nil }

        func summarise(_ subset: [ProbeResult]) -> (min: Double?, median: Double?, loss: Double)? {
            guard !subset.isEmpty else { return nil }
            let replies = subset.compactMap(\.rttMs).sorted()
            let loss = Double(subset.count - replies.count) / Double(subset.count)
            return (replies.first, replies.median, loss)
        }

        return ProbeSummary(
            gateway: summarise(results.filter { $0.kind == .gateway }),
            anchors: summarise(results.filter { $0.kind == .anchor }),
            samples: results.count
        )
    }
}

public struct ProbeSummary: Sendable {
    public let gateway: (min: Double?, median: Double?, loss: Double)?
    public let anchors: (min: Double?, median: Double?, loss: Double)?
    public let samples: Int

    /// Where the trouble is, when the two halves disagree enough to say.
    public var reading: String? {
        guard let gateway, let anchors else { return nil }
        let gatewayBad = gateway.loss > 0.02 || (gateway.median ?? 0) > 25
        let anchorsBad = anchors.loss > 0.02 || (anchors.median ?? 0) > 150

        switch (gatewayBad, anchorsBad) {
        case (true, _):
            return """
                The first hop out of this machine is itself slow or lossy, so the trouble \
                starts on your own network — Wi-Fi, cabling, or the router — before \
                anything your ISP controls.
                """
        case (false, true):
            return """
                The first hop is clean while distant addresses are not, which places the \
                trouble upstream of your router: your ISP or beyond.
                """
        case (false, false):
            return "Both the first hop and distant addresses are responding normally."
        }
    }
}
