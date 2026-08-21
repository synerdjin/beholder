import CBeholderShim
import Foundation

/// Grouped reads over the history database.
///
/// `FlowStoreQueries` returns rows, which is what a terminal table and a scrolling list
/// want. This file returns totals, which is what a question wants — and, more bluntly,
/// what fits. Two days of capture on one laptop is roughly twenty thousand flow rows
/// across five hundred hostnames: about thirty rows per host-and-process pair, and over a
/// thousand rows for a single busy API endpoint. Handing five hundred of those to a reader
/// to add up is both expensive and unreliable when the answer wanted was one number.
///
/// So: group in SQLite, which is good at it, and send the summary.

/// One remote endpoint as seen by one process over a window.
public struct HostDigest: Sendable, Equatable {
    public let hostName: String?
    public let remoteAddress: String
    public let processName: String?
    public let connectionCount: Int
    public let bytesOut: UInt64
    public let bytesIn: UInt64
    public let firstSeen: Date
    public let lastSeen: Date
    public let country: String?
    public let networkOperator: String?
    public let ownerCompany: String?

    public var totalBytes: UInt64 { bytesOut + bytesIn }

    /// The best label available, in the same order of preference the live view uses.
    public var remoteDescription: String {
        hostName ?? networkOperator ?? remoteAddress
    }
}

/// Everything recorded about one endpoint, across the whole retained history.
public struct EndpointHistory: Sendable, Equatable {
    public struct ProcessShare: Sendable, Equatable {
        public let processName: String
        public let connectionCount: Int
        public let bytesOut: UInt64
        public let bytesIn: UInt64
    }

    public struct Day: Sendable, Equatable {
        public let day: String
        public let connectionCount: Int
        public let bytes: UInt64
    }

    public let matched: Bool
    public let matchedExactly: Bool
    public let hostNames: [String]
    public let addresses: [String]
    public let connectionCount: Int
    public let bytesOut: UInt64
    public let bytesIn: UInt64
    public let firstSeen: Date?
    public let lastSeen: Date?
    public let processes: [ProcessShare]
    public let countries: [String]
    public let networkOperators: [String]
    public let ownerCompanies: [String]
    public let byDay: [Day]
}

/// A process's share of the window, in the terms `ProxyDetection` judges by.
public struct ProxyCandidate: Sendable, Equatable {
    public let processName: String
    public let processPath: String
    public let flowCount: Int
    public let distinctRemoteHosts: Int
}

public enum HistoryOrder: String, Sendable {
    /// Heaviest first. What "what used all my bandwidth" means.
    case bytes
    /// Most recent first. What "what happened at 3am" means — see the note on `flows()`.
    case recent
}

extension FlowStore {

    // MARK: - Grouped by endpoint

    /// Endpoints contacted in a window, one row per (host, process) pair.
    ///
    /// Grouping is done here rather than by the caller because the point is to never
    /// materialise the rows in the first place.
    public func hostDigests(
        since: Date,
        until: Date = Date(),
        matching: String? = nil,
        order: HistoryOrder = .bytes,
        limit: Int = 25
    ) throws -> (rows: [HostDigest], totalGroups: Int) {
        let filter =
            matching == nil
            ? ""
            : """
             AND (
                IFNULL(process_name,'') LIKE ?
                OR IFNULL(host_name,'') LIKE ?
                OR remote_address LIKE ?
                OR IFNULL(owner_company,'') LIKE ?
                OR IFNULL(network_operator,'') LIKE ?
             )
            """

        // Grouping on the hostname when there is one and the address otherwise: a host
        // reached over several addresses is one endpoint to a reader, but an address with
        // no name still deserves its own row rather than being merged with every other
        // unnamed one.
        let grouping = "IFNULL(host_name, remote_address), IFNULL(process_name,'')"
        let ordering = order == .bytes ? "SUM(bytes_out + bytes_in) DESC" : "MAX(last_seen) DESC"

        let sql = """
            SELECT host_name, remote_address, process_name, COUNT(*),
                   SUM(bytes_out), SUM(bytes_in), MIN(first_seen), MAX(last_seen),
                   country, network_operator, owner_company
            FROM flows
            WHERE last_seen >= ? AND first_seen <= ?\(filter)
            GROUP BY \(grouping)
            ORDER BY \(ordering)
            LIMIT ?;
            """

        var rows: [HostDigest] = []
        try withStatement(sql) { statement in
            var index = bindWindow(statement, since: since, until: until)
            index = bindPattern(statement, from: index, matching: matching, count: 5)
            sqlite3_bind_int64(statement, index, Int64(limit))

            while sqlite3_step(statement) == SQLITE_ROW {
                rows.append(
                    HostDigest(
                        hostName: text(statement, 0),
                        remoteAddress: text(statement, 1) ?? "",
                        processName: text(statement, 2),
                        connectionCount: Int(sqlite3_column_int64(statement, 3)),
                        bytesOut: unsigned(statement, 4),
                        bytesIn: unsigned(statement, 5),
                        firstSeen: Date(timeIntervalSince1970: sqlite3_column_double(statement, 6)),
                        lastSeen: Date(timeIntervalSince1970: sqlite3_column_double(statement, 7)),
                        country: text(statement, 8),
                        networkOperator: text(statement, 9),
                        ownerCompany: text(statement, 10)
                    )
                )
            }
        }

        // The true group count, so a truncated answer can say what it truncated. Reporting
        // "showing 25" without "of 312" is the same ambiguity the history summary already
        // avoids by always naming the window it covers.
        let countSQL = """
            SELECT COUNT(*) FROM (
                SELECT 1 FROM flows
                WHERE last_seen >= ? AND first_seen <= ?\(filter)
                GROUP BY \(grouping)
            );
            """
        var total = 0
        try withStatement(countSQL) { statement in
            var index = bindWindow(statement, since: since, until: until)
            index = bindPattern(statement, from: index, matching: matching, count: 5)
            if sqlite3_step(statement) == SQLITE_ROW {
                total = Int(sqlite3_column_int64(statement, 0))
            }
        }

        return (rows, total)
    }

    // MARK: - Grouped by process, with a filter

    /// Per-process totals restricted to flows matching a term.
    ///
    /// `processTotals` reads the rollups, which are tiny and span a year but carry no host
    /// or address columns — so the moment a question has a "matching" in it, the answer has
    /// to come from the flow rows instead. Narrower window, but it can answer
    /// "which apps talked to Google".
    public func processTotalsMatching(
        _ matching: String,
        since: Date,
        until: Date = Date(),
        limit: Int = 25
    ) throws -> [ProcessTotal] {
        let sql = """
            SELECT IFNULL(process_path,'(unattributed)'), MAX(process_name),
                   SUM(bytes_out), SUM(bytes_in), COUNT(*)
            FROM flows
            WHERE last_seen >= ? AND first_seen <= ?
              AND (
                IFNULL(process_name,'') LIKE ?
                OR IFNULL(host_name,'') LIKE ?
                OR remote_address LIKE ?
                OR IFNULL(owner_company,'') LIKE ?
                OR IFNULL(network_operator,'') LIKE ?
              )
            GROUP BY process_path
            ORDER BY SUM(bytes_out) + SUM(bytes_in) DESC
            LIMIT ?;
            """

        var results: [ProcessTotal] = []
        try withStatement(sql) { statement in
            var index = bindWindow(statement, since: since, until: until)
            index = bindPattern(statement, from: index, matching: matching, count: 5)
            sqlite3_bind_int64(statement, index, Int64(limit))

            while sqlite3_step(statement) == SQLITE_ROW {
                let path = text(statement, 0) ?? "(unattributed)"
                results.append(
                    ProcessTotal(
                        processName: text(statement, 1) ?? path,
                        processPath: path,
                        bytesOut: unsigned(statement, 2),
                        bytesIn: unsigned(statement, 3),
                        flowCount: Int(sqlite3_column_int64(statement, 4))
                    )
                )
            }
        }
        return results
    }

    // MARK: - One endpoint, whole history

    /// Everything recorded about one host, address, company or network.
    ///
    /// The question this exists for — "have I ever contacted this?" — cannot be answered by
    /// `flows(matching:limit:)` at all. That returns the heaviest rows, so the earliest one
    /// it hands back is whichever *large* connection happened to be oldest, not the first
    /// contact; and for a busy endpoint the rows are truncated long before the beginning of
    /// the history is reached. First contact needs `MIN` over everything, not a page of rows.
    public func endpointHistory(
        endpoint: String,
        since: Date? = nil,
        until: Date = Date()
    ) throws -> EndpointHistory {
        // Exact first, so the indexes on remote_address and host_name are used and a
        // search for "10.0.0.1" cannot drag in "10.0.0.100". Substring only as a fallback,
        // which is also what makes a domain suffix like "slack.com" work.
        let exact = "(remote_address = ? OR IFNULL(host_name,'') = ?)"
        let loose = """
            (IFNULL(host_name,'') LIKE ? OR remote_address LIKE ?
             OR IFNULL(owner_company,'') LIKE ? OR IFNULL(network_operator,'') LIKE ?)
            """

        let window =
            since == nil ? "" : " AND last_seen >= ? AND first_seen <= ?"

        func bindWhere(_ statement: OpaquePointer?, exactMatch: Bool) -> Int32 {
            var index: Int32 = 1
            if exactMatch {
                bindText(statement, index, endpoint)
                index += 1
                bindText(statement, index, endpoint)
                index += 1
            } else {
                let pattern = "%\(endpoint)%"
                for _ in 0..<4 {
                    bindText(statement, index, pattern)
                    index += 1
                }
            }
            if let since {
                sqlite3_bind_double(statement, index, since.timeIntervalSince1970)
                index += 1
                sqlite3_bind_double(statement, index, until.timeIntervalSince1970)
                index += 1
            }
            return index
        }

        func totals(exactMatch: Bool) throws -> (Int, UInt64, UInt64, Date?, Date?) {
            let sql = """
                SELECT COUNT(*), SUM(bytes_out), SUM(bytes_in), MIN(first_seen), MAX(last_seen)
                FROM flows WHERE \(exactMatch ? exact : loose)\(window);
                """
            var result: (Int, UInt64, UInt64, Date?, Date?) = (0, 0, 0, nil, nil)
            try withStatement(sql) { statement in
                _ = bindWhere(statement, exactMatch: exactMatch)
                guard sqlite3_step(statement) == SQLITE_ROW else { return }
                let count = Int(sqlite3_column_int64(statement, 0))
                guard count > 0 else { return }
                result = (
                    count, unsigned(statement, 1), unsigned(statement, 2),
                    Date(timeIntervalSince1970: sqlite3_column_double(statement, 3)),
                    Date(timeIntervalSince1970: sqlite3_column_double(statement, 4))
                )
            }
            return result
        }

        var exactMatch = true
        var summary = try totals(exactMatch: true)
        if summary.0 == 0 {
            exactMatch = false
            summary = try totals(exactMatch: false)
        }

        guard summary.0 > 0 else {
            return EndpointHistory(
                matched: false, matchedExactly: false, hostNames: [], addresses: [],
                connectionCount: 0, bytesOut: 0, bytesIn: 0, firstSeen: nil, lastSeen: nil,
                processes: [], countries: [], networkOperators: [], ownerCompanies: [],
                byDay: []
            )
        }

        let predicate = exactMatch ? exact : loose

        func distinct(_ column: String, limit: Int) throws -> [String] {
            var values: [String] = []
            let sql = """
                SELECT DISTINCT \(column) FROM flows
                WHERE \(predicate)\(window) AND \(column) IS NOT NULL AND \(column) != ''
                LIMIT \(limit);
                """
            try withStatement(sql) { statement in
                _ = bindWhere(statement, exactMatch: exactMatch)
                while sqlite3_step(statement) == SQLITE_ROW {
                    if let value = text(statement, 0) { values.append(value) }
                }
            }
            return values
        }

        var processes: [EndpointHistory.ProcessShare] = []
        try withStatement(
            """
            SELECT IFNULL(process_name,'(unattributed)'), COUNT(*), SUM(bytes_out), SUM(bytes_in)
            FROM flows WHERE \(predicate)\(window)
            GROUP BY process_name ORDER BY COUNT(*) DESC LIMIT 10;
            """
        ) { statement in
            _ = bindWhere(statement, exactMatch: exactMatch)
            while sqlite3_step(statement) == SQLITE_ROW {
                processes.append(
                    EndpointHistory.ProcessShare(
                        processName: text(statement, 0) ?? "(unattributed)",
                        connectionCount: Int(sqlite3_column_int64(statement, 1)),
                        bytesOut: unsigned(statement, 2),
                        bytesIn: unsigned(statement, 3)
                    )
                )
            }
        }

        var byDay: [EndpointHistory.Day] = []
        try withStatement(
            """
            SELECT date(last_seen, 'unixepoch', 'localtime') AS d, COUNT(*),
                   SUM(bytes_out + bytes_in)
            FROM flows WHERE \(predicate)\(window)
            GROUP BY d ORDER BY d DESC LIMIT 30;
            """
        ) { statement in
            _ = bindWhere(statement, exactMatch: exactMatch)
            while sqlite3_step(statement) == SQLITE_ROW {
                byDay.append(
                    EndpointHistory.Day(
                        day: text(statement, 0) ?? "",
                        connectionCount: Int(sqlite3_column_int64(statement, 1)),
                        bytes: unsigned(statement, 2)
                    )
                )
            }
        }

        return EndpointHistory(
            matched: true,
            matchedExactly: exactMatch,
            hostNames: try distinct("host_name", limit: 20),
            addresses: try distinct("remote_address", limit: 20),
            connectionCount: summary.0,
            bytesOut: summary.1,
            bytesIn: summary.2,
            firstSeen: summary.3,
            lastSeen: summary.4,
            processes: processes,
            countries: try distinct("country", limit: 10),
            networkOperators: try distinct("network_operator", limit: 10),
            ownerCompanies: try distinct("owner_company", limit: 10),
            byDay: byDay
        )
    }

    // MARK: - Attribution caveat

    /// Per-process flow shares over a window, counting only the flows a transparent proxy
    /// would plausibly be carrying on somebody's behalf.
    ///
    /// This exists because `ProxyDetection.findLikelyProxies` takes `[Flow]` and runs
    /// against the live table only — the `flows` table has no column recording that a
    /// warning was raised, so a historical answer would otherwise present the proxy as the
    /// application and be confidently wrong in a way the reader cannot detect.
    ///
    /// The infrastructure ports are excluded here for the same reason they are excluded
    /// there: `mDNSResponder` talks to every resolver on the network and can easily own a
    /// third of all flows without carrying anyone's payload. That false positive was
    /// already found and fixed once; re-deriving the share without it would reintroduce it.
    public func proxyCandidates(since: Date, until: Date = Date()) throws -> (
        candidates: [ProxyCandidate], totalFlows: Int
    ) {
        let excluded = ProxyDetection.infrastructurePorts.map(String.init).joined(separator: ",")
        let eligible = """
            FROM flows
            WHERE last_seen >= ? AND first_seen <= ?
              AND process_path IS NOT NULL AND process_path != ''
              AND remote_port NOT IN (\(excluded))
            """

        var total = 0
        try withStatement("SELECT COUNT(*) \(eligible);") { statement in
            _ = bindWindow(statement, since: since, until: until)
            if sqlite3_step(statement) == SQLITE_ROW {
                total = Int(sqlite3_column_int64(statement, 0))
            }
        }
        guard total >= 20 else { return ([], total) }

        var candidates: [ProxyCandidate] = []
        try withStatement(
            """
            SELECT process_path, MAX(process_name), COUNT(*), COUNT(DISTINCT remote_address)
            \(eligible)
            GROUP BY process_path ORDER BY COUNT(*) DESC LIMIT 5;
            """
        ) { statement in
            _ = bindWindow(statement, since: since, until: until)
            while sqlite3_step(statement) == SQLITE_ROW {
                let path = text(statement, 0) ?? ""
                candidates.append(
                    ProxyCandidate(
                        processName: text(statement, 1) ?? path,
                        processPath: path,
                        flowCount: Int(sqlite3_column_int64(statement, 2)),
                        distinctRemoteHosts: Int(sqlite3_column_int64(statement, 3))
                    )
                )
            }
        }
        return (candidates, total)
    }

    /// The sentence to attach to a historical answer, or nil when nothing looks like a proxy.
    ///
    /// Applies `ProxyDetection`'s own thresholds and its system-extension test rather than
    /// a fresh guess, so the live view and the historical view agree about what counts.
    public func proxyCaveat(since: Date, until: Date = Date()) throws -> String? {
        let (candidates, total) = try proxyCandidates(since: since, until: until)
        guard total > 0 else { return nil }

        for candidate in candidates {
            guard ProxyDetection.looksLikeSystemExtension(candidate.processPath) else { continue }
            let share = Double(candidate.flowCount) / Double(total)
            guard share >= ProxyDetection.flowShareThreshold,
                candidate.distinctRemoteHosts >= ProxyDetection.distinctHostThreshold
            else { continue }

            return """
                \(candidate.processName) owns \(Int(share * 100))% of the connections in this \
                window, reaching \(candidate.distinctRemoteHosts) different hosts, and runs as a \
                system extension or privileged helper. It is almost certainly a transparent proxy \
                re-originating other applications' connections, which means rows attributed to it \
                were probably made by some other application that cannot be recovered from \
                captured packets.
                """
        }
        return nil
    }

    // MARK: - Counting

    /// The public way to ask, and the reason `count(of:)` is not itself public: a caller
    /// outside Core gets the question it actually has, with no table name to supply.
    public func flowRowCount() throws -> Int {
        try count(of: .flows)
    }

    // MARK: - Shared plumbing

    /// Prepares, runs and finalizes a statement. Every query above needs the same
    /// prepare-guard-defer-finalize preamble, and writing it out five more times is five
    /// more chances to forget the `sqlite3_finalize`.
    func withStatement(_ sql: String, _ body: (OpaquePointer?) throws -> Void) throws {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(rawHandle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(lastErrorMessage)
        }
        defer { sqlite3_finalize(statement) }
        try body(statement)
    }

    func bindWindow(_ statement: OpaquePointer?, since: Date, until: Date) -> Int32 {
        sqlite3_bind_double(statement, 1, since.timeIntervalSince1970)
        sqlite3_bind_double(statement, 2, until.timeIntervalSince1970)
        return 3
    }

    func bindPattern(
        _ statement: OpaquePointer?, from index: Int32, matching: String?, count: Int
    ) -> Int32 {
        guard let matching else { return index }
        var next = index
        let pattern = "%\(matching)%"
        for _ in 0..<count {
            bindText(statement, next, pattern)
            next += 1
        }
        return next
    }

    /// SQLITE_TRANSIENT: sqlite copies the bytes, so the Swift string need not outlive
    /// the call. Spelled out because the constant is a cast of -1 that Swift cannot import.
    func bindText(_ statement: OpaquePointer?, _ index: Int32, _ value: String) {
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(statement, index, value, -1, transient)
    }

    func text(_ statement: OpaquePointer?, _ column: Int32) -> String? {
        guard let pointer = sqlite3_column_text(statement, column) else { return nil }
        return String(cString: pointer)
    }

    /// Byte counts are stored as signed integers and read back as unsigned. Clamping at
    /// zero rather than truncating, so a corrupt negative can never wrap to an enormous
    /// total that looks like a real finding.
    func unsigned(_ statement: OpaquePointer?, _ column: Int32) -> UInt64 {
        UInt64(max(0, sqlite3_column_int64(statement, column)))
    }

    /// A measurement column, where NULL means nothing measured it. Distinct from zero, and
    /// the whole quality feature turns on that distinction, so it is never defaulted here.
    func optionalDouble(_ statement: OpaquePointer?, _ column: Int32) -> Double? {
        sqlite3_column_type(statement, column) == SQLITE_NULL
            ? nil : sqlite3_column_double(statement, column)
    }
}
