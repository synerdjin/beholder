import CBeholderShim
import Foundation

/// One historical conversation, read back out.
public struct HistoricalFlow: Sendable, Equatable {
    public let firstSeen: Date
    public let lastSeen: Date
    public let transport: String
    public let remoteAddress: String
    public let remotePort: UInt16
    public let hostName: String?
    public let processName: String?
    public let bytesOut: UInt64
    public let bytesIn: UInt64
    public let country: String?
    public let networkOperator: String?
    public let ownerCompany: String?

    public var totalBytes: UInt64 { bytesOut + bytesIn }

    /// The best label available for the far end, in the same order of preference the live
    /// view uses: a name if known, otherwise the operator, otherwise the address.
    public var remoteDescription: String {
        hostName ?? networkOperator ?? remoteAddress
    }
}

/// Per-process totals over a window.
public struct ProcessTotal: Sendable, Equatable {
    public let processName: String
    public let processPath: String
    public let bytesOut: UInt64
    public let bytesIn: UInt64
    public let flowCount: Int

    public var totalBytes: UInt64 { bytesOut + bytesIn }
}

extension FlowStore {

    /// Flows active within a window, heaviest first.
    ///
    /// `matching` filters on process name, hostname, address, company or network — the
    /// same fields the live view searches, so a query learned in one place works in the
    /// other.
    public func flows(
        since: Date,
        until: Date = Date(),
        matching: String? = nil,
        limit: Int = 500
    ) throws -> [HistoricalFlow] {
        var sql = """
            SELECT first_seen, last_seen, transport, remote_address, remote_port,
                   host_name, process_name, bytes_out, bytes_in, country,
                   network_operator, owner_company
            FROM flows
            WHERE last_seen >= ? AND first_seen <= ?
            """
        if matching != nil {
            sql += """
                 AND (
                    IFNULL(process_name,'') LIKE ?
                    OR IFNULL(host_name,'') LIKE ?
                    OR remote_address LIKE ?
                    OR IFNULL(owner_company,'') LIKE ?
                    OR IFNULL(network_operator,'') LIKE ?
                 )
                """
        }
        sql += " ORDER BY (bytes_out + bytes_in) DESC LIMIT ?;"

        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(rawHandle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(lastErrorMessage)
        }
        defer { sqlite3_finalize(statement) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        var index: Int32 = 1
        sqlite3_bind_double(statement, index, since.timeIntervalSince1970)
        index += 1
        sqlite3_bind_double(statement, index, until.timeIntervalSince1970)
        index += 1
        if let matching {
            let pattern = "%\(matching)%"
            for _ in 0..<5 {
                sqlite3_bind_text(statement, index, pattern, -1, transient)
                index += 1
            }
        }
        sqlite3_bind_int64(statement, index, Int64(limit))

        var results: [HistoricalFlow] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            results.append(
                HistoricalFlow(
                    firstSeen: Date(timeIntervalSince1970: sqlite3_column_double(statement, 0)),
                    lastSeen: Date(timeIntervalSince1970: sqlite3_column_double(statement, 1)),
                    transport: text(statement, 2) ?? "",
                    remoteAddress: text(statement, 3) ?? "",
                    remotePort: UInt16(truncatingIfNeeded: sqlite3_column_int64(statement, 4)),
                    hostName: text(statement, 5),
                    processName: text(statement, 6),
                    bytesOut: UInt64(max(0, sqlite3_column_int64(statement, 7))),
                    bytesIn: UInt64(max(0, sqlite3_column_int64(statement, 8))),
                    country: text(statement, 9),
                    networkOperator: text(statement, 10),
                    ownerCompany: text(statement, 11)
                )
            )
        }
        return results
    }

    /// Per-process totals over a window, from the rollups.
    ///
    /// Reads rollups rather than summing flows because this is what a chart spanning
    /// weeks asks for, and scanning millions of flow rows to draw it would not do.
    public func processTotals(since: Date, until: Date = Date()) throws -> [ProcessTotal] {
        let sql = """
            SELECT process_path, MAX(process_name), SUM(bytes_out), SUM(bytes_in), SUM(flow_count)
            FROM rollups
            WHERE minute >= ? AND minute <= ?
            GROUP BY process_path
            ORDER BY SUM(bytes_out) + SUM(bytes_in) DESC;
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(rawHandle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(lastErrorMessage)
        }
        defer { sqlite3_finalize(statement) }

        sqlite3_bind_int64(statement, 1, Int64(since.timeIntervalSince1970 / 60))
        sqlite3_bind_int64(statement, 2, Int64(until.timeIntervalSince1970 / 60))

        var results: [ProcessTotal] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            let path = text(statement, 0) ?? "(unattributed)"
            results.append(
                ProcessTotal(
                    processName: text(statement, 1) ?? path,
                    processPath: path,
                    bytesOut: UInt64(max(0, sqlite3_column_int64(statement, 2))),
                    bytesIn: UInt64(max(0, sqlite3_column_int64(statement, 3))),
                    flowCount: Int(sqlite3_column_int64(statement, 4))
                )
            )
        }
        return results
    }

    /// The window the database actually covers, which is what tells a reader whether an
    /// empty result means "nothing happened" or "nothing was recorded then".
    public func coverage() throws -> (earliest: Date, latest: Date)? {
        var statement: OpaquePointer?
        let sql = "SELECT MIN(first_seen), MAX(last_seen) FROM flows;"
        guard sqlite3_prepare_v2(rawHandle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(lastErrorMessage)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW,
            sqlite3_column_type(statement, 0) != SQLITE_NULL
        else { return nil }

        return (
            Date(timeIntervalSince1970: sqlite3_column_double(statement, 0)),
            Date(timeIntervalSince1970: sqlite3_column_double(statement, 1))
        )
    }

    private func text(_ statement: OpaquePointer?, _ column: Int32) -> String? {
        guard let pointer = sqlite3_column_text(statement, column) else { return nil }
        return String(cString: pointer)
    }
}
