import CBeholderShim
import Foundation

/// Persists retired flows so the picture survives the daemon stopping.
///
/// Everything above this is live-only: close the daemon and the table is gone. That makes
/// Beholder a thing you run to look at, rather than a thing that watched while you were
/// not looking — and the second is what answers "what did this app do last Tuesday" or
/// "have I ever talked to this host before".
///
/// Two tables. `flows` keeps one row per completed conversation, which is the detail.
/// `rollups` keeps per-minute totals per process, which is what a chart spanning weeks
/// needs — querying millions of flow rows to draw a month of history would not do.
///
/// Not thread-safe; confine to one queue. SQLite is opened in WAL mode so a reader (the
/// query commands) never blocks the writer (the daemon).
public final class FlowStore {

    public enum StoreError: Error, CustomStringConvertible {
        case cannotOpen(path: String, message: String)
        case migrationFailed(String)
        case statementFailed(String)

        public var description: String {
            switch self {
            case .cannotOpen(let path, let message):
                return "cannot open the flow database at \(path): \(message)"
            case .migrationFailed(let message):
                return "cannot prepare the flow database: \(message)"
            case .statementFailed(let message):
                return "database error: \(message)"
            }
        }
    }

    public struct Retention: Sendable {
        /// Individual flows are the bulky part, so they are kept for weeks rather than
        /// forever. Rollups are tiny and keep the long view.
        public var flowDays = 30
        public var rollupDays = 365
        public init() {}
    }

    private var handle: OpaquePointer?
    public let path: String
    public var retention = Retention()

    public private(set) var flowsWritten: UInt64 = 0
    public private(set) var flowsPruned: UInt64 = 0

    /// Where the database lives by default. Resolved centrally so the daemon and the
    /// query commands cannot disagree about it — see BeholderPaths.
    public static func defaultPath() -> String {
        BeholderPaths.historyDatabase()
    }

    public init(path: String) throws {
        self.path = path
        try FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )

        var database: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(path, &database, flags, nil) == SQLITE_OK, let database else {
            let message = database.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(database)
            throw StoreError.cannotOpen(path: path, message: message)
        }
        self.handle = database

        // The file lists everywhere this machine has been, so it gets the same treatment
        // as the transcript and the socket: owner-only, and owned by the real user rather
        // than root.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: path
        )
        Self.giveToInvokingUser(path)
        Self.giveToInvokingUser((path as NSString).deletingLastPathComponent)

        try migrate()
    }

    deinit {
        if let handle { sqlite3_close(handle) }
    }

    public func close() {
        if let handle { sqlite3_close(handle) }
        handle = nil
    }

    // MARK: - Schema

    private func migrate() throws {
        // WAL so a query never blocks capture; NORMAL synchronous because losing the last
        // few seconds of history to a power cut is not worth an fsync per transaction.
        let statements = [
            "PRAGMA journal_mode = WAL;",
            "PRAGMA synchronous = NORMAL;",
            """
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                transport TEXT NOT NULL,
                local_address TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_address TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                host_name TEXT,
                host_name_source TEXT,
                process_name TEXT,
                process_path TEXT,
                pid INTEGER,
                bytes_out INTEGER NOT NULL,
                bytes_in INTEGER NOT NULL,
                packets_out INTEGER NOT NULL,
                packets_in INTEGER NOT NULL,
                direction TEXT NOT NULL,
                country TEXT,
                city TEXT,
                network_operator TEXT,
                owner_company TEXT,
                interface TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS flows_last_seen ON flows(last_seen);",
            "CREATE INDEX IF NOT EXISTS flows_process ON flows(process_path);",
            "CREATE INDEX IF NOT EXISTS flows_remote ON flows(remote_address);",
            "CREATE INDEX IF NOT EXISTS flows_host ON flows(host_name);",
            """
            CREATE TABLE IF NOT EXISTS rollups (
                minute INTEGER NOT NULL,
                process_path TEXT NOT NULL,
                process_name TEXT,
                bytes_out INTEGER NOT NULL,
                bytes_in INTEGER NOT NULL,
                flow_count INTEGER NOT NULL,
                PRIMARY KEY (minute, process_path)
            );
            """,
            "CREATE INDEX IF NOT EXISTS rollups_minute ON rollups(minute);",
        ]

        for statement in statements {
            guard sqlite3_exec(handle, statement, nil, nil, nil) == SQLITE_OK else {
                throw StoreError.migrationFailed(errorMessage)
            }
        }
    }

    private var errorMessage: String { lastErrorMessage }

    /// Exposed to the query extension, which lives in another file.
    var rawHandle: OpaquePointer? { handle }
    var lastErrorMessage: String {
        handle.map { String(cString: sqlite3_errmsg($0)) } ?? "no database"
    }

    // MARK: - Writing

    /// Records a batch of retired flows. Batched into one transaction because a busy
    /// machine retires flows in bursts and a commit per row would dominate the cost.
    @discardableResult
    public func record(_ flows: [Flow]) throws -> Int {
        guard !flows.isEmpty, handle != nil else { return 0 }

        try execute("BEGIN IMMEDIATE;")
        do {
            try insertFlows(flows)
            try updateRollups(flows)
            try execute("COMMIT;")
        } catch {
            try? execute("ROLLBACK;")
            throw error
        }
        flowsWritten += UInt64(flows.count)
        return flows.count
    }

    private func insertFlows(_ flows: [Flow]) throws {
        let sql = """
            INSERT INTO flows (
                first_seen, last_seen, transport, local_address, local_port,
                remote_address, remote_port, host_name, host_name_source,
                process_name, process_path, pid, bytes_out, bytes_in,
                packets_out, packets_in, direction, country, city,
                network_operator, owner_company, interface
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(errorMessage)
        }
        defer { sqlite3_finalize(statement) }

        for flow in flows {
            sqlite3_reset(statement)
            sqlite3_clear_bindings(statement)

            var index: Int32 = 1
            func bind(_ value: Double) { sqlite3_bind_double(statement, index, value); index += 1 }
            func bind(_ value: Int64) { sqlite3_bind_int64(statement, index, value); index += 1 }
            func bind(_ value: String?) {
                if let value {
                    // SQLITE_TRANSIENT: SQLite copies the bytes, which it must, because
                    // the Swift string may be gone before the statement runs.
                    sqlite3_bind_text(statement, index, value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
                } else {
                    sqlite3_bind_null(statement, index)
                }
                index += 1
            }

            bind(flow.firstSeen.timeIntervalSince1970)
            bind(flow.lastSeen.timeIntervalSince1970)
            bind(flow.key.transport.name)
            bind(flow.key.local.description)
            bind(Int64(flow.key.localPort))
            bind(flow.key.remote.description)
            bind(Int64(flow.key.remotePort))
            bind(flow.hostName)
            bind(flow.hostNameSource?.rawValue)
            bind(flow.owner?.name)
            bind(flow.owner?.path)
            if let pid = flow.owner?.pid {
                sqlite3_bind_int64(statement, index, Int64(pid))
            } else {
                sqlite3_bind_null(statement, index)
            }
            index += 1
            bind(Int64(flow.bytesOut))
            bind(Int64(flow.bytesIn))
            bind(Int64(flow.packetsOut))
            bind(Int64(flow.packetsIn))
            bind(String(describing: flow.direction))
            bind(flow.location?.countryCode)
            bind(flow.location?.city)
            bind(flow.networkOperator?.organization)
            bind(flow.classification?.owner)
            bind(flow.interfaceName)

            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw StoreError.statementFailed(errorMessage)
            }
        }
    }

    /// Per-minute totals per process. Upserted, since a minute accumulates as flows in it
    /// retire at different times.
    private func updateRollups(_ flows: [Flow]) throws {
        let sql = """
            INSERT INTO rollups (minute, process_path, process_name, bytes_out, bytes_in, flow_count)
            VALUES (?,?,?,?,?,1)
            ON CONFLICT(minute, process_path) DO UPDATE SET
                bytes_out = bytes_out + excluded.bytes_out,
                bytes_in = bytes_in + excluded.bytes_in,
                flow_count = flow_count + 1;
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(errorMessage)
        }
        defer { sqlite3_finalize(statement) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for flow in flows {
            sqlite3_reset(statement)
            sqlite3_clear_bindings(statement)

            let minute = Int64(flow.lastSeen.timeIntervalSince1970 / 60)
            sqlite3_bind_int64(statement, 1, minute)
            // Flows with no identified owner are still recorded, under a stable label
            // rather than being dropped from the totals.
            sqlite3_bind_text(statement, 2, flow.owner?.path ?? "(unattributed)", -1, transient)
            sqlite3_bind_text(statement, 3, flow.owner?.name ?? "(unattributed)", -1, transient)
            sqlite3_bind_int64(statement, 4, Int64(flow.bytesOut))
            sqlite3_bind_int64(statement, 5, Int64(flow.bytesIn))

            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw StoreError.statementFailed(errorMessage)
            }
        }
    }

    // MARK: - Retention

    /// Deletes what is past its keep-by date. Returns how many flow rows went.
    @discardableResult
    public func prune(now: Date = Date()) throws -> Int {
        let flowCutoff = now.addingTimeInterval(-Double(retention.flowDays) * 86400)
            .timeIntervalSince1970
        let rollupCutoff = Int64(
            now.addingTimeInterval(-Double(retention.rollupDays) * 86400)
                .timeIntervalSince1970 / 60
        )

        let before = try count(of: "flows")
        try execute("DELETE FROM flows WHERE last_seen < \(flowCutoff);")
        try execute("DELETE FROM rollups WHERE minute < \(rollupCutoff);")
        let removed = before - (try count(of: "flows"))
        flowsPruned += UInt64(max(0, removed))
        return max(0, removed)
    }

    public func count(of table: String) throws -> Int {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM \(table);", -1, &statement, nil)
            == SQLITE_OK
        else { throw StoreError.statementFailed(errorMessage) }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private func execute(_ sql: String) throws {
        guard sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK else {
            throw StoreError.statementFailed(errorMessage)
        }
    }

    private static func giveToInvokingUser(_ path: String) {
        let environment = ProcessInfo.processInfo.environment
        guard
            let uidText = environment["SUDO_UID"], let uid = uid_t(uidText),
            let gidText = environment["SUDO_GID"], let gid = gid_t(gidText)
        else { return }
        chown(path, uid, gid)
    }
}
