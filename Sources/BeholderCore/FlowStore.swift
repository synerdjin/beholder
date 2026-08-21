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
        case schemaTooNew(found: Int32, supported: Int32)

        public var description: String {
            switch self {
            case .cannotOpen(let path, let message):
                return "cannot open the flow database at \(path): \(message)"
            case .migrationFailed(let message):
                return "cannot prepare the flow database: \(message)"
            case .statementFailed(let message):
                return "database error: \(message)"
            case .schemaTooNew(let found, let supported):
                return """
                    the history database was written by a newer Beholder (schema \(found), \
                    this build understands \(supported)). Update Beholder, or move the \
                    database aside to start a new one.
                    """
            }
        }
    }

    public struct Retention: Sendable {
        /// Individual flows are the bulky part, so they are kept for weeks rather than
        /// forever. Rollups are tiny and keep the long view.
        public var flowDays = 30
        public var rollupDays = 365
        /// Per-minute quality is the bulky part of the time series, so it keeps the same
        /// window as individual flows. Older minutes are folded into hours before being
        /// deleted, which is what keeps a year of trend available without a year of rows.
        public var qualityMinuteDays = 30
        public var qualityHourDays = 365
        public var probeDays = 90
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

    /// Opens the database.
    ///
    /// `readOnly` is what a viewer wants: it neither creates the file nor runs a
    /// migration, so an app looking at history can never alter what the daemon recorded,
    /// and opening a database that does not exist fails plainly instead of silently
    /// creating an empty one that looks like a run with no traffic.
    public init(path: String, readOnly: Bool = false) throws {
        self.path = path
        if !readOnly {
            try FileManager.default.createDirectory(
                atPath: (path as NSString).deletingLastPathComponent,
                withIntermediateDirectories: true
            )
        }

        var database: OpaquePointer?
        let flags =
            readOnly
            ? SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(path, &database, flags, nil) == SQLITE_OK, let database else {
            let message = database.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(database)
            throw StoreError.cannotOpen(path: path, message: message)
        }
        self.handle = database

        guard !readOnly else { return }

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

    /// The schema version this build understands, which is the last entry in `migrations`.
    public static let schemaVersion: Int32 = 2

    /// Ordered and append-only.
    ///
    /// Each step runs exactly once, inside a transaction that also bumps `user_version`,
    /// so an interrupted upgrade leaves the database at the last version that completed
    /// rather than part-way through one.
    ///
    /// Never edit a shipped step. A database in the field has already run it, so an edit
    /// only ever reaches new databases — which quietly gives two files the same version
    /// number and different shapes, the worst outcome available here. Append instead.
    ///
    /// Step 1 is the original schema verbatim. Databases written before versioning report
    /// version 0 but already have these tables, so `IF NOT EXISTS` makes the step a no-op
    /// for them and they adopt version 1 with nothing touched.
    private static let migrations: [(version: Int32, statements: [String])] = [
        (
            1,
            [
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
        ),
        (
            2,
            [
                """
                CREATE TABLE IF NOT EXISTS quality_minutes (
                    minute INTEGER NOT NULL,
                    interface TEXT NOT NULL,
                    destination_group TEXT NOT NULL,
                    destination_label TEXT,
                    rtt_samples INTEGER NOT NULL,
                    rtt_min_ms REAL,
                    rtt_p50_ms REAL,
                    rtt_p95_ms REAL,
                    handshake_samples INTEGER NOT NULL,
                    handshake_min_ms REAL,
                    segments_out INTEGER NOT NULL,
                    segments_in INTEGER NOT NULL,
                    retransmits_out INTEGER NOT NULL,
                    retransmits_in INTEGER NOT NULL,
                    bytes_out INTEGER NOT NULL,
                    bytes_in INTEGER NOT NULL,
                    measured_bytes INTEGER NOT NULL,
                    unmeasurable_bytes INTEGER NOT NULL,
                    flow_count INTEGER NOT NULL,
                    connection_attempts INTEGER NOT NULL,
                    connection_timeouts INTEGER NOT NULL,
                    PRIMARY KEY (minute, interface, destination_group)
                );
                """,
                "CREATE INDEX IF NOT EXISTS quality_minutes_minute ON quality_minutes(minute);",
                """
                CREATE TABLE IF NOT EXISTS quality_hours (
                    hour INTEGER NOT NULL,
                    interface TEXT NOT NULL,
                    destination_group TEXT NOT NULL,
                    destination_label TEXT,
                    rtt_samples INTEGER NOT NULL,
                    rtt_min_ms REAL,
                    segments_out INTEGER NOT NULL,
                    segments_in INTEGER NOT NULL,
                    retransmits_out INTEGER NOT NULL,
                    retransmits_in INTEGER NOT NULL,
                    bytes_out INTEGER NOT NULL,
                    bytes_in INTEGER NOT NULL,
                    measured_bytes INTEGER NOT NULL,
                    unmeasurable_bytes INTEGER NOT NULL,
                    connection_attempts INTEGER NOT NULL,
                    connection_timeouts INTEGER NOT NULL,
                    PRIMARY KEY (hour, interface, destination_group)
                );
                """,
                "CREATE INDEX IF NOT EXISTS quality_hours_hour ON quality_hours(hour);",
                """
                CREATE TABLE IF NOT EXISTS quality_probes (
                    at REAL NOT NULL,
                    interface TEXT NOT NULL,
                    target TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    rtt_ms REAL,
                    PRIMARY KEY (at, target)
                );
                """,
                "CREATE INDEX IF NOT EXISTS quality_probes_at ON quality_probes(at);",
            ]
        ),
    ]

    private func migrate() throws {
        // WAL so a query never blocks capture; NORMAL synchronous because losing the last
        // few seconds of history to a power cut is not worth an fsync per transaction.
        // Both are properties of the connection rather than of the schema, so they are set
        // on every open instead of inside a versioned step. WAL in particular cannot run
        // inside a transaction, which is the other reason it stays out here.
        try execute("PRAGMA journal_mode = WAL;")
        try execute("PRAGMA synchronous = NORMAL;")

        let current = try userVersion()

        // A database from a newer Beholder may carry tables and columns this build knows
        // nothing about. Reading it would mostly work, which is exactly the problem: the
        // failure would surface as quietly absent data rather than as an error. Refuse it,
        // for the same reason WireProtocol.version refuses a snapshot it cannot decode.
        guard current <= Self.schemaVersion else {
            throw StoreError.schemaTooNew(found: current, supported: Self.schemaVersion)
        }

        for step in Self.migrations where step.version > current {
            try execute("BEGIN IMMEDIATE;")
            do {
                for statement in step.statements {
                    guard sqlite3_exec(handle, statement, nil, nil, nil) == SQLITE_OK else {
                        throw StoreError.migrationFailed(errorMessage)
                    }
                }
                // Interpolated rather than bound because PRAGMA takes no parameters. The
                // value is one of our own literals above and never comes from input.
                try execute("PRAGMA user_version = \(step.version);")
                try execute("COMMIT;")
            } catch {
                try? execute("ROLLBACK;")
                throw error
            }
        }
    }

    /// The database's schema version. Zero for a database created before versioning, and
    /// also zero for a brand-new empty one — the two are indistinguishable here and do not
    /// need to be told apart, since step 1 is a no-op against an existing schema.
    func userVersion() throws -> Int32 {
        var statement: OpaquePointer?
        guard
            sqlite3_prepare_v2(handle, "PRAGMA user_version;", -1, &statement, nil) == SQLITE_OK
        else {
            throw StoreError.migrationFailed(errorMessage)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw StoreError.migrationFailed(errorMessage)
        }
        return sqlite3_column_int(statement, 0)
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

    /// Internal rather than private because `FlowStoreQuality` runs the same statements
    /// against the same handle, and had copied this verbatim to reach it.
    func execute(_ sql: String) throws {
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
