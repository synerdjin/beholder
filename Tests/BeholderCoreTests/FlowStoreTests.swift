import CBeholderShim
import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!
private let server = IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!

private func makeFlow(
    localPort: UInt16 = 51234,
    remotePort: UInt16 = 443,
    host: String? = nil,
    process: String? = "Safari",
    processPath: String = "/Applications/Safari.app/Safari",
    bytesOut: UInt64 = 1000,
    bytesIn: UInt64 = 5000,
    at timestamp: Date = Date()
) -> Flow {
    var flow = Flow(
        key: FlowKey(
            transport: .tcp, local: laptop, localPort: localPort,
            remote: server, remotePort: remotePort
        ),
        interfaceName: "utun8",
        at: timestamp
    )
    flow.bytesOut = bytesOut
    flow.bytesIn = bytesIn
    flow.packetsOut = 10
    flow.packetsIn = 20
    flow.lastSeen = timestamp
    flow.hostName = host
    if host != nil { flow.hostNameSource = .dns }
    if let process {
        flow.owner = ProcessOwner(pid: 100, path: processPath)
        _ = process
    }
    flow.location = GeoLocation(
        countryCode: "US", countryName: "United States", city: "Ashburn",
        latitude: 39.0, longitude: -77.5
    )
    flow.networkOperator = NetworkOperator(number: 15169, organization: "GOOGLE")
    flow.classification = HostClassification(owner: "Google", categories: ["Analytics"])
    return flow
}

/// A store in a fresh temporary directory, removed afterwards.
private func withStore(_ body: (FlowStore) throws -> Void) throws {
    let directory = NSTemporaryDirectory() + "beholder-test-\(UUID().uuidString)"
    let path = directory + "/history.sqlite"
    defer { try? FileManager.default.removeItem(atPath: directory) }

    let store = try FlowStore(path: path)
    defer { store.close() }
    try body(store)
}

@Suite("Flow history")
struct FlowStoreTests {

    @Test("A store is created with its schema")
    func createsSchema() throws {
        try withStore { store in
            let flowCount = try store.count(of: "flows")
            let rollupCount = try store.count(of: "rollups")
            #expect(flowCount == 0)
            #expect(rollupCount == 0)
        }
    }

    @Test("Flows are written and read back")
    func roundTrip() throws {
        try withStore { store in
            let now = Date()
            try store.record([
                makeFlow(localPort: 1000, host: "example.com", bytesOut: 100, bytesIn: 900, at: now),
                makeFlow(localPort: 1001, host: "other.com", bytesOut: 50, bytesIn: 50, at: now),
            ])
            let written = try store.count(of: "flows")
            #expect(written == 2)

            let results = try store.flows(since: now.addingTimeInterval(-60))
            #expect(results.count == 2)

            // Heaviest first, so the interesting row is at the top.
            let first = try #require(results.first)
            #expect(first.hostName == "example.com")
            #expect(first.totalBytes == 1000)
            #expect(first.country == "US")
            #expect(first.networkOperator == "GOOGLE")
            #expect(first.ownerCompany == "Google")
        }
    }

    @Test("A window excludes flows outside it")
    func windowFiltering() throws {
        try withStore { store in
            let now = Date()
            try store.record([
                makeFlow(localPort: 1000, at: now.addingTimeInterval(-7200)),
                makeFlow(localPort: 1001, at: now),
            ])

            let recent = try store.flows(since: now.addingTimeInterval(-600))
            #expect(recent.count == 1)

            let everything = try store.flows(since: now.addingTimeInterval(-86400))
            #expect(everything.count == 2)
        }
    }

    /// The same fields the live view searches, so a query learned in one place works in
    /// the other.
    @Test(
        "Search matches across every identifying field",
        arguments: ["example", "Safari", "93.184", "Google", "GOOGLE"]
    )
    func searchMatches(term: String) throws {
        try withStore { store in
            let now = Date()
            try store.record([makeFlow(host: "example.com", at: now)])
            let results = try store.flows(
                since: now.addingTimeInterval(-60), matching: term
            )
            #expect(results.count == 1, "\(term) matched nothing")
        }
    }

    @Test("Search excludes what does not match")
    func searchExcludes() throws {
        try withStore { store in
            let now = Date()
            try store.record([makeFlow(host: "example.com", at: now)])
            let results = try store.flows(
                since: now.addingTimeInterval(-60), matching: "nothing-like-this"
            )
            #expect(results.isEmpty)
        }
    }

    /// Rollups are what a chart spanning weeks reads, so they must accumulate rather than
    /// replace when several flows land in the same minute.
    @Test("Rollups accumulate within a minute")
    func rollupsAccumulate() throws {
        try withStore { store in
            let now = Date()
            try store.record([
                makeFlow(localPort: 1000, bytesOut: 100, bytesIn: 200, at: now),
                makeFlow(localPort: 1001, bytesOut: 300, bytesIn: 400, at: now),
            ])

            let totals = try store.processTotals(since: now.addingTimeInterval(-120))
            #expect(totals.count == 1)
            let total = try #require(totals.first)
            #expect(total.bytesOut == 400)
            #expect(total.bytesIn == 600)
            #expect(total.flowCount == 2)
        }
    }

    /// A flow nobody could attribute still counts toward the totals; dropping it would
    /// quietly understate what the machine did.
    @Test("Unattributed flows are recorded under a stable label")
    func unattributedFlowsAreKept() throws {
        try withStore { store in
            let now = Date()
            var flow = makeFlow(at: now)
            flow.owner = nil
            try store.record([flow])

            let totals = try store.processTotals(since: now.addingTimeInterval(-120))
            #expect(totals.count == 1)
            let onlyTotal = try #require(totals.first)
            #expect(onlyTotal.processName == "(unattributed)")
        }
    }

    @Test("Retention removes what is past its keep-by date")
    func pruning() throws {
        try withStore { store in
            let now = Date()
            store.retention.flowDays = 7
            try store.record([
                makeFlow(localPort: 1000, at: now.addingTimeInterval(-30 * 86400)),
                makeFlow(localPort: 1001, at: now),
            ])
            let before = try store.count(of: "flows")
            #expect(before == 2)

            let removed = try store.prune(now: now)
            let remaining = try store.count(of: "flows")
            #expect(removed == 1)
            #expect(remaining == 1)
            // Pruning again removes nothing, rather than reporting phantom deletions.
            let removedAgain = try store.prune(now: now)
            #expect(removedAgain == 0)
        }
    }

    /// Whether an empty result means "nothing happened" or "nothing was recorded then" is
    /// not something a reader should have to guess.
    @Test("Coverage reports the window actually recorded")
    func coverageWindow() throws {
        try withStore { store in
            let emptyCoverage = try store.coverage()
            #expect(emptyCoverage == nil)

            let now = Date()
            try store.record([
                makeFlow(localPort: 1000, at: now.addingTimeInterval(-3600)),
                makeFlow(localPort: 1001, at: now),
            ])

            let recorded = try store.coverage()
            let coverage = try #require(recorded)
            #expect(coverage.earliest <= now.addingTimeInterval(-3599))
            #expect(coverage.latest >= now.addingTimeInterval(-1))
        }
    }

    @Test("Reopening a store keeps what was written")
    func persistsAcrossOpens() throws {
        let directory = NSTemporaryDirectory() + "beholder-test-\(UUID().uuidString)"
        let path = directory + "/history.sqlite"
        defer { try? FileManager.default.removeItem(atPath: directory) }

        let now = Date()
        do {
            let store = try FlowStore(path: path)
            try store.record([makeFlow(host: "persisted.example.com", at: now)])
            store.close()
        }

        let reopened = try FlowStore(path: path)
        defer { reopened.close() }
        let results = try reopened.flows(since: now.addingTimeInterval(-60))
        #expect(results.count == 1)
        let restored = try #require(results.first)
        #expect(restored.hostName == "persisted.example.com")
    }

    /// The database records every host this machine contacted, so it gets the same
    /// treatment as the transcript and the socket.
    @Test("The database is not readable by other users")
    func fileIsPrivate() throws {
        try withStore { store in
            let attributes = try FileManager.default.attributesOfItem(atPath: store.path)
            let permissions = try #require(attributes[.posixPermissions] as? NSNumber)
            #expect(permissions.intValue == 0o600)
        }
    }

    @Test("An empty batch is accepted without a transaction")
    func emptyBatch() throws {
        try withStore { store in
            let recorded = try store.record([])
            let stored = try store.count(of: "flows")
            #expect(recorded == 0)
            #expect(stored == 0)
        }
    }
}

/// Regression: the list filter keyed on "recognised by the tracker database". Once the
/// ASN lookup landed, almost nothing was in that database and almost everything had a
/// network operator, so the filter kept practically every flow and read as broken.
@Suite("Identification")
struct IdentificationTests {

    private func wireFlow(
        hostName: String? = nil,
        company: String? = nil,
        network: String? = nil
    ) -> WireFlow {
        WireFlow(
            id: "x", processName: nil, processPath: nil, pid: nil,
            transport: "TCP", localAddress: "10.0.0.1", localPort: 50000,
            remoteAddress: "1.2.3.4", remotePort: 443,
            hostName: hostName, hostNameIsProof: false, isPrivateRelay: false,
            bytesOut: 0, bytesIn: 0, packetsOut: 0, packetsIn: 0,
            tcpState: nil, firstSeen: Date(), lastSeen: Date(),
            location: nil,
            classification: company.map { HostClassification(owner: $0) },
            networkOperator: network.map { NetworkOperator(number: 1, organization: $0) },
            isOutgoing: true, initiationIsCertain: true
        )
    }

    @Test("Any one source counts as identification")
    func anySourceIdentifies() {
        #expect(wireFlow(hostName: "example.com").isIdentified)
        #expect(wireFlow(company: "Google").isIdentified)
        #expect(wireFlow(network: "CLOUDFLARE").isIdentified)
    }

    /// The set worth isolating: an address, a port, and nothing else.
    @Test("A flow with no name, company or network is unidentified")
    func nothingKnownIsUnidentified() {
        #expect(!wireFlow().isIdentified)
    }

    /// The precise case that made the old filter useless — a host in no tracker list but
    /// with a perfectly good network operator is identified, not a mystery.
    @Test("A host absent from every tracker list is still identified by its network")
    func trackerAbsenceIsNotMystery() {
        let flow = wireFlow(network: "PacketHub S.A.")
        #expect(flow.classification?.owner == nil)
        #expect(flow.isIdentified)
    }
}

// MARK: - Schema versioning

/// A directory that removes itself, so each schema test gets a database of its own.
private final class TemporaryDatabase {
    let directory: String
    let path: String

    init() {
        directory = NSTemporaryDirectory() + "beholder-schema-\(UUID().uuidString)"
        path = directory + "/history.sqlite"
    }

    deinit {
        try? FileManager.default.removeItem(atPath: directory)
    }

    /// Stamps a version onto the file behind the store's back, which is how a database
    /// written by another build of Beholder is reproduced without keeping one around.
    func stamp(version: Int32) throws {
        var database: OpaquePointer?
        guard
            sqlite3_open_v2(path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK,
            let database
        else {
            Issue.record("cannot reopen \(path) to stamp a version")
            return
        }
        defer { sqlite3_close(database) }
        sqlite3_exec(database, "PRAGMA user_version = \(version);", nil, nil, nil)
    }
}

@Suite("History database schema")
struct FlowStoreSchemaTests {

    @Test("A new database is stamped with the current schema version")
    func newDatabaseIsStamped() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }
        #expect(try store.userVersion() == FlowStore.schemaVersion)
    }

    /// The upgrade every existing installation will take. A database written before
    /// versioning reports version 0 and already has the tables, so the first step must
    /// find nothing to do and must not disturb what is already recorded — the failure
    /// this guards against is an upgrade that starts the history over.
    @Test("A database from before versioning keeps its rows and adopts the current version")
    func preVersioningDatabaseUpgradesInPlace() throws {
        let temporary = TemporaryDatabase()

        let before = try FlowStore(path: temporary.path)
        try before.record([makeFlow(), makeFlow(localPort: 51235)])
        #expect(try before.flowRowCount() == 2)
        before.close()

        try temporary.stamp(version: 0)

        let after = try FlowStore(path: temporary.path)
        defer { after.close() }
        #expect(try after.userVersion() == FlowStore.schemaVersion)
        #expect(try after.flowRowCount() == 2)
    }

    /// Refused rather than read. A newer schema mostly reads fine, and that is the danger:
    /// the symptom would be quietly missing data instead of an error.
    @Test("A database from a newer Beholder is refused")
    func newerSchemaIsRefused() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        store.close()

        try temporary.stamp(version: FlowStore.schemaVersion + 1)

        #expect(throws: FlowStore.StoreError.self) {
            _ = try FlowStore(path: temporary.path)
        }
    }

    /// A viewer must never alter what the daemon recorded, and a migration is an
    /// alteration. Opening read-only leaves the version alone, even a stale one.
    @Test("Opening read-only does not migrate")
    func readOnlyDoesNotMigrate() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        store.close()

        try temporary.stamp(version: 0)

        let reader = try FlowStore(path: temporary.path, readOnly: true)
        defer { reader.close() }
        #expect(try reader.userVersion() == 0)
    }
}

// MARK: - Quality history

private func qualityRow(
    minute: Int64,
    group: String = "AS15169",
    label: String? = "GOOGLE",
    interface: String = "en0",
    samples: Int = 10,
    minMs: Double? = 12.5,
    p50: Double? = 20,
    segmentsOut: UInt64 = 1000,
    retransmitsOut: UInt64 = 3,
    bytesIn: UInt64 = 50_000,
    measured: UInt64 = 40_000,
    unmeasurable: UInt64 = 10_000,
    attempts: Int = 4,
    timeouts: Int = 0
) -> QualityMinute {
    QualityMinute(
        minute: minute,
        interface: interface,
        destinationGroup: group,
        destinationLabel: label,
        rttSamples: samples,
        rttMinMs: minMs,
        rttP50Ms: p50,
        rttP95Ms: p50.map { $0 * 3 },
        handshakeSamples: 2,
        handshakeMinMs: minMs,
        segmentsOut: segmentsOut,
        segmentsIn: 900,
        retransmitsOut: retransmitsOut,
        retransmitsIn: 1,
        bytesOut: 5_000,
        bytesIn: bytesIn,
        measuredBytes: measured,
        unmeasurableBytes: unmeasurable,
        flowCount: 3,
        connectionAttempts: attempts,
        connectionTimeouts: timeouts
    )
}

@Suite("Quality history")
struct FlowStoreQualityTests {

    private func minute(_ date: Date) -> Int64 { Int64(date.timeIntervalSince1970 / 60) }

    @Test("A minute of measurement survives a round trip")
    func roundTrip() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }

        let now = Date()
        try store.recordQuality([qualityRow(minute: minute(now))])
        let rows = try store.qualityMinutes(
            since: now.addingTimeInterval(-600), until: now.addingTimeInterval(600)
        )

        let row = try #require(rows.first)
        #expect(row.destinationGroup == "AS15169")
        #expect(row.destinationLabel == "GOOGLE")
        #expect(row.rttSamples == 10)
        #expect(row.rttMinMs == 12.5)
        #expect(row.retransmitsOut == 3)
        #expect(abs(try #require(row.measuredByteShare) - 0.8) < 1e-9)
    }

    /// A connection that turns out never to have been answered is filed against the minute
    /// it was *attempted* in — which may already be on disk. The write has to be able to
    /// join a minute already written rather than replacing or duplicating it.
    @Test("A late fact joins a minute already written instead of replacing it")
    func upsertMergesCounters() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }

        let now = Date()
        try store.recordQuality([qualityRow(minute: minute(now), attempts: 4, timeouts: 0)])
        try store.recordQuality([
            QualityMinute(
                minute: minute(now),
                interface: "en0",
                destinationGroup: "AS15169",
                connectionTimeouts: 2
            )
        ])

        let rows = try store.qualityMinutes(
            since: now.addingTimeInterval(-600), until: now.addingTimeInterval(600)
        )
        #expect(rows.count == 1)
        let row = try #require(rows.first)
        #expect(row.connectionAttempts == 4)
        #expect(row.connectionTimeouts == 2)
        // The percentile came with the row that had samples behind it, and the row with
        // none must not have blanked it.
        #expect(row.rttP50Ms == 20)
        #expect(row.rttSamples == 10)
        #expect(row.destinationLabel == "GOOGLE")
    }

    @Test("The lower of two minima wins when a minute is written twice")
    func minimumTakesTheLower() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }

        let now = Date()
        try store.recordQuality([qualityRow(minute: minute(now), minMs: 30)])
        try store.recordQuality([qualityRow(minute: minute(now), minMs: 11)])

        let rows = try store.qualityMinutes(
            since: now.addingTimeInterval(-600), until: now.addingTimeInterval(600)
        )
        #expect(try #require(rows.first).rttMinMs == 11)
    }

    @Test("Interfaces are reported apart, since a tunnel is not the link beneath it")
    func interfacesReportedApart() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }

        let now = Date()
        try store.recordQuality([
            qualityRow(minute: minute(now), interface: "en0", bytesIn: 10),
            qualityRow(minute: minute(now), interface: "utun8", bytesIn: 900),
        ])

        let interfaces = try store.qualityInterfaces(
            since: now.addingTimeInterval(-600), until: now.addingTimeInterval(600)
        )
        #expect(interfaces.count == 2)
        #expect(interfaces.first?.0 == "utun8")
    }

    /// An empty window is ambiguous between a quiet network and a daemon that was not
    /// running, and only the coverage tells them apart.
    @Test("Coverage states the window the series actually spans")
    func coverage() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }

        #expect(try store.qualityCoverage() == nil)

        let now = Date()
        try store.recordQuality([
            qualityRow(minute: minute(now) - 10),
            qualityRow(minute: minute(now)),
        ])

        let coverage = try #require(try store.qualityCoverage())
        #expect(coverage.minutes == 2)
        #expect(coverage.earliest < coverage.latest)
    }

    /// Percentiles are deliberately not carried into the hourly rollup: they came from a
    /// distribution that no longer exists, and averaging two percentiles is not one.
    @Test("Old minutes are folded into hours, keeping the minimum exactly")
    func pruningFoldsIntoHours() throws {
        let temporary = TemporaryDatabase()
        let store = try FlowStore(path: temporary.path)
        defer { store.close() }

        let now = Date()
        let old = now.addingTimeInterval(-40 * 86400)
        // Anchored to the start of an hour, so the two old minutes are always in the *same*
        // hour. Taken raw, they straddle an hour boundary whenever the wall clock happens to
        // sit on minute 59, which folds them into two rows instead of one and fails this
        // roughly once in every sixty runs.
        let oldHourStart = minute(old) - (minute(old) % 60)
        try store.recordQuality([
            qualityRow(minute: oldHourStart, minMs: 40),
            qualityRow(minute: oldHourStart + 1, minMs: 18),
            qualityRow(minute: minute(now), minMs: 12),
        ])

        _ = try store.pruneQuality(now: now)

        let remaining = try store.qualityMinutes(
            since: old.addingTimeInterval(-86400), until: now.addingTimeInterval(600)
        )
        #expect(remaining.count == 1)
        #expect(remaining.first?.rttMinMs == 12)

        var hourlyMinimum: Double?
        var hourlySamples = 0
        try store.withStatement(
            "SELECT rtt_min_ms, rtt_samples FROM quality_hours;"
        ) { statement in
            if sqlite3_step(statement) == SQLITE_ROW {
                hourlyMinimum = sqlite3_column_double(statement, 0)
                hourlySamples = Int(sqlite3_column_int64(statement, 1))
            }
        }
        #expect(hourlyMinimum == 18)
        #expect(hourlySamples == 20)
    }
}
