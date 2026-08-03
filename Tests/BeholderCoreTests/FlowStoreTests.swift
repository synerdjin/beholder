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
