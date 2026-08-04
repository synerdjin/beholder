import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!

/// `ProcessOwner` derives its display name from the last component of its path, so a test
/// that wants a particular process name spells it at the end of `processPath`.
private func flow(
    port: UInt16,
    remote: [UInt8] = [93, 184, 216, 34],
    host: String? = nil,
    processPath: String? = "/Applications/Safari.app/Safari",
    remotePort: UInt16 = 443,
    bytesOut: UInt64 = 1000,
    bytesIn: UInt64 = 5000,
    at timestamp: Date
) -> Flow {
    var value = Flow(
        key: FlowKey(
            transport: .tcp, local: laptop, localPort: port,
            remote: IPAddress(networkOrderBytes: remote, family: .v4)!, remotePort: remotePort
        ),
        interfaceName: "utun8",
        at: timestamp
    )
    value.bytesOut = bytesOut
    value.bytesIn = bytesIn
    value.lastSeen = timestamp
    value.hostName = host
    if host != nil { value.hostNameSource = .dns }
    if let processPath {
        value.owner = ProcessOwner(pid: 100, path: processPath)
    }
    return value
}

private func withStore(_ body: (FlowStore) throws -> Void) throws {
    let directory = NSTemporaryDirectory() + "beholder-mcp-test-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let store = try FlowStore(path: directory + "/history.sqlite")
    defer { store.close() }
    try body(store)
}

/// Runs a tool against a database seeded by `seed`, returning the parsed JSON body.
private func callTool(
    _ name: String,
    _ arguments: JSONValue = .object([:]),
    seed: (FlowStore) throws -> Void
) throws -> (body: [String: Any], isError: Bool) {
    let directory = NSTemporaryDirectory() + "beholder-mcp-test-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let path = directory + "/history.sqlite"

    let store = try FlowStore(path: path)
    try seed(store)
    store.close()

    // A socket path that cannot exist, so nothing here can accidentally depend on a daemon
    // running on the machine the tests happen to be executed on.
    let toolbox = MCPToolbox(historyPath: path, socketPath: directory + "/absent.sock")
    let result = toolbox.invoke(name, arguments)

    let text = result.text
    let json = text.contains("\n") ? String(text.split(separator: "\n", maxSplits: 1)[1]) : "{}"
    let body = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
    return (body, result.isError)
}

@Suite("MCP tools")
struct MCPToolsTests {

    // MARK: - The sort regression

    @Test("Ranking by volume hides a small recent connection; ranking by time finds it")
    func sortByRecentFindsTheQuietOne() throws {
        // This is the whole reason `sort` exists. "What was this laptop doing overnight" is
        // an eight-hour window, and a 200-byte beacon at 03:14 sits behind every video
        // segment of the evening when ranked by volume — the interesting row is the one
        // that never appears.
        let now = Date()
        let seed: (FlowStore) throws -> Void = { store in
            try store.record([
                flow(
                    port: 1000, remote: [1, 1, 1, 1], host: "big-download.example",
                    bytesOut: 10, bytesIn: 500_000_000, at: now.addingTimeInterval(-20 * 3600)
                ),
                flow(
                    port: 1001, remote: [2, 2, 2, 2], host: "quiet-beacon.example",
                    bytesOut: 200, bytesIn: 100, at: now.addingTimeInterval(-3600)
                ),
            ])
        }

        let byBytes = try callTool(
            "network_history", ["since": "48h", "sort": "bytes"], seed: seed
        )
        let byRecent = try callTool(
            "network_history", ["since": "48h", "sort": "recent"], seed: seed
        )

        func firstHost(_ body: [String: Any]) -> String? {
            ((body["rows"] as? [[String: Any]])?.first)?["host"] as? String
        }
        #expect(firstHost(byBytes.body) == "big-download.example")
        #expect(firstHost(byRecent.body) == "quiet-beacon.example")
    }

    // MARK: - Grouping

    @Test("Many connections to one host collapse into one row")
    func groupsByHost() throws {
        let now = Date()
        let (body, isError) = try callTool("network_history", ["since": "24h"]) { store in
            // The measured shape of the real database is about thirty rows per
            // host-and-process pair, and over a thousand for one busy API endpoint.
            try store.record(
                (0..<40).map { index in
                    flow(
                        port: UInt16(2000 + index), host: "api.example.com",
                        bytesOut: 100, bytesIn: 200,
                        at: now.addingTimeInterval(-Double(index) * 60)
                    )
                }
            )
        }

        #expect(!isError)
        let rows = try #require(body["rows"] as? [[String: Any]])
        #expect(rows.count == 1, "forty connections to one host should be one row")
        #expect(rows[0]["conns"] as? Int == 40)
        #expect(rows[0]["out"] as? Int == 4000)
        #expect(rows[0]["in"] as? Int == 8000)
    }

    @Test("An answer says what window it covers")
    func statesItsCoverage() throws {
        let (body, _) = try callTool("network_history", ["since": "24h"]) { store in
            try store.record([flow(port: 3000, host: "a.example", at: Date())])
        }
        // An empty or partial result is ambiguous between "nothing happened" and "nothing
        // was watching" unless the answer names what it actually covers.
        #expect(body["coverage"] != nil)
        #expect(body["window"] != nil)
    }

    // MARK: - endpoint_lookup

    @Test("An endpoint's first contact is found across the whole history")
    func endpointFirstContact() throws {
        let now = Date()
        let (body, isError) = try callTool(
            "endpoint_lookup", ["endpoint": "tracker.example"]
        ) { store in
            // The oldest connection is also the smallest. Ranking by bytes — which is what
            // the row-returning query does — would surface the big recent one and report
            // the wrong first-contact date.
            try store.record([
                flow(
                    port: 4000, remote: [5, 5, 5, 5], host: "tracker.example",
                    bytesOut: 10, bytesIn: 10, at: now.addingTimeInterval(-20 * 86400)
                ),
                flow(
                    port: 4001, remote: [5, 5, 5, 5], host: "tracker.example",
                    bytesOut: 9_000_000, bytesIn: 9_000_000, at: now.addingTimeInterval(-3600)
                ),
            ])
        }

        #expect(!isError)
        #expect(body["matched"] as? Bool == true)
        #expect(body["conns"] as? Int == 2)
        let first = try #require(body["first_seen"] as? String)
        let formatter = ISO8601DateFormatter()
        let firstDate = try #require(formatter.date(from: first))
        #expect(
            abs(firstDate.timeIntervalSince(now.addingTimeInterval(-20 * 86400))) < 5,
            "first_seen must be the earliest connection, not the earliest large one"
        )
    }

    @Test("An endpoint never contacted says so without claiming it never happened")
    func endpointNotFound() throws {
        let (body, isError) = try callTool(
            "endpoint_lookup", ["endpoint": "never-seen.example"]
        ) { store in
            try store.record([flow(port: 5000, host: "other.example", at: Date())])
        }
        #expect(!isError)
        #expect(body["matched"] as? Bool == false)
        let notes = try #require(body["notes"] as? [String])
        #expect(notes.contains { $0.contains("30 days") })
    }

    @Test("An exact address match does not drag in substring neighbours")
    func exactMatchIsPreferred() throws {
        let (body, _) = try callTool("endpoint_lookup", ["endpoint": "10.0.0.1"]) { store in
            try store.record([
                flow(port: 6000, remote: [10, 0, 0, 1], at: Date()),
                flow(port: 6001, remote: [10, 0, 0, 100], at: Date()),
                flow(port: 6002, remote: [10, 0, 0, 199], at: Date()),
            ])
        }
        #expect(body["conns"] as? Int == 1, "10.0.0.1 must not also match 10.0.0.100")
        #expect(body["addresses"] as? [String] == ["10.0.0.1"])
    }

    // MARK: - Arguments

    @Test("Durations and timestamps are understood")
    func parsesTimes() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(MCPToolbox.parseTime("30m", relativeTo: now) == now.addingTimeInterval(-1800))
        #expect(MCPToolbox.parseTime("12h", relativeTo: now) == now.addingTimeInterval(-43200))
        #expect(MCPToolbox.parseTime("7d", relativeTo: now) == now.addingTimeInterval(-604_800))
        #expect(MCPToolbox.parseTime("2w", relativeTo: now) == now.addingTimeInterval(-1_209_600))
        #expect(MCPToolbox.parseTime("2026-08-01T09:00:00Z", relativeTo: now) != nil)
        #expect(MCPToolbox.parseTime("2026-08-01", relativeTo: now) != nil)
    }

    @Test("An unreadable time is refused rather than silently defaulted")
    func refusesGarbageTime() throws {
        // Falling back to the default window would answer a question nobody asked, and do
        // it confidently.
        let (_, isError) = try callTool("network_history", ["since": "last tuesday"]) { _ in }
        #expect(isError)
    }

    @Test("A missing database names the path it looked at")
    func missingDatabaseNamesThePath() {
        let toolbox = MCPToolbox(
            historyPath: "/nonexistent/beholder/history.sqlite", socketPath: "/nonexistent/x.sock"
        )
        let result = toolbox.invoke("network_history", .object([:]))
        #expect(result.isError)
        // Capture started via `su -` writes under root's home, and the only way to notice
        // is for the answer to say where it looked.
        #expect(result.text.contains("/nonexistent/beholder/history.sqlite"))
    }

    @Test("A daemon that is not running is a readable failure, not a crash")
    func absentDaemon() {
        let toolbox = MCPToolbox(
            historyPath: "/nonexistent/history.sqlite", socketPath: "/nonexistent/beholder.sock"
        )
        let result = toolbox.invoke("live_connections", .object([:]))
        #expect(result.isError)
        #expect(result.text.contains("beholder_status"), "it should point at the diagnosis tool")
    }

    // MARK: - Sanitizing

    @Test("Control characters and over-long names are defanged")
    func cleansHostileStrings() {
        let hostile = "evil\n\r\u{7}host\u{2028}.example" + String(repeating: "a", count: 400)
        let cleaned = MCPToolbox.clean(hostile, limit: 253)
        let value = cleaned.value ?? ""

        #expect(!value.contains("\n"))
        #expect(!value.contains("\r"))
        #expect(!value.contains("\u{7}"))
        #expect(!value.contains("\u{2028}"))
        // 253 is the longest a real DNS name can be, so anything longer is already not a
        // name; the ellipsis is one extra scalar marking that it was cut.
        #expect(value.utf8.count <= 253 + 3)
        #expect(cleaned.modified)
    }

    @Test("An ordinary hostname is left exactly as it is")
    func leavesGoodNamesAlone() {
        // No content filtering: a network-visibility tool that quietly hides the
        // interesting hostname has defeated its own purpose.
        let cleaned = MCPToolbox.clean("ignore-previous-instructions.example.com", limit: 253)
        #expect(cleaned.value == "ignore-previous-instructions.example.com")
        #expect(!cleaned.modified)
    }

    @Test("A row built from a hostile hostname is flagged")
    func flagsCleanedRows() throws {
        let (body, _) = try callTool("network_history", ["since": "24h"]) { store in
            try store.record([flow(port: 7000, host: "bad\u{7}host.example", at: Date())])
        }
        let rows = try #require(body["rows"] as? [[String: Any]])
        #expect(rows.first?["flagged"] as? Bool == true)
    }

    // MARK: - Size

    @Test("An oversized answer is truncated and says so")
    func capsResultSize() throws {
        let now = Date()
        let padding: String = String(repeating: "x", count: 120)
        let (body, _) = try callTool("network_history", ["since": "24h", "limit": 200]) { store in
            try store.record(
                (0..<200).map { index -> Flow in
                    let host: String = "host-\(index)-\(padding).example.com"
                    return flow(
                        port: UInt16(10000 + index),
                        remote: [10, 0, UInt8(index / 256), UInt8(index % 256)],
                        host: host,
                        at: now.addingTimeInterval(-Double(index))
                    )
                }
            )
        }

        let rows = try #require(body["rows"] as? [[String: Any]])
        let notes = (body["notes"] as? [String]) ?? []
        #expect(rows.count < 200, "a wide 200-row answer should not be returned whole")
        #expect(
            notes.contains { $0.contains("Truncated") },
            "truncation has to be stated or the answer looks complete"
        )
    }

    @Test("Every answer either frames its data or explains its failure")
    func rendersSafely() {
        let toolbox = MCPToolbox(historyPath: "/nonexistent/x", socketPath: "/nonexistent/y")
        let arguments: JSONValue = ["endpoint": "x"]
        for definition in MCPToolbox.definitions {
            let result: MCPToolResult = toolbox.invoke(definition.name, arguments)
            let framed: Bool = result.text.hasPrefix(ResultDocument.preamble)
            #expect(framed || result.isError, "\(definition.name)")
        }
    }
}

@Suite("History digests")
struct FlowStoreDigestTests {

    @Test("Host digests report the true group count, not just what was returned")
    func reportsTotalGroups() throws {
        try withStore { store in
            let now = Date()
            try store.record(
                (0..<10).map { index in
                    flow(
                        port: UInt16(9000 + index),
                        remote: [10, 0, 0, UInt8(index)],
                        host: "host-\(index).example",
                        at: now
                    )
                }
            )
            let (rows, total) = try store.hostDigests(
                since: now.addingTimeInterval(-3600), until: now.addingTimeInterval(60), limit: 3
            )
            #expect(rows.count == 3)
            #expect(total == 10, "the answer must know what it truncated")
        }
    }

    @Test("A proxy holding most of the traffic is called out")
    func detectsProxy() throws {
        try withStore { store in
            let now = Date()
            // A system extension reaching many hosts and dominating the table: the shape
            // ProxyDetection judges by, applied to history rather than the live table.
            try store.record(
                (0..<40).map { index in
                    flow(
                        port: UInt16(11000 + index),
                        remote: [10, 1, 0, UInt8(index)],
                        host: "host-\(index).example",
                        processPath: "/Library/SystemExtensions/com.vpn.Shield.systemextension/Shield",
                        at: now
                    )
                }
            )
            let caveat = try store.proxyCaveat(since: now.addingTimeInterval(-3600))
            let text = try #require(caveat)
            #expect(text.contains("Shield"))
            #expect(text.contains("transparent proxy"))
        }
    }

    @Test("A busy resolver is not mistaken for a proxy")
    func ignoresResolver() throws {
        try withStore { store in
            let now = Date()
            // mDNSResponder talks to every resolver on the network and can own a third of
            // all flows without carrying anybody's payload. That false positive was found
            // and fixed once in the live detector; excluding infrastructure ports here is
            // what keeps it from coming back through the history path.
            try store.record(
                (0..<40).map { index in
                    flow(
                        port: UInt16(12000 + index),
                        remote: [10, 2, 0, UInt8(index)],
                        processPath: "/usr/sbin/mDNSResponder",
                        remotePort: 53,
                        at: now
                    )
                }
            )
            #expect(try store.proxyCaveat(since: now.addingTimeInterval(-3600)) == nil)
        }
    }

    @Test("A quiet window raises no proxy caveat at all")
    func ignoresSmallWindows() throws {
        try withStore { store in
            let now = Date()
            try store.record([
                flow(
                    port: 13000, processPath: "/Library/SystemExtensions/x.systemextension/Shield", at: now
                )
            ])
            // One flow is not evidence of anything.
            #expect(try store.proxyCaveat(since: now.addingTimeInterval(-3600)) == nil)
        }
    }
}
