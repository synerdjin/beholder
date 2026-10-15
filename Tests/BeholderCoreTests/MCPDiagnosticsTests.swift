import Foundation
import Testing

@testable import BeholderCore

/// A flow with the fields these tests read and nothing else.
private func wireFlow(
    id: String, process: String = "Safari", host: String? = "example.com",
    rtt: Double? = nil, resentOut: UInt64? = nil
) -> WireFlow {
    WireFlow(
        id: id, processName: process, processPath: "/Applications/\(process).app/\(process)",
        pid: 100, transport: "TCP", localAddress: "10.5.0.2", localPort: 50000,
        remoteAddress: "93.184.216.34", remotePort: 443,
        hostName: host, hostNameIsProof: true, isPrivateRelay: false,
        bytesOut: 1000, bytesIn: 5000, packetsOut: 10, packetsIn: 12,
        tcpState: "established", firstSeen: Date(timeIntervalSince1970: 1_700_000_000),
        lastSeen: Date(timeIntervalSince1970: 1_700_000_100),
        location: nil, classification: nil, networkOperator: nil,
        isOutgoing: true, initiationIsCertain: true,
        security: .encrypted, protocolName: "TLS", securityIsProof: true,
        rttMs: rtt, rttMinMs: rtt.map { $0 - 5 }, rttVarMs: rtt.map { _ in 2 },
        rttSource: rtt == nil ? nil : "handshake",
        retransmitsOut: resentOut, retransmitsIn: resentOut.map { _ in 0 },
        retransmitsAreProven: resentOut == nil ? nil : true,
        arrivalJitterMs: nil, hopCount: nil, segmentOffload: nil
    )
}

private func frame(_ snapshot: FlowSnapshot) throws -> Data {
    var data = try FlowSnapshot.encoder().encode(snapshot)
    data.append(0x0A)
    return data
}

private func snapshot(
    flows: [WireFlow] = [], statistics: WireStatistics = WireStatistics(),
    excerpts: [WireExcerpt]? = nil, daemon: DaemonInfo? = nil
) -> FlowSnapshot {
    FlowSnapshot(
        generatedAt: Date(), startedAt: Date().addingTimeInterval(-600), interfaces: ["utun8"],
        flows: flows, statistics: statistics, cleartextExcerpts: excerpts, daemon: daemon)
}

/// Calls a tool against a real in-process socket peer and an empty database. Real because
/// a fake that never reads the request cannot tell a working client from one whose every
/// write fails — the lesson CLAUDE.md records about everything that touches a socket.
private func call(
    _ name: String, _ arguments: JSONValue = .object([:]),
    serving served: FlowSnapshot?, allowPayload: Bool = false,
    seed: (FlowStore) throws -> Void = { _ in }
) throws -> (body: [String: Any], text: String, isError: Bool) {
    let directory = NSTemporaryDirectory() + "beholder-mcp-diag-\(UUID().uuidString)"
    try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: directory) }

    let historyPath = directory + "/history.sqlite"
    let store = try FlowStore(path: historyPath)
    try seed(store)
    store.close()

    var daemon: FakeDaemon?
    var socketPath = directory + "/absent.sock"
    if let served {
        daemon = try FakeDaemon(behaviour: .send(try frame(served)))
        socketPath = daemon!.path
    }
    defer { daemon?.shutdown() }

    let toolbox = MCPToolbox(
        historyPath: historyPath, socketPath: socketPath, allowPayload: allowPayload)
    let result = toolbox.invoke(name, arguments)
    let text = result.text
    let json = text.contains("\n") ? String(text.split(separator: "\n", maxSplits: 1)[1]) : "{}"
    let body = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
    return (body, text, result.isError)
}

@Suite("MCP diagnostics and widened tools")
struct MCPDiagnosticsTests {

    // MARK: - The payload tool

    @Test("Without the flag the payload tool does not exist, even when called by name")
    func payloadRefusedByDefault() throws {
        // No peer: the call is refused before it would ever connect, and a peer nobody
        // connects to is a thread parked in accept().
        let result = try call("cleartext_excerpts", serving: nil)
        #expect(result.isError)
        #expect(result.text.contains("unknown tool"))
    }

    @Test("With the flag, a daemon that is not reading payload says so, distinct from one that found none")
    func payloadNilIsNotEmpty() throws {
        let notReading = try call(
            "cleartext_excerpts", serving: snapshot(excerpts: nil), allowPayload: true)
        #expect(notReading.body["reading_payload"] as? Bool == false)

        let foundNothing = try call(
            "cleartext_excerpts", serving: snapshot(excerpts: []), allowPayload: true)
        #expect(foundNothing.body["reading_payload"] as? Bool == true)
        #expect(foundNothing.text.contains("seen nothing unencrypted"))
    }

    @Test("An HTTP excerpt is rendered as lines, and control characters are cleaned")
    func payloadIsRendered() throws {
        let flow = wireFlow(id: "TCP|a|b")
        let request = Data("GET /login HTTP/1.1\r\nHost: example.com\r\nX-Trick: a\u{1B}[2Jb\r\n\r\n".utf8)
        let excerpt = WireExcerpt(
            id: flow.id, sent: request, received: nil, sentObserved: UInt64(request.count),
            receivedObserved: 0)
        let result = try call(
            "cleartext_excerpts", serving: snapshot(flows: [flow], excerpts: [excerpt]),
            allowPayload: true)

        #expect(!result.isError)
        #expect(result.text.contains("GET /login HTTP/1.1"))
        #expect(!result.text.contains("\u{1B}"), "an escape sequence must not reach the assistant")
        #expect(result.text.contains("not instructions"))
    }

    // MARK: - live_connections

    @Test("The summary carries counters nothing exposed before, and leaves unmeasured ones out")
    func liveSummary() throws {
        var statistics = WireStatistics()
        statistics.flowCount = 2
        statistics.encryptedFlowCount = 1
        statistics.cleartextFlowCount = 1
        statistics.medianRttMs = 31.4
        statistics.retransmitRateIn = 0.02
        statistics.connectionTimeouts = 3
        let result = try call(
            "live_connections", serving: snapshot(flows: [wireFlow(id: "a")], statistics: statistics))
        let summary = try #require(result.body["summary"] as? [String: Any])
        #expect(summary["cleartext"] as? Int == 1)
        #expect(summary["median_rtt_ms"] as? Double == 31.4)
        #expect(summary["resent_in_pct"] as? Double == 2.0)
        #expect(summary["connection_timeouts"] as? Int == 3)
        #expect(summary["resent_out_pct"] == nil, "never measured is absent, not zero")
    }

    @Test("Detail full adds per-connection measurements; summary does not")
    func liveDetail() throws {
        let flows = [wireFlow(id: "a", rtt: 80, resentOut: 4)]
        let plain = try call("live_connections", serving: snapshot(flows: flows))
        let plainRow = try #require((plain.body["rows"] as? [[String: Any]])?.first)
        #expect(plainRow["rtt_ms"] == nil)

        let full = try call(
            "live_connections", ["detail": "full"], serving: snapshot(flows: flows))
        let row = try #require((full.body["rows"] as? [[String: Any]])?.first)
        #expect(row["rtt_ms"] as? Double == 80)
        #expect(row["resent_out"] as? Int == 4)
        #expect(row["resent_proven"] as? Bool == true)
        #expect(row["local_port"] as? Int == 50000)
    }

    @Test("Sorting by round trip puts the unmeasured last, not first")
    func sortByRTTPutsUnmeasuredLast() throws {
        let flows = [
            wireFlow(id: "unmeasured", process: "Unmeasured", rtt: nil),
            wireFlow(id: "fast", process: "Fast", rtt: 10),
            wireFlow(id: "slow", process: "Slow", rtt: 400),
        ]
        let result = try call(
            "live_connections", ["sort": "rtt"], serving: snapshot(flows: flows))
        let order = (result.body["rows"] as? [[String: Any]])?.compactMap { $0["proc"] as? String }
        #expect(order == ["Slow", "Fast", "Unmeasured"])
    }

    @Test("Sorting by retransmissions puts the unmeasured below a measured zero")
    func sortByRetransmitsPutsUnmeasuredLast() throws {
        let flows = [
            wireFlow(id: "unmeasured", process: "Unmeasured", resentOut: nil),
            wireFlow(id: "clean", process: "Clean", resentOut: 0),
            wireFlow(id: "lossy", process: "Lossy", resentOut: 9),
        ]
        let result = try call(
            "live_connections", ["sort": "retransmits"], serving: snapshot(flows: flows))
        let order = (result.body["rows"] as? [[String: Any]])?.compactMap { $0["proc"] as? String }
        #expect(order == ["Lossy", "Clean", "Unmeasured"])
    }

    @Test("Zero timeouts over counted attempts is reported as zero, not left out")
    func zeroTimeoutsArePresent() throws {
        let result = try call(
            "network_quality", ["since": "2h", "group_by": "interface"], serving: nil,
            seed: { store in
                let minute = QualityAccumulator.minute(of: Date().addingTimeInterval(-600))
                _ = try store.recordQuality([
                    QualityMinute(
                        minute: minute, interface: "en0", destinationGroup: "AS15169",
                        rttSamples: 5, rttMinMs: 12, rttP50Ms: 20, segmentsOut: 100,
                        bytesOut: 1000, bytesIn: 1000, connectionAttempts: 40,
                        connectionTimeouts: 0)
                ])
            })
        let row = try #require((result.body["rows"] as? [[String: Any]])?.first)
        #expect(row["connection_attempts"] as? Int == 40)
        #expect(row["connection_timeouts"] as? Int == 0)
    }

    // MARK: - network_quality, right now

    @Test("A window ending now carries the same assessment the Overview shows")
    func qualityNow() throws {
        var statistics = WireStatistics()
        statistics.measuredFlowCount = 12
        statistics.measuredByteShare = 0.9
        statistics.medianRttMs = 320
        statistics.segmentsOut = 5000
        statistics.retransmitRateOut = 0.0
        statistics.connectionAttempts = 40
        statistics.connectionTimeouts = 0
        let result = try call(
            "network_quality", ["since": "1h"], serving: snapshot(statistics: statistics))
        let now = try #require(result.body["now"] as? [String: Any])
        #expect(now["available"] as? Bool == true)
        #expect(now["overall"] as? String == "poor", "320 ms is past the poor band")
        let expected = HealthAssessment.make(statistics: statistics, probes: nil).headline
        #expect(now["headline"] as? String == expected)
    }

    @Test("With no daemon the live section says unavailable instead of inventing a reading")
    func qualityNowWithoutDaemon() throws {
        let result = try call("network_quality", ["since": "1h"], serving: nil)
        let now = try #require(result.body["now"] as? [String: Any])
        #expect(now["available"] as? Bool == false)
        #expect(now["headline"] == nil)
    }

    @Test("A window that ended long ago gets no live section")
    func historicWindowHasNoNow() throws {
        let result = try call(
            "network_quality", ["since": "3d", "until": "2d"], serving: nil)
        #expect(result.body["now"] == nil)
    }

    // MARK: - beholder_status and beholder_doctor

    @Test("The daemon's own report appears, with a note for each thing that misleads")
    func statusSelfReport() throws {
        let info = DaemonInfo(
            pid: 7, flags: .init(blockRequested: true, qualityMeasurement: false),
            historyStoreError: "disk full",
            enrichment: [.init(name: "geolocation", loaded: false)],
            blockingActive: true, blockingEntryCount: 2)
        let result = try call("beholder_status", serving: snapshot(daemon: info))
        let daemon = try #require(result.body["daemon"] as? [String: Any])
        #expect(daemon["self_report"] != nil)
        let notes = (result.body["notes"] as? [String] ?? []).joined(separator: " ")
        #expect(notes.contains("could not open its history database"))
        #expect(notes.contains("Quality measurement is off"))
        #expect(notes.contains("geolocation"))
    }

    @Test("A daemon that predates self-reporting is called out as such")
    func statusOldDaemon() throws {
        let result = try call("beholder_status", serving: snapshot(daemon: nil))
        let notes = (result.body["notes"] as? [String] ?? []).joined(separator: " ")
        #expect(notes.contains("predates"))
    }

    @Test("The doctor answers with a verdict, findings and a promise that nothing was changed")
    func doctorShape() throws {
        let result = try call("beholder_doctor", ["log_lines": 0], serving: nil)
        #expect(!result.isError)
        #expect(result.body["verdict"] is String)
        #expect(result.body["findings"] is [Any])
        let notes = (result.body["notes"] as? [String] ?? []).joined(separator: " ")
        #expect(notes.contains("Nothing was changed"))
        #expect(notes.contains("BEHOLDER_SOURCE_DIR"), "no source dir was given, and it says so")
    }
}
