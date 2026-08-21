import Foundation
import Testing

@testable import BeholderCore

/// A handler with one tool that reports what it was given, so dispatch can be checked
/// without a database anywhere near it.
private func makeHandler(
    onCall: @escaping @Sendable (String, JSONValue) -> MCPToolResult = { name, _ in
        MCPToolResult(text: "called \(name)")
    }
) -> MCPHandler {
    MCPHandler(
        definitions: [
            MCPToolDefinition(
                name: "echo", title: "Echo", description: "Repeats itself",
                inputSchema: ["type": "object", "properties": .object([:])]
            )
        ],
        invoke: onCall
    )
}

private func response(_ handler: MCPHandler, _ json: String) -> [String: Any]? {
    guard let line = handler.handle(line: Data(json.utf8)) else { return nil }
    return try? JSONSerialization.jsonObject(with: line) as? [String: Any]
}

@Suite("MCP protocol")
struct MCPProtocolTests {

    // MARK: - Versions

    @Test("Every supported revision is echoed back")
    func echoesSupportedVersions() {
        let handler = makeHandler()
        for version in MCPVersion.supported {
            let reply = response(
                handler,
                """
                {"jsonrpc":"2.0","id":1,"method":"initialize",\
                "params":{"protocolVersion":"\(version)"}}
                """
            )
            let result = reply?["result"] as? [String: Any]
            #expect(
                result?["protocolVersion"] as? String == version,
                "the client's choice of \(version) should be honoured, not negotiated down"
            )
        }
    }

    @Test("An unknown or absent revision falls back to the preferred one")
    func fallsBackToPreferred() {
        let handler = makeHandler()
        let unknown = response(
            handler,
            """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}
            """
        )
        let absent = response(handler, #"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)

        #expect((unknown?["result"] as? [String: Any])?["protocolVersion"] as? String
            == MCPVersion.preferred)
        #expect((absent?["result"] as? [String: Any])?["protocolVersion"] as? String
            == MCPVersion.preferred)
    }

    // MARK: - Statelessness

    @Test("Tools work on a connection that never sent initialize")
    func servesWithoutHandshake() {
        // The 2026-07-28 revision removed the handshake entirely, so a modern client may
        // never send one. Holding no session state is what makes both eras work with no
        // branching — and this is the property most likely to be broken by someone later
        // adding a "have we initialized yet" guard.
        let handler = makeHandler()
        let list = response(handler, #"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        #expect(list?["result"] != nil)

        let call = response(
            handler,
            """
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}
            """
        )
        #expect(call?["result"] != nil)
    }

    @Test("server/discover advertises the versions and the tools")
    func discoverAdvertises() {
        let reply = response(makeHandler(), #"{"jsonrpc":"2.0","id":9,"method":"server/discover"}"#)
        let result = reply?["result"] as? [String: Any]
        #expect(result?["supportedVersions"] as? [String] == MCPVersion.supported)
        #expect((result?["tools"] as? [Any])?.count == 1)
        #expect(result?["serverInfo"] != nil)
    }

    // MARK: - Errors

    @Test("An unknown method is method-not-found")
    func unknownMethod() {
        let reply = response(makeHandler(), #"{"jsonrpc":"2.0","id":1,"method":"what"}"#)
        let error = reply?["error"] as? [String: Any]
        #expect(error?["code"] as? Int == MCPError.methodNotFound)
    }

    @Test("An unknown tool is invalid-params, not a tool failure")
    func unknownTool() {
        let reply = response(
            makeHandler(),
            """
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}
            """
        )
        #expect((reply?["error"] as? [String: Any])?["code"] as? Int == MCPError.invalidParams)
    }

    @Test("A tools/call with no name is invalid-params")
    func namelessCall() {
        let reply = response(
            makeHandler(), #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#
        )
        #expect((reply?["error"] as? [String: Any])?["code"] as? Int == MCPError.invalidParams)
    }

    @Test("Unparseable input is a parse error against a null id")
    func parseError() {
        let reply = response(makeHandler(), "{not json")
        #expect((reply?["error"] as? [String: Any])?["code"] as? Int == MCPError.parseError)
        #expect(reply?["id"] is NSNull)
    }

    @Test("A tool that fails returns isError rather than a JSON-RPC error")
    func toolFailureIsAResult() {
        // The distinction decides whether the model can recover: a JSON-RPC error is a
        // wall, while isError carries a sentence it can read and act on.
        let handler = makeHandler { _, _ in .failure("no database at /nowhere/history.sqlite") }
        let reply = response(
            handler,
            """
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}
            """
        )
        #expect(reply?["error"] == nil)
        let result = reply?["result"] as? [String: Any]
        #expect(result?["isError"] as? Bool == true)
        let content = result?["content"] as? [[String: Any]]
        #expect(content?.first?["text"] as? String == "no database at /nowhere/history.sqlite")
    }

    // MARK: - Notifications

    @Test("Notifications are never answered")
    func notificationsAreSilent() {
        let handler = makeHandler()
        // Including one the server does not know: an unknown *notification* must not fall
        // through into method-not-found and put an unexpected line on the wire.
        #expect(handler.handle(line: Data(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.utf8)) == nil)
        #expect(handler.handle(line: Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#.utf8)) == nil)
        #expect(handler.handle(line: Data(#"{"jsonrpc":"2.0","id":null,"method":"whatever"}"#.utf8)) == nil)
    }

    // MARK: - Framing

    @Test("No response ever contains a raw newline")
    func responsesAreSingleLines() {
        // The stdio transport is newline-delimited with no way to resynchronise, so a raw
        // newline anywhere in an encoded message corrupts the stream permanently.
        let handler = makeHandler { _, _ in
            MCPToolResult(text: "a line\nand another\r\nand \u{2028} too")
        }
        let inputs = [
            #"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            #"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            #"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
            "{bad",
        ]
        for input in inputs {
            guard let line = handler.handle(line: Data(input.utf8)) else { continue }
            #expect(!line.contains(0x0A), "encoded response contained a raw newline")
        }
    }

    // MARK: - The real toolbox

    @Test("The tool surface is exactly the five documented tools")
    func toolNamesArePinned() {
        // Pinned deliberately. A rename silently breaks every saved conversation and every
        // habit a user has built, so it should take a failing test to do it.
        //
        // The count is pinned as much as the names. Every tool's schema sits in the
        // client's context on every turn of every conversation, so growth here is a cost
        // paid by people who never ask about networking at all — see the note at the top
        // of MCPTools for why the fifth was judged to earn its place.
        #expect(
            MCPToolbox.definitions.map(\.name) == [
                "network_history", "endpoint_lookup", "live_connections", "beholder_status",
                "network_quality",
            ]
        )
    }

    @Test("Every schema is a well-formed object schema")
    func schemasAreWellFormed() throws {
        for definition in MCPToolbox.definitions {
            let schema = definition.inputSchema
            #expect(schema["type"]?.stringValue == "object", "\(definition.name)")
            #expect(schema["additionalProperties"]?.boolValue == false, "\(definition.name)")
            #expect(!definition.description.isEmpty, "\(definition.name)")

            let properties = schema["properties"]?.objectValue ?? [:]
            for required in schema["required"]?.arrayValue ?? [] {
                let name = try #require(required.stringValue)
                #expect(
                    properties[name] != nil,
                    "\(definition.name) requires \(name) but does not declare it"
                )
            }
            // Encoding is what a client actually receives; a schema that cannot encode
            // would fail far away from here.
            #expect(throws: Never.self) { try definition.json.encoded() }
        }
    }
}
