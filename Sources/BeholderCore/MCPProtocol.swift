import Foundation

/// The JSON-RPC layer of the MCP server, as a function of its input.
///
/// This lives in BeholderCore rather than in the executable for the same reason
/// `WireProtocol` does: it is a contract, and a contract that cannot be unit-tested drifts.
/// `Scripts/test-publishing-socket.sh` exists precisely because `FlowServer` was put in an
/// executable target where a test could not reach it, and that lesson is worth applying
/// once rather than learning twice. Everything here is pure — the process I/O lives in the
/// `BeholderMCP` target, and the tool bodies arrive as a closure.
public enum MCPVersion {
    /// Protocol revisions this server will answer to.
    ///
    /// Checked against the specification on 2026-08-04. Nothing this server does differs
    /// between these revisions — it lists tools and it calls them — so the client's choice
    /// is honoured rather than negotiated down, and adding a future revision is a one-line
    /// change here with no behaviour to go with it. There is deliberately no
    /// `if version >= x` anywhere in this file: a per-revision branch is the thing that
    /// rots when the next revision lands.
    public static let supported = [
        "2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05",
    ]

    /// What we answer with when the client asks for something we do not recognise, or
    /// does not ask at all. Not the newest revision: `2025-11-25` is the newest that
    /// deployed clients broadly speak, and a client that wants `2026-07-28` asks for it
    /// by name and gets it echoed back.
    public static let preferred = "2025-11-25"

    public static func resolve(requested: String?) -> String {
        guard let requested, supported.contains(requested) else { return preferred }
        return requested
    }
}

public enum MCPServerInfo {
    public static let name = "beholder"
    public static let version = "0.1.0"
}

// MARK: - Messages

public struct MCPRequest: Sendable {
    /// Absent for a notification. JSON-RPC forbids responding to those at all, which is
    /// why this is an `Optional` rather than defaulted to something.
    public let id: JSONValue?
    public let method: String
    public let params: JSONValue

    public init(id: JSONValue?, method: String, params: JSONValue = .null) {
        self.id = id
        self.method = method
        self.params = params
    }

    /// Decodes one line. Returns nil when the line is not a JSON-RPC request, which the
    /// caller reports as a parse error rather than treating as a notification.
    public init?(decoding value: JSONValue) {
        guard let method = value["method"]?.stringValue else { return nil }
        self.method = method
        // A present-but-null id is a notification too. Some clients send it that way.
        let rawID = value["id"]
        self.id = (rawID?.isNull ?? true) ? nil : rawID
        self.params = value["params"] ?? .null
    }
}

public struct MCPError: Sendable, Equatable {
    public let code: Int
    public let message: String

    public static let parseError = -32700
    public static let invalidRequest = -32600
    public static let methodNotFound = -32601
    public static let invalidParams = -32602
    public static let internalError = -32603

    public init(code: Int, message: String) {
        self.code = code
        self.message = message
    }
}

public struct MCPResponse: Sendable {
    public let id: JSONValue
    public let payload: Payload

    public enum Payload: Sendable {
        case result(JSONValue)
        case failure(MCPError)
    }

    public init(id: JSONValue, result: JSONValue) {
        self.id = id
        self.payload = .result(result)
    }

    public init(id: JSONValue, error: MCPError) {
        self.id = id
        self.payload = .failure(error)
    }

    public var json: JSONValue {
        switch payload {
        case .result(let value):
            return ["jsonrpc": "2.0", "id": id, "result": value]
        case .failure(let error):
            return [
                "jsonrpc": "2.0", "id": id,
                "error": ["code": .integer(error.code), "message": .string(error.message)],
            ]
        }
    }
}

// MARK: - Tools

public struct MCPToolDefinition: Sendable {
    public let name: String
    public let title: String
    public let description: String
    public let inputSchema: JSONValue

    public init(name: String, title: String, description: String, inputSchema: JSONValue) {
        self.name = name
        self.title = title
        self.description = description
        self.inputSchema = inputSchema
    }

    public var json: JSONValue {
        [
            "name": .string(name),
            "title": .string(title),
            "description": .string(description),
            "inputSchema": inputSchema,
            // Every tool here reads and nothing writes, so a client can auto-approve
            // rather than prompting once per call. `openWorldHint: false` is the honest
            // answer too: the data comes from two local files and a local socket.
            "annotations": [
                "readOnlyHint": true,
                "destructiveHint": false,
                "openWorldHint": false,
            ],
        ]
    }
}

/// What a tool call produced.
///
/// `isError` is not the same thing as a JSON-RPC error, and the distinction decides
/// whether the model can recover. A missing database or a stopped daemon is a normal
/// result with `isError: true` and a sentence saying which path or which daemon — the
/// model reads it and calls `beholder_status`. A JSON-RPC error is for the call not
/// making sense at all: an unknown tool, or arguments that do not parse.
public struct MCPToolResult: Sendable {
    public let text: String
    public let isError: Bool

    public init(text: String, isError: Bool = false) {
        self.text = text
        self.isError = isError
    }

    public static func failure(_ message: String) -> MCPToolResult {
        MCPToolResult(text: message, isError: true)
    }

    public var json: JSONValue {
        [
            "content": [["type": "text", "text": .string(text)]],
            "isError": .bool(isError),
        ]
    }
}

// MARK: - Dispatch

public struct MCPHandler: Sendable {
    private let definitions: [MCPToolDefinition]
    private let invoke: @Sendable (String, JSONValue) -> MCPToolResult

    public init(
        definitions: [MCPToolDefinition],
        invoke: @escaping @Sendable (String, JSONValue) -> MCPToolResult
    ) {
        self.definitions = definitions
        self.invoke = invoke
    }

    /// Handles one line from the client, returning the line to write back, or nil when
    /// there is nothing to say (a notification).
    public func handle(line: Data) -> Data? {
        let decoded: JSONValue
        do {
            decoded = try JSONDecoder().decode(JSONValue.self, from: line)
        } catch {
            // A parse error cannot be attributed to a request id, so it is reported
            // against a null one — and it is emphatically not fatal. A single bad byte on
            // stdin must not end the session.
            return encode(
                MCPResponse(
                    id: .null,
                    error: MCPError(code: MCPError.parseError, message: "invalid JSON")
                )
            )
        }

        guard let request = MCPRequest(decoding: decoded) else {
            return encode(
                MCPResponse(
                    id: decoded["id"] ?? .null,
                    error: MCPError(
                        code: MCPError.invalidRequest, message: "not a JSON-RPC request"
                    )
                )
            )
        }

        guard let response = handle(request) else { return nil }
        return encode(response)
    }

    /// The pure core: a request in, a response or nothing out.
    public func handle(_ request: MCPRequest) -> MCPResponse? {
        // JSON-RPC forbids responding to a notification, whatever it asks for. Checked
        // before the method switch so an unknown notification cannot fall through into
        // "method not found" and put an unexpected line on the wire.
        guard let id = request.id else { return nil }

        switch request.method {
        case "initialize":
            return MCPResponse(id: id, result: identity(requestedBy: request))

        case "server/discover":
            // The 2026-07-28 revision made this the way a client learns what a server is
            // before talking to it. Strictly optional for us — a modern client falls back
            // to `initialize` on any error — but it is a few lines, and implementing it
            // means this server survives the day a client stops bothering to fall back.
            var result = identity(requestedBy: request).objectValue ?? [:]
            result["supportedVersions"] = .array(MCPVersion.supported.map { .string($0) })
            result["tools"] = .array(definitions.map(\.json))
            return MCPResponse(id: id, result: .object(result))

        case "ping":
            return MCPResponse(id: id, result: .object([:]))

        case "tools/list":
            return MCPResponse(id: id, result: ["tools": .array(definitions.map(\.json))])

        case "tools/call":
            guard let name = request.params["name"]?.stringValue else {
                return MCPResponse(
                    id: id,
                    error: MCPError(
                        code: MCPError.invalidParams, message: "tools/call needs a name"
                    )
                )
            }
            guard definitions.contains(where: { $0.name == name }) else {
                return MCPResponse(
                    id: id,
                    error: MCPError(
                        code: MCPError.invalidParams, message: "unknown tool: \(name)"
                    )
                )
            }
            let arguments = request.params["arguments"] ?? .object([:])
            return MCPResponse(id: id, result: invoke(name, arguments).json)

        default:
            return MCPResponse(
                id: id,
                error: MCPError(
                    code: MCPError.methodNotFound, message: "unknown method: \(request.method)"
                )
            )
        }
    }

    /// What this server is, and which revision it will speak back.
    private func identity(requestedBy request: MCPRequest) -> JSONValue {
        let requested = request.params["protocolVersion"]?.stringValue
        return [
            "protocolVersion": .string(MCPVersion.resolve(requested: requested)),
            "capabilities": ["tools": .object([:])],
            "serverInfo": [
                "name": .string(MCPServerInfo.name),
                "version": .string(MCPServerInfo.version),
            ],
        ]
    }

    private func encode(_ response: MCPResponse) -> Data {
        // The only failure mode an encoder has here is a non-finite Double, and nothing
        // upstream produces one — byte counts are integers and timestamps are formatted
        // as strings. Failing loudly in that impossible case beats writing a broken line.
        do {
            return try response.json.encoded()
        } catch {
            let fallback: JSONValue = [
                "jsonrpc": "2.0", "id": response.id,
                "error": [
                    "code": .integer(MCPError.internalError),
                    "message": "the server could not encode its own response",
                ],
            ]
            return (try? fallback.encoded()) ?? Data()
        }
    }
}
