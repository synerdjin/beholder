import Foundation

/// A JSON document as a value.
///
/// MCP carries tool arguments and JSON Schemas as arbitrary JSON, and Swift's `Codable`
/// wants a concrete type at both ends. Rather than take a dependency for this — the
/// project has none, and the format is small enough to write down — the shapes MCP
/// actually needs are spelled out here.
///
/// Integers are a separate case from doubles on purpose. A JSON Schema saying
/// `"minimum": 1` must not encode as `1.0`: some clients validate the schema itself, and
/// a float where an integer belongs is the kind of thing that fails far away from here.
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case integer(Int)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "not a JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

// MARK: - Reading

extension JSONValue {
    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var intValue: Int? {
        switch self {
        case .integer(let value): return value
        // A client that sends `25.0` for a limit means 25. Accepting it costs nothing and
        // refusing it would be a confusing error about a number the model got right.
        case .double(let value) where value == value.rounded(): return Int(value)
        default: return nil
        }
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// Member lookup on an object, or nil for anything else. Never throws: callers are
    /// reading model-supplied arguments, where "absent" and "wrong shape" both mean
    /// "fall back to the default".
    public subscript(key: String) -> JSONValue? {
        guard case .object(let members) = self else { return nil }
        return members[key]
    }
}

// MARK: - Writing

extension JSONValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}

extension JSONValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) { self = .integer(value) }
}

extension JSONValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}

extension JSONValue: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
}

extension JSONValue: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
}

extension JSONValue {
    /// Builds an object, dropping members whose value is nil.
    ///
    /// This is what keeps result rows narrow. Most enrichment fields — hostname, country,
    /// operator, company — are null on most rows, and a key with a null value costs
    /// tokens in every row to say nothing.
    public static func object(omittingNils members: [String: JSONValue?]) -> JSONValue {
        var kept: [String: JSONValue] = [:]
        for (key, value) in members {
            guard let value, !value.isNull else { continue }
            kept[key] = value
        }
        return .object(kept)
    }

    /// The encoder used for everything on the wire.
    ///
    /// Not pretty-printed, which is what guarantees the stdio framing rule: a newline
    /// inside a string is escaped as the two characters `\n`, so an encoded message can
    /// never contain a raw newline and can always be written as one line.
    ///
    /// Slashes are left unescaped because process paths and URLs are full of them and
    /// `\/` doubles their cost for no benefit.
    ///
    /// Keys are sorted because a Swift dictionary has no order, and without this the same
    /// question asked twice produces the same data with the members shuffled — which reads
    /// as a different answer, defeats any caching the client does on identical results, and
    /// makes a test that compares output flaky for no reason.
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        return encoder
    }

    public func encoded() throws -> Data {
        try JSONValue.encoder().encode(self)
    }
}
