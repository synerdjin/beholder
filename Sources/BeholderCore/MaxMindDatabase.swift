import Foundation

/// A reader for the MaxMind DB (`.mmdb`) file format.
///
/// Written rather than taken from a package for the same reason as everything else here:
/// the format is well specified, the code is testable, and a network monitor with no
/// third-party dependencies is easier to trust.
///
/// The file is memory-mapped and searched in place. A city-level database is around
/// 100 MB, and a long-running daemon has no business holding that resident — mapping it
/// lets the kernel page in only the handful of nodes each lookup touches.
public final class MaxMindDatabase {

    public enum LoadError: Error, CustomStringConvertible {
        case unreadable(path: String)
        case metadataNotFound
        case malformedMetadata(String)
        case unsupportedRecordSize(UInt64)

        public var description: String {
            switch self {
            case .unreadable(let path):
                return "cannot read \(path)"
            case .metadataNotFound:
                return "not a MaxMind database: the metadata marker is missing"
            case .malformedMetadata(let detail):
                return "malformed database metadata: \(detail)"
            case .unsupportedRecordSize(let size):
                return "unsupported record size \(size); expected 24, 28 or 32"
            }
        }
    }

    /// A decoded value from the data section. Only the types a geolocation database
    /// actually uses are modelled.
    public indirect enum Value: Sendable, Equatable {
        case map([String: Value])
        case array([Value])
        case string(String)
        case double(Double)
        case float(Float)
        case bytes([UInt8])
        case unsigned(UInt64)
        case signed(Int32)
        case boolean(Bool)

        public subscript(key: String) -> Value? {
            guard case .map(let contents) = self else { return nil }
            return contents[key]
        }

        public var stringValue: String? {
            guard case .string(let text) = self else { return nil }
            return text
        }

        public var doubleValue: Double? {
            switch self {
            case .double(let value): return value
            case .float(let value): return Double(value)
            case .unsigned(let value): return Double(value)
            case .signed(let value): return Double(value)
            default: return nil
            }
        }
    }

    private let data: Data
    private let nodeCount: UInt32
    private let recordSize: UInt32
    private let ipVersion: UInt16
    private let searchTreeSize: Int
    public let databaseType: String
    public let buildEpoch: UInt64

    /// The marker that precedes the metadata block, per the format specification.
    private static let metadataMarker: [UInt8] =
        [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)

    public init(path: String) throws {
        guard
            let mapped = try? Data(
                contentsOf: URL(fileURLWithPath: path), options: .alwaysMapped
            )
        else { throw LoadError.unreadable(path: path) }
        self.data = mapped

        guard let markerRange = Self.findMetadataMarker(in: mapped) else {
            throw LoadError.metadataNotFound
        }

        let decoder = Decoder(data: mapped, dataSectionStart: markerRange.upperBound)
        let metadata = try decoder.decode(at: markerRange.upperBound).value

        guard
            case .unsigned(let nodes) = metadata["node_count"] ?? .unsigned(0),
            case .unsigned(let bits) = metadata["record_size"] ?? .unsigned(0),
            case .unsigned(let version) = metadata["ip_version"] ?? .unsigned(0)
        else {
            throw LoadError.malformedMetadata("missing node_count, record_size or ip_version")
        }
        guard bits == 24 || bits == 28 || bits == 32 else {
            throw LoadError.unsupportedRecordSize(bits)
        }

        self.nodeCount = UInt32(nodes)
        self.recordSize = UInt32(bits)
        self.ipVersion = UInt16(version)
        self.searchTreeSize = Int(nodes) * Int(bits) * 2 / 8
        self.databaseType = metadata["database_type"]?.stringValue ?? "unknown"
        if case .unsigned(let epoch) = metadata["build_epoch"] ?? .unsigned(0) {
            self.buildEpoch = epoch
        } else {
            self.buildEpoch = 0
        }
    }

    /// Looks up an address, returning the decoded record or nil when the database has no
    /// entry for it.
    public func lookup(_ address: IPAddress) -> Value? {
        // An IPv6 database stores IPv4 under the v4-mapped prefix, so searching the
        // 128-bit mapped form works for both. A v4-only database is searched directly.
        let bytes: [UInt8]
        if ipVersion == 6 && address.family == .v4 {
            bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] + address.networkOrderBytes
        } else {
            bytes = address.networkOrderBytes
        }

        var node: UInt32 = 0
        for byte in bytes {
            for shift in stride(from: 7, through: 0, by: -1) {
                guard node < nodeCount else { break }
                let bit = (byte >> UInt8(shift)) & 1
                node = record(at: node, right: bit == 1)
            }
            if node >= nodeCount { break }
        }

        // Exactly nodeCount means "no data here"; anything larger points into the data
        // section. Falling off the end of the address without resolving means the tree
        // is malformed, which is treated the same as no data.
        guard node > nodeCount else { return nil }

        let offset = searchTreeSize + Int(node - nodeCount)
        guard offset >= 0, offset < data.count else { return nil }

        let decoder = Decoder(data: data, dataSectionStart: searchTreeSize + 16)
        return try? decoder.decode(at: offset).value
    }

    /// Reads one half of a node in the search tree.
    private func record(at node: UInt32, right: Bool) -> UInt32 {
        let base = Int(node) * Int(recordSize) * 2 / 8
        guard base >= 0, base + Int(recordSize) * 2 / 8 <= data.count else { return nodeCount }

        switch recordSize {
        case 24:
            let start = base + (right ? 3 : 0)
            return UInt32(data[start]) << 16 | UInt32(data[start + 1]) << 8
                | UInt32(data[start + 2])

        case 28:
            // The middle byte is shared: its high nibble extends the left record and its
            // low nibble extends the right.
            let middle = data[base + 3]
            if right {
                return UInt32(middle & 0x0F) << 24 | UInt32(data[base + 4]) << 16
                    | UInt32(data[base + 5]) << 8 | UInt32(data[base + 6])
            }
            return UInt32(middle >> 4) << 24 | UInt32(data[base]) << 16
                | UInt32(data[base + 1]) << 8 | UInt32(data[base + 2])

        default:  // 32
            let start = base + (right ? 4 : 0)
            return UInt32(data[start]) << 24 | UInt32(data[start + 1]) << 16
                | UInt32(data[start + 2]) << 8 | UInt32(data[start + 3])
        }
    }

    private static func findMetadataMarker(in data: Data) -> Range<Int>? {
        let marker = metadataMarker
        // The specification caps the metadata section at 128 KiB from the end.
        let searchStart = max(0, data.count - 128 * 1024)
        guard data.count >= marker.count else { return nil }

        var index = data.count - marker.count
        while index >= searchStart {
            var matched = true
            for offset in 0..<marker.count where data[index + offset] != marker[offset] {
                matched = false
                break
            }
            if matched { return index..<(index + marker.count) }
            index -= 1
        }
        return nil
    }
}

// MARK: - Data section decoding

extension MaxMindDatabase {
    /// Decodes the typed, self-describing values in the data section.
    struct Decoder {
        let data: Data
        let dataSectionStart: Int

        /// Guards against a corrupt file sending the decoder round in circles.
        private static let maximumDepth = 32

        func decode(at offset: Int, depth: Int = 0) throws -> (value: Value, next: Int) {
            guard depth < Self.maximumDepth else {
                throw LoadError.malformedMetadata("value nesting is too deep")
            }
            guard offset >= 0, offset < data.count else {
                throw LoadError.malformedMetadata("offset \(offset) is outside the file")
            }

            let control = data[offset]
            var type = Int(control >> 5)
            var cursor = offset + 1

            // Type 0 means the real type is in the following byte, plus seven.
            if type == 0 {
                guard cursor < data.count else {
                    throw LoadError.malformedMetadata("truncated extended type")
                }
                type = Int(data[cursor]) + 7
                cursor += 1
            }

            // Pointers encode their payload in the size field, so they are read before
            // the ordinary size decoding below.
            if type == 1 {
                let sizeBits = Int((control >> 3) & 0x03)
                var pointer = Int(control & 0x07)
                switch sizeBits {
                case 0:
                    pointer = pointer << 8 | Int(data[cursor])
                    cursor += 1
                case 1:
                    pointer = pointer << 16 | Int(data[cursor]) << 8 | Int(data[cursor + 1])
                    pointer += 2048
                    cursor += 2
                case 2:
                    pointer = pointer << 24 | Int(data[cursor]) << 16
                        | Int(data[cursor + 1]) << 8 | Int(data[cursor + 2])
                    pointer += 526_336
                    cursor += 3
                default:
                    pointer = Int(data[cursor]) << 24 | Int(data[cursor + 1]) << 16
                        | Int(data[cursor + 2]) << 8 | Int(data[cursor + 3])
                    cursor += 4
                }
                // A pointer's target is read, but the cursor continues after the pointer
                // itself — the target is elsewhere in the file.
                let target = try decode(at: dataSectionStart + pointer, depth: depth + 1)
                return (target.value, cursor)
            }

            var size = Int(control & 0x1F)
            switch size {
            case 29:
                size = 29 + Int(data[cursor])
                cursor += 1
            case 30:
                size = 285 + Int(data[cursor]) << 8 + Int(data[cursor + 1])
                cursor += 2
            case 31:
                size = 65821 + Int(data[cursor]) << 16 + Int(data[cursor + 1]) << 8
                    + Int(data[cursor + 2])
                cursor += 3
            default:
                break
            }

            guard cursor + size <= data.count || type == 7 || type == 11 else {
                throw LoadError.malformedMetadata("value of \(size) bytes runs past the file")
            }

            switch type {
            case 2:  // UTF-8 string
                let bytes = [UInt8](data[cursor..<(cursor + size)])
                return (.string(String(decoding: bytes, as: UTF8.self)), cursor + size)

            case 3:  // double
                let bits = readUnsigned(at: cursor, count: 8)
                return (.double(Double(bitPattern: bits)), cursor + 8)

            case 4:  // bytes
                return (.bytes([UInt8](data[cursor..<(cursor + size)])), cursor + size)

            case 5, 6, 9, 10:  // uint16, uint32, uint64, uint128
                return (.unsigned(readUnsigned(at: cursor, count: size)), cursor + size)

            case 7:  // map
                var contents: [String: Value] = [:]
                var position = cursor
                for _ in 0..<size {
                    let key = try decode(at: position, depth: depth + 1)
                    position = key.next
                    let value = try decode(at: position, depth: depth + 1)
                    position = value.next
                    if let name = key.value.stringValue {
                        contents[name] = value.value
                    }
                }
                return (.map(contents), position)

            case 8:  // int32
                let raw = readUnsigned(at: cursor, count: size)
                return (.signed(Int32(bitPattern: UInt32(truncatingIfNeeded: raw))), cursor + size)

            case 11:  // array
                var elements: [Value] = []
                elements.reserveCapacity(size)
                var position = cursor
                for _ in 0..<size {
                    let element = try decode(at: position, depth: depth + 1)
                    elements.append(element.value)
                    position = element.next
                }
                return (.array(elements), position)

            case 14:  // boolean, whose value lives in the size field
                return (.boolean(size != 0), cursor)

            case 15:  // float
                let bits = UInt32(truncatingIfNeeded: readUnsigned(at: cursor, count: 4))
                return (.float(Float(bitPattern: bits)), cursor + 4)

            default:
                // Types Beholder does not need (cache containers, end markers) are
                // skipped rather than treated as corruption.
                return (.unsigned(0), cursor + size)
            }
        }

        private func readUnsigned(at offset: Int, count: Int) -> UInt64 {
            var value: UInt64 = 0
            for index in 0..<min(count, 8) where offset + index < data.count {
                value = value << 8 | UInt64(data[offset + index])
            }
            return value
        }
    }
}
