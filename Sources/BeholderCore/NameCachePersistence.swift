import Foundation

/// One remembered address-to-name mapping, in a form that survives a restart.
public struct PersistedName: Codable, Sendable, Equatable {
    public let address: String
    public let name: String
    public let expiresAt: Date
    public let source: String

    public init(address: String, name: String, expiresAt: Date, source: String) {
        self.address = address
        self.name = name
        self.expiresAt = expiresAt
        self.source = source
    }
}

extension NameResolutionCache {
    /// Why persistence matters more than it looks: macOS caches DNS answers for hours, so
    /// a freshly started capture sees almost no lookups — the machine already knows where
    /// everything is and simply connects. Names are therefore learned slowly and lost
    /// completely on every restart, which is why coverage sat around a fifth of flows.
    /// Carrying the cache across runs turns each restart into a warm start.
    public func persistableEntries(at now: Date = Date()) -> [PersistedName] {
        entriesForPersistence.compactMap { address, entry in
            guard entry.expiresAt > now else { return nil }
            return PersistedName(
                address: address.description,
                name: entry.name,
                expiresAt: entry.expiresAt,
                source: entry.source.rawValue
            )
        }
    }

    /// Reloads previously learned names, discarding anything already expired.
    public func restore(_ entries: [PersistedName], at now: Date = Date()) {
        for entry in entries {
            guard entry.expiresAt > now, let address = IPAddress(text: entry.address) else {
                continue
            }
            adopt(
                name: entry.name,
                for: address,
                expiresAt: entry.expiresAt,
                source: NameSource(rawValue: entry.source) ?? .reverseLookup
            )
        }
    }

    /// Writes the cache to disk. Failure is reported but never fatal: losing remembered
    /// names costs coverage on the next run, nothing more.
    @discardableResult
    public func save(to url: URL, at now: Date = Date()) -> Bool {
        let entries = persistableEntries(at: now)
        guard !entries.isEmpty else { return false }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard let data = try? encoder.encode(entries) else { return false }

        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        // Resolved names are a record of everywhere this machine has been, so the file
        // gets the same treatment as the transcript and the socket.
        guard (try? data.write(to: url, options: [.atomic])) != nil else { return false }
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path
        )
        return true
    }

    @discardableResult
    public func load(from url: URL, at now: Date = Date()) -> Int {
        guard let data = try? Data(contentsOf: url) else { return 0 }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let entries = try? decoder.decode([PersistedName].self, from: data) else {
            return 0
        }
        restore(entries, at: now)
        return count
    }
}
