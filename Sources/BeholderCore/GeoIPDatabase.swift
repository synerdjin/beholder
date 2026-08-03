import Foundation

/// Where an address is, as far as a geolocation database is willing to say.
public struct GeoLocation: Sendable, Hashable, Codable {
    public let countryCode: String?
    public let countryName: String?
    public let city: String?
    public let latitude: Double?
    public let longitude: Double?

    public init(
        countryCode: String?, countryName: String?, city: String?,
        latitude: Double?, longitude: Double?
    ) {
        self.countryCode = countryCode
        self.countryName = countryName
        self.city = city
        self.latitude = latitude
        self.longitude = longitude
    }

    public var hasCoordinates: Bool { latitude != nil && longitude != nil }

    /// "Amsterdam, NL", or whatever part of that is actually known.
    public var description: String {
        [city, countryCode ?? countryName]
            .compactMap { $0 }
            .joined(separator: ", ")
    }
}

/// Resolves addresses to places, from a local database.
///
/// Entirely offline. A tool built to show you who your machine talks to would have no
/// business shipping every address you contact to a geolocation API — the lookup would
/// leak exactly the information it is meant to reveal.
///
/// Not thread-safe; confine to one queue, as with `FlowTable`.
public final class GeoIPDatabase {
    private let database: MaxMindDatabase
    private var cache: [IPAddress: GeoLocation?] = [:]

    /// Addresses repeat constantly — one host is typically many flows — and every miss
    /// pages in tree nodes, so results are remembered, including the misses.
    private static let maximumCacheEntries = 32768

    public var databaseType: String { database.databaseType }

    /// Standard locations, newest first. Returns nil when no database is installed,
    /// which is a normal state: geolocation is optional and separately licensed.
    public static func standardPaths() -> [String] {
        [
            "/usr/local/share/beholder/geoip.mmdb",
            FileManager.default.currentDirectoryPath + "/Resources/geoip/geoip.mmdb",
        ]
    }

    public static func loadFromStandardPaths() -> GeoIPDatabase? {
        for path in standardPaths() where FileManager.default.fileExists(atPath: path) {
            if let database = try? GeoIPDatabase(path: path) { return database }
        }
        return nil
    }

    public init(path: String) throws {
        self.database = try MaxMindDatabase(path: path)
    }

    public func location(for address: IPAddress) -> GeoLocation? {
        // Private, loopback and link-local addresses have no location, and asking the
        // database wastes a lookup on every LAN packet.
        guard address.isGloballyRoutable else { return nil }

        if let cached = cache[address] { return cached }

        let resolved = resolve(address)
        if cache.count >= Self.maximumCacheEntries { cache.removeAll(keepingCapacity: true) }
        cache[address] = resolved
        return resolved
    }

    private func resolve(_ address: IPAddress) -> GeoLocation? {
        guard let record = database.lookup(address) else { return nil }

        let country = record["country"] ?? record["registered_country"]
        let location = record["location"]

        // Databases carry names in several languages; English is what the interface uses.
        let countryName = country?["names"]?["en"]?.stringValue
        let city = record["city"]?["names"]?["en"]?.stringValue

        let result = GeoLocation(
            countryCode: country?["iso_code"]?.stringValue,
            countryName: countryName,
            city: city,
            latitude: location?["latitude"]?.doubleValue,
            longitude: location?["longitude"]?.doubleValue
        )

        // A record with nothing usable in it is the same as no record.
        guard result.countryCode != nil || result.countryName != nil || result.hasCoordinates
        else { return nil }
        return result
    }
}
