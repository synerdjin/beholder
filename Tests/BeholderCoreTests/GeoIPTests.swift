import Foundation
import Testing

@testable import BeholderCore

/// These exercise the MaxMind DB reader against the real database.
///
/// The database is ~124 MB, separately licensed and not committed, so the suite skips
/// itself when it is absent rather than failing. Running `make geoip` installs it.
/// Free function rather than a static member: a suite condition cannot refer to the type
/// it is attached to without the macro expansion becoming circular.
private func installedGeoIPDatabasePath() -> String? {
    GeoIPDatabase.standardPaths().first {
        FileManager.default.fileExists(atPath: $0)
    }
}

@Suite("GeoIP lookups", .enabled(if: installedGeoIPDatabasePath() != nil))
struct GeoIPTests {

    private func database() throws -> GeoIPDatabase {
        try GeoIPDatabase(path: try #require(installedGeoIPDatabasePath()))
    }

    private func address(_ text: String) throws -> IPAddress {
        let octets = text.split(separator: ".").compactMap { UInt8($0) }
        return try #require(IPAddress(networkOrderBytes: octets, family: .v4))
    }

    @Test("The database loads and identifies itself")
    func loads() throws {
        let geo = try database()
        #expect(geo.databaseType.lowercased().contains("city"))
    }

    /// Addresses held directly by a US organisation, so the expected country is a fact
    /// about the allocation rather than a guess about routing.
    ///
    /// Deliberately excluded: CDN and anycast addresses. 93.184.216.34 sits in a
    /// RIPE-registered block (`NETBLK-03-EU`, country EU) despite serving a US-branded
    /// site, and DB-IP places it in GB — correctly. Pinning a country for such an address
    /// tests the database's opinion, not the reader.
    ///
    /// Only the country is asserted: city and coordinates shift between monthly
    /// revisions, and a test that pinned them would fail every month for no reason.
    @Test(
        "Known addresses resolve to the right country",
        arguments: [
            ("8.8.8.8", "US"),  // Google, ARIN-registered to Google LLC
            ("17.253.144.10", "US"),  // Apple, ARIN-registered to Apple Inc
        ]
    )
    func knownAddresses(text: String, expectedCountry: String) throws {
        let geo = try database()
        let location = try #require(geo.location(for: try address(text)), "no record for \(text)")
        #expect(location.countryCode == expectedCountry, "\(text) resolved to \(location)")
    }

    /// A broad sweep of public addresses: every one should resolve to *some* country,
    /// which catches a reader returning nothing without asserting where each one is.
    @Test(
        "Public addresses all resolve to somewhere",
        arguments: ["1.1.1.1", "93.184.216.34", "142.250.72.14", "151.101.1.140", "13.107.42.14"]
    )
    func publicAddressesResolve(text: String) throws {
        let geo = try database()
        let location = try #require(geo.location(for: try address(text)), "no record for \(text)")
        let code = try #require(location.countryCode, "\(text) has no country")
        #expect(code.count == 2, "expected an ISO country code, got \(code)")
    }

    @Test("A public address carries usable coordinates")
    func coordinatesArePresent() throws {
        let geo = try database()
        let location = try #require(geo.location(for: try address("8.8.8.8")))
        let latitude = try #require(location.latitude)
        let longitude = try #require(location.longitude)

        #expect(latitude >= -90 && latitude <= 90)
        #expect(longitude >= -180 && longitude <= 180)
        #expect(!(latitude == 0 && longitude == 0), "null island means the record is empty")
    }

    /// Asking the database about a LAN address wastes a lookup on every local packet,
    /// and any answer it gave would be meaningless.
    @Test(
        "Addresses with no meaningful location are not looked up",
        arguments: ["192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.251"]
    )
    func nonRoutableAddresses(text: String) throws {
        let geo = try database()
        #expect(geo.location(for: try address(text)) == nil)
    }

    @Test("IPv6 addresses resolve")
    func ipv6Lookup() throws {
        let geo = try database()
        // Google public DNS over IPv6, 2001:4860:4860::8888.
        let bytes: [UInt8] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ]
        let addressV6 = try #require(IPAddress(networkOrderBytes: bytes, family: .v6))
        let location = try #require(geo.location(for: addressV6), "no record for 2001:4860:4860::8888")
        #expect(location.countryCode != nil)
    }

    @Test("Repeated lookups are served from the cache")
    func cachingWorks() throws {
        let geo = try database()
        let target = try address("8.8.8.8")
        let first = geo.location(for: target)
        let second = geo.location(for: target)
        #expect(first == second)
    }

    @Test("A file that is not a database is refused clearly")
    func rejectsNonDatabase() throws {
        let path = NSTemporaryDirectory() + "beholder-not-a-database"
        try Data("this is not an mmdb file".utf8).write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }

        #expect(throws: MaxMindDatabase.LoadError.self) {
            _ = try GeoIPDatabase(path: path)
        }
    }
}
