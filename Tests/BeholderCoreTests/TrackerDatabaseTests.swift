import Foundation
import Testing

@testable import BeholderCore

private func installedTrackerDatabasePath() -> String? {
    TrackerDatabase.standardPaths().first {
        FileManager.default.fileExists(atPath: $0)
    }
}

/// The naming signal is pure logic and needs no database.
@Suite("Hostname naming signals")
struct NamingSignalTests {

    /// These are the endpoints from real capture transcripts that no tracker database
    /// recognises, because Tracker Radar is built from crawling websites and knows
    /// nothing about native application telemetry.
    @Test(
        "Collection-related words in a hostname are recognised",
        arguments: [
            ("telemetry.individual.githubcopilot.com", "telemetry"),
            ("crash.steampowered.com", "crash"),
            ("browser-intake-us5-datadoghq.com", "intake"),
            ("http-intake.logs.us5.datadoghq.com", "intake"),
            ("mobile.events.data.microsoft.com", nil),  // "events" is too broad to claim
            ("metrics.example.com", "metrics"),
            ("o12345.ingest.sentry.io", "sentry"),
        ]
    )
    func signalsAreFound(hostName: String, expected: String?) {
        #expect(TrackerDatabase.namingSignal(in: hostName) == expected)
    }

    /// A signal that fires on innocent names is worse than no signal, so matching is on
    /// whole labels and hyphen-separated parts rather than substrings.
    @Test(
        "Innocent hostnames are not flagged",
        arguments: [
            "api.anthropic.com",
            "imap.gmail.com",
            "www.facebook.com",
            "mycrashpad.example.com",  // contains "crash" but is not a crash endpoint
            "statsmodels.example.org",  // contains "stats"
            "github.com",
        ]
    )
    func innocentNamesAreNotFlagged(hostName: String) {
        #expect(
            TrackerDatabase.namingSignal(in: hostName) == nil,
            "\(hostName) was wrongly flagged"
        )
    }
}

/// These need the fetched index, so they skip when it is absent. `make trackers` installs it.
@Suite("Tracker identification", .enabled(if: installedTrackerDatabasePath() != nil))
struct TrackerDatabaseTests {

    private func database() throws -> TrackerDatabase {
        try TrackerDatabase(path: try #require(installedTrackerDatabasePath()))
    }

    @Test("The index loads and identifies its source")
    func loads() throws {
        let database = try self.database()
        #expect(database.source.contains("Tracker Radar"))
        #expect(database.domainCount > 1000)
    }

    /// Subdomains resolve through their parent, which is how a CDN edge host gets
    /// attributed to the company that runs it.
    @Test(
        "Hosts are attributed to the company that operates them",
        arguments: [
            ("static.xx.fbcdn.net", "Facebook"),
            ("graph.facebook.com", "Facebook"),
            ("mobile.events.data.microsoft.com", "Microsoft"),
            ("www.google-analytics.com", "Google"),
        ]
    )
    func ownershipIsResolved(hostName: String, expectedOwnerFragment: String) throws {
        let database = try self.database()
        let classification = database.classify(hostName: hostName)
        let owner = try #require(classification.owner, "\(hostName) was not recognised")
        #expect(
            owner.localizedCaseInsensitiveContains(expectedOwnerFragment),
            "\(hostName) resolved to \(owner)"
        )
        #expect(classification.isRecognised)
    }

    /// Matching walks whole labels, so a domain that merely ends in the same letters is
    /// not mistaken for a subdomain of it.
    @Test("A lookalike domain is not matched")
    func lookalikeDomainsAreNotMatched() throws {
        let database = try self.database()
        #expect(database.classify(hostName: "notfacebook.com").owner == nil)
        #expect(database.classify(hostName: "facebook.com.evil.example").owner == nil)
    }

    /// Being unrecognised is the ordinary case for most of the internet and says nothing
    /// bad about a host.
    @Test("An unknown host is simply unrecognised")
    func unknownHostsAreUnrecognised() throws {
        let database = try self.database()
        let classification = database.classify(hostName: "api.anthropic.com")
        #expect(!classification.isRecognised)
        #expect(classification.categories.isEmpty)
    }

    /// The two signals are independent: a host the database has never heard of can still
    /// announce its purpose in its name, which is the gap this pairing exists to cover.
    @Test("Naming signals apply to hosts no database recognises")
    func namingSignalWorksWithoutOwnership() throws {
        let database = try self.database()
        let classification = database.classify(hostName: "telemetry.individual.githubcopilot.com")
        #expect(!classification.isRecognised)
        #expect(classification.namingSignal == "telemetry")
        #expect(!classification.isEmpty)
    }

    @Test("Repeated lookups are cached")
    func cachingWorks() throws {
        let database = try self.database()
        let first = database.classify(hostName: "graph.facebook.com")
        let second = database.classify(hostName: "graph.facebook.com")
        #expect(first == second)
    }
}
