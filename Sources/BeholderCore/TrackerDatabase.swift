import Foundation

/// What is known about the far end of a connection, beyond its name.
///
/// Deliberately descriptive. Beholder does not decide whether a connection is legitimate,
/// because it cannot: `api.anthropic.com` is an application doing its job, and
/// `browser-intake-us5-datadoghq.com` is telemetry, yet both are an app talking to its
/// vendor over TLS. Only the person using the machine can judge which they want. So this
/// reports who operates a host and what the host is called, and stops there.
public struct HostClassification: Sendable, Hashable, Codable {
    /// The company operating this host, when a tracker database recognises it.
    public let owner: String?
    /// Categories from the tracker database, such as Analytics or Advertising.
    public let categories: [String]
    /// Which parent domain matched, so a match on `facebook.com` for
    /// `edge-star.xx.fbcdn.net` can be seen for what it is.
    public let matchedDomain: String?
    /// A word in the hostname that operators conventionally use for data collection —
    /// "telemetry", "crash", "metrics". A fact about the *name*, not about behaviour, and
    /// presented as such.
    public let namingSignal: String?

    public init(
        owner: String? = nil,
        categories: [String] = [],
        matchedDomain: String? = nil,
        namingSignal: String? = nil
    ) {
        self.owner = owner
        self.categories = categories
        self.matchedDomain = matchedDomain
        self.namingSignal = namingSignal
    }

    /// True when a database identified the operator. Everything else is *unrecognised*,
    /// which is not the same as suspicious — most unrecognised hosts are ordinary CDN
    /// edges — and the interface is careful not to imply otherwise.
    public var isRecognised: Bool { owner != nil }

    public var isEmpty: Bool { owner == nil && namingSignal == nil }
}

/// Identifies who operates a host, from a locally installed tracker database.
///
/// Not thread-safe; confine to one queue.
public final class TrackerDatabase {
    private struct Index: Decodable {
        struct Entry: Decodable {
            let o: String
            let c: [String]?
            let p: Double?
        }
        let version: Int
        let generated: String
        let source: String
        let entries: [String: Entry]
    }

    private let index: Index
    private var cache: [String: HostClassification] = [:]

    public var source: String { index.source }
    public var generated: String { index.generated }
    public var domainCount: Int { index.entries.count }

    /// Words operators conventionally use when naming a data-collection endpoint.
    ///
    /// This exists because Tracker Radar is built by crawling websites: it covers
    /// third-party web trackers thoroughly and native application telemetry not at all.
    /// `crash.steampowered.com` and `telemetry.individual.githubcopilot.com` appear in no
    /// tracker list, yet both announce their purpose in the hostname. Reporting that is
    /// honest — it says what the operator called the host, and claims nothing more.
    static let namingSignals = [
        "telemetry", "analytics", "metrics", "crashlytics", "crash-report", "crashreport",
        "crash", "beacon", "tracking", "tracker", "collector", "intake", "diagnostics",
        "logging", "logs-intake", "stats", "insights", "sentry", "datadog",
    ]

    public static func standardPaths() -> [String] {
        [
            "/usr/local/share/beholder/trackers.json",
            FileManager.default.currentDirectoryPath + "/Resources/trackers/trackers.json",
        ]
    }

    public static func loadFromStandardPaths() -> TrackerDatabase? {
        for path in standardPaths() where FileManager.default.fileExists(atPath: path) {
            if let database = try? TrackerDatabase(path: path) { return database }
        }
        return nil
    }

    public init(path: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        self.index = try JSONDecoder().decode(Index.self, from: data)
    }

    public func classify(hostName: String) -> HostClassification {
        let name = hostName.lowercased()
        if let cached = cache[name] { return cached }

        let result = HostClassification(
            owner: ownership(for: name)?.owner,
            categories: ownership(for: name)?.categories ?? [],
            matchedDomain: ownership(for: name)?.domain,
            namingSignal: Self.namingSignal(in: name)
        )
        cache[name] = result
        return result
    }

    /// Walks up the labels, most specific first, so `graph.facebook.com` matches an entry
    /// for `facebook.com` while `notfacebook.com` does not.
    private func ownership(
        for name: String
    ) -> (owner: String, categories: [String], domain: String)? {
        let labels = name.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return nil }

        for start in 0..<(labels.count - 1) {
            let candidate = labels[start...].joined(separator: ".")
            if let entry = index.entries[candidate] {
                return (entry.o, entry.c ?? [], candidate)
            }
        }
        return nil
    }

    /// Looks for a collection-related word as a whole label, not a substring. Matching
    /// substrings would flag `mycrashpad.example.com` and anything containing "stats",
    /// and a signal that fires on innocent names is worse than no signal.
    static func namingSignal(in name: String) -> String? {
        let labels = name.lowercased().split(separator: ".").map(String.init)
        for label in labels {
            // Labels are frequently compound: browser-intake-us5, mobile-metrics-1.
            let parts = label.split(whereSeparator: { $0 == "-" || $0 == "_" }).map(String.init)
            for signal in namingSignals where parts.contains(signal) || label == signal {
                return signal
            }
        }
        return nil
    }
}
