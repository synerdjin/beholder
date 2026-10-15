import Foundation

/// How a measured quantity compares with what a person would call normal.
///
/// `unmeasured` sorts *below* `good` on purpose, and is never drawn as good. Nil is not
/// zero for anything measured here, and "we did not look" rendered green would be the
/// reassuring kind of wrong this project refuses everywhere else — the same reason
/// `ProtocolSniffer` never guesses `encrypted`.
public enum HealthRating: Int, Comparable, Sendable, CaseIterable {
    case unmeasured
    case good
    case fair
    case poor

    public static func < (lhs: HealthRating, rhs: HealthRating) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// The word shown beside a figure, chosen for someone who does not know what a
    /// millisecond of round trip feels like.
    public var label: String {
        switch self {
        case .unmeasured: return "Not measured"
        case .good: return "Good"
        case .fair: return "Okay"
        case .poor: return "Struggling"
        }
    }
}

/// The fixed thresholds behind every rating Beholder shows. The only copy of them.
///
/// Fixed rather than learnt from this machine's history, so that "struggling" means the
/// same thing on a first run as on the hundredth, and so that a network that has always
/// been bad is not graded against itself into looking normal. They are rules of thumb, not
/// physics; the README's "Reading the Overview" section gives the reason for each, and
/// `HealthScaleTests` pins every boundary so a change to one is a decision rather than a
/// drift.
public enum HealthScale {
    /// Three bands over one quantity where more is worse. A value at or below `good` is
    /// good, at or below `fair` is okay, and anything above is struggling.
    public struct Bands: Sendable, Equatable {
        public let good: Double
        public let fair: Double

        public init(good: Double, fair: Double) {
            precondition(good < fair, "bands must rise")
            self.good = good
            self.fair = fair
        }

        public func rate(_ value: Double?) -> HealthRating {
            guard let value, value.isFinite else { return .unmeasured }
            if value <= good { return .good }
            if value <= fair { return .fair }
            return .poor
        }

        /// Where a scale drawn over these bands should end. Twice the upper limit leaves
        /// the struggling band as wide as the other two together, so a bad value has
        /// visibly somewhere to sit without the good band shrinking to a sliver.
        public var displayMaximum: Double { fair * 2 }
    }

    /// Typical round trip, in milliseconds. Under 50 ms nothing interactive feels slow;
    /// past about 150 ms calls start to talk over each other and pages visibly hesitate —
    /// the ITU-T G.114 figure for one-way voice delay sits in the same place.
    public static let responseTime = Bands(good: 50, fair: 150)

    /// Retransmitted segments as a share of segments sent. A healthy wired or Wi-Fi path
    /// repeats well under 1%; TCP's throughput collapses quickly past a few percent, which
    /// is what a person experiences as a download that stalls.
    public static let resent = Bands(good: 0.01, fair: 0.03)

    /// Connection attempts that never got an answer, as a share of attempts. The odd
    /// timeout is a dead host somewhere; one in ten is the path failing.
    public static let unanswered = Bands(good: 0.02, fair: 0.10)

    /// Per-connection jitter, in milliseconds. Real-time audio buffers absorb about 30 ms
    /// before it becomes audible.
    public static let jitter = Bands(good: 10, fair: 30)

    /// Probe limits. The first hop is inside the house and has no excuse for more than a
    /// few tens of milliseconds; distant anchors get the same allowance as `responseTime`.
    /// Loss is real loss here, unlike retransmissions: a probe that got no reply is a
    /// reply that did not arrive.
    public static let gatewayMaximumLoss = 0.02
    public static let gatewayMaximumMedianMs = 25.0
    public static let anchorMaximumLoss = 0.02
    public static let anchorMaximumMedianMs = 150.0

    /// Below these, a rate is a coin toss and is not rated at all. Two repeats in twenty
    /// segments is 10% and says nothing; rating it would call an idle machine broken.
    public static let minimumSegments: UInt64 = 100
    public static let minimumAttempts = 10

    /// Coverage below which every latency rating carries a caveat, matching the threshold
    /// `Reliability.caveats` uses for the long view.
    public static let coverageCaveat = 0.75
}

/// One area of the network, rated, with the reason in plain words and the measurement
/// behind it for anyone who wants it.
public struct HealthFinding: Sendable, Equatable, Identifiable {
    /// Ordered by how precisely each one locates a problem. When several are bad, the
    /// headline names the first: "your router" is more useful than "things are slow".
    public enum Area: Int, Sendable, Comparable, CaseIterable {
        case localNetwork
        case internet
        case responseTime
        case unanswered
        case resent

        public static func < (lhs: Area, rhs: Area) -> Bool { lhs.rawValue < rhs.rawValue }

        public var title: String {
            switch self {
            case .localNetwork: return "Your Wi-Fi and router"
            case .internet: return "The internet beyond your router"
            case .responseTime: return "Response time"
            case .unanswered: return "Connections that failed to start"
            case .resent: return "Data sent again"
            }
        }

        /// What the area means, for the "What does this mean?" disclosure.
        public var explanation: String {
            switch self {
            case .localNetwork:
                return """
                    Beholder sends a small ping to your router every 30 seconds. If those go \
                    unanswered or come back slowly, the problem is inside your home — weak \
                    Wi-Fi, interference, or the router itself — not your internet provider.
                    """
            case .internet:
                return """
                    Beholder also pings a few well-known public servers. Comparing them with \
                    your router tells apart a problem in your home from one at your \
                    internet provider or beyond.
                    """
            case .responseTime:
                return """
                    How long it takes for a reply to come back from the sites and apps you \
                    are using. Lower is better. Under 50 ms feels instant; above 150 ms, \
                    pages hesitate and video calls lag.
                    """
            case .unanswered:
                return """
                    How often this Mac tried to open a connection and heard nothing back at \
                    all within five seconds. A site that refuses is not counted — that is \
                    the site's choice, not your network failing.
                    """
            case .resent:
                return """
                    When a piece of data is not acknowledged in time, it is sent again. A \
                    little of this is normal. A lot means the connection is unreliable and \
                    downloads stall. This counts repeats; it cannot see which packets were \
                    actually lost, so it is not a "packet loss" figure.
                    """
            }
        }
    }

    public var id: Area { area }
    public let area: Area
    public let rating: HealthRating
    /// The plain-language sentence. Written for someone who does not know what TCP is.
    public let sentence: String
    /// The measurement behind it, in the terms the Quality tab uses.
    public let detail: String
    /// The measured value and the bands it was rated against, for drawing a scale. Nil for
    /// pass-or-fail findings, which have no single quantity to place.
    public let value: Double?
    public let bands: HealthScale.Bands?
    /// Something worth knowing that the rating deliberately leaves out, said beside it so
    /// that leaving it out is visible rather than silent.
    public var aside: String? = nil
}

/// Everything the Overview says, decided in Core where a test can reach it.
///
/// Deliberately not a score. `Reliability.verdict` refuses one because a single number
/// throws away the caveats that make it mean anything, and the same holds here: the
/// headline names the worst *area*, and each area keeps its own reason, its own
/// measurement and its own window.
public struct HealthAssessment: Sendable, Equatable {
    public let findings: [HealthFinding]
    /// The worst rating among the findings, or `unmeasured` when none could be rated.
    public let overall: HealthRating
    public let headline: String
    /// Present whenever the latency figures cover too little of the traffic to stand on
    /// their own. Caveats travel with the data.
    public let coverageNote: String?
    /// Whether probe results were available. Without them the Overview offers `--probe`,
    /// since nothing passive can say whether the trouble is at home or upstream.
    public let hasProbes: Bool
    /// False when the daemon runs with `--no-quality`, so the screen can say measurement is
    /// off rather than that nothing was found.
    public let qualityMeasured: Bool

    public static let notEnoughHeadline = "Not enough traffic to judge yet."
    public static let normalHeadline = "Everything looks normal."
    public static let measurementOffHeadline =
        "Connection quality isn't being measured, so there is nothing to judge."

    /// Rates live statistics and, when the daemon was probing, the recent probe summary.
    public static func make(statistics: WireStatistics, probes: ProbeSummary?) -> HealthAssessment {
        var findings: [HealthFinding] = []

        let probeFindings = probes.map(Self.probeFindings) ?? []
        findings.append(contentsOf: probeFindings)

        let qualityMeasured = statistics.measuredFlowCount != nil
        if qualityMeasured {
            findings.append(responseTime(statistics))
            findings.append(unanswered(statistics))
            findings.append(resent(statistics))
        }

        let overall = findings.map(\.rating).max() ?? .unmeasured
        let headline: String
        switch overall {
        case .unmeasured:
            headline = qualityMeasured || !probeFindings.isEmpty
                ? notEnoughHeadline : measurementOffHeadline
        case .good:
            headline = normalHeadline
        case .fair, .poor:
            // The worst rating wins; among equals, the area that locates the problem best.
            let worst = findings
                .filter { $0.rating == overall }
                .min { $0.area < $1.area }
            headline = worst?.sentence ?? normalHeadline
        }

        return HealthAssessment(
            findings: findings,
            overall: overall,
            headline: headline,
            coverageNote: coverageNote(statistics),
            hasProbes: !probeFindings.isEmpty,
            qualityMeasured: qualityMeasured
        )
    }

    // MARK: Areas

    static func responseTime(_ statistics: WireStatistics) -> HealthFinding {
        let bands = HealthScale.responseTime
        let value = statistics.medianRttMs
        let rating = bands.rate(value)
        let shown = value.map { "about \(Int($0.rounded())) ms" } ?? ""
        let sentence: String
        switch rating {
        case .unmeasured: sentence = "No connection has been timed yet."
        case .good: sentence = "Replies come back quickly — \(shown)."
        case .fair:
            sentence = "Replies are a little slow — \(shown). Most things work; video calls may lag."
        case .poor: sentence = "Pages and apps may feel slow: replies take \(shown)."
        }
        var detail = "Median smoothed round trip "
            + (value.map { formatMs($0) } ?? "—")
        if let floor = statistics.minRttMs { detail += ", floor \(formatMs(floor))" }
        if let flows = statistics.measuredFlowCount {
            detail += ", across \(pluralised(flows, "measured connection"))."
        }
        return HealthFinding(
            area: .responseTime, rating: rating, sentence: sentence, detail: detail,
            value: value, bands: bands)
    }

    static func unanswered(_ statistics: WireStatistics) -> HealthFinding {
        let bands = HealthScale.unanswered
        // Only connections to the internet are rated. A device at home that does not answer
        // — most often an iPhone asleep while the Mac keeps trying to sync with it — says
        // nothing about whether websites open, which is the question this row answers.
        let localAttempts = statistics.localConnectionAttempts ?? 0
        let localTimeouts = statistics.localConnectionTimeouts ?? 0
        let attempts = max((statistics.connectionAttempts ?? 0) - localAttempts, 0)
        let timeouts = max((statistics.connectionTimeouts ?? 0) - localTimeouts, 0)
        let value = attempts >= HealthScale.minimumAttempts
            ? Double(timeouts) / Double(attempts) : nil
        let rating = bands.rate(value)
        let tally = "\(timeouts) of \(attempts)"
        let sentence: String
        switch rating {
        case .unmeasured: sentence = "Too few new connections yet to judge."
        case .good: sentence = "Nearly every connection got an answer (\(tally) did not)."
        case .fair: sentence = "Some connections got no answer at all (\(tally))."
        case .poor:
            sentence = "Many connections got no answer at all (\(tally)) — sites may fail to open."
        }
        var detail = "\(pluralised(attempts, "TCP connection")) to the internet opened by "
            + "this Mac, \(timeouts) unanswered after \(Int(QualitySummary.handshakeGrace)) s, "
            + "\(statistics.connectionRefusals ?? 0) refused by the far end (not counted)."
        if localAttempts > 0 {
            detail += " Not rated: \(localTimeouts) of \(localAttempts) to devices on the local network."
        }
        let aside = localTimeouts > 0
            ? "\(pluralised(localTimeouts, "attempt")) to reach a device on your home network "
                + "went unanswered. That is usually an iPhone or iPad that is asleep or away "
                + "while your Mac keeps trying to sync with it — harmless, and not counted above."
            : nil
        return HealthFinding(
            area: .unanswered, rating: rating, sentence: sentence, detail: detail,
            value: value, bands: bands, aside: aside)
    }

    static func resent(_ statistics: WireStatistics) -> HealthFinding {
        let bands = HealthScale.resent
        // An older daemon does not publish the denominator. Without it the rate cannot be
        // told apart from noise over a handful of segments, so it goes unrated rather than
        // rated on trust.
        let segments = statistics.segmentsOut ?? 0
        let value = segments >= HealthScale.minimumSegments ? statistics.retransmitRateOut : nil
        let rating = bands.rate(value)
        let shown = value.map(formatShare) ?? ""
        let sentence: String
        switch rating {
        case .unmeasured: sentence = "Not enough data sent yet to judge reliability."
        case .good: sentence = "Very little data has to be sent twice (\(shown))."
        case .fair: sentence = "Some data has to be sent again (\(shown)), which slows downloads."
        case .poor:
            sentence = "A lot of data has to be sent again (\(shown)) — the connection is unreliable, so things stall and retry."
        }
        var detail = "Retransmitted segments out: "
            + (statistics.retransmitRateOut.map(formatShare) ?? "—")
        if let sent = statistics.segmentsOut { detail += " of \(sent) sent" }
        detail += ". A passive observer sees repeats, not drops, so this is not a loss rate."
        return HealthFinding(
            area: .resent, rating: rating, sentence: sentence, detail: detail,
            value: value, bands: bands)
    }

    static func probeFindings(_ probes: ProbeSummary) -> [HealthFinding] {
        var findings: [HealthFinding] = []
        let gatewayBad = probes.gatewayIsBad

        if let gateway = probes.gateway, let bad = gatewayBad {
            findings.append(
                HealthFinding(
                    area: .localNetwork,
                    rating: bad ? .poor : .good,
                    sentence: bad
                        ? "The problem is close to you: your Wi-Fi or router is slow or not answering (\(formatShare(gateway.loss)) of pings unanswered)."
                        : "Your Wi-Fi and router are answering normally.",
                    detail: probeDetail("Router", gateway),
                    value: nil, bands: nil))
        }
        if let anchors = probes.anchors, let bad = probes.anchorsAreBad {
            let sentence: String
            switch (bad, gatewayBad ?? false) {
            case (false, _): sentence = "The wider internet is answering normally."
            case (true, true):
                sentence = "Distant servers are affected too, which is expected while the link to your router is struggling."
            case (true, false):
                sentence = "Your Wi-Fi is fine, but the internet beyond it is slow — most likely your internet provider."
            }
            findings.append(
                HealthFinding(
                    area: .internet, rating: bad ? .poor : .good, sentence: sentence,
                    detail: probeDetail("Public servers", anchors),
                    value: nil, bands: nil))
        }
        return findings
    }

    static func probeDetail(
        _ name: String, _ summary: (min: Double?, median: Double?, loss: Double)
    ) -> String {
        "\(name): median \(summary.median.map(formatMs) ?? "—"), "
            + "floor \(summary.min.map(formatMs) ?? "—"), "
            + "\(formatShare(summary.loss)) of pings unanswered."
    }

    static func coverageNote(_ statistics: WireStatistics) -> String? {
        guard let share = statistics.measuredByteShare, share < HealthScale.coverageCaveat
        else { return nil }
        return "These figures cover \(Int((share * 100).rounded()))% of the data moved. "
            + "The rest uses QUIC, a newer protocol whose timing can't be read from outside."
    }
}

func formatMs(_ value: Double) -> String {
    value < 10 ? String(format: "%.1f ms", value) : "\(Int(value.rounded())) ms"
}

func formatShare(_ value: Double) -> String {
    let percent = value * 100
    if percent == 0 { return "0%" }
    return percent < 10 ? String(format: "%.1f%%", percent) : "\(Int(percent.rounded()))%"
}

extension WireFlow {
    /// One connection's round trip against the same scale the Overview uses, so a row
    /// coloured "struggling" in the Quality list and the headline agree on what that means.
    public var responseTimeRating: HealthRating { HealthScale.responseTime.rate(rttMs) }

    /// Round-trip variation where there is one, arrival spacing otherwise — the same
    /// precedence the Quality list displays.
    public var jitterRating: HealthRating { HealthScale.jitter.rate(rttVarMs ?? arrivalJitterMs) }

    /// Repeats as a share of packets sent, unrated below `HealthScale.minimumSegments`.
    ///
    /// Packets rather than segments because packets are what a flow publishes; they
    /// include bare acknowledgements, so the share is if anything understated. The old rule
    /// coloured any repeat at all orange, which made one resent segment in a long download
    /// look like a fault.
    public var resentRating: HealthRating {
        guard let out = retransmitsOut, packetsOut >= HealthScale.minimumSegments else {
            return .unmeasured
        }
        return HealthScale.resent.rate(Double(out) / Double(packetsOut))
    }
}
