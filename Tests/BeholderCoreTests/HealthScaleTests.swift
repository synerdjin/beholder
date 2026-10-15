import Foundation
import Testing

@testable import BeholderCore

@Suite("Health scale bands")
struct HealthScaleBandTests {

    /// The boundaries are the whole of the scale. A change to one should be a decision,
    /// recorded in the README, rather than a drift nobody noticed.
    @Test("Every band boundary is pinned")
    func boundaries() {
        #expect(HealthScale.responseTime.rate(50) == .good)
        #expect(HealthScale.responseTime.rate(50.1) == .fair)
        #expect(HealthScale.responseTime.rate(150) == .fair)
        #expect(HealthScale.responseTime.rate(150.1) == .poor)

        #expect(HealthScale.resent.rate(0.01) == .good)
        #expect(HealthScale.resent.rate(0.0101) == .fair)
        #expect(HealthScale.resent.rate(0.03) == .fair)
        #expect(HealthScale.resent.rate(0.0301) == .poor)

        #expect(HealthScale.unanswered.rate(0.02) == .good)
        #expect(HealthScale.unanswered.rate(0.021) == .fair)
        #expect(HealthScale.unanswered.rate(0.10) == .fair)
        #expect(HealthScale.unanswered.rate(0.101) == .poor)

        #expect(HealthScale.jitter.rate(10) == .good)
        #expect(HealthScale.jitter.rate(30) == .fair)
        #expect(HealthScale.jitter.rate(30.1) == .poor)
    }

    /// Nil is not zero. "Nobody measured it" drawn as good is the reassuring kind of wrong.
    @Test("An absent value is unmeasured, never good")
    func nilIsUnmeasured() {
        #expect(HealthScale.responseTime.rate(nil) == .unmeasured)
        #expect(HealthScale.responseTime.rate(.nan) == .unmeasured)
        #expect(HealthRating.unmeasured < .good)
    }

    @Test("The probe limits are the ones the probe reading uses")
    func probeLimitsShared() {
        let summary = ProbeSummary(
            gateway: (min: 2, median: HealthScale.gatewayMaximumMedianMs + 1, loss: 0),
            anchors: (min: 10, median: 20, loss: 0),
            samples: 10)
        #expect(summary.gatewayIsBad == true)
        #expect(summary.anchorsAreBad == false)
        #expect(summary.reading?.contains("your own network") == true)
    }
}

@Suite("Health assessment")
struct HealthAssessmentTests {

    private func statistics(
        median: Double? = 20,
        resent: Double? = 0.001, segments: UInt64? = 5000,
        attempts: Int? = 40, timeouts: Int? = 0,
        share: Double? = 0.9
    ) -> WireStatistics {
        var statistics = WireStatistics()
        statistics.measuredFlowCount = 10
        statistics.medianRttMs = median
        statistics.minRttMs = median.map { $0 / 2 }
        statistics.retransmitRateOut = resent
        statistics.segmentsOut = segments
        statistics.connectionAttempts = attempts
        statistics.connectionTimeouts = timeouts
        statistics.connectionRefusals = 0
        statistics.measuredByteShare = share
        return statistics
    }

    private func probes(gatewayLoss: Double, anchorMedian: Double) -> ProbeSummary {
        ProbeSummary(
            gateway: (min: 2, median: 4, loss: gatewayLoss),
            anchors: (min: 10, median: anchorMedian, loss: 0),
            samples: 30)
    }

    @Test("A healthy network says so")
    func healthy() {
        let assessment = HealthAssessment.make(statistics: statistics(), probes: nil)
        #expect(assessment.overall == .good)
        #expect(assessment.headline == HealthAssessment.normalHeadline)
        #expect(assessment.hasProbes == false)
        #expect(assessment.coverageNote == nil)
    }

    @Test("The headline names the worst area")
    func worstWins() {
        let assessment = HealthAssessment.make(
            statistics: statistics(median: 90, resent: 0.08), probes: nil)
        #expect(assessment.overall == .poor)
        #expect(assessment.headline.contains("sent again"))
    }

    /// The router finding locates a problem more precisely than a slow reply does, so it
    /// takes the headline when both are bad — which is what this session's 80% loss to the
    /// router needed to be told.
    @Test("A lossy router takes the headline and is blamed locally")
    func routerBlamed() {
        let assessment = HealthAssessment.make(
            statistics: statistics(median: 300),
            probes: probes(gatewayLoss: 0.8, anchorMedian: 20))
        #expect(assessment.overall == .poor)
        #expect(assessment.headline.contains("Wi-Fi or router"))
        #expect(assessment.findings.first { $0.area == .localNetwork }?.rating == .poor)
    }

    @Test("A clean router with slow servers blames upstream")
    func upstreamBlamed() {
        let assessment = HealthAssessment.make(
            statistics: statistics(),
            probes: probes(gatewayLoss: 0, anchorMedian: 400))
        #expect(assessment.findings.first { $0.area == .localNetwork }?.rating == .good)
        let internet = assessment.findings.first { $0.area == .internet }
        #expect(internet?.rating == .poor)
        #expect(internet?.sentence.contains("internet provider") == true)
    }

    @Test("Too little traffic is not rated")
    func belowMinimumsUnrated() {
        let assessment = HealthAssessment.make(
            statistics: statistics(
                median: nil, resent: 0.5, segments: 20, attempts: 3, timeouts: 3),
            probes: nil)
        #expect(assessment.overall == .unmeasured)
        #expect(assessment.headline == HealthAssessment.notEnoughHeadline)
    }

    /// An older daemon publishes the rate without its denominator; rating it on trust
    /// would let twenty segments call a network broken.
    @Test("A rate without its denominator is not rated")
    func missingDenominator() {
        let finding = HealthAssessment.resent(statistics(resent: 0.2, segments: nil))
        #expect(finding.rating == .unmeasured)
    }

    /// What this session found: 29 of 80 unanswered, every one of them a sleeping iPhone,
    /// and the Overview's headline telling someone their sites might not open.
    @Test("Unanswered devices at home are noted, not rated")
    func localTimeoutsNotRated() {
        var stats = statistics(attempts: 80, timeouts: 29)
        stats.localConnectionAttempts = 29
        stats.localConnectionTimeouts = 29
        let assessment = HealthAssessment.make(statistics: stats, probes: nil)
        let finding = assessment.findings.first { $0.area == .unanswered }
        #expect(finding?.rating == .good)
        #expect(finding?.aside?.contains("29 attempts") == true)
        #expect(assessment.headline == HealthAssessment.normalHeadline)
    }

    @Test("Internet timeouts are still rated when local ones are set aside")
    func internetTimeoutsStillRated() {
        var stats = statistics(attempts: 80, timeouts: 29)
        stats.localConnectionAttempts = 10
        stats.localConnectionTimeouts = 9
        // 20 of 70 to the internet unanswered.
        #expect(HealthAssessment.unanswered(stats).rating == .poor)
    }

    @Test("Measurement switched off is said, not shown as nothing found")
    func measurementOff() {
        let assessment = HealthAssessment.make(statistics: WireStatistics(), probes: nil)
        #expect(assessment.qualityMeasured == false)
        #expect(assessment.findings.isEmpty)
        #expect(assessment.headline == HealthAssessment.measurementOffHeadline)
    }

    @Test("Low coverage travels with the ratings")
    func coverageCaveat() {
        let assessment = HealthAssessment.make(statistics: statistics(share: 0.4), probes: nil)
        #expect(assessment.coverageNote?.contains("40%") == true)
    }

    /// A passive observer sees repeats, not drops. The wording must not claim otherwise
    /// anywhere a person reads it — except to say that it is not a loss figure.
    @Test("Retransmissions are never called loss")
    func notLoss() {
        for rate in [0.0, 0.02, 0.2] {
            let finding = HealthAssessment.resent(statistics(resent: rate))
            #expect(!finding.sentence.lowercased().contains("loss"))
            #expect(!finding.sentence.lowercased().contains("lost"))
        }
    }
}

@Suite("Per-connection ratings")
struct FlowRatingTests {

    private func flow(
        packetsOut: UInt64, retransmitsOut: UInt64?, rttMs: Double? = nil,
        rttVarMs: Double? = nil, arrivalJitterMs: Double? = nil
    ) -> WireFlow {
        WireFlow(
            id: "TCP|10.0.0.2:5000|1.1.1.1:443", processName: nil, processPath: nil, pid: nil,
            transport: "TCP", localAddress: "10.0.0.2", localPort: 5000,
            remoteAddress: "1.1.1.1", remotePort: 443,
            hostName: nil, hostNameIsProof: false, isPrivateRelay: false,
            bytesOut: 0, bytesIn: 0, packetsOut: packetsOut, packetsIn: 0,
            tcpState: nil, firstSeen: Date(), lastSeen: Date(),
            location: nil, classification: nil, networkOperator: nil,
            isOutgoing: true, initiationIsCertain: true,
            rttMs: rttMs, rttVarMs: rttVarMs, retransmitsOut: retransmitsOut,
            arrivalJitterMs: arrivalJitterMs)
    }

    /// One repeat in a long download is not a fault. The rule this replaced coloured any
    /// repeat at all as a warning.
    @Test("A single repeat in a busy connection is good")
    func singleRepeatIsGood() {
        #expect(flow(packetsOut: 5000, retransmitsOut: 1).resentRating == .good)
        #expect(flow(packetsOut: 1000, retransmitsOut: 50).resentRating == .poor)
    }

    @Test("A short connection's repeats are not rated")
    func shortConnectionUnrated() {
        #expect(flow(packetsOut: 20, retransmitsOut: 5).resentRating == .unmeasured)
        #expect(flow(packetsOut: 5000, retransmitsOut: nil).resentRating == .unmeasured)
    }

    @Test("Jitter falls back to arrival spacing, and absence is unmeasured")
    func jitterPrecedence() {
        #expect(flow(packetsOut: 0, retransmitsOut: nil, rttVarMs: 5, arrivalJitterMs: 90).jitterRating == .good)
        #expect(flow(packetsOut: 0, retransmitsOut: nil, arrivalJitterMs: 90).jitterRating == .poor)
        #expect(flow(packetsOut: 0, retransmitsOut: nil).jitterRating == .unmeasured)
        #expect(flow(packetsOut: 0, retransmitsOut: nil).responseTimeRating == .unmeasured)
    }
}
