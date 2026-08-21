import CBeholderShim
import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!
private let server = IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!

private func flowKey(port: UInt16) -> FlowKey {
    FlowKey(transport: .tcp, local: laptop, localPort: port, remote: server, remotePort: 443)
}

/// 1_700_000_040 falls exactly on a minute boundary, so an offset says plainly which
/// minute a test means.
private func moment(_ seconds: TimeInterval) -> Date {
    Date(timeIntervalSince1970: 1_700_000_040 + seconds)
}

private func event(rtt: TimeInterval? = nil, bytesIn: UInt64 = 1000) -> QualityEvent {
    var event = QualityEvent()
    event.rttSample = rtt
    event.bytesIn = bytesIn
    event.segmentsIn = 1
    event.flowIsMeasured = rtt != nil
    return event
}

@Suite("Round-trip histogram")
struct RTTHistogramTests {

    @Test("A percentile over nothing is absent, not zero")
    func emptyHistogram() {
        let histogram = RTTHistogram()
        #expect(histogram.percentile(0.5) == nil)
        #expect(histogram.total == 0)
    }

    /// The resolution this trades memory for. A bucket spans about a fifth of its own
    /// value, so a percentile read back lands within that — good enough for a trend, which
    /// is why the minimum is kept exactly and separately everywhere this is used.
    @Test("Percentiles land within a bucket's width of the truth")
    func percentileAccuracy() throws {
        var histogram = RTTHistogram()
        for value in stride(from: 10.0, through: 100.0, by: 1.0) {
            histogram.add(milliseconds: value)
        }

        let median = try #require(histogram.percentile(0.5))
        #expect(abs(median - 55) / 55 < 0.25)

        let tail = try #require(histogram.percentile(0.95))
        #expect(tail > median)
        #expect(abs(tail - 96) / 96 < 0.25)
    }

    @Test("Values below the floor and above the ceiling still land somewhere")
    func clamping() throws {
        var histogram = RTTHistogram()
        histogram.add(milliseconds: 0.001)
        histogram.add(milliseconds: 900_000)
        #expect(histogram.total == 2)
        #expect(try #require(histogram.percentile(0.5)) > 0)
    }

    @Test("Merging adds distributions together")
    func merging() {
        var left = RTTHistogram()
        var right = RTTHistogram()
        left.add(milliseconds: 10)
        right.add(milliseconds: 20)
        right.add(milliseconds: 30)
        left.merge(right)
        #expect(left.total == 3)
    }
}

@Suite("Per-minute accumulation")
struct QualityAccumulatorTests {

    /// The failure the existing `rollups` table has, written as a test. Measurement must
    /// land in the minute the packet arrived in, not the minute the row was written.
    @Test("Samples land in the minute they happened in, not the minute they were flushed")
    func minuteAttribution() throws {
        let accumulator = QualityAccumulator()
        // Ten seconds into one minute, then thirty seconds into the next.
        accumulator.record(
            event(rtt: 0.020), flow: flowKey(port: 1), interface: "en0",
            group: "AS15169", label: "GOOGLE", at: moment(10)
        )
        accumulator.record(
            event(rtt: 0.030), flow: flowKey(port: 2), interface: "en0",
            group: "AS15169", label: "GOOGLE", at: moment(90)
        )

        let drained = accumulator.drainAll()
        #expect(drained.count == 2)
        #expect(drained[0].key.minute + 1 == drained[1].key.minute)
        #expect(drained[0].bucket.rttSamples == 1)
        #expect(drained[1].bucket.rttSamples == 1)
    }

    @Test("The minimum is kept exactly rather than read back off the histogram")
    func exactMinimum() throws {
        let accumulator = QualityAccumulator()
        for sample in [0.0123, 0.080, 0.200] {
            accumulator.record(
                event(rtt: sample), flow: flowKey(port: 1), interface: "en0",
                group: "AS15169", label: nil, at: moment(0)
            )
        }

        let bucket = try #require(accumulator.drainAll().first).bucket
        #expect(bucket.rttMinimum == 0.0123)
        #expect(bucket.rttSamples == 3)
    }

    /// A minute in progress must not be written: a packet still crossing from the capture
    /// queue would arrive after its row had gone out and be dropped without trace.
    @Test("Only minutes that have certainly finished are drained")
    func onlyClosedMinutes() {
        let accumulator = QualityAccumulator()
        accumulator.record(
            event(rtt: 0.020), flow: flowKey(port: 1), interface: "en0",
            group: "AS15169", label: nil, at: moment(0)
        )

        #expect(accumulator.drainClosedMinutes(now: moment(30)).isEmpty)
        #expect(accumulator.drainClosedMinutes(now: moment(200)).count == 1)
    }

    /// A peer-to-peer client can touch thousands of networks in a minute. Without a cap
    /// the time series becomes a log; with one, the overflow has to be admitted rather
    /// than quietly changing what a "network" means.
    @Test("Networks beyond the cap are pooled, and the pooling is admitted")
    func groupCardinalityCap() {
        let accumulator = QualityAccumulator()
        for index in 0..<(QualityAccumulator.maximumGroupsPerMinute + 20) {
            accumulator.record(
                event(rtt: 0.020), flow: flowKey(port: UInt16(1000 + index)),
                interface: "en0", group: "AS\(index)", label: nil, at: moment(0)
            )
        }

        let minute = QualityAccumulator.minute(of: moment(0))
        #expect(accumulator.overflowed(minute: minute))

        let drained = accumulator.drainAll()
        #expect(drained.count == QualityAccumulator.maximumGroupsPerMinute + 1)
        #expect(drained.contains { $0.key.destinationGroup == QualityAccumulator.overflowGroup })
    }

    @Test("Distinct conversations in a minute are counted once each")
    func flowCounting() throws {
        let accumulator = QualityAccumulator()
        for port in [UInt16(1), 1, 2, 3] {
            accumulator.record(
                event(rtt: 0.02), flow: flowKey(port: port), interface: "en0",
                group: "AS15169", label: nil, at: moment(0)
            )
        }
        let bucket = try #require(accumulator.drainAll().first).bucket
        #expect(bucket.flowCount == 3)
    }

    @Test("Bytes are split by whether the connection could be measured at all")
    func coverageSplit() throws {
        let accumulator = QualityAccumulator()
        accumulator.record(
            event(rtt: 0.02, bytesIn: 500), flow: flowKey(port: 1), interface: "en0",
            group: "AS15169", label: nil, at: moment(0)
        )
        // No sample: what a QUIC conversation looks like from here.
        accumulator.record(
            event(rtt: nil, bytesIn: 1500), flow: flowKey(port: 2), interface: "en0",
            group: "AS15169", label: nil, at: moment(0)
        )

        let bucket = try #require(accumulator.drainAll().first).bucket
        #expect(bucket.measuredBytes == 500)
        #expect(bucket.unmeasurableBytes == 1500)
    }

    @Test("Interfaces are kept apart, because a tunnel is not the link underneath it")
    func interfacesAreSeparate() {
        let accumulator = QualityAccumulator()
        accumulator.record(
            event(rtt: 0.02), flow: flowKey(port: 1), interface: "en0",
            group: "AS15169", label: nil, at: moment(0)
        )
        accumulator.record(
            event(rtt: 0.09), flow: flowKey(port: 1), interface: "utun8",
            group: "AS15169", label: nil, at: moment(0)
        )

        #expect(accumulator.drainAll().count == 2)
    }

    @Test("An empty event contributes nothing")
    func emptyEventIgnored() {
        let accumulator = QualityAccumulator()
        accumulator.record(
            QualityEvent(), flow: flowKey(port: 1), interface: "en0",
            group: "AS15169", label: nil, at: moment(0)
        )
        #expect(accumulator.bucketCount == 0)
    }
}

@Suite("Destination grouping")
struct DestinationGroupTests {

    /// Grouping by bare address would give a new group per host contacted, and with the
    /// cardinality cap that means everything falls into the overflow bucket and the series
    /// says nothing. This is the fallback that matters on a machine with no ASN database.
    @Test("Without a known network, addresses group by prefix")
    func prefixFallback() {
        #expect(Flow.addressGroup(for: server) == "93.184.216.0/24")

        let v6 = IPAddress(
            networkOrderBytes: [
                0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
            ],
            family: .v6
        )!
        #expect(Flow.addressGroup(for: v6) == "2606:2800:220::/48")
    }

    @Test("A named network groups by its autonomous system number, not its name")
    func autonomousSystemGrouping() {
        var flow = Flow(key: flowKey(port: 1), interfaceName: "en0", at: Date())
        #expect(flow.destinationGroupKey == "93.184.216.0/24")

        flow.adoptNetworkOperator(NetworkOperator(number: 15169, organization: "GOOGLE"))
        #expect(flow.destinationGroupKey == "AS15169")
        #expect(flow.destinationGroupLabel == "GOOGLE")
    }
}
