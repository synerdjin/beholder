import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!
private let server = IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!

private func key(_ port: UInt16) -> FlowKey {
    FlowKey(transport: .tcp, local: laptop, localPort: port, remote: server, remotePort: 80)
}

private func excerpt(_ count: Int, _ direction: FlowDirection = .outbound) -> PayloadExcerpt {
    PayloadExcerpt(direction: direction, bytes: Array(repeating: 0x41, count: count))
}

@Suite("Buffering the opening bytes of unencrypted connections")
struct PayloadExcerptStoreTests {

    @Test("Both directions are kept apart")
    func directionsAreSeparate() throws {
        let store = PayloadExcerptStore()
        store.append(PayloadExcerpt(direction: .outbound, bytes: Array("GET /".utf8)), for: key(1))
        store.append(PayloadExcerpt(direction: .inbound, bytes: Array("HTTP/1.1".utf8)), for: key(1))

        let stored = try #require(store.excerpt(for: key(1)))
        #expect(String(decoding: stored.sent, as: UTF8.self) == "GET /")
        #expect(String(decoding: stored.received, as: UTF8.self) == "HTTP/1.1")
    }

    @Test("A direction stops at its cap, exactly")
    func capIsExact() throws {
        let store = PayloadExcerptStore()
        let limit = PayloadExcerptStore.maximumBytesPerDirection
        for _ in 0..<10 { store.append(excerpt(1000), for: key(1)) }

        let stored = try #require(store.excerpt(for: key(1)))
        #expect(stored.sent.count == limit)
    }

    /// The whole basis for telling a reader it is looking at a fragment. If the observed
    /// counter stopped when the buffer filled, a 4 KB excerpt of an 800 KB upload would
    /// present itself as the entire conversation.
    @Test("Bytes keep being counted after the buffer is full")
    func observedKeepsCounting() throws {
        let store = PayloadExcerptStore()
        for _ in 0..<10 { store.append(excerpt(1000), for: key(1)) }

        let stored = try #require(store.excerpt(for: key(1)))
        #expect(stored.sentObserved == 10_000)
        #expect(stored.sent.count == PayloadExcerptStore.maximumBytesPerDirection)

        // The difference is what the reader turns into "first 4,096 of 10,000 bytes".
        let published = try #require(store.publishable(budget: 1 << 20).excerpts.first)
        #expect(published.isTruncated)
    }

    @Test("A connection that fits entirely is not reported as truncated")
    func shortConnectionIsComplete() throws {
        let store = PayloadExcerptStore()
        store.append(excerpt(100), for: key(1))

        let stored = try #require(store.excerpt(for: key(1)))
        #expect(stored.sentObserved == 100)

        let published = try #require(store.publishable(budget: 1 << 20).excerpts.first)
        #expect(!published.isTruncated)
    }

    /// The buffer filling must not stop the counting. A connection that has moved 900 KB
    /// has to say so, or the reader's "first 4 KB of …" caveat quietly reports the size of
    /// the buffer instead of the size of the conversation.
    @Test("A full buffer keeps counting what it is no longer keeping")
    func fullBufferKeepsCounting() throws {
        let store = PayloadExcerptStore()
        let limit = PayloadExcerptStore.maximumBytesPerDirection

        // Fill both directions completely, then keep going.
        store.append(excerpt(limit, .outbound), for: key(1))
        store.append(excerpt(limit, .inbound), for: key(1))
        for _ in 0..<100 {
            store.append(excerpt(1000, .outbound), for: key(1))
        }

        let stored = try #require(store.excerpt(for: key(1)))
        #expect(stored.sent.count == limit, "the buffer still holds only its limit")
        #expect(stored.sentObserved == UInt64(limit) + 100_000, "but the total kept rising")
    }

    /// A packet carrying more than the per-packet copy limit still contributes its whole
    /// length to the total. Counting the copy would understate the conversation by exactly
    /// the amount that was too big to keep.
    @Test("A packet larger than the copy limit is counted at its real size")
    func oversizedPacketCountsInFull() throws {
        let store = PayloadExcerptStore()
        let big = PayloadExcerpt(
            direction: .outbound,
            bytes: Array(repeating: 0x41, count: PayloadExcerpt.maximumBytesPerPacket),
            observedBytes: 9000
        )
        store.append(big, for: key(1))

        let stored = try #require(store.excerpt(for: key(1)))
        #expect(stored.sent.count == PayloadExcerpt.maximumBytesPerPacket)
        #expect(stored.sentObserved == 9000, "not the 2 KB that was kept")
    }

    // MARK: - Bounds

    @Test("Past the flow cap, the least recently active connection is dropped")
    func evictsOldest() {
        let store = PayloadExcerptStore()
        let cap = PayloadExcerptStore.maximumFlows

        for port in 0..<cap {
            store.append(excerpt(10), for: key(UInt16(port)))
        }
        #expect(store.count == cap)
        #expect(store.excerpt(for: key(0)) != nil)

        store.append(excerpt(10), for: key(UInt16(cap)))
        #expect(store.count == cap, "the cap holds")
        #expect(store.excerpt(for: key(0)) == nil, "the oldest went")
        #expect(store.excerpt(for: key(UInt16(cap))) != nil, "the newest stayed")
        #expect(store.evictedFlowCount == 1, "the loss is counted, not silent")
    }

    /// Recency has to mean *last active*, not *first seen*, or a busy long-lived
    /// connection is thrown away in favour of a burst of one-packet flows.
    @Test("Appending to a flow makes it recent again")
    func appendingRefreshesRecency() {
        let store = PayloadExcerptStore()
        let cap = PayloadExcerptStore.maximumFlows

        for port in 0..<cap {
            store.append(excerpt(10), for: key(UInt16(port)))
        }
        store.append(excerpt(10), for: key(0))
        store.append(excerpt(10), for: key(UInt16(cap)))

        #expect(store.excerpt(for: key(0)) != nil, "touched, so it survived")
        #expect(store.excerpt(for: key(1)) == nil, "now the oldest")
    }

    @Test("A retired connection's bytes are released at once")
    func forgetReleases() {
        let store = PayloadExcerptStore()
        store.append(excerpt(100), for: key(1))
        store.append(excerpt(100), for: key(2))

        store.forget(key(1))
        #expect(store.excerpt(for: key(1)) == nil)
        #expect(store.excerpt(for: key(2)) != nil)
        #expect(store.count == 1)
        #expect(store.evictedFlowCount == 0, "retirement is not an eviction")
    }

    @Test("Forgetting a flow that was never buffered does nothing")
    func forgetUnknownFlow() {
        let store = PayloadExcerptStore()
        store.append(excerpt(100), for: key(1))
        store.forget(key(99))
        #expect(store.count == 1)
    }

    // MARK: - Selecting what to publish

    /// This is the only per-snapshot bound on the one structure that holds the contents of
    /// traffic, which is why it lives in Core where these can reach it.
    @Test("Everything buffered is published when the budget is generous")
    func publishesEverythingWhenItFits() {
        let store = PayloadExcerptStore()
        store.append(excerpt(100), for: key(1))
        store.append(excerpt(100, .inbound), for: key(2))

        let selected = store.publishable(budget: 1 << 20)
        #expect(selected.excerpts.count == 2)
        #expect(selected.dropped == 0)
    }

    @Test("A connection is named by the same id its flow carries")
    func idMatchesTheFlow() throws {
        let store = PayloadExcerptStore()
        store.append(excerpt(10), for: key(1))

        let published = try #require(store.publishable(budget: 1 << 20).excerpts.first)
        #expect(published.id == key(1).wireID, "or the app cannot match payload to a flow")
    }

    /// Biggest first: a connection that has moved more unencrypted data is the one worth
    /// seeing when not everything fits.
    @Test("When the budget bites, the largest connections are kept and the rest counted")
    func budgetKeepsTheBiggest() throws {
        let store = PayloadExcerptStore()
        store.append(excerpt(100), for: key(1))
        store.append(excerpt(3000), for: key(2))
        store.append(excerpt(500), for: key(3))

        // Room for the 3000 and the 500, but not the 100 as well.
        let selected = store.publishable(budget: 3550)
        #expect(selected.excerpts.map(\.sentCaptured) == [3000, 500])
        #expect(selected.dropped == 1, "the loss is reported, not silent")
    }

    @Test("A budget of nothing publishes nothing and says how much it dropped")
    func zeroBudget() {
        let store = PayloadExcerptStore()
        store.append(excerpt(100), for: key(1))
        store.append(excerpt(100), for: key(2))

        let selected = store.publishable(budget: 0)
        #expect(selected.excerpts.isEmpty)
        #expect(selected.dropped == 2)
    }

    /// Empty is not absent. An empty list is what tells the app the daemon is looking and
    /// found nothing, as distinct from not looking at all.
    @Test("An empty store publishes an empty list, not a failure")
    func emptyStorePublishesEmpty() {
        let selected = PayloadExcerptStore().publishable(budget: 1 << 20)
        #expect(selected.excerpts.isEmpty)
        #expect(selected.dropped == 0)
    }

    /// Swift seeds its hashing per process, so leaving the order to the dictionary would
    /// change which equal-sized flows survive the budget between snapshots — payload
    /// appearing and vanishing in the view for no visible reason.
    @Test("Equal-sized connections are ordered the same way every time")
    func tiesAreBrokenDeterministically() {
        func published() -> [String] {
            let store = PayloadExcerptStore()
            for port in UInt16(1)...20 { store.append(excerpt(100), for: key(port)) }
            return store.publishable(budget: 1 << 20).excerpts.map(\.id)
        }
        let first = published()
        #expect(published() == first)
        #expect(first == first.sorted(), "ties fall back to the id")
    }

    @Test("A direction with no bytes is omitted rather than sent empty")
    func absentDirectionIsNil() throws {
        let store = PayloadExcerptStore()
        store.append(excerpt(50, .outbound), for: key(1))

        let published = try #require(store.publishable(budget: 1 << 20).excerpts.first)
        #expect(published.sent != nil)
        #expect(published.received == nil)
    }

    // MARK: - Copying out of the capture buffer

    @Test("A copy is bounded to one packet's share")
    func copyIsBounded() throws {
        let big = [UInt8](repeating: 0x42, count: 60_000)
        let copied = try #require(big.withUnsafeBytes { PayloadExcerpt.copy(from: $0) })
        #expect(copied.count == PayloadExcerpt.maximumBytesPerPacket)
    }

    @Test("A packet with no payload yields nothing to copy")
    func emptyPayloadCopiesNothing() {
        let empty: [UInt8] = []
        let copied = empty.withUnsafeBytes { PayloadExcerpt.copy(from: $0) }
        #expect(copied == nil, "pure ACKs must not cost a queue hop")
    }
}

@Suite("Payload reading only happens when it is asked for")
struct PayloadInspectorCaptureTests {

    private func inspect(
        _ bytes: [UInt8],
        remotePort: UInt16,
        capturePayload: Bool,
        transport: TransportProtocol = .tcp
    ) -> PacketObservation? {
        let packet = ParsedPacket(
            transport: transport, source: laptop, destination: server,
            sourcePort: 51234, destinationPort: remotePort, tcpFlags: [],
            wireBytes: 100, isFragment: false, payloadOffset: 0, payloadCapturedLength: 0
        )
        return bytes.withUnsafeBytes {
            PayloadInspector.inspect(packet: packet, payload: $0, capturePayload: capturePayload)
        }
    }

    /// The default path, and every run that existed before this feature: classification
    /// happens, bytes are not copied.
    @Test("Without the flag, no payload is copied")
    func defaultCopiesNothing() throws {
        let observation = try #require(
            inspect(Array("GET / HTTP/1.1\r\n".utf8), remotePort: 80, capturePayload: false)
        )
        #expect(observation.excerptBytes == nil)
        #expect(observation.reading?.security == .cleartext)
    }

    @Test("With the flag, cleartext payload is copied")
    func cleartextIsCopied() throws {
        let observation = try #require(
            inspect(Array("GET / HTTP/1.1\r\n".utf8), remotePort: 80, capturePayload: true)
        )
        let bytes = try #require(observation.excerptBytes)
        #expect(String(decoding: bytes, as: UTF8.self).hasPrefix("GET /"))
    }

    /// The gate that keeps copying off the hot path. On a real machine almost everything
    /// is TLS, so almost nothing is copied.
    @Test("Payload proven to be TLS is not copied")
    func provenEncryptedIsSkipped() throws {
        let observation = try #require(
            inspect([0x17, 0x03, 0x03, 0x01, 0x00], remotePort: 443, capturePayload: true)
        )
        #expect(observation.excerptBytes == nil)
        #expect(observation.reading?.security == .encrypted)
    }

    /// Port 443 is the internet's junk drawer. Exempting it on the port alone would mean
    /// the one thing worth catching — something plaintext where TLS was promised — is the
    /// one thing never looked at.
    @Test("Port 443 alone does not exempt a packet from being read")
    func portAloneDoesNotSkip() throws {
        let observation = try #require(
            inspect(Array("GET / HTTP/1.1\r\n".utf8), remotePort: 443, capturePayload: true)
        )
        #expect(observation.excerptBytes != nil)
        #expect(observation.reading?.security == .cleartext, "read, not assumed from 443")
    }

    @Test("Unidentifiable payload is copied, since that is what there is to look at")
    func unknownIsCopied() throws {
        let observation = try #require(
            inspect([0x9F, 0x2B, 0xE1, 0x77], remotePort: 51820, capturePayload: true)
        )
        #expect(observation.excerptBytes != nil)
        #expect(observation.reading?.security == .unknown)
    }

    /// ICMP has no ports, so it never gets a security reading, so the Cleartext view can
    /// never show it. Copying it anyway spent the bounded 64-connection buffer and the
    /// per-snapshot byte budget on payload nothing could display — evicting the cleartext
    /// connections the buffer exists for. A few pings were enough to do it.
    @Test("A protocol with no ports is not buffered, since nothing could ever show it")
    func portlessProtocolIsNotBuffered() {
        let observation = inspect(
            [0x08, 0x00, 0x4D, 0x2A, 0x00, 0x01],
            remotePort: 0,
            capturePayload: true,
            transport: .icmp
        )
        #expect(observation?.excerptBytes == nil)
    }

    /// The store needs the packet's real size, not the size of the copy, or a conversation
    /// larger than the per-packet limit reports itself as smaller than it was.
    @Test("The full payload length travels alongside the truncated copy")
    func observedLengthTravelsWithTheCopy() throws {
        let big = [UInt8]("GET / HTTP/1.1\r\n".utf8)
            + Array(repeating: 0x41, count: PayloadExcerpt.maximumBytesPerPacket)
        let observation = try #require(inspect(big, remotePort: 80, capturePayload: true))

        #expect(observation.excerptBytes?.count == PayloadExcerpt.maximumBytesPerPacket)
        #expect(observation.payloadBytesSeen == big.count, "the whole packet is counted")
    }
}
