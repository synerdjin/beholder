import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!
private let server = IPAddress(networkOrderBytes: [93, 184, 216, 34], family: .v4)!
private let loopback = IPAddress(networkOrderBytes: [127, 0, 0, 1], family: .v4)!
private let localAddresses: Set<IPAddress> = [laptop, loopback]

private func packet(
    from source: IPAddress,
    port sourcePort: UInt16,
    to destination: IPAddress,
    port destinationPort: UInt16,
    transport: TransportProtocol = .tcp,
    bytes: UInt32 = 1000,
    flags: TCPFlags = []
) -> ParsedPacket {
    ParsedPacket(
        transport: transport,
        source: source,
        destination: destination,
        sourcePort: sourcePort,
        destinationPort: destinationPort,
        tcpFlags: flags,
        wireBytes: bytes,
        isFragment: false,
        payloadOffset: 0,
        payloadCapturedLength: 0
    )
}

@Suite("Flow key normalisation")
struct FlowKeyTests {

    /// The property everything else depends on: a request and its reply must land on one
    /// key, or the table holds two half-conversations and cannot report direction.
    @Test("Both directions of a conversation share one key")
    func directionsShareAKey() {
        let outgoing = packet(from: laptop, port: 51234, to: server, port: 443)
        let incoming = packet(from: server, port: 443, to: laptop, port: 51234)

        let out = FlowKey.make(from: outgoing, localAddresses: localAddresses)
        let back = FlowKey.make(from: incoming, localAddresses: localAddresses)

        #expect(out.key == back.key)
        #expect(out.direction == .outbound)
        #expect(back.direction == .inbound)
        #expect(out.key.local == laptop)
        #expect(out.key.localPort == 51234)
        #expect(out.key.remote == server)
        #expect(out.key.remotePort == 443)
    }

    @Test("Loopback traffic, where both ends are local, still normalises consistently")
    func loopbackIsConsistent() {
        let request = packet(from: loopback, port: 55000, to: loopback, port: 8080)
        let reply = packet(from: loopback, port: 8080, to: loopback, port: 55000)

        let first = FlowKey.make(from: request, localAddresses: localAddresses)
        let second = FlowKey.make(from: reply, localAddresses: localAddresses)

        #expect(first.key == second.key)
        #expect(first.direction != second.direction)
        // The ephemeral (higher) port is treated as the local end.
        #expect(first.key.localPort == 55000)
    }

    @Test("Traffic between two unknown addresses is still keyed consistently")
    func neitherEndLocal() {
        let one = packet(from: server, port: 40000, to: laptop, port: 443)
        let two = packet(from: laptop, port: 443, to: server, port: 40000)

        let first = FlowKey.make(from: one, localAddresses: [])
        let second = FlowKey.make(from: two, localAddresses: [])
        #expect(first.key == second.key)
    }

    @Test("Different protocols on the same ports are different flows")
    func protocolSeparatesFlows() {
        let tcp = FlowKey.make(
            from: packet(from: laptop, port: 5353, to: server, port: 5353, transport: .tcp),
            localAddresses: localAddresses
        )
        let udp = FlowKey.make(
            from: packet(from: laptop, port: 5353, to: server, port: 5353, transport: .udp),
            localAddresses: localAddresses
        )
        #expect(tcp.key != udp.key)
    }
}

@Suite("Flow table")
struct FlowTableTests {

    @Test("Bytes accumulate into the correct direction")
    func bytesAccumulateByDirection() {
        let table = FlowTable()
        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443, bytes: 500),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        table.record(
            packet(from: server, port: 443, to: laptop, port: 51234, bytes: 1500),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        table.record(
            packet(from: server, port: 443, to: laptop, port: 51234, bytes: 1500),
            interfaceName: "utun8", localAddresses: localAddresses
        )

        #expect(table.count == 1)
        let flow = table.activeFlows()[0]
        #expect(flow.bytesOut == 500)
        #expect(flow.bytesIn == 3000)
        #expect(flow.packetsOut == 1)
        #expect(flow.packetsIn == 2)
        #expect(flow.totalBytes == 3500)
    }

    @Test("TCP teardown flags mark a flow as closing")
    func teardownIsTracked() {
        let table = FlowTable()
        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443, flags: .syn),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        #expect(table.activeFlows()[0].isClosing == false)

        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443, flags: [.fin, .ack]),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        #expect(table.activeFlows()[0].isClosing)
    }

    @Test("Idle flows are retired, active ones are kept")
    func idleFlowsExpire() {
        let table = FlowTable()
        let start = Date()

        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443),
            interfaceName: "utun8", localAddresses: localAddresses, at: start
        )
        table.record(
            packet(from: laptop, port: 51235, to: server, port: 53, transport: .udp),
            interfaceName: "utun8", localAddresses: localAddresses, at: start
        )
        #expect(table.count == 2)

        // 90s later: the UDP flow is past its 60s timeout, the TCP one is not.
        let retired = table.expire(at: start.addingTimeInterval(90))
        #expect(retired.count == 1)
        #expect(retired[0].key.transport == .udp)
        #expect(table.count == 1)

        // 400s in, the TCP flow is past its 300s timeout too.
        #expect(table.expire(at: start.addingTimeInterval(400)).count == 1)
        #expect(table.count == 0)
    }

    @Test("A torn-down flow is retired sooner than an idle open one")
    func closedFlowsExpireSooner() {
        let table = FlowTable()
        let start = Date()

        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443, flags: .rst),
            interfaceName: "utun8", localAddresses: localAddresses, at: start
        )
        // Past the 30s closed timeout but well inside the 300s open one.
        #expect(table.expire(at: start.addingTimeInterval(45)).count == 1)
    }

    @Test("The table is bounded, and reports what it dropped")
    func evictionIsBoundedAndReported() {
        var configuration = FlowTable.Configuration()
        configuration.maximumFlows = 10
        let table = FlowTable(configuration: configuration)
        let start = Date()

        for index in 0..<25 {
            table.record(
                packet(from: laptop, port: UInt16(40000 + index), to: server, port: 443),
                interfaceName: "utun8", localAddresses: localAddresses,
                at: start.addingTimeInterval(Double(index))
            )
        }

        table.expire(at: start.addingTimeInterval(25))
        #expect(table.count == 10)
        #expect(table.evictedFlowCount == 15)
        // The survivors must be the most recently active ones.
        let survivingPorts = Set(table.activeFlows().map(\.key.localPort))
        #expect(survivingPorts.contains(40024))
        #expect(!survivingPorts.contains(40000))
    }

    @Test("Attribution fills unknown owners and never overwrites known ones")
    func attributionDoesNotOverwrite() {
        let table = FlowTable()
        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        #expect(table.hasUnattributedFlows)

        let firefox = ProcessOwner(pid: 100, path: "/Applications/Firefox.app/firefox")
        table.attribute { _ in (owner: firefox, tcpState: .established) }
        #expect(!table.hasUnattributedFlows)
        #expect(table.activeFlows()[0].owner == firefox)

        // A later poll sees the port reused by another process. The established answer
        // must win, because overwriting it would rename traffic that firefox generated.
        let curl = ProcessOwner(pid: 200, path: "/usr/bin/curl")
        table.attribute { _ in (owner: curl, tcpState: .established) }
        #expect(table.activeFlows()[0].owner == firefox)
    }

    @Test("Unresolvable flows stay listed as unknown rather than vanishing")
    func unattributedFlowsSurvive() {
        let table = FlowTable()
        table.record(
            packet(from: laptop, port: 51234, to: server, port: 443),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        table.attribute { _ in nil }

        #expect(table.count == 1)
        #expect(table.activeFlows()[0].owner == nil)

        let groups = table.flowsByProcess()
        #expect(groups.count == 1)
        #expect(groups[0].owner == nil)
        #expect(groups[0].flows.count == 1)
    }

    @Test("Flows group by process, ordered by volume")
    func groupingOrdersByVolume() {
        let table = FlowTable()
        let quiet = ProcessOwner(pid: 1, path: "/usr/bin/quiet")
        let noisy = ProcessOwner(pid: 2, path: "/usr/bin/noisy")

        table.record(
            packet(from: laptop, port: 1000, to: server, port: 443, bytes: 100),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        table.record(
            packet(from: laptop, port: 2000, to: server, port: 443, bytes: 9000),
            interfaceName: "utun8", localAddresses: localAddresses
        )
        table.attribute { key in
            (owner: key.localPort == 1000 ? quiet : noisy, tcpState: .established)
        }

        let groups = table.flowsByProcess()
        #expect(groups.count == 2)
        #expect(groups[0].owner == noisy)
        #expect(groups[0].totalBytes == 9000)
        #expect(groups[1].owner == quiet)
    }

    @Test("Retired flows are handed over once and then cleared")
    func retiredFlowsDrainOnce() {
        let table = FlowTable()
        let start = Date()
        table.record(
            packet(from: laptop, port: 51235, to: server, port: 53, transport: .udp),
            interfaceName: "utun8", localAddresses: localAddresses, at: start
        )
        table.expire(at: start.addingTimeInterval(120))

        #expect(table.drainRetired().count == 1)
        #expect(table.drainRetired().isEmpty)
    }
}
