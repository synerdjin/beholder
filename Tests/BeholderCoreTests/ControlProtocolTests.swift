import Foundation
import Testing

@testable import BeholderCore

@Suite("Enforced block list")
struct EnforcedBlockListTests {

    private func lists(fixed: String, managed: String) -> EnforcedBlockList {
        EnforcedBlockList(fixed: BlockList.parse(fixed), managed: BlockList.parse(managed))
    }

    @Test("pf is asked to hold both files at once")
    func union() {
        let both = lists(fixed: "1.1.1.1\n10.0.0.0/8", managed: "9.9.9.9\n10.0.0.0/8")
        #expect(both.tableEntries == ["1.1.1.1", "10.0.0.0/8", "9.9.9.9"])
    }

    /// The app shows these and cannot remove them. Root wrote it; root takes it back.
    @Test("Entries from the hand-edited file are not removable")
    func ownership() {
        let both = lists(fixed: "1.1.1.1  # from the file", managed: "9.9.9.9  # from the app")
        let entries = both.controlEntries
        #expect(entries.count == 2)
        #expect(entries[0].destination == "1.1.1.1")
        #expect(entries[0].isRemovable == false)
        #expect(entries[0].note == "from the file")
        #expect(entries[1].destination == "9.9.9.9")
        #expect(entries[1].isRemovable)
    }

    /// Removing it from the managed file would not unblock it, so calling it removable would
    /// be offering a button that cannot do what it says.
    @Test("A destination in both files counts as fixed")
    func overlapIsFixed() {
        let both = lists(fixed: "1.1.1.1", managed: "1.1.1.1")
        #expect(both.controlEntries.count == 1)
        #expect(both.controlEntries[0].isRemovable == false)
        #expect(both.isFixed("1.1.1.1"))
    }

    @Test("An absent managed list is simply empty")
    func emptyManaged() {
        let both = lists(fixed: "1.1.1.1", managed: "")
        #expect(both.tableEntries == ["1.1.1.1"])
        #expect(both.controlEntries.allSatisfy { !$0.isRemovable })
    }
}

@Suite("Managed list rendering")
struct BlockListRenderingTests {

    @Test("Renders entries a parser reads back identically")
    func roundTrip() {
        let original = BlockList.parse("93.184.216.34  # example\n10.0.0.0/8")
        let text = BlockList.render(original.entries, generatedBy: "a test")
        let reparsed = BlockList.parse(text)
        #expect(reparsed.problems.isEmpty)
        #expect(reparsed.tableEntries == original.tableEntries)
        #expect(reparsed.entries[0].note == "example")
    }

    /// A note is the one part of an entry that arrives as free text from another process,
    /// and this is where free text becomes lines in a file that is parsed back as
    /// configuration. A newline in it would write a destination of its own onto the next
    /// line — blocking something nobody asked to block, from a field nobody thought of as
    /// dangerous.
    @Test("A note cannot smuggle a second destination into the file")
    func noteCannotInjectALine() {
        let entry = BlockList.Entry(
            address: IPAddress(text: "1.1.1.1")!, prefixLength: 32,
            note: "harmless\n8.8.8.8  # smuggled")
        let text = BlockList.render([entry], generatedBy: "a test")
        let reparsed = BlockList.parse(text)

        #expect(reparsed.tableEntries == ["1.1.1.1"])
        #expect(reparsed.entries.count == 1)
        #expect(text.contains("8.8.8.8  # smuggled") == false)
    }

    @Test("A note cannot start a comment of its own, and cannot run on forever")
    func noteIsFlattened() {
        #expect(BlockList.sanitiseNote("before # after")?.contains("#") == false)
        #expect(BlockList.sanitiseNote("   ") == nil)
        #expect(BlockList.sanitiseNote(nil) == nil)
        #expect(BlockList.sanitiseNote(String(repeating: "x", count: 500))?.count == 120)
    }
}

@Suite("Control protocol")
struct ControlProtocolTests {

    @Test("A request survives the round trip both ends make")
    func requestRoundTrip() throws {
        let request = ControlRequest(action: .block, destination: "1.1.1.1", note: "a tracker")
        let decoded = try JSONDecoder().decode(
            ControlRequest.self, from: try JSONEncoder().encode(request))
        #expect(decoded == request)
        #expect(decoded.version == ControlProtocol.version)
    }

    @Test("A response carries the whole state, not just an acknowledgement")
    func responseCarriesState() throws {
        let response = ControlResponse(
            ok: true,
            state: ControlState(
                isBlocking: true,
                entries: [ControlEntry(destination: "1.1.1.1", note: nil, isRemovable: true)]))
        let decoded = try JSONDecoder().decode(
            ControlResponse.self, from: try JSONEncoder().encode(response))
        #expect(decoded == response)
        #expect(decoded.state?.entries.first?.isRemovable == true)
    }

    /// Not the same as an empty list, and the app draws a different screen for each — the
    /// same distinction `cleartextExcerpts` makes between nil and empty. "Nothing is blocked"
    /// and "nothing is enforcing anything" answer different questions.
    @Test("Not blocking is a different state from blocking nothing")
    func notBlockingIsNotEmpty() {
        let idle = ControlState(isBlocking: false, entries: [], reason: "running without --block")
        let empty = ControlState(isBlocking: true, entries: [])
        #expect(idle != empty)
        #expect(idle.reason != nil)
        #expect(empty.reason == nil)
    }

    @Test("A failure carries a sentence and no state")
    func failureShape() {
        let failure = ControlResponse.failure("no")
        #expect(failure.ok == false)
        #expect(failure.error == "no")
        #expect(failure.state == nil)
    }

    /// The control socket is a second socket, not a widening of the publishing one. Sharing a
    /// path would be the change that quietly made a reader into a writer.
    @Test("The control socket is not the publishing socket")
    func distinctSocket() {
        #expect(ControlProtocol.defaultSocketPath != WireProtocol.defaultSocketPath)
    }
}

@Suite("Single destination reading")
struct DestinationReadingTests {

    @Test("Takes the same path as a line of the file")
    func parsesTheSameWay() {
        #expect(BlockList.parseDestination("1.1.1.1") == .parsed(
            BlockList.Entry(address: IPAddress(text: "1.1.1.1")!, prefixLength: 32)))
        #expect(BlockList.parseDestination("192.168.1.5/24") == .parsed(
            BlockList.Entry(address: IPAddress(text: "192.168.1.0")!, prefixLength: 24)))
    }

    /// There is no second, looser way into the block table. What the file refuses, the
    /// socket refuses, with the same words.
    @Test("Refuses what the file would refuse, for the same reason")
    func refusesTheSameWay() {
        guard case .rejected(let reason) = BlockList.parseDestination("doubleclick.net") else {
            Issue.record("a host name should be refused")
            return
        }
        #expect(reason.contains("host names cannot be blocked"))

        guard case .rejected = BlockList.parseDestination("10.0.0.0/99") else {
            Issue.record("an impossible prefix should be refused")
            return
        }
    }
}
