import Foundation
import Testing

@testable import BeholderCore

@Suite("Block list")
struct BlockListTests {

    @Test("Reads addresses, networks and the notes beside them")
    func parsesEntries() {
        let list = BlockList.parse(
            """
            # Beholder block list
            93.184.216.34      # example.com

            10.0.0.0/8         # the lab network
            2606:2800:220:1::  # a v6 host
            """)

        #expect(list.problems.isEmpty)
        #expect(list.entries.count == 3)
        #expect(list.entries[0].tableEntry == "93.184.216.34")
        #expect(list.entries[0].note == "example.com")
        #expect(list.entries[0].isHost)
        #expect(list.entries[1].tableEntry == "10.0.0.0/8")
        #expect(list.entries[1].isHost == false)
        #expect(list.entries[2].address.family == .v6)
        #expect(list.entries[2].isHost)
    }

    /// A host has to render without a prefix length because that is how `pfctl -T show`
    /// prints it back, and the two are compared directly to decide what to add and remove.
    /// A `/32` on one side only would make every reload treat every host as both new and
    /// stale, adding and deleting the same address forever.
    @Test("Hosts render the way pfctl prints them back")
    func hostsRenderBare() {
        let list = BlockList.parse("93.184.216.34/32\n2606:2800:220:1::/128")
        #expect(list.entries.map(\.tableEntry) == ["93.184.216.34", "2606:2800:220:1::"])
    }

    /// Two spellings of one network are one table entry. Left unmasked, a reload would
    /// compute a difference against pf's canonical form and churn on every SIGHUP.
    @Test("Networks are masked to their prefix")
    func masksNetworks() {
        let list = BlockList.parse("192.168.1.5/24\n2606:2800:220:1:abcd::/64")
        #expect(list.entries[0].tableEntry == "192.168.1.0/24")
        #expect(list.entries[1].tableEntry == "2606:2800:220:1::/64")
    }

    @Test("The same destination written twice is one entry")
    func deduplicates() {
        let list = BlockList.parse("10.0.0.0/8   # first\n10.0.0.1/8   # second")
        #expect(list.entries.count == 1)
        #expect(list.entries[0].note == "first")
        #expect(list.tableEntries == ["10.0.0.0/8"])
    }

    /// The mistake everyone makes first, and it deserves an answer that says blocking by
    /// name is a different feature rather than implying a typo.
    @Test("A host name is refused, and says why")
    func refusesHostNames() {
        let list = BlockList.parse("doubleclick.net")
        #expect(list.entries.isEmpty)
        #expect(list.problems.count == 1)
        #expect(list.problems[0].line == 1)
        #expect(list.problems[0].reason.contains("host names cannot be blocked"))
    }

    @Test("Bad lines are reported with their line number, not skipped")
    func reportsProblems() {
        let list = BlockList.parse(
            """
            93.184.216.34
            not-an-address
            10.0.0.0/99
            10.0.0.0 10.0.0.1
            """)
        #expect(list.entries.count == 1)
        #expect(list.problems.map(\.line) == [2, 3, 4])
    }

    @Test("Comments and blank lines produce nothing")
    func ignoresCommentary() {
        let list = BlockList.parse("# everything\n\n   \n#\n")
        #expect(list.entries.isEmpty)
        #expect(list.problems.isEmpty)
    }

    /// The file decides what a root process puts in the kernel's firewall. If the account
    /// being observed can write it, so can anything running as that account.
    @Test("Only a root-owned, root-writable list is usable")
    func fileOwnership() {
        #expect(BlockList.verdict(ownerUID: 0, mode: 0o644) == .usable)
        #expect(BlockList.verdict(ownerUID: 0, mode: 0o600) == .usable)
        #expect(BlockList.verdict(ownerUID: 501, mode: 0o644) == .notOwnedByRoot(uid: 501))
        #expect(BlockList.verdict(ownerUID: 0, mode: 0o664) == .writableByOthers(mode: 0o664))
        #expect(BlockList.verdict(ownerUID: 0, mode: 0o666) == .writableByOthers(mode: 0o666))
        #expect(BlockList.verdict(ownerUID: 0, mode: 0o777) == .writableByOthers(mode: 0o777))
    }
}

@Suite("Address masking")
struct AddressMaskingTests {

    @Test("IPv4 prefixes clear the bits below them")
    func maskingIPv4() {
        let address = IPAddress(text: "192.168.130.77")!
        #expect("\(address.masked(prefixLength: 32))" == "192.168.130.77")
        #expect("\(address.masked(prefixLength: 24))" == "192.168.130.0")
        #expect("\(address.masked(prefixLength: 16))" == "192.168.0.0")
        #expect("\(address.masked(prefixLength: 12))" == "192.160.0.0")
        #expect("\(address.masked(prefixLength: 0))" == "0.0.0.0")
    }

    /// The width boundary is the one worth pinning: in C a shift of the full word is
    /// undefined, and the /64 and /0 cases sit exactly on it.
    @Test("IPv6 prefixes clear the bits below them, including at the word boundary")
    func maskingIPv6() {
        let address = IPAddress(text: "2606:2800:220:1:248:1893:25c8:1946")!
        #expect("\(address.masked(prefixLength: 128))" == "2606:2800:220:1:248:1893:25c8:1946")
        #expect("\(address.masked(prefixLength: 64))" == "2606:2800:220:1::")
        #expect("\(address.masked(prefixLength: 48))" == "2606:2800:220::")
        #expect("\(address.masked(prefixLength: 32))" == "2606:2800::")
        #expect("\(address.masked(prefixLength: 0))" == "::")
    }
}

@Suite("Block list coverage")
struct BlockListCoverageTests {

    /// The question the UI actually asks, and the reason it is here rather than at the call
    /// site: it was a string comparison in a SwiftUI menu builder, so an address inside a
    /// blocked network still offered "Block this" — proposing an entry that changes nothing
    /// and that removing later would not unblock.
    @Test("A network entry covers the addresses inside it")
    func networksCover() {
        let list = BlockList.parse("10.0.0.0/8\n93.184.216.34")
        #expect(list.covers(IPAddress(text: "10.1.2.3")!))
        #expect(list.covers(IPAddress(text: "10.255.255.255")!))
        #expect(list.covers(IPAddress(text: "93.184.216.34")!))

        #expect(list.covers(IPAddress(text: "11.0.0.1")!) == false)
        #expect(list.covers(IPAddress(text: "93.184.216.35")!) == false)
    }

    @Test("Coverage does not cross address families")
    func familiesDoNotMix() {
        let v6 = BlockList.parse("2606:2800:220:1::/64")
        #expect(v6.covers(IPAddress(text: "2606:2800:220:1:abcd::1")!))
        #expect(v6.covers(IPAddress(text: "2606:2800:220:2::1")!) == false)
        #expect(v6.covers(IPAddress(text: "10.0.0.1")!) == false)

        // A v4 /0 must not swallow every v6 address, which is what a family-blind mask
        // comparison would do.
        let everything = BlockList.parse("0.0.0.0/0")
        #expect(everything.covers(IPAddress(text: "8.8.8.8")!))
        #expect(everything.covers(IPAddress(text: "2606:2800:220:1::1")!) == false)
    }

    @Test("Both files are consulted")
    func enforcedCoverage() {
        let both = EnforcedBlockList(
            fixed: BlockList.parse("10.0.0.0/8"), managed: BlockList.parse("1.1.1.1"))
        #expect(both.covers(IPAddress(text: "10.9.9.9")!))
        #expect(both.covers(IPAddress(text: "1.1.1.1")!))
        #expect(both.covers(IPAddress(text: "8.8.8.8")!) == false)
    }
}

@Suite("Unix socket paths")
struct UnixSocketPathTests {

    /// The check that turns a plausible-looking configuration into a daemon that cannot bind.
    /// It lived inside two executable-target servers, where no test could reach it.
    @Test("A path too long for sockaddr_un is refused rather than truncated")
    func pathLength() {
        #expect(UnixSocket.address(for: "/tmp/fine.sock") != nil)
        #expect(UnixSocket.address(for: "/" + String(repeating: "x", count: 200)) == nil)
        #expect(UnixSocket.maximumPathLength > 90)
    }

    @Test("Nothing is listening on a path that does not exist")
    func notAccepting() {
        #expect(UnixSocket.isAccepting(at: "/tmp/beholder-absent-\(getpid()).sock") == false)
    }
}
