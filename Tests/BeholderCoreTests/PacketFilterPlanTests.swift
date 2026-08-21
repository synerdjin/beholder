import Foundation
import Testing

@testable import BeholderCore

@Suite("Packet filter plan")
struct PacketFilterPlanTests {

    /// These four words are the whole safety argument of the ruleset, and every one of them
    /// was chosen against a specific alternative. A test that pins them is what stops the
    /// rule being "tidied" into something that fails open or hangs the application.
    @Test("The ruleset blocks outbound, quickly, and answers the sender")
    func rulesetShape() {
        let rules = PacketFilterPlan.anchorRuleset
        #expect(rules.contains("table <beholder_blocked> persist"))
        // quick: pf is last-match-wins, so without it a later anchor could pass what this
        // rule matched. return: the kernel refuses to the local program, so nothing is
        // forged onto the network and the application fails instead of hanging. out: this
        // machine's own traffic, which is all Beholder has any business filtering.
        #expect(rules.contains("block return out log quick from any to <beholder_blocked>"))
        #expect(rules.contains("block drop") == false)
    }

    /// A nested anchor that the main ruleset never names is never evaluated — it loads
    /// without complaint and blocks nothing. Both halves have to be present.
    @Test("The pf.conf lines both name and load the anchor")
    func mainConfigurationLines() {
        let lines = PacketFilterPlan.mainConfigurationLines
        #expect(lines.contains("anchor \"com.beholder\""))
        #expect(lines.contains("load anchor \"com.beholder\" from \"/etc/pf.anchors/com.beholder\""))
        // Marked at both ends so the installer can add it once and the uninstaller can
        // remove exactly it, without a stray sed taking a neighbouring line with it.
        #expect(lines.hasPrefix(PacketFilterPlan.beginMarker))
        #expect(lines.hasSuffix(PacketFilterPlan.endMarker))
    }

    @Test("pfctl is named absolutely, never resolved through PATH")
    func pfctlIsAbsolute() {
        #expect(PacketFilterPlan.pfctlPath.hasPrefix("/"))
    }

    @Test("Enabling takes a reference rather than switching pf on")
    func enableTakesAReference() {
        // -e/-d would let Beholder switch pf off underneath Internet Sharing or a VPN
        // client that had switched it on. /etc/pf.conf asks for -E/-X in its own comments.
        #expect(PacketFilterPlan.enable().arguments == ["-E"])
        #expect(PacketFilterPlan.release(token: "1234").arguments == ["-X", "1234"])
    }

    @Test("Synchronising adds what is missing and removes what is stale")
    func synchronisation() {
        let commands = PacketFilterPlan.synchronise(
            desired: ["1.1.1.1", "10.0.0.0/8"],
            current: ["10.0.0.0/8", "9.9.9.9"])

        #expect(commands.count == 2)
        #expect(
            commands[0].arguments
                == ["-a", "com.beholder", "-t", "beholder_blocked", "-T", "add", "1.1.1.1"])
        #expect(
            commands[1].arguments
                == ["-a", "com.beholder", "-t", "beholder_blocked", "-T", "delete", "9.9.9.9"])
    }

    /// A flush-and-refill would unblock everything for the moment it takes to refill, and a
    /// reload happens on a running machine — which is exactly when that gap would be used.
    @Test("An unchanged list issues no commands at all")
    func noChangeNoCommands() {
        let entries: Set<String> = ["1.1.1.1", "10.0.0.0/8"]
        #expect(PacketFilterPlan.synchronise(desired: entries, current: entries).isEmpty)
    }

    /// An argument vector has a size limit and a block list does not.
    @Test("Long lists are split across invocations")
    func chunking() {
        let desired = Set((0..<300).map { "10.\($0 / 256).\($0 % 256).1" })
        let commands = PacketFilterPlan.synchronise(desired: desired, current: [])
        #expect(commands.count == 3)
        let addressed = commands.reduce(0) { $0 + $1.arguments.count - 6 }
        #expect(addressed == 300)
    }

    /// pf looks up state before it evaluates rules, so an established connection to a newly
    /// blocked address carries on until it ends by itself. Blocking something and watching
    /// it keep working reads as the block having failed.
    @Test("Newly blocked destinations have their existing connections killed")
    func stateKill() {
        let v4 = PacketFilterPlan.killStates(for: "1.1.1.1", family: .v4)
        #expect(v4.arguments == ["-k", "0.0.0.0/0", "-k", "1.1.1.1"])
        let v6 = PacketFilterPlan.killStates(for: "2606:2800:220:1::", family: .v6)
        #expect(v6.arguments == ["-k", "::/0", "-k", "2606:2800:220:1::"])
        // pfctl reports failure when no state matched, which is the ordinary case.
        #expect(v4.isAdvisory)
    }

    @Test("Reads back what pf currently holds")
    func tableParsing() {
        let output = """
               1.1.1.1
               10.0.0.0/8
               2606:2800:220:1::

            """
        #expect(
            PacketFilterPlan.parseTable(output) == ["1.1.1.1", "10.0.0.0/8", "2606:2800:220:1::"])
    }

    /// The exact output that crash-looped the daemon on a live machine. `pfctl` writes these
    /// warnings on every Mac — no kernel here has ALTQ — and reading them as table entries
    /// produced a `-T delete No ALTQ no`, which exits 255 and takes the daemon down with it.
    /// Unrecognised output is harmless; unrecognised output promoted to a command argument
    /// is not.
    @Test("pfctl's own warnings are never mistaken for table entries")
    func tableParsingIgnoresWarnings() {
        let output = """
            No ALTQ support in kernel
            ALTQ related functions disabled
               1.1.1.1
            no IP address found for ALTQ
               10.0.0.0/8

            """
        #expect(PacketFilterPlan.parseTable(output) == ["1.1.1.1", "10.0.0.0/8"])
    }

    /// The consequence of the above, stated as the thing that actually mattered: nothing
    /// pfctl says about ALTQ can become an argument to a command.
    @Test("A table full of warnings asks pfctl to delete nothing")
    func warningsProduceNoCommands() {
        let noise = PacketFilterPlan.parseTable("No ALTQ support in kernel\nALTQ disabled")
        #expect(noise.isEmpty)
        #expect(PacketFilterPlan.synchronise(desired: [], current: noise).isEmpty)
    }

    @Test("Finds the reference token pfctl prints")
    func tokenParsing() {
        #expect(
            PacketFilterPlan.parseEnableToken("pf enabled\nToken : 13800827389748029234\n")
                == "13800827389748029234")
        #expect(PacketFilterPlan.parseEnableToken("Token: 42") == "42")
        #expect(PacketFilterPlan.parseEnableToken("pf enabled\n") == nil)
    }

    /// An anchor that exists but holds someone else's rules is not one to start adding
    /// addresses to, so the check is for the table reference rather than for any output.
    @Test("An anchor without Beholder's table does not count as loaded")
    func anchorDetection() {
        #expect(
            PacketFilterPlan.anchorIsLoaded(
                rulesOutput: "block return out log quick from any to <beholder_blocked>"))
        #expect(PacketFilterPlan.anchorIsLoaded(rulesOutput: "") == false)
        #expect(
            PacketFilterPlan.anchorIsLoaded(rulesOutput: "block drop out all") == false)
    }
}
