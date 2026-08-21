import Foundation

/// Everything Beholder knows about driving pf, expressed as values rather than as calls.
///
/// The daemon does the spawning; this decides what to spawn. Keeping the decision here is
/// what makes it testable — `PacketFilter` lives in an executable target that no unit test
/// can reach, so a diff computed there would be covered by nothing.
///
/// **The ruleset is static and the table is dynamic, and that split is the security
/// design.** Rule *text* is written once, at install time, from the constant below. Nothing
/// derived from a block list, a captured packet or a DNS answer is ever concatenated into a
/// pf rule. The only thing that changes at run time is which addresses are in a table, and
/// every address that gets there has been through `IPAddress` and been re-rendered by
/// `inet_ntop`. There is no string a hostile input could contain that arrives at `pfctl` as
/// anything other than an address — and `pfctl` is spawned with an argument vector, never
/// through a shell, so there is no second layer to get wrong either.
public enum PacketFilterPlan {

    /// The anchor Beholder's rules live in.
    ///
    /// A nested anchor is only evaluated if the main ruleset names it, which is why
    /// installing this means editing `/etc/pf.conf`. Apple's own note at the top of that
    /// file says the main ruleset must not be flushed for exactly this reason.
    public static let anchorName = "com.beholder"
    public static let tableName = "beholder_blocked"
    public static let anchorPath = "/etc/pf.anchors/com.beholder"
    public static let mainConfigurationPath = "/etc/pf.conf"

    /// Absolute, because a root process must never resolve a program name through `PATH`.
    public static let pfctlPath = "/sbin/pfctl"

    /// The rules, in full. Written to `anchorPath` at install time and never generated.
    ///
    /// Four decisions worth keeping:
    ///
    /// - **`quick`.** pf is last-match-wins, so without it a later rule — in an anchor some
    ///   system service inserted while Beholder was not looking — could pass a packet this
    ///   rule had already matched. `quick` ends evaluation at the match.
    /// - **`return`, not `drop`.** pf generates the refusal itself: a TCP RST or an ICMP
    ///   unreachable, from the kernel, addressed to the local program that sent the packet.
    ///   The application fails immediately instead of hanging until its own timeout, and
    ///   nothing is forged onto the network — the alternative, injecting a reset from
    ///   userspace, would mean Beholder crafting packets, which is a much larger claim than
    ///   this project should be making.
    /// - **`out` only.** Beholder blocks what this machine initiates. Inbound filtering is
    ///   the built-in firewall's job and this has nothing to add to it.
    /// - **`log`.** Blocked packets go to `pflog0`, so "did that actually block anything"
    ///   has an answer — `tcpdump -n -e -ttt -i pflog0` — instead of being inferred from an
    ///   absence. With no listener the log packets are discarded, so it costs nothing.
    ///
    /// No address family is named: one rule covers both, and the table holds whichever
    /// families the block list mentions.
    public static let anchorRuleset = """
        # Beholder's pf anchor. Written by Scripts/install-pf-anchor.sh - edits here are
        # replaced on the next install.
        #
        # The rules are fixed. What changes is the table, which beholderd fills from its
        # block list while it runs and empties again when it stops.
        table <\(tableName)> persist
        block return out log quick from any to <\(tableName)>

        """

    /// The lines `/etc/pf.conf` needs for the anchor above to be evaluated at all.
    ///
    /// Exposed rather than left in the install script because three things check for them —
    /// the installer, `doctor.sh`, and the daemon at startup — and the daemon's check is the
    /// one that matters most: a macOS update can restore the stock `pf.conf`, which silently
    /// removes these lines and leaves a daemon that believes it is blocking and is not.
    public static let mainConfigurationLines = """
        \(beginMarker)
        anchor "\(anchorName)"
        load anchor "\(anchorName)" from "\(anchorPath)"
        \(endMarker)
        """

    /// Markers around the block, so adding it twice and removing it cleanly are both
    /// one-liners for a shell script — and so removal can never take a neighbouring line
    /// with it. ASCII only: this is a system file that other tools read.
    public static let beginMarker = "# BEGIN Beholder - added by Scripts/install-pf-anchor.sh"
    public static let endMarker = "# END Beholder"

    /// One `pfctl` invocation, as an argument vector.
    public struct Command: Equatable, Sendable {
        public let arguments: [String]

        /// Whether a non-zero exit means the whole operation failed.
        ///
        /// State kills are the exception: pf may have no matching state, `pfctl` says so,
        /// and nothing is wrong. Everything else failing means Beholder is not enforcing
        /// what it was asked to, and saying so is the entire point.
        public let isAdvisory: Bool

        public init(arguments: [String], isAdvisory: Bool = false) {
            self.arguments = arguments
            self.isAdvisory = isAdvisory
        }

        /// The command as a person would type it, for the transcript and for error text.
        public var commandLine: String {
            ([pfctlPath] + arguments).joined(separator: " ")
        }
    }

    // MARK: - Lifecycle

    /// Enables pf, taking a reference rather than switching it on.
    ///
    /// `-E` and `-X` rather than `-e` and `-d` because `/etc/pf.conf` asks for it in its own
    /// comments: pf is shared. Internet Sharing uses it, and so do several VPN clients —
    /// including the one this machine runs. `-e`/`-d` would let Beholder switch pf off under
    /// something else that had switched it on, which is a fault that shows up as somebody
    /// else's firewall silently not working.
    public static func enable() -> Command {
        Command(arguments: ["-E"])
    }

    public static func release(token: String) -> Command {
        Command(arguments: ["-X", token])
    }

    /// Reads back the anchor's rules, to prove the anchor is actually loaded.
    public static func showAnchorRules() -> Command {
        Command(arguments: ["-a", anchorName, "-s", "rules"])
    }

    public static func showTable() -> Command {
        Command(arguments: ["-a", anchorName, "-t", tableName, "-T", "show"])
    }

    public static func flushTable() -> Command {
        Command(arguments: ["-a", anchorName, "-t", tableName, "-T", "flush"])
    }

    // MARK: - Keeping the table in step with the list

    /// How many addresses go in one `pfctl` invocation.
    ///
    /// A block list can be long, and an argument vector cannot. Chunking keeps every
    /// invocation far below `ARG_MAX` without anyone having to know what it is.
    static let chunkSize = 128

    /// The commands that turn what pf currently holds into what the block list asks for.
    ///
    /// A difference rather than a flush-and-reload, because flushing would unblock
    /// everything for the moment it takes to refill — and a reload happens while the machine
    /// is running, which is exactly when that gap would be used.
    public static func synchronise(
        desired: Set<String>,
        current: Set<String>
    ) -> [Command] {
        var commands: [Command] = []

        // Both directions are the same operation with a different verb, so they are written
        // once. Two copies of the chunking arithmetic could drift, and only one of them
        // would be exercised by a list that has only ever grown.
        for (verb, entries) in [
            ("add", desired.subtracting(current).sorted()),
            ("delete", current.subtracting(desired).sorted()),
        ] {
            for start in stride(from: 0, to: entries.count, by: chunkSize) {
                let slice = Array(entries[start..<min(start + chunkSize, entries.count)])
                commands.append(
                    Command(arguments: ["-a", anchorName, "-t", tableName, "-T", verb] + slice))
            }
        }
        return commands
    }

    /// Tears down the connections a newly blocked destination already had.
    ///
    /// Adding a rule does nothing to traffic that is already flowing: pf looks up state
    /// before it evaluates rules, so an established connection to a freshly blocked address
    /// keeps running until it ends on its own. Blocking something and watching it carry on
    /// reads as the block having failed, and the fix is to drop the state as well.
    ///
    /// Advisory: `pfctl -k` reports failure when nothing matched, which is the ordinary case
    /// for a destination that was not being talked to.
    public static func killStates(for entry: String, family: IPAddress.Family) -> Command {
        let anySource = family == .v4 ? "0.0.0.0/0" : "::/0"
        return Command(arguments: ["-k", anySource, "-k", entry], isAdvisory: true)
    }

    // MARK: - Reading pfctl back

    /// The addresses in `pfctl -T show` output.
    ///
    /// One per line and indented. Parsed rather than assumed so that a future `pfctl` that
    /// pads differently does not turn every entry into a permanent add-and-remove cycle.
    ///
    /// **Every line must parse as an address, and anything else is discarded.** This is not
    /// defensive tidiness; it is the fix for a real crash loop. `pfctl` writes warnings that
    /// have nothing to do with the table — on any Mac without ALTQ in the kernel, which is
    /// all of them, `-T show` is accompanied by "No ALTQ support in kernel" and two more
    /// lines like it. Taking the first field of each line turned those into table entries
    /// named `No`, `ALTQ` and `no`, which the very next step dutifully tried to delete from
    /// the table. `pfctl` exited 255, the daemon refused to start, and launchd restarted it
    /// forever.
    ///
    /// The daemon now keeps `pfctl`'s two output streams apart so the warnings never reach
    /// here at all. This check stays anyway, because the escalation is what made that bug
    /// expensive: unrecognised *output* is harmless, and an unrecognised output turned into
    /// a *command argument* is not.
    public static func parseTable(_ output: String) -> Set<String> {
        var result: Set<String> = []
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            // A table can be shown with counters attached; take only the address.
            guard let first = trimmed.split(separator: " ").first else { continue }
            guard case .parsed(let entry) = BlockList.parseDestination(String(first)) else {
                continue
            }
            result.insert(entry.tableEntry)
        }
        return result
    }

    /// The reference token `pfctl -E` prints, which `-X` needs to give it back.
    ///
    /// It goes to stderr, not stdout, and the spacing around the colon has varied between
    /// releases — so this matches on the label and takes the last field rather than a fixed
    /// column.
    public static func parseEnableToken(_ output: String) -> String? {
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.lowercased().hasPrefix("token") else { continue }
            guard let token = trimmed.split(separator: ":").last?
                .trimmingCharacters(in: .whitespaces), !token.isEmpty
            else { continue }
            return token
        }
        return nil
    }

    /// Whether `pfctl -a com.beholder -s rules` shows Beholder's rule.
    ///
    /// The check is for the table reference, which is the part that makes the rule Beholder's
    /// rather than merely present. An anchor that exists but holds someone else's rules is
    /// not something to start adding addresses to.
    public static func anchorIsLoaded(rulesOutput: String) -> Bool {
        rulesOutput.contains("<\(tableName)>")
    }
}
