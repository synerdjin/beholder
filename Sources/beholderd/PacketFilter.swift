import BeholderCore
import Darwin
import Dispatch
import Foundation

/// Blocking, which is the one thing here that changes what the machine does.
///
/// Everything else in Beholder observes. This does not: it puts addresses into a pf table
/// and packets to them stop leaving. That is why it is off unless asked for, announced on
/// startup the way `--probe` is, and why it refuses to run rather than partially work.
///
/// **Refusing is the important behaviour.** Every failure here — no anchor, an unreadable
/// list, a line that does not parse — stops the daemon instead of continuing without
/// enforcement. Capture that quietly carries on while blocking is off leaves someone
/// believing a destination is unreachable when it is not, and being wrong in the reassuring
/// direction is the worst way to be wrong. The same reasoning `ProtocolSniffer` uses for
/// never guessing `encrypted`.
///
/// The enforcement itself lives in `PacketFilterPlan`, in Core, where tests can reach it.
/// What is left here is spawning, the pf reference token, and the file on disk.
final class PacketFilter {

    enum FilterError: Error, CustomStringConvertible {
        case notRoot
        case anchorNotLoaded
        case listUnreadable(path: String, reason: String)
        case listInsecure(path: String, verdict: BlockList.FileVerdict)
        case listHasProblems(path: String, problems: [BlockList.Problem])
        case commandFailed(command: String, status: Int32, output: String)

        var description: String {
            switch self {
            case .notRoot:
                return "--block needs root: pf is configured through /dev/pf, which is root-only"

            case .anchorNotLoaded:
                return """
                    --block asked for, but Beholder's pf anchor is not loaded, so nothing \
                    would actually be blocked. Install it with:

                        sudo ./Scripts/install-pf-anchor.sh

                    If it was installed already, a macOS update may have restored the stock \
                    /etc/pf.conf, which removes the anchor line and silently disarms every \
                    block. Running the installer again is the fix; `make doctor` reports \
                    which case this is.
                    """

            case .listUnreadable(let path, let reason):
                return "cannot read the block list at \(path): \(reason)"

            case .listInsecure(let path, let verdict):
                return """
                    refusing to read the block list at \(path): \(verdict.description).

                    Fix it with:

                        sudo chown root:wheel \(path) && sudo chmod 644 \(path)
                    """

            case .listHasProblems(let path, let problems):
                let detail = problems
                    .map { "  line \($0.line): \($0.text) — \($0.reason)" }
                    .joined(separator: "\n")
                return """
                    the block list at \(path) has \(problems.count) line\
                    \(problems.count == 1 ? "" : "s") that cannot be used:

                    \(detail)

                    Refusing to start rather than enforcing part of a list you believe is \
                    being enforced whole.
                    """

            case .commandFailed(let command, let status, let output):
                let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
                return "\(command) exited \(status)\(trimmed.isEmpty ? "" : ": \(trimmed)")"
            }
        }
    }

    private let listPath: String

    /// The file the daemon owns and rewrites, holding whatever the app has asked for. Kept
    /// apart from `listPath`, which is written by a person and never regenerated — see
    /// `EnforcedBlockList` for why the split is worth a second file.
    private let managedListPath: String
    private let log: RunLog?

    /// Serialises arming, reloading and tearing down against each other. A SIGHUP arriving
    /// while shutdown is running would otherwise refill the table Beholder is emptying.
    private let queue = DispatchQueue(label: "com.beholder.packet-filter")

    /// pf's reference token, held from `arm()` to `disarm()`. Nil means pf was never
    /// enabled by us and must not be disabled by us.
    private var token: String?

    /// What the two files most recently said, so a control request can add to the managed
    /// half without re-reading the hand-edited half and silently picking up an edit that was
    /// half-written at the moment the button was pressed.
    private var lists = EnforcedBlockList(fixed: BlockList(entries: []), managed: BlockList(entries: []))
    private var hangupSource: DispatchSourceSignal?

    /// Set once teardown has run, so a second signal cannot flush a table twice or release
    /// a token that is already back.
    private var isDisarmed = false

    /// Whether any `pfctl` command that changes the table has been issued.
    ///
    /// Teardown keys off this rather than off `lists`, because the two disagree in exactly
    /// the case that matters. `applyLocked` updates `lists` only after every command has
    /// succeeded, so a chunked add that fails partway leaves entries in pf that Beholder does
    /// not believe are there — and on a first `arm()` that means `lists` is still empty, the
    /// flush is skipped, and the destinations stay blocked after the daemon has exited. This
    /// is set before the first such command runs, so teardown cleans up anything that might
    /// have landed.
    private var didModifyTable = false

    init(listPath: String, managedListPath: String, log: RunLog?) {
        self.listPath = listPath
        self.managedListPath = managedListPath
        self.log = log
    }

    // MARK: - Arming

    /// Reads the list, checks pf is in a state worth trusting, and starts blocking.
    ///
    /// The order matters. The anchor is checked *before* pf is enabled, so a machine that
    /// was never installed for blocking does not end up with pf switched on and a reference
    /// held for a daemon that is about to exit.
    func arm() throws -> String {
        guard geteuid() == 0 else { throw FilterError.notRoot }

        // Read before taking the queue, and before touching pf at all: a list that cannot be
        // used should fail without having enabled anything.
        let list = try readLists()

        return try queue.sync {
            let rules = try Self.run(PacketFilterPlan.showAnchorRules())
            guard PacketFilterPlan.anchorIsLoaded(rulesOutput: rules.standardOutput) else {
                throw FilterError.anchorNotLoaded
            }

            // The token goes to stderr; combined rather than stderr alone only because
            // which stream it lands on has varied between releases, and the line is
            // recognised by its label rather than by its position.
            let enableOutput = try Self.run(PacketFilterPlan.enable())
            token = PacketFilterPlan.parseEnableToken(enableOutput.combined)
            if token == nil {
                // Not fatal: pf is enabled either way, and the only thing lost is the ability
                // to hand the reference back cleanly on exit. Worth saying out loud, because
                // it means pf may stay enabled after Beholder stops.
                Beholderd.note(
                    "pf is enabled but returned no reference token; it will be left enabled on exit"
                )
            }

            return try applyLocked(list, reason: "startup")
        }
    }

    /// Re-reads the list and adjusts what pf holds. Bound to SIGHUP.
    ///
    /// A reload that cannot be applied leaves the previous rules in place and says so. That
    /// is the opposite of the startup policy on purpose: refusing to start protects someone
    /// who thinks blocking is on when it is not, while refusing to *change* protects them
    /// from an edit that would have unblocked everything.
    func installReloadHandler() {
        signal(SIGHUP, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGHUP, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            do {
                // Already on `queue` — the signal source was created against it — so this
                // calls the queue-confined form directly. Going through a `queue.sync` here
                // would deadlock on the first reload, which is a fault that would only ever
                // have appeared under root, on a running machine.
                let list = try self.readLists()
                let summary = try self.applyLocked(list, reason: "SIGHUP")
                Beholderd.note("block list reloaded: \(summary)")
            } catch {
                Beholderd.note(
                    "block list reload failed, keeping the previous rules: "
                        + "\((error as? FilterError)?.description ?? "\(error)")")
            }
        }
        source.resume()
        hangupSource = source
    }

    // MARK: - Disarming

    /// Empties the table and hands pf's reference back.
    ///
    /// Blocking lasts exactly as long as the daemon does. The alternative — leaving the
    /// table populated so blocks survive — was rejected because it turns a crash into a
    /// machine with a firewall nobody is managing and no obvious way to find out why a site
    /// stopped loading. Stopping capture restoring the network is a property worth having.
    ///
    /// A daemon killed with SIGKILL never gets here, which is what `make unblock` is for.
    /// Safe to call on a filter that never armed, or armed only partly — which is exactly
    /// when it matters most. `arm()` enables pf before it has finished deciding whether it
    /// can enforce anything, so the failure paths in between have to be able to give that
    /// back. Both the table flush and the reference release are conditional on something
    /// having been taken.
    func disarm() {
        queue.sync {
            guard !isDisarmed else { return }
            isDisarmed = true

            // Flushed whenever anything might have been added, not merely when Beholder
            // believes something was. Flushing an empty table is harmless; leaving a
            // half-applied one behind is a machine that cannot reach a destination and no
            // longer has a daemon to ask about it.
            if didModifyTable {
                let held = lists.tableEntries
                if let error = Self.attempt(PacketFilterPlan.flushTable()) {
                    Beholderd.note("could not flush the block table: \(error)")
                } else if held.isEmpty {
                    Beholderd.note("blocking stopped; the table was emptied")
                } else {
                    Beholderd.note("blocking stopped; \(held.count) destination(s) released")
                }
                didModifyTable = false
                lists = EnforcedBlockList(
                    fixed: BlockList(entries: []), managed: BlockList(entries: []))
            }
            if let token {
                if let error = Self.attempt(PacketFilterPlan.release(token: token)) {
                    Beholderd.note("could not release the pf reference: \(error)")
                }
                self.token = nil
            }
        }
    }

    // MARK: - The control surface

    /// What is blocked right now, and by which file.
    func state() -> ControlState {
        queue.sync { currentState }
    }

    /// The shape of every successful reply, in one place.
    ///
    /// It was built at three call sites, which is three chances for a field added later to
    /// reach two of them — and the difference would show as the app answering differently
    /// depending on which button was pressed. Queue-confined, like everything it reads.
    private var currentState: ControlState {
        dispatchPrecondition(condition: .onQueue(queue))
        return ControlState(isBlocking: true, entries: lists.controlEntries)
    }

    /// Parses a destination the way the file would, then runs `body` on the queue.
    ///
    /// `add` and `remove` opened with the same seven lines of parse-reject-then-`queue.sync`,
    /// which put the rejection wording in two places and nested both methods' real work a
    /// level deeper than it needed to be.
    private func withDestination(
        _ text: String,
        _ body: (BlockList.Entry) -> ControlResponse
    ) -> ControlResponse {
        switch BlockList.parseDestination(text) {
        case .rejected(let reason):
            return .failure("\(text): \(reason)")
        case .parsed(let entry):
            return queue.sync { body(entry) }
        }
    }

    /// Adds a destination to the managed list and starts blocking it.
    ///
    /// The file is written first and pf second. If the write fails nothing is enforced, which
    /// is the honest failure — the alternative order would block something that vanishes on
    /// the next restart, and a block the user cannot find in any file is worse than one that
    /// did not happen.
    func add(destination: String, note: String?) -> ControlResponse {
        withDestination(destination) { entry in
            if lists.isFixed(entry.tableEntry) {
                // Not an error: the destination is blocked, which is what was asked for.
                // Saying so beats silently adding a duplicate to a file that cannot change
                // the outcome.
                return ControlResponse(ok: true, state: currentState)
            }

            var entries = lists.managed.entries
            if let existing = entries.firstIndex(where: { $0.tableEntry == entry.tableEntry }) {
                entries[existing] = entry
            } else {
                entries.append(entry)
            }
            return commit(managed: entries, reason: "blocked \(entry.tableEntry)")
        }
    }

    /// Removes a destination the managed list added.
    func remove(destination: String) -> ControlResponse {
        withDestination(destination) { entry in
            guard !lists.isFixed(entry.tableEntry) else {
                return .failure(
                    "\(entry.tableEntry) is blocked by \(listPath), which only root edits. "
                        + "Beholder will not rewrite a file a person wrote.")
            }
            let entries = lists.managed.entries.filter { $0.tableEntry != entry.tableEntry }
            guard entries.count != lists.managed.entries.count else {
                return .failure("\(entry.tableEntry) is not blocked")
            }
            return commit(managed: entries, reason: "unblocked \(entry.tableEntry)")
        }
    }

    /// Writes the managed list and brings pf into line with it.
    ///
    /// Must be called on `queue`. On any failure the previous file is left in place and the
    /// error is returned rather than thrown: this is answering a request from the app, and a
    /// sentence it can display beats an exception it would have to translate.
    private func commit(managed entries: [BlockList.Entry], reason: String) -> ControlResponse {
        dispatchPrecondition(condition: .onQueue(queue))

        let text = BlockList.render(entries, generatedBy: "beholderd, from Beholder.app")
        do {
            try writeManagedList(text)
        } catch {
            return .failure("could not write \(managedListPath): \(error)")
        }

        let updated = EnforcedBlockList(fixed: lists.fixed, managed: BlockList(entries: entries))
        do {
            _ = try applyLocked(updated, reason: reason)
        } catch {
            return .failure(
                "the list was saved but pf did not accept it: "
                    + "\((error as? FilterError)?.description ?? "\(error)")")
        }
        Beholderd.note(reason)
        return ControlResponse(ok: true, state: currentState)
    }

    /// Writes the managed list atomically, root-owned and not writable by anyone else.
    ///
    /// Through a temporary file in the same directory and a rename, so a daemon killed
    /// mid-write leaves the previous list rather than half of the new one — this file is read
    /// back at startup as configuration, and half a list of blocks is a state nobody could
    /// diagnose. The permissions are set before the rename for the same reason: the file is
    /// never visible at its final path in a state the reader would refuse.
    private func writeManagedList(_ text: String) throws {
        let directory = (managedListPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755, .ownerAccountID: 0])

        let temporary = managedListPath + ".new"
        try text.write(toFile: temporary, atomically: false, encoding: .utf8)
        chown(temporary, 0, 0)
        chmod(temporary, 0o644)
        guard rename(temporary, managedListPath) == 0 else {
            // Captured before the unlink, which is free to overwrite it — the same rule
            // `SnapshotClient` states on its own connect path. Read afterwards, the reported
            // cause describes the cleanup rather than the failure.
            let code = errno
            unlink(temporary)
            throw FilterError.commandFailed(
                command: "rename \(temporary)", status: code,
                output: String(cString: strerror(code)))
        }
    }

    // MARK: - Internals

    /// Reads both list files.
    ///
    /// The reading itself lives in `EnforcedBlockList.read`, in Core, so that
    /// `--check-blocklist` previews exactly what this enforces rather than re-deriving it —
    /// two implementations of "what does this file mean" is how a preview comes to disagree
    /// with the daemon. What is left here is turning a stated reason into this type's errors.
    private func readLists() throws -> EnforcedBlockList {
        switch EnforcedBlockList.read(fixed: listPath, managed: managedListPath) {
        case .lists(let lists):
            return lists
        case .failed(let path, .missing(let reason)):
            throw FilterError.listUnreadable(path: path, reason: reason)
        case .failed(let path, .insecure(let verdict)):
            throw FilterError.listInsecure(path: path, verdict: verdict)
        case .failed(let path, .unusable(let problems)):
            throw FilterError.listHasProblems(path: path, problems: problems)
        }
    }

    /// Brings pf's table in line with the list, and drops the connections that a newly
    /// blocked destination already had.
    ///
    /// Must be called on `queue`, and does not take it itself: one caller is the SIGHUP
    /// handler, which the signal source already runs there, so a `queue.sync` here would
    /// deadlock on the first reload — under root, on a running machine, which is the worst
    /// place to find it. The precondition is what makes that a crash in a debug build rather
    /// than a hang in a release one.
    private func applyLocked(_ list: EnforcedBlockList, reason: String) throws -> String {
        dispatchPrecondition(condition: .onQueue(queue))

        // Strictly stdout. See `CommandOutput`: pfctl's ALTQ warnings on stderr were read
        // as table entries here, and the entries it then tried to delete crash-looped the
        // daemon.
        let current = PacketFilterPlan.parseTable(
            try Self.run(PacketFilterPlan.showTable()).standardOutput)
        let desired = list.tableEntries
        let allEntries = list.fixed.entries + list.managed.entries

        let changes = PacketFilterPlan.synchronise(desired: desired, current: current)
        if !changes.isEmpty { didModifyTable = true }
        for command in changes {
            _ = try Self.run(command)
        }

        // Only what was not already blocked: an established connection to something that has
        // been in the table all along was torn down when it was added.
        //
        // Off the critical path, because there is one `pfctl -k` spawn per destination and
        // `pfctl` has no multi-host form to batch them into. At `arm()` the table is empty, so
        // *every* entry is newly blocked — a few hundred lines of block list became seconds of
        // fork/exec before `engine.start` opened capture, and packets went unseen for the
        // whole window. The table itself is already correct by this point; these only tear
        // down connections that predate the rule, and doing that a moment later is
        // indistinguishable from doing it now.
        let newlyBlocked = desired.subtracting(current)
        let kills = allEntries
            .filter { newlyBlocked.contains($0.tableEntry) }
            .map { PacketFilterPlan.killStates(for: $0.tableEntry, family: $0.address.family) }
        if !kills.isEmpty {
            queue.async { for kill in kills { _ = try? Self.run(kill) } }
        }

        lists = list
        let added = newlyBlocked.count
        let removed = current.subtracting(desired).count
        let summary =
            "\(desired.count) destination\(desired.count == 1 ? "" : "s") blocked"
            + (added > 0 ? ", \(added) added" : "")
            + (removed > 0 ? ", \(removed) removed" : "")

        log?.section(
            "BLOCKING (\(reason))",
            """
            Lists:   \(listPath)
                     \(managedListPath)
            State:   \(summary)
            Entries:
            \(list.controlEntries.map { "  \($0.destination)\($0.isRemovable ? "" : "  [fixed]")\($0.note.map { note in "  # \(note)" } ?? "")" }.joined(separator: "\n"))
            """
        )
        return summary
    }

    /// What one `pfctl` invocation said, with its two streams kept apart.
    ///
    /// **They must not be merged, and that is not a matter of tidiness.** `pfctl` writes
    /// warnings unrelated to the command on stderr — every Mac lacks ALTQ in the kernel, so
    /// `-T show` is accompanied by three lines about it — and merging them put those lines
    /// into output that is parsed as a list of addresses. The result was a daemon that asked
    /// pf to delete table entries called `No` and `ALTQ`, failed, refused to start, and was
    /// restarted by launchd forever.
    ///
    /// The general shape of that mistake has now appeared three times in this project: the
    /// MCP server's stdout carrying nothing but protocol, the pf anchor being written from a
    /// binary's stdout, and this. A stream that something parses cannot also be a place to
    /// write remarks.
    private struct CommandOutput {
        let standardOutput: String
        let standardError: String

        /// For error messages, where the reader is a person and more context is better.
        var combined: String {
            [standardOutput, standardError]
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: "\n")
        }
    }

    /// Runs `pfctl`.
    ///
    /// Spawned with an argument vector and an absolute path: no shell, so nothing in an
    /// argument can be read as syntax, and no `PATH` lookup, so a root process cannot be
    /// pointed at a different `pfctl`.
    @discardableResult
    private static func run(_ command: PacketFilterPlan.Command) throws -> CommandOutput {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: PacketFilterPlan.pfctlPath)
        process.arguments = command.arguments

        let outPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errorPipe

        do {
            try process.run()
        } catch {
            throw FilterError.commandFailed(
                command: command.commandLine, status: -1, output: "\(error)")
        }

        // Both streams are drained concurrently, and before waiting. Reading one to the end
        // and then the other deadlocks the moment the unread one fills its pipe buffer, with
        // pfctl blocked on a write nobody is reading and this blocked on a read that will
        // never complete.
        //
        // The box exists because the draining closure has to write somewhere the caller can
        // read afterwards. `group.wait()` is the ordering — the write happens-before the
        // read — which the compiler cannot see, hence the unchecked conformance rather than
        // a lock that would do nothing.
        final class Buffer: @unchecked Sendable { var data = Data() }
        let errorBuffer = Buffer()
        let group = DispatchGroup()
        DispatchQueue(label: "com.beholder.pfctl-stderr").async(group: group) {
            errorBuffer.data = errorPipe.fileHandleForReading.readDataToEndOfFile()
        }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        process.waitUntilExit()

        let output = CommandOutput(
            standardOutput: String(data: outData, encoding: .utf8) ?? "",
            standardError: String(data: errorBuffer.data, encoding: .utf8) ?? "")

        guard process.terminationStatus == 0 || command.isAdvisory else {
            throw FilterError.commandFailed(
                command: command.commandLine,
                status: process.terminationStatus,
                output: output.combined)
        }
        return output
    }

    /// `run` for the teardown path, where there is nothing useful to do with a throw.
    private static func attempt(_ command: PacketFilterPlan.Command) -> String? {
        do {
            _ = try run(command)
            return nil
        } catch {
            return (error as? FilterError)?.description ?? "\(error)"
        }
    }
}
