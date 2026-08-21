import Foundation

/// The list of destinations Beholder has been asked to block.
///
/// Beholder blocks by *destination*, never by process, and that is not a temporary
/// shortcoming. The enforcement mechanism is pf, which matches on address, port, protocol
/// and interface and has no concept of a process; the only macOS API that can filter per
/// application is `NEFilterDataProvider`, which needs an entitlement Apple grants by
/// individual application. So attribution decides *what to block* and the block applies to
/// everything on the machine. Any interface that implies otherwise is lying, which is why
/// this type carries no process field for a caller to be tempted by.
///
/// The consequence to keep in mind while using it: one address commonly serves many names.
/// Blocking a CDN address to stop one tracker stops everything else behind that address
/// too, and there is no passive way to tell from the outside which those are.
public struct BlockList: Equatable, Sendable {

    /// One destination: a single address, or a network in CIDR form.
    public struct Entry: Hashable, Sendable {
        public let address: IPAddress
        public let prefixLength: UInt8

        /// Why it was blocked, if the file said. Carried through to the transcript and the
        /// status output, because a list of bare addresses is unreadable a month later and
        /// "what is this and can I remove it" is the question actually asked of it.
        public let note: String?

        /// True when the entry names one address rather than a network.
        public var isHost: Bool {
            prefixLength == (address.family == .v4 ? 32 : 128)
        }

        /// Equality and hashing ignore `tableEntry`: it is derived from the other two
        /// identity fields, and a note is commentary rather than identity. Without this,
        /// re-parsing a list with a reworded comment would look like a different list.
        public static func == (lhs: Entry, rhs: Entry) -> Bool {
            lhs.address == rhs.address && lhs.prefixLength == rhs.prefixLength
        }

        public func hash(into hasher: inout Hasher) {
            hasher.combine(address)
            hasher.combine(prefixLength)
        }

        /// The entry as pf writes it in a table.
        ///
        /// Rendered from the parsed address rather than echoed from the file, which is what
        /// makes this safe to hand to `pfctl`: whatever the file contained, what leaves here
        /// is `inet_ntop` output and a small integer. There is no arrangement of bytes in
        /// the input that survives a round trip through `IPAddress` as anything else.
        ///
        /// Hosts render bare, matching how `pfctl -T show` prints them back — the two are
        /// compared directly to work out what to add and remove, and a `/32` on one side
        /// only would make every sync think every host was both new and stale.
        ///
        /// Stored rather than computed, because it is a pure function of two immutable
        /// fields and everything here reads it repeatedly: one control request walks the
        /// entries half a dozen times, and re-rendering meant an `inet_ntop` and a fresh
        /// `String` every time.
        public let tableEntry: String

        public init(address: IPAddress, prefixLength: UInt8, note: String? = nil) {
            self.address = address
            self.prefixLength = prefixLength
            self.note = note
            let isHost = prefixLength == (address.family == .v4 ? 32 : 128)
            self.tableEntry = isHost ? "\(address)" : "\(address)/\(prefixLength)"
        }

        /// Whether this entry is what stops traffic to `candidate`.
        ///
        /// A network entry covers every address inside it, and the UI has to know that: with
        /// `10.0.0.0/8` blocked, offering to block `10.1.2.3` proposes an addition that
        /// changes nothing and cannot later be removed by taking it back out. Prefix
        /// arithmetic belongs here beside `masked(prefixLength:)` rather than as a string
        /// comparison at a call site, which is what it had become.
        public func covers(_ candidate: IPAddress) -> Bool {
            guard candidate.family == address.family else { return false }
            return candidate.masked(prefixLength: prefixLength) == address
        }
    }

    /// A line that could not be used, kept rather than dropped.
    ///
    /// A block list that silently ignores the line you got wrong is the worst kind: you
    /// believe a destination is blocked and it is not. Every rejected line is reported with
    /// its number, and the daemon refuses to arm when the list it was handed does not parse
    /// cleanly, rather than enforcing a subset of what was asked for.
    public struct Problem: Equatable, Sendable {
        public let line: Int
        public let text: String
        public let reason: String

        public init(line: Int, text: String, reason: String) {
            self.line = line
            self.text = text
            self.reason = reason
        }
    }

    public let entries: [Entry]
    public let problems: [Problem]

    /// What the pf table should contain, deduplicated.
    ///
    /// Built once here rather than on each read: the sync path, the ownership check and the
    /// UI listing all ask for it, and `entries` cannot change after `init`.
    public let tableEntries: Set<String>

    public init(entries: [Entry], problems: [Problem] = []) {
        self.entries = entries
        self.problems = problems
        self.tableEntries = Set(entries.map(\.tableEntry))
    }

    /// Whether any entry here stops traffic to `address`, networks included.
    public func covers(_ address: IPAddress) -> Bool {
        entries.contains { $0.covers(address) }
    }

    // MARK: - Parsing

    /// Reads a block list.
    ///
    /// The format is one destination per line, `#` starting a comment. A comment on the
    /// same line as an entry becomes that entry's note:
    ///
    /// ```
    /// # Beholder block list
    /// 93.184.216.34            # example.com
    /// 10.0.0.0/8               # everything on the lab network
    /// 2606:2800:220:1::/64
    /// ```
    ///
    /// Host names are deliberately *not* accepted. A name is not a destination pf can
    /// match on, and resolving one here would freeze a single answer for a rotating CDN
    /// record and quietly stop matching an hour later. Blocking by name needs the addresses
    /// to be learned from observed DNS answers as they arrive, which is a live-capture
    /// concern rather than a file-parsing one; until that exists, a name is refused with an
    /// explanation rather than half-honoured.
    public static func parse(_ text: String) -> BlockList {
        var entries: [Entry] = []
        var problems: [Problem] = []
        var seen: Set<String> = []

        for (index, rawLine) in text.split(separator: "\n", omittingEmptySubsequences: false)
            .enumerated()
        {
            let number = index + 1
            let line = String(rawLine)

            // Split the comment off first, so a note can never be mistaken for part of the
            // destination and a full-line comment costs nothing to skip.
            let (body, note) = splitComment(line)
            let token = body.trimmingCharacters(in: .whitespaces)
            guard !token.isEmpty else { continue }

            guard !token.contains(" "), !token.contains("\t") else {
                problems.append(
                    Problem(
                        line: number, text: token,
                        reason: "one destination per line; put anything else after a '#'"))
                continue
            }

            guard let entry = parseEntry(token, note: note) else {
                problems.append(Problem(line: number, text: token, reason: reason(for: token)))
                continue
            }

            // First mention wins, so the note nearest the top is the one that survives.
            // Duplicates are common when a list is edited by hand and are not worth
            // reporting as problems — the resulting table is the same either way.
            guard seen.insert(entry.tableEntry).inserted else { continue }
            entries.append(entry)
        }

        return BlockList(entries: entries, problems: problems)
    }

    private static func splitComment(_ line: String) -> (body: String, note: String?) {
        guard let hash = line.firstIndex(of: "#") else { return (line, nil) }
        let note = line[line.index(after: hash)...].trimmingCharacters(in: .whitespaces)
        return (String(line[..<hash]), note.isEmpty ? nil : note)
    }

    private static func parseEntry(_ token: String, note: String?) -> Entry? {
        let parts = token.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }

        guard let address = IPAddress(text: String(parts[0])) else { return nil }
        let width: UInt8 = address.family == .v4 ? 32 : 128

        guard parts.count == 2 else {
            return Entry(address: address, prefixLength: width, note: note)
        }
        guard let length = UInt8(parts[1]), length <= width else { return nil }

        // Masked, so `192.168.1.5/24` and `192.168.1.0/24` are one table entry rather than
        // two spellings of it. pf would accept either; the sync diff would not, and would
        // add and remove the same network on every reload.
        return Entry(
            address: address.masked(prefixLength: length), prefixLength: length, note: note)
    }

    /// A reason worth reading, rather than "invalid entry".
    ///
    /// The name case gets its own message because it is the mistake everybody makes first,
    /// and "not an address" does not tell them that blocking by name is a different feature
    /// rather than a typo they can fix.
    private static func reason(for token: String) -> String {
        let head = token.split(separator: "/").first.map(String.init) ?? token
        if head.contains(".") || head.contains(":"), IPAddress(text: head) == nil,
            head.rangeOfCharacter(from: .letters) != nil
        {
            return
                "host names cannot be blocked — pf matches addresses, and a name would fix "
                + "one answer for a record that rotates. Give the address instead."
        }
        if token.contains("/") {
            return "not an address and prefix length (expected something like 10.0.0.0/8)"
        }
        return "not an IPv4 or IPv6 address"
    }

    // MARK: - The file itself

    /// The ownership rule, which is `SecureFile`'s: this file tells root what to add to the
    /// kernel's firewall, so anything that can write it can block anything. Aliased rather
    /// than re-stated, because it is the same rule the pinned code identity is held to and
    /// two copies of a security check are two chances to get one of them wrong.
    public typealias FileVerdict = SecureFile.Verdict

    public static func verdict(
        ownerUID: UInt32,
        mode: UInt16,
        readerUID: UInt32 = 0
    ) -> FileVerdict {
        SecureFile.verdict(ownerUID: ownerUID, mode: mode, readerUID: readerUID)
    }

    /// Reads one list file, applying the ownership rule and refusing a list that does not
    /// wholly parse.
    ///
    /// In Core rather than in the daemon because two callers needed it and both were in
    /// executable targets: the daemon that enforces the list, and `--check-blocklist`, which
    /// exists to preview what the daemon will do. Two implementations of "what does this file
    /// mean" is precisely how a preview comes to disagree with enforcement.
    ///
    /// `required` is the only difference between the two list files. The hand-edited one must
    /// exist — `--block` without it is a request nobody can satisfy — while the app's is
    /// absent until the app first adds something, which is an ordinary state and not a fault.
    public static func read(
        at path: String,
        readerUID: UInt32 = 0,
        required: Bool
    ) -> FileReading {
        switch SecureFile.read(at: path, readerUID: readerUID) {
        case .absent(let reason):
            return required ? .failed(.missing(reason: reason)) : .list(BlockList(entries: []))
        case .insecure(let verdict):
            return .failed(.insecure(verdict))
        case .unreadable(let reason):
            return .failed(.missing(reason: reason))
        case .text(let text):
            let list = parse(text)
            guard list.problems.isEmpty else { return .failed(.unusable(problems: list.problems)) }
            return .list(list)
        }
    }

    /// Why a list file could not be used. Deliberately separate from `FileReading` so that a
    /// failure cannot carry a usable list: callers were having to write an unreachable
    /// `case .list:` branch inside a failure switch, and both of them defaulted it to an
    /// empty list — which is to say, to unblocking everything.
    public enum FileFailure: Sendable {
        case missing(reason: String)
        case insecure(FileVerdict)
        case unusable(problems: [Problem])

        public var description: String {
            switch self {
            case .missing(let reason): return reason
            case .insecure(let verdict): return verdict.description
            case .unusable(let problems):
                return "\(problems.count) line(s) cannot be used"
            }
        }
    }

    public enum FileReading: Sendable {
        case list(BlockList)
        case failed(FileFailure)
    }

    /// The block list Beholder reads unless told otherwise.
    ///
    /// Under `/usr/local/etc` rather than the user's Application Support, which is where
    /// everything else Beholder keeps lives. The difference is who it belongs to: history is
    /// a record *about* you and is yours, while this is configuration *for* a root process
    /// and has to be out of reach of anything running as you.
    public static let defaultPath = "/usr/local/etc/beholder/blocklist.conf"
}

/// What pf is asked to enforce: the hand-edited list, plus whatever the app has added.
///
/// Two files rather than one, because they have different owners in the human sense.
/// `blocklist.conf` is written by a person and carries their reasons; regenerating it from
/// a GUI would eventually eat the comments explaining why each line is there. The app's
/// additions go in their own file, which the daemon owns and rewrites freely.
///
/// pf enforces the union. The asymmetry that falls out of it — the app can take back what
/// the app added, and cannot take back what the file pinned — is surfaced to the user rather
/// than papered over, because "root wrote it, root takes it back" is a rule someone can hold
/// in their head.
public struct EnforcedBlockList: Sendable {
    public let fixed: BlockList
    public let managed: BlockList

    public init(fixed: BlockList, managed: BlockList) {
        self.fixed = fixed
        self.managed = managed
    }

    /// Everything pf should hold.
    public var tableEntries: Set<String> {
        fixed.tableEntries.union(managed.tableEntries)
    }

    /// Whether anything here stops traffic to `address`, networks included.
    public func covers(_ address: IPAddress) -> Bool {
        fixed.covers(address) || managed.covers(address)
    }

    /// Every entry with the whole list's notion of who owns it.
    ///
    /// An entry in both files counts as fixed: the more restrictive answer is the honest
    /// one, since removing it from the managed file would not unblock it.
    public var controlEntries: [ControlEntry] {
        let fixedDestinations = fixed.tableEntries
        var seen: Set<String> = []
        var result: [ControlEntry] = []

        for entry in fixed.entries where seen.insert(entry.tableEntry).inserted {
            result.append(
                ControlEntry(
                    destination: entry.tableEntry, note: entry.note, isRemovable: false))
        }
        for entry in managed.entries where seen.insert(entry.tableEntry).inserted {
            result.append(
                ControlEntry(
                    destination: entry.tableEntry, note: entry.note,
                    isRemovable: !fixedDestinations.contains(entry.tableEntry)))
        }
        return result.sorted { $0.destination < $1.destination }
    }

    /// Whether the hand-edited file is what is holding a destination.
    public func isFixed(_ destination: String) -> Bool {
        fixed.tableEntries.contains(destination)
    }

    /// Reads both files.
    ///
    /// The pairing is the point. What pf enforces is the union, so anything that reads only
    /// one of them is answering a different question — which is what `--check-blocklist` was
    /// doing: previewing the hand-edited list alone, and under-reporting for anyone who had
    /// ever blocked something from the app.
    public static func read(
        fixed fixedPath: String,
        managed managedPath: String,
        readerUID: UInt32 = 0
    ) -> Reading {
        let fixedList: BlockList
        switch BlockList.read(at: fixedPath, readerUID: readerUID, required: true) {
        case .list(let list): fixedList = list
        case .failed(let failure): return .failed(path: fixedPath, failure: failure)
        }

        let managedList: BlockList
        switch BlockList.read(at: managedPath, readerUID: readerUID, required: false) {
        case .list(let list): managedList = list
        case .failed(let failure): return .failed(path: managedPath, failure: failure)
        }

        return .lists(EnforcedBlockList(fixed: fixedList, managed: managedList))
    }

    public enum Reading: Sendable {
        case lists(EnforcedBlockList)
        /// Which file failed, and how. Naming the path matters when there are two of them.
        case failed(path: String, failure: BlockList.FileFailure)
    }
}

extension BlockList {

    /// Reads a single destination, the way one arrives over the control socket.
    ///
    /// Goes through exactly the same parser as a line of the file, so a destination that
    /// would be refused in the file is refused here too, with the same explanation. There is
    /// no second, looser path into the block table.
    public static func parseDestination(_ text: String) -> DestinationReading {
        let list = parse(text)
        if let entry = list.entries.first { return .parsed(entry) }
        if let problem = list.problems.first { return .rejected(reason: problem.reason) }
        return .rejected(reason: "not an IPv4 or IPv6 address")
    }

    /// The outcome of reading one destination. An enum rather than `Result`, whose failure
    /// type would have to be an `Error` — and the reason a destination was refused is a
    /// sentence for a person to read, not something anyone should be throwing.
    public enum DestinationReading: Sendable, Equatable {
        case parsed(Entry)
        case rejected(reason: String)
    }

    /// Renders a list back to file text, for the file the daemon owns.
    ///
    /// Notes are stripped of newlines and of `#` before they are written. A note is the one
    /// part of an entry that arrives as free text from another process, and this is the only
    /// place free text becomes lines in a file that is parsed back as configuration — a note
    /// containing a newline would otherwise write a destination of its own onto the next
    /// line. The address never needs this treatment because it has already been through
    /// `IPAddress` and back out of `inet_ntop`.
    public static func render(_ entries: [Entry], generatedBy: String) -> String {
        var text = """
            # Written by \(generatedBy). Edits here are replaced.
            #
            # This is what Beholder.app has been asked to block. The hand-edited list beside
            # it is never touched by the daemon; pf enforces both together.

            """
        for entry in entries {
            if let note = sanitiseNote(entry.note) {
                text += "\(entry.tableEntry)  # \(note)\n"
            } else {
                text += "\(entry.tableEntry)\n"
            }
        }
        return text
    }

    /// At most one line, no comment character, and short enough to stay readable.
    static func sanitiseNote(_ note: String?) -> String? {
        guard let note else { return nil }
        let flattened =
            note
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "#", with: " ")
            .trimmingCharacters(in: .whitespaces)
        guard !flattened.isEmpty else { return nil }
        return String(flattened.prefix(120))
    }
}
