import Foundation

/// The one channel into the daemon that changes something.
///
/// Everything else Beholder exposes is read-only by construction. This is not, so the
/// asymmetry is worth stating: the publishing socket at `WireProtocol.defaultSocketPath`
/// still accepts no command at all, and this is a **second, separate socket** rather than a
/// widening of the first. Splitting them keeps the property that a passive reader — the
/// terminal view, the MCP server, anything else that connects to watch — cannot become a
/// writer by accident, and it lets the two carry completely different admission rules.
///
/// **This socket authenticates its peer; the publishing one does not and does not need to.**
/// File permissions cannot do the job here. Both sockets are mode 0600 owned by the invoking
/// user, which stops other accounts and stops nobody else: anything running as you can open
/// them. For a reader that is fine, since it learns only what `lsof` would already tell it.
/// For a writer it is not — the interesting thing to block is not your browsing but your
/// update server, or whatever else would notice something was wrong. So a connection here is
/// admitted only if the peer's code identity matches a hash pinned at install time. See
/// `PeerAuthenticator`; the short version is that an ad-hoc signature has a stable `cdhash`,
/// which is all the identity this needs and needs no Developer ID to obtain.
public enum ControlProtocol {

    /// Beside the publishing socket, and deliberately not the same path.
    public static let defaultSocketPath = "/var/run/beholder-control.sock"

    /// Bumped on an incompatible change, exactly as `WireProtocol.version` is, and checked
    /// by both ends. Adding an optional field is not an incompatible change.
    public static let version = 1

    /// The most one request may be.
    ///
    /// A request is a single line of JSON naming one destination, so anything approaching
    /// this is either a bug or someone seeing how much a root process will buffer on their
    /// behalf. The reader gives up on the connection rather than growing without bound.
    public static let maximumRequestBytes = 8 * 1024

    /// Where the daemon keeps what the app asked for.
    ///
    /// A *second* file, next to the hand-edited one, and the split matters. `blocklist.conf`
    /// is written by a person, carries their comments, and is never rewritten by the daemon —
    /// a program that regenerates a hand-edited config file eventually eats the notes
    /// explaining why each line is there. What arrives over this socket goes here instead,
    /// and what pf enforces is the union of the two.
    ///
    /// The consequence is deliberate and surfaced rather than hidden: the app can remove what
    /// the app added, and cannot remove what the file pinned. Something blocked by a root-only
    /// file stays blocked until root edits that file.
    public static let managedListPath = "/usr/local/etc/beholder/blocklist.app.conf"

    /// Where the peer's expected code identity is pinned.
    ///
    /// Root-owned, for the same reason the block list is: anything that can write this can
    /// nominate itself as the program allowed to change the firewall.
    public static let pinPath = "/usr/local/etc/beholder/control-peer.requirement"
}

/// One request. A line of JSON, terminated by a newline.
public struct ControlRequest: Codable, Sendable, Equatable {

    public enum Action: String, Codable, Sendable {
        /// What is blocked, and whether blocking is running at all.
        case status
        /// Add a destination to the managed list.
        case block
        /// Remove one the managed list added.
        case unblock
    }

    public let version: Int
    public let action: Action

    /// An address or CIDR network. Parsed and re-rendered by `BlockList` before it reaches
    /// pf, so nothing that arrives here can be anything but an address by the time it is
    /// acted on. Absent for `status`.
    public let destination: String?

    /// What the app wants recorded beside it in the managed file.
    public let note: String?

    public init(
        action: Action,
        destination: String? = nil,
        note: String? = nil,
        version: Int = ControlProtocol.version
    ) {
        self.version = version
        self.action = action
        self.destination = destination
        self.note = note
    }
}

/// One reply. Also a line of JSON.
public struct ControlResponse: Codable, Sendable, Equatable {
    public let version: Int
    public let ok: Bool

    /// Why not, in words meant for a person. Present exactly when `ok` is false.
    public let error: String?

    /// The full state after the request, so the app never has to infer what happened from
    /// an acknowledgement. Every successful reply carries it, including `block` and
    /// `unblock` — a UI that guesses at the new state and a daemon that failed halfway are
    /// how a list on screen stops matching the one being enforced.
    public let state: ControlState?

    public init(ok: Bool, error: String? = nil, state: ControlState? = nil) {
        self.version = ControlProtocol.version
        self.ok = ok
        self.error = error
        self.state = state
    }

    public static func failure(_ message: String) -> ControlResponse {
        ControlResponse(ok: false, error: message)
    }
}

/// What is being blocked, and whether anything is enforcing it.
public struct ControlState: Codable, Sendable, Equatable {

    /// False when the daemon is running without `--block`.
    ///
    /// Not the same as an empty list, and the app draws different screens for the two — the
    /// same distinction `cleartextExcerpts` makes between nil and empty. "Nothing is
    /// blocked" and "nothing is enforcing anything" answer different questions.
    public let isBlocking: Bool

    public let entries: [ControlEntry]

    /// Why blocking is not running, when it is not. Nil when it is.
    public let reason: String?

    public init(isBlocking: Bool, entries: [ControlEntry], reason: String? = nil) {
        self.isBlocking = isBlocking
        self.entries = entries
        self.reason = reason
    }
}

public struct ControlEntry: Codable, Sendable, Equatable, Identifiable, Hashable {
    public let destination: String
    public let note: String?

    /// False for entries that came from the root-edited `blocklist.conf`.
    ///
    /// The app shows these but cannot remove them, and says why rather than offering a
    /// button that fails. Root wrote it; root takes it back.
    public let isRemovable: Bool

    public var id: String { destination }

    public init(destination: String, note: String?, isRemovable: Bool) {
        self.destination = destination
        self.note = note
        self.isRemovable = isRemovable
    }
}
