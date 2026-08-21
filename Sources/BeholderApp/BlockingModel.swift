import BeholderCore
import Foundation
import Observation

/// What the app knows about blocking, and the only place it asks the daemon to change it.
///
/// Three states rather than two, and the middle one is the point. "Cannot reach the daemon",
/// "the daemon is running but not enforcing anything", and "these are the destinations being
/// blocked" are different answers to different questions, and collapsing the middle one into
/// an empty list would tell someone nothing is blocked when in fact nothing is *checking*.
/// It is the same distinction `cleartextExcerpts` draws between nil and empty, for the same
/// reason.
@MainActor
@Observable
final class BlockingModel {

    enum State: Equatable {
        /// Nothing asked yet.
        case unknown
        /// The control socket could not be reached, with the reason.
        case unreachable(String)
        /// The daemon answered, and is running without `--block`.
        case notEnforcing(String)
        /// The daemon is enforcing. The list may still be empty.
        case enforcing
    }

    private(set) var state: State = .unknown
    private(set) var entries: [ControlEntry] = []

    /// The last thing that went wrong in response to something the user did, as opposed to
    /// the connection state above. Cleared by the next successful action, because an error
    /// that outlives the thing it was about is worse than none.
    private(set) var actionError: String?

    /// True while a request is in flight, so the UI can stop a second click from racing the
    /// first — a double-press on "Block" is otherwise two writes of the same file.
    private(set) var isBusy = false

    private let socketPath: String

    init(socketPath: String = ControlProtocol.defaultSocketPath) {
        self.socketPath = socketPath
    }

    func refresh() async {
        await perform(ControlRequest(action: .status), clearsActionError: false)
    }

    func block(_ destination: String, note: String?) async {
        await perform(ControlRequest(action: .block, destination: destination, note: note))
    }

    func unblock(_ destination: String) async {
        await perform(ControlRequest(action: .unblock, destination: destination))
    }

    /// Whether a destination is already blocked, for a menu that would otherwise offer to
    /// block something twice.
    ///
    /// Containment, not string equality. A block list entry is commonly a network — the
    /// template file installed alongside it teaches `10.0.0.0/8` — and comparing rendered
    /// strings meant every address inside a blocked network still offered "Block this",
    /// proposing an addition that changes nothing and cannot later be removed by taking it
    /// back out. The prefix arithmetic lives in `BlockList.Entry.covers`, beside `masked`,
    /// rather than here in a menu builder.
    func isBlocked(_ destination: String) -> Bool {
        coveringEntry(for: destination) != nil
    }

    /// The entry that is stopping traffic to `destination`, if any.
    ///
    /// Returned rather than reduced to a Bool because the caller needs to know *which* entry:
    /// an address covered by a network is blocked, but unblocking that address is not
    /// something anyone can do — the entry to remove is the network, and it may be in the
    /// file the app never rewrites. A menu built on a Bool offered "Unblock 10.1.2.3" for
    /// every address inside a blocked `10.0.0.0/8`, and every click failed.
    func coveringEntry(for destination: String) -> ControlEntry? {
        guard let address = IPAddress(text: destination) else { return nil }
        guard let index = blockedEntries.firstIndex(where: { $0?.covers(address) ?? false })
        else {
            return nil
        }
        return entries.indices.contains(index) ? entries[index] : nil
    }

    /// Whether this exact destination is one the app can take back.
    ///
    /// Exact, not covering: removing `10.1.2.3` does nothing while `10.0.0.0/8` is listed.
    func removableEntry(for destination: String) -> ControlEntry? {
        entries.first { $0.destination == destination && $0.isRemovable }
    }

    /// The blocked destinations as parsed entries, rebuilt only when the list changes.
    ///
    /// Cached because `isBlocked` is asked once per visible connection row per snapshot, and
    /// re-parsing every entry each time would put string parsing on a once-a-second UI path.
    private var blockedEntries: [BlockList.Entry?] = []

    private func perform(_ request: ControlRequest, clearsActionError: Bool = true) async {
        guard !isBusy else {
            // Reported, not dropped. A block issued while the on-appear refresh is still in
            // flight used to return here silently, leaving the UI indistinguishable from
            // success — which is the worst possible outcome for this particular feature,
            // since the user walks away believing a destination is unreachable.
            if request.action != .status {
                actionError = "Another change is still in progress — try that again."
            }
            return
        }
        isBusy = true
        defer { isBusy = false }

        let path = socketPath
        let outcome = await Task.detached {
            // Off the main actor: this opens a socket and waits for a reply, and a spinning
            // window is not an improvement on a slow one.
            Result { try ControlClient.send(request, to: path) }
        }.value

        switch outcome {
        case .failure(let error):
            let reason = (error as? SnapshotClient.Failure)?.description ?? "\(error)"
            state = .unreachable(reason)
            entries = []
            blockedEntries = []

        case .success(let response):
            if let state = response.state {
                entries = state.entries
                // Parsed once, and kept index-aligned with `entries` so a covering match can
                // be mapped back to the ControlEntry it came from. `map`, not `compactMap`:
                // dropping an unparsable destination would shift every index after it.
                blockedEntries = state.entries.map {
                    guard case .parsed(let entry) = BlockList.parseDestination($0.destination)
                    else { return nil }
                    return entry
                }
                self.state =
                    state.isBlocking
                    ? .enforcing
                    : .notEnforcing(state.reason ?? "the daemon is not enforcing anything")
            }
            if response.ok {
                if clearsActionError { actionError = nil }
            } else {
                // A refusal is not a connection problem: the daemon answered, and said no.
                // Keeping the two apart is what lets the UI show "that address is pinned by
                // the file" without also claiming the daemon is unreachable.
                actionError = response.error
                if case .unknown = state { state = .enforcing }
            }
        }
    }
}
