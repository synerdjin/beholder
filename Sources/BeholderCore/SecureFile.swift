import Foundation

/// Reading a file that a privileged process is about to act on.
///
/// Three things in this project are configuration for root: the block list, the list the app
/// writes, and the pinned code identity of the program allowed to change them. All three
/// carry the same rule — **the file must not be writable by anyone less privileged than the
/// process reading it** — and all three were checking it by hand, with the `st_mode` mask
/// re-derived at each site and the whole sequence living in executable targets where no test
/// could reach it.
///
/// It lives here for the reason `BeholderPaths` does: the policy is worth stating once, and
/// three copies of a security check are three chances for one of them to be subtly kinder
/// than the others.
public enum SecureFile {

    /// Whether a file is safe for a privileged process to act on.
    ///
    /// Root-owned always qualifies; owned by the reader itself qualifies too, since a process
    /// cannot be a threat to its own privileges. `readerUID` defaults to root because the
    /// daemon is root wherever this matters — pf needs it — and is a parameter so an
    /// unprivileged process can apply the same rule to a file it owns without either
    /// loosening it or growing a second copy.
    public enum Verdict: Equatable, Sendable {
        case usable
        case notOwnedByRoot(uid: UInt32)
        case writableByOthers(mode: UInt16)

        public var description: String {
            switch self {
            case .usable:
                return "usable"
            case .notOwnedByRoot(let uid):
                return
                    "owned by uid \(uid), not root — it decides what a root process does, so "
                    + "anything that can write it can decide that too"
            case .writableByOthers(let mode):
                return String(
                    format:
                        "mode %04o — writable by group or other, so it decides what a root "
                        + "process does on someone else's behalf", mode)
            }
        }
    }

    public static func verdict(
        ownerUID: UInt32,
        mode: UInt16,
        readerUID: UInt32 = 0
    ) -> Verdict {
        guard ownerUID == 0 || ownerUID == readerUID else {
            return .notOwnedByRoot(uid: ownerUID)
        }
        guard mode & 0o022 == 0 else { return .writableByOthers(mode: mode & 0o7777) }
        return .usable
    }

    /// What came back, with the failures kept apart.
    ///
    /// They are distinguished rather than collapsed into one error because the fixes differ
    /// and the callers say different things about them: a missing block list may be fatal or
    /// ordinary depending on which file it is, while an insecure one always wants the same
    /// `chown` and is worth spelling out.
    public enum Reading: Sendable {
        case text(String)
        case absent(reason: String)
        case insecure(Verdict)
        case unreadable(reason: String)
    }

    public static func read(at path: String, readerUID: UInt32 = 0) -> Reading {
        var info = stat()
        guard stat(path, &info) == 0 else {
            return .absent(reason: String(cString: strerror(errno)))
        }

        let verdict = verdict(
            ownerUID: info.st_uid, mode: UInt16(info.st_mode & 0o7777), readerUID: readerUID)
        guard verdict == .usable else { return .insecure(verdict) }

        guard let data = FileManager.default.contents(atPath: path),
            let text = String(data: data, encoding: .utf8)
        else {
            return .unreadable(reason: "not readable as UTF-8")
        }
        return .text(text)
    }
}
