import Foundation

/// Where Beholder keeps the data it accumulates.
///
/// One place, because the daemon and the query commands must agree and previously did
/// not. Capture runs under `sudo` and resolved this from `SUDO_USER`; the query commands
/// run as you, found no `SUDO_USER`, and fell back to the working directory — so history
/// was written to your home and looked for in the repository, and every query reported an
/// empty database that was in fact being filled.
public enum BeholderPaths {

    /// The directory holding the history database and the learned-name cache.
    ///
    /// Under the user's own Application Support rather than a system path, because these
    /// files record every host the machine has contacted and belong to the person they
    /// are about, not to root.
    public static func dataDirectory() -> String {
        // Running under sudo: the invoking user's directory, never root's. Writing to
        // root's home would leave the data unreadable to the person it describes.
        if let user = ProcessInfo.processInfo.environment["SUDO_USER"], !user.isEmpty,
            user != "root"
        {
            return "/Users/\(user)/Library/Application Support/Beholder"
        }
        // Otherwise the current user's own home — not the working directory, so a query
        // finds the same file no matter where it is run from.
        return NSHomeDirectory() + "/Library/Application Support/Beholder"
    }

    public static func historyDatabase() -> String {
        dataDirectory() + "/history.sqlite"
    }

    public static func nameCache() -> String {
        dataDirectory() + "/names.json"
    }
}
