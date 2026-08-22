import Foundation

/// Where Beholder keeps the data it accumulates.
///
/// One place, because the daemon and the query commands must agree and previously did
/// not. Capture runs under `sudo` and resolved this from `SUDO_USER`; the query commands
/// run as you, found no `SUDO_USER`, and fell back to the working directory — so history
/// was written to your home and looked for in the repository, and every query reported an
/// empty database that was in fact being filled.
public enum BeholderPaths {

    /// The launchd job description, when Beholder is installed as a daemon.
    ///
    /// Here rather than spelled out at each call site for the reason this whole type
    /// exists: the label is chosen by `install-daemon.sh` and read back by both the app and
    /// the MCP `network_status` tool, and two of the three getting it right is the same as
    /// none of them. Renaming the job is now one edit on the Swift side.
    public static let launchdPlist = "/Library/LaunchDaemons/com.beholder.daemon.plist"

    /// Whether a launchd job is installed.
    ///
    /// Deliberately a function rather than a cached constant: the app is long-lived, and a
    /// value read once at launch goes stale the moment someone installs or removes the
    /// daemon while the window is open.
    public static func isInstalledAsDaemon() -> Bool {
        FileManager.default.fileExists(atPath: launchdPlist)
    }

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

    /// Hands a file the daemon created to the user who invoked `sudo`.
    ///
    /// Capture runs as root, and every file it makes for the app to read — the socket, the
    /// transcript — has to belong to the person the data is about rather than to root, or
    /// the app cannot open it. Here rather than in each server for the reason this type
    /// exists: two copies of this eventually disagree about which environment variables to
    /// read.
    public static func giveToInvokingUser(_ path: String) {
        let environment = ProcessInfo.processInfo.environment
        guard
            let uidText = environment["SUDO_UID"], let uid = uid_t(uidText),
            let gidText = environment["SUDO_GID"], let gid = gid_t(gidText)
        else { return }
        chown(path, uid, gid)
    }

    public static func nameCache() -> String {
        dataDirectory() + "/names.json"
    }
}
