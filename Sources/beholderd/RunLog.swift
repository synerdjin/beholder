import Darwin
import Foundation

/// Writes a transcript of a run to disk.
///
/// Two details matter more than the mechanics.
///
/// **Ownership.** Capture needs root, so anything this process creates is root-owned by
/// default — unreadable to the person who actually ran it without another `sudo`. The log
/// is therefore handed to the invoking user, taken from `SUDO_UID`/`SUDO_GID`.
///
/// **Permissions.** This file lists every host the machine spoke to, which is exactly the
/// material Beholder exists to keep an eye on and precisely what should not be
/// world-readable. It is created 0600. That is the same reasoning applied to the flow
/// database, and it is why the log is not simply dropped in `/var/log`.
final class RunLog: @unchecked Sendable {
    private let handle: FileHandle
    private let queue = DispatchQueue(label: "com.beholder.runlog")
    let url: URL

    /// Opens a log, creating the directory if needed. Returns nil rather than throwing:
    /// failing to log is not a reason to refuse to capture.
    init?(directory: URL, startedAt: Date) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let name = "beholder-\(formatter.string(from: startedAt)).log"
        let target = directory.appendingPathComponent(name)

        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
        } catch {
            return nil
        }

        guard
            FileManager.default.createFile(
                atPath: target.path,
                contents: nil,
                attributes: [.posixPermissions: 0o600]
            ),
            let handle = FileHandle(forWritingAtPath: target.path)
        else { return nil }

        self.handle = handle
        self.url = target

        Self.giveToInvokingUser(directory.path)
        Self.giveToInvokingUser(target.path)
        Self.updateLatestSymlink(in: directory, pointingAt: name)
    }

    func write(_ text: String) {
        queue.async { [self] in
            guard let data = (text + "\n").data(using: .utf8) else { return }
            try? handle.write(contentsOf: data)
        }
    }

    /// Writes a titled block, so a long transcript stays navigable.
    func section(_ title: String, _ body: String) {
        let rule = String(repeating: "─", count: 100)
        write("\n\(rule)\n\(title)\n\(rule)\n\(body)")
    }

    func close() {
        queue.sync {
            try? handle.synchronize()
            try? handle.close()
        }
    }

    // MARK: - Privilege handling

    /// Transfers a path to the user who invoked sudo, so they can read their own log.
    private static func giveToInvokingUser(_ path: String) {
        let environment = ProcessInfo.processInfo.environment
        guard
            let uidText = environment["SUDO_UID"], let uid = uid_t(uidText),
            let gidText = environment["SUDO_GID"], let gid = gid_t(gidText)
        else { return }
        chown(path, uid, gid)
    }

    /// Maintains a stable `latest.log` alongside the timestamped files, so the most
    /// recent run is always at a predictable path.
    private static func updateLatestSymlink(in directory: URL, pointingAt name: String) {
        let link = directory.appendingPathComponent("latest.log")
        try? FileManager.default.removeItem(at: link)
        try? FileManager.default.createSymbolicLink(
            atPath: link.path, withDestinationPath: name
        )
        // Symlink ownership, not the target's — lchown, so the link itself is changed.
        let environment = ProcessInfo.processInfo.environment
        if let uidText = environment["SUDO_UID"], let uid = uid_t(uidText),
            let gidText = environment["SUDO_GID"], let gid = gid_t(gidText)
        {
            lchown(link.path, uid, gid)
        }
    }
}
