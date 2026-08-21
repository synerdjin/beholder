import BeholderCore
import Darwin
import Foundation
import Security

/// Decides whether the process on the other end of a control connection is allowed to
/// change the firewall.
///
/// The problem this solves is the one that kept the publishing socket read-only for so
/// long. A Unix socket's permissions distinguish *accounts*, and both ends of this run as
/// the same account: the app is yours and so is anything else you happen to be running. So
/// mode 0600 keeps out other users and keeps out nothing else, and for a reader that is
/// enough — it learns only what `lsof` would tell it — while for a writer it is not.
///
/// The missing piece was thought to be a signing identity, which this project has no way to
/// obtain. It is not. What is needed is a *stable* identity, not an Apple-issued one, and an
/// **ad-hoc signature already provides one**: `codesign -s -` produces a `cdhash`, the app
/// bundle gets one at build time, and `install-control-pin.sh` records it in a root-owned
/// file. A connection is admitted only if the peer's running code satisfies a requirement
/// built from that hash.
///
/// Three details that make it hold up:
///
/// - **The peer is identified by audit token, never by pid.** `LOCAL_PEERPID` would name a
///   process that can exit between the lookup and the check, with the number reused by
///   something else. `LOCAL_PEERTOKEN` names *that* process and cannot be recycled.
/// - **The check is on the running code, not the file on disk.** `SecCodeCheckValidity`
///   against a `SecCode` obtained from the audit token validates the process as it is now.
///   Reading the cdhash of the executable's path would check a file that need not be what is
///   running any more.
/// - **The requirement is loaded once, at startup, from a root-owned file.** Anything that
///   can write that file can nominate itself as the program allowed to change the firewall,
///   so it gets exactly the same ownership check as the block list.
///
/// What it does not defend against: another process as your account injecting code into a
/// running app that has no hardened runtime. `build-app.sh` therefore signs with
/// `--options runtime`, which brings library validation with it. That closes the ordinary
/// path; a account-level attacker with a debugger is out of scope for a tool with no
/// Developer ID, and pretending otherwise would be the reassuring kind of wrong.
enum PeerAuthenticator {

    enum Verdict {
        case allowed(pid: pid_t)
        case denied(reason: String, pid: pid_t)
    }

    /// Reads the pinned requirement.
    ///
    /// The file holds a code-signing requirement in `csreq` text form — for an ad-hoc signed
    /// app that is `cdhash H"..."`, which is what `codesign -dr -` prints for it. Storing the
    /// requirement rather than the bare hash means a Developer ID, if this project ever gets
    /// one, is a change to one file and none of this code.
    /// Either the pinned requirement, or why there is none. An enum rather than a `Result`,
    /// whose failure type would have to conform to `Error` — and "the pin file is missing" is
    /// a sentence for the operator, not something to throw.
    enum LoadedRequirement {
        case loaded(SecRequirement)
        case unavailable(reason: String)
    }

    static func loadRequirement(at path: String) -> LoadedRequirement {
        var info = stat()
        guard stat(path, &info) == 0 else {
            return .unavailable(reason: "no pinned peer at \(path): \(String(cString: strerror(errno)))")
        }

        // The same policy the block list uses, for the same reason and deliberately not a
        // second copy of it: this file decides who may change the firewall, which is at
        // least as sensitive as the list of what is blocked.
        let verdict = BlockList.verdict(
            ownerUID: info.st_uid, mode: UInt16(info.st_mode & 0o7777), readerUID: geteuid())
        guard verdict == .usable else {
            return .unavailable(
                reason: "refusing the pinned peer at \(path): \(verdict.description)")
        }

        guard let data = FileManager.default.contents(atPath: path),
            let text = String(data: data, encoding: .utf8)
        else {
            return .unavailable(reason: "cannot read \(path)")
        }

        let requirementText = text
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty && !$0.hasPrefix("#") }

        guard let requirementText, !requirementText.isEmpty else {
            return .unavailable(reason: "\(path) contains no requirement")
        }

        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(
            requirementText as CFString, [], &requirement)
        guard status == errSecSuccess, let requirement else {
            return .unavailable(
                reason:
                    "\(path) is not a valid code requirement (OSStatus \(status)): \(requirementText)"
            )
        }
        return .loaded(requirement)
    }

    /// Whether a bundle on disk satisfies the pinned requirement.
    ///
    /// The question `doctor.sh` needs answered, answered with the API the daemon itself uses.
    /// It was being decided in shell by string-comparing `codesign -dr -` output against the
    /// pin file — which is a different test. Requirement *satisfaction* and requirement *text
    /// equality* coincide for an ad-hoc `cdhash` pin and need not coincide for any other,
    /// including the Developer ID case `install-control-pin.sh` explicitly designs for. A
    /// diagnostic that can be wrong about the very failure it exists to catch is worse than
    /// none.
    static func satisfies(bundlePath: String, requirement: SecRequirement) -> BundleVerdict {
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: bundlePath) as CFURL
        let status = SecStaticCodeCreateWithPath(url, [], &code)
        guard status == errSecSuccess, let code else {
            return .unreadable(reason: "no code signature could be read (OSStatus \(status))")
        }

        let validity = SecStaticCodeCheckValidity(code, [], requirement)
        return validity == errSecSuccess ? .satisfies : .doesNotSatisfy(status: validity)
    }

    /// Three answers, not two.
    ///
    /// "This app does not match the pin" and "there is no app here to check" are different
    /// facts with different fixes, and collapsing them made `doctor.sh` tell anyone who runs
    /// an installed copy — and therefore has no `.build/Beholder.app` — that their pin was
    /// stale when it may have been perfectly correct. Confidently wrong is the one thing a
    /// diagnostic must not be.
    enum BundleVerdict: Equatable {
        case satisfies
        case doesNotSatisfy(status: OSStatus)
        case unreadable(reason: String)
    }

    /// The code directory hash of a running process, for diagnostics only.
    ///
    /// Never used to make the decision — that is `SecCodeCheckValidity`'s job against a
    /// requirement, which handles the cases a hash comparison here would get subtly wrong.
    /// This exists so a refusal can say what it saw.
    static func cdhash(of code: SecCode) -> String? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
            let staticCode
        else { return nil }

        var information: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess,
            let dictionary = information as? [String: Any],
            let unique = dictionary[kSecCodeInfoUnique as String] as? Data
        else { return nil }

        return unique.map { String(format: "%02x", $0) }.joined()
    }

    /// Whether the process on the other end of `descriptor` satisfies `requirement`.
    static func authorise(descriptor: Int32, against requirement: SecRequirement) -> Verdict {
        // For the log line only. Authentication uses the audit token below; a pid is
        // reusable and is never what a decision rests on here.
        var peerPID: pid_t = -1
        var pidSize = socklen_t(MemoryLayout<pid_t>.size)
        _ = getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &pidSize)

        var token = audit_token_t()
        var tokenSize = socklen_t(MemoryLayout<audit_token_t>.size)
        guard
            getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &tokenSize) == 0,
            tokenSize == socklen_t(MemoryLayout<audit_token_t>.size)
        else {
            return .denied(
                reason: "could not read the peer's audit token: \(String(cString: strerror(errno)))",
                pid: peerPID)
        }

        let tokenData = withUnsafeBytes(of: token) { Data($0) }
        var code: SecCode?
        let guestStatus = SecCodeCopyGuestWithAttributes(
            nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &code)
        guard guestStatus == errSecSuccess, let code else {
            return .denied(
                reason: "the peer has no code identity (OSStatus \(guestStatus))", pid: peerPID)
        }

        let validity = SecCodeCheckValidity(code, [], requirement)
        guard validity == errSecSuccess else {
            // The identity that was actually presented, named in the refusal. Rebuilding the
            // app changes its cdhash by design, so "does not match" is the message someone
            // will see most often and the useful version of it says what to re-pin against.
            let seen = cdhash(of: code).map { " — the peer is cdhash H\"\($0)\"" } ?? ""
            return .denied(
                reason:
                    "the peer does not match the pinned identity (OSStatus \(validity))\(seen). "
                    + "If the app was rebuilt, re-run install-control-pin.sh",
                pid: peerPID)
        }
        return .allowed(pid: peerPID)
    }
}
