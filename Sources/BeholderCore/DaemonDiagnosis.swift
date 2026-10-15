import Darwin
import Foundation

/// Why Beholder's daemon is or is not working, decided in one place.
///
/// This judgement used to live only in `Scripts/doctor.sh`, and the MCP's `beholder_status`
/// refused to copy it — correctly, since two copies of "is this a crash loop or a pending
/// approval" is how the two answers come to disagree. The way to honour that without leaving
/// an assistant unable to answer the first question a broken install raises is to move the
/// judgement somewhere both can call. `beholderd --diagnose` prints it and `doctor.sh` now
/// delegates to that; the MCP's `beholder_doctor` renders the same `Report`.
///
/// Split in two on purpose. `gather` touches the machine and `diagnose` is a pure function
/// of what it gathered, so every verdict is testable from a captured `launchctl print`
/// without a daemon, a root shell or a crash loop to hand.
public enum DaemonDiagnosis {

    // MARK: - launchd

    /// The few fields of `launchctl print` that settle the question.
    public struct LaunchdJob: Sendable, Equatable {
        public var state: String?
        public var pid: Int?
        public var runs: Int?
        public var lastExitCode: String?
        public var lastTerminatingSignal: String?

        public init(
            state: String? = nil, pid: Int? = nil, runs: Int? = nil,
            lastExitCode: String? = nil, lastTerminatingSignal: String? = nil
        ) {
            self.state = state
            self.pid = pid
            self.runs = runs
            self.lastExitCode = lastExitCode
            self.lastTerminatingSignal = lastTerminatingSignal
        }

        public var isRunning: Bool { pid != nil || state == "running" }

        /// The numeric part of `last exit code`, which launchctl may follow with a
        /// description ("78: Function not implemented") or replace with "(never exited)".
        public var lastExitStatus: Int32? {
            lastExitCode.flatMap { Int32($0.prefix { $0.isNumber || $0 == "-" }) }
        }

        /// Reads `launchctl print`'s output.
        ///
        /// Only lines indented by exactly one tab count. `launchctl` repeats keys such as
        /// `state` inside the nested resource-coalition block, and matching any indentation
        /// drags those in as duplicates — the same anchoring `doctor.sh` used and for the
        /// same reason.
        public static func parse(_ output: String) -> LaunchdJob {
            var job = LaunchdJob()
            for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
                guard line.hasPrefix("\t"), !line.hasPrefix("\t\t") else { continue }
                guard let separator = line.range(of: " = ") else { continue }
                let key = line[line.index(after: line.startIndex)..<separator.lowerBound]
                let value = String(line[separator.upperBound...])
                    .trimmingCharacters(in: .whitespaces)
                switch key {
                case "state": job.state = value
                case "pid": job.pid = Int(value)
                case "runs": job.runs = Int(value)
                case "last exit code": job.lastExitCode = value
                case "last terminating signal": job.lastTerminatingSignal = value
                default: break
                }
            }
            return job
        }
    }

    /// What launchd said about the job. Three states, not a job plus a flag: "could not ask"
    /// and "asked, and there is no such job" lead to different verdicts.
    public enum JobState: Sendable, Equatable {
        case unknown
        case absent
        case present(LaunchdJob)
    }

    /// What the publishing socket did when read.
    public enum SocketState: Sendable {
        case absent
        /// The file is there and nothing is listening: left behind by a daemon that is gone.
        case refusing
        case read(FlowSnapshot)
        /// Belongs to another user: capture runs as someone else, and the fix is different
        /// from a daemon that is gone — so it is kept apart from both.
        case forbidden(String)
        /// Something accepted the connection but no usable snapshot came back.
        case unreadable(String)
    }

    // MARK: - What was found

    public enum Verdict: String, Sendable, Equatable {
        case running
        case notInstalled
        /// Registered with launchd but never started: macOS holds an unidentified
        /// developer's daemon until it is approved under Login Items.
        case awaitingApproval
        /// Started, and killed by a signal. The job is *not* waiting for anything.
        case crashLooping
        case stoppedAfterRunning
        /// launchd could not be asked, so nothing can be concluded about the job.
        case unknown
    }

    public enum Severity: String, Sendable, Equatable {
        case ok, note, warning, problem
    }

    public struct Finding: Sendable, Equatable {
        public var severity: Severity
        public var area: String
        public var message: String
        /// A command for a person to run. Never run by anything here.
        public var fix: String?

        public init(_ severity: Severity, _ area: String, _ message: String, fix: String? = nil) {
            self.severity = severity
            self.area = area
            self.message = message
            self.fix = fix
        }
    }

    public struct Report: Sendable, Equatable {
        public var verdict: Verdict
        public var summary: String
        public var findings: [Finding]
        public var logs: [LogTail]

        public var hasProblem: Bool { findings.contains { $0.severity == .problem } }
    }

    public struct LogTail: Sendable, Equatable {
        public var path: String
        public var lines: [String]
        public var isEmpty: Bool { lines.isEmpty }

        public init(path: String, lines: [String]) {
            self.path = path
            self.lines = lines
        }
    }

    // MARK: - Facts

    /// Everything `diagnose` is allowed to know. Plain values, so a test can write one out.
    public struct Facts: Sendable {
        public var job: JobState = .absent
        public var plistInstalled = false
        /// Whether the installed job's arguments include `--block`, read from the plist.
        public var installedWithBlock = false
        public var socketPath = WireProtocol.defaultSocketPath
        public var socket: SocketState = .absent
        public var anchorFilePresent = false
        public var pfConfigurationNamesAnchor = false
        public var pinFilePresent = false
        public var blockListProblems: [String] = []
        /// Installed binaries the checkout's source is newer than. Empty when no source
        /// directory was given, which `sourceChecked` distinguishes from "all current".
        public var staleBinaries: [String] = []
        public var sourceChecked = false
        public var sourceDirectory: String?
        public var enrichmentMissing: [String] = []
        public var logs: [LogTail] = []

        public init() {}
    }

    // MARK: - Judgement

    /// Turns facts into a verdict and the findings behind it.
    ///
    /// The ordering is the lesson `doctor.sh` records: evidence that the job HAS run is
    /// weighed before any conclusion that it has not. "No process plus empty logs" reads as
    /// approval-pending and sent a real crash loop to System Settings, where it ran 4,000
    /// times. A process killed by a signal never flushes a block-buffered stdout, so empty
    /// logs are exactly what a daemon dying during startup leaves behind.
    public static func diagnose(_ facts: Facts) -> Report {
        var findings: [Finding] = []
        let verdict: Verdict
        let summary: String

        // The commonest cause of "ran many times, no signal": `--block` refuses to start
        // without a wired-in anchor and exits cleanly through `fail()`, so launchd sees an
        // ordinary exit and restarts it forever. Decided from the facts that cause it — the
        // job's own arguments and the state of pf.conf — rather than from the wording of a
        // log line, which a reworded error message or a weeks-old refusal would fool.
        //
        // A newer daemon also says so itself, through its exit status, which covers the case
        // pf.conf cannot show: the anchor named there but never loaded into the running
        // ruleset. Reading that would need root; the exit code does not.
        let anchorUnusable = !facts.anchorFilePresent || !facts.pfConfigurationNamesAnchor
        var refusedByExitCode = false
        if case .present(let job) = facts.job {
            refusedByExitCode = job.lastExitStatus == BeholderPaths.blockRefusedExitCode
        }
        let blockRefusal = facts.installedWithBlock && (anchorUnusable || refusedByExitCode)

        // A daemon answering on the socket is capture working, whatever launchd says about
        // the installed job. A foreground `make serve` beside a stopped job is the usual
        // shape, and calling it broken would send someone to fix a capture that is running.
        var serving = false
        if case .read = facts.socket { serving = true }

        switch facts.job {
        case .present(let job) where serving && !job.isRunning:
            verdict = .running
            summary =
                "Capture is running outside launchd (a foreground run); the installed job "
                + "is not."
            findings.append(
                Finding(
                    .note, "daemon",
                    "The installed job is stopped (it has run \(job.runs ?? 0) times), so "
                        + "capture ends when this foreground run does."
                        + (blockRefusal
                            ? " It stops because --block refuses to run while the pf anchor "
                                + "is not loaded." : ""),
                    fix: blockRefusal ? "sudo ./Scripts/install-pf-anchor.sh" : "make restart"))
        case .absent where serving && !facts.plistInstalled:
            verdict = .running
            summary = "Capture is running in the foreground; no daemon is installed."
            findings.append(
                Finding(
                    .note, "daemon",
                    "Capture ends when this run does. To capture continuously and across "
                        + "reboots, install it.", fix: "make install"))
        case .unknown:
            verdict = .unknown
            summary = "launchd could not be asked about the job, so its state is unknown."
        case .present(let job) where job.isRunning:
            verdict = .running
            summary = "The daemon is running."
        case .present(let job):
            if let signal = job.lastTerminatingSignal {
                verdict = .crashLooping
                summary =
                    "The job is not waiting for approval — it has been running and dying "
                    + "(launchd recorded: last terminating signal = \(signal))."
                var message =
                    "Empty logs do not contradict this: a process killed by a signal never "
                    + "flushes buffered output, so a daemon that dies during startup leaves "
                    + "nothing behind."
                if let runs = job.runs { message = "Restarted \(runs) times. " + message }
                findings.append(
                    Finding(
                        .problem, "daemon", message,
                        fix: "make install  # the current build is the only thing that changes what it does"
                    ))
            } else if (job.runs ?? 0) == 0 {
                verdict = .awaitingApproval
                summary =
                    "The job is loaded but has never run: no process, no recorded exit, no output."
                findings.append(
                    Finding(
                        .problem, "daemon",
                        "macOS registers daemons from unidentified developers and refuses to "
                            + "start them until approved: System Settings > General > Login "
                            + "Items & Extensions, find Beholder and turn it on.",
                        fix: "open x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
                    ))
            } else {
                verdict = .stoppedAfterRunning
                summary =
                    "The job has run \(job.runs ?? 0) times but is not running now, and "
                    + "recorded no signal."
                if blockRefusal {
                    findings.append(
                        Finding(
                            .problem, "daemon",
                            "The daemon is exiting at startup: it is installed with --block, and "
                                + "--block refuses to run while the pf anchor is not wired in, "
                                + "because enforcing half a configuration would leave "
                                + "destinations looking blocked when they are not. launchd "
                                + "restarts it each time.",
                            fix: "sudo ./Scripts/install-pf-anchor.sh"))
                } else {
                    findings.append(
                        Finding(.problem, "daemon", "Check the logs below.", fix: "make restart"))
                }
            }
        case .absent where facts.plistInstalled:
            verdict = .unknown
            summary = "The launch plist is installed but launchd does not know the job."
            findings.append(
                Finding(
                    .problem, "daemon",
                    "The plist exists at \(BeholderPaths.launchdPlist) but launchd has no job "
                        + "by that label, so it was removed or never bootstrapped.",
                    fix: "make install"))
        case .absent:
            verdict = .notInstalled
            summary =
                "No daemon is installed, so only a foreground `make run` will feed the app."
            findings.append(
                Finding(
                    .note, "daemon",
                    "To capture continuously and across reboots, install it.", fix: "make install"
                ))
        }

        // The socket. Reported against the verdict because the two disagreeing is itself
        // the finding: a running job whose socket refuses is a different fault from a
        // stopped job that left its socket behind.
        switch facts.socket {
        case .read:
            findings.append(
                Finding(.ok, "socket", "\(facts.socketPath) is publishing snapshots."))
        case .unreadable(let failure):
            findings.append(
                Finding(
                    .warning, "socket",
                    "\(facts.socketPath) accepts connections but a snapshot could not be "
                        + "read: \(failure)"))
        case .forbidden(let reason):
            findings.append(
                Finding(
                    .warning, "socket",
                    "\(reason) Capture is running as another user. Restart it as yourself, "
                        + "or query from that account."))
        case .refusing:
            findings.append(
                Finding(
                    .warning, "socket",
                    "\(facts.socketPath) is present but refusing connections — left behind by "
                        + "a daemon that is gone."))
        case .absent:
            findings.append(Finding(.note, "socket", "No socket at \(facts.socketPath)."))
        }

        // Blocking, only when it was ever installed. The failure is silent: pf.conf is a
        // system file and a macOS update can restore the stock copy, removing the line
        // naming Beholder's anchor. Everything else keeps working and nothing is blocked.
        if facts.anchorFilePresent {
            if facts.pfConfigurationNamesAnchor {
                findings.append(
                    Finding(.ok, "blocking", "\(PacketFilterPlan.mainConfigurationPath) names the anchor."))
            } else {
                findings.append(
                    Finding(
                        .problem, "blocking",
                        "The anchor file is present but \(PacketFilterPlan.mainConfigurationPath) "
                            + "does not name it. Nothing is being blocked, whatever the block "
                            + "list says. A macOS update restoring the stock pf.conf does "
                            + "exactly this.",
                        fix: "sudo ./Scripts/install-pf-anchor.sh"))
            }
            if !facts.pinFilePresent {
                findings.append(
                    Finding(
                        .warning, "blocking",
                        "No control pin at \(ControlProtocol.pinPath), so the app cannot "
                            + "change what is blocked.",
                        fix: "sudo ./Scripts/install-control-pin.sh"))
            }
        }
        for problem in facts.blockListProblems {
            findings.append(Finding(.problem, "blocking", problem))
        }

        // A binary older than the source it was built from explains a bug that is fixed in
        // the checkout and still crashing in the field: the installed copy is a snapshot.
        for path in facts.staleBinaries {
            findings.append(
                Finding(
                    .warning, "install",
                    "\(path) is older than the source in "
                        + "\(facts.sourceDirectory ?? "the checkout"). Whatever it is doing, "
                        + "it is not doing what the current code says.",
                    fix: "make install"))
        }

        if !facts.enrichmentMissing.isEmpty {
            findings.append(
                Finding(
                    .note, "enrichment",
                    "Not loaded: \(facts.enrichmentMissing.joined(separator: ", ")). "
                        + "Countries, operators or trackers will be missing from results.",
                    fix: "make data"))
        }

        return Report(verdict: verdict, summary: summary, findings: findings, logs: facts.logs)
    }

    // MARK: - Gathering

    public static let logPaths = ["/var/log/beholderd.log", "/var/log/beholderd.err"]

    /// Collects the facts. Never throws and never needs root: every check that would need
    /// it (the live pf table) is simply absent, and `doctor.sh` adds it under `sudo`.
    ///
    /// The one subprocess is `/bin/launchctl print system/com.beholder.daemon` — see
    /// `askLaunchd`. It runs alongside the socket read rather than before it, since both
    /// can wait for seconds and neither needs the other.
    public static func gather(
        socketPath: String = WireProtocol.defaultSocketPath,
        sourceDirectory: String? = nil,
        logLines: Int = 20
    ) -> Facts {
        let launchd = Asked()
        let asked = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            launchd.output = askLaunchd()
            asked.signal()
        }

        var facts = Facts()
        facts.socketPath = socketPath
        facts.plistInstalled = BeholderPaths.isInstalledAsDaemon()
        facts.installedWithBlock = installedArguments().contains("--block")

        var info = stat()
        if stat(socketPath, &info) == 0 {
            // One read answers both "is anything listening" and "does it speak": a refused
            // connection is `notRunning`, anything else got far enough to accept.
            do {
                facts.socket = .read(try SnapshotClient.readOne(from: socketPath))
            } catch SnapshotClient.Failure.notRunning {
                facts.socket = .refusing
            } catch let failure as SnapshotClient.Failure {
                if case .notYours = failure {
                    facts.socket = .forbidden(failure.description)
                } else {
                    facts.socket = .unreadable(failure.description)
                }
            } catch {
                facts.socket = .unreadable("\(error)")
            }
        }

        let manager = FileManager.default
        facts.anchorFilePresent = manager.fileExists(atPath: PacketFilterPlan.anchorPath)
        if let configuration = try? String(
            contentsOfFile: PacketFilterPlan.mainConfigurationPath, encoding: .utf8)
        {
            facts.pfConfigurationNamesAnchor = configuration.contains(
                "anchor \"\(PacketFilterPlan.anchorName)\"")
        }
        facts.pinFilePresent = manager.fileExists(atPath: ControlProtocol.pinPath)

        // Read exactly as `--block` reads them, by the same function, so a list that would
        // stop the daemon at startup is named here — including one line it cannot parse.
        if facts.installedWithBlock,
            case .failed(let path, let failure) = EnforcedBlockList.read(
                fixed: BlockList.defaultPath, managed: ControlProtocol.managedListPath)
        {
            facts.blockListProblems.append(
                "\(path) cannot be used by --block: \(failure.description)")
        }

        if let sourceDirectory {
            facts.sourceDirectory = sourceDirectory
            facts.sourceChecked = true
            for path in [BeholderPaths.installedDaemon, BeholderPaths.installedMCP] {
                guard
                    let modified = (try? manager.attributesOfItem(atPath: path))?[
                        .modificationDate] as? Date
                else { continue }
                if hasSwiftSource(under: sourceDirectory + "/Sources", newerThan: modified) {
                    facts.staleBinaries.append(path)
                }
            }
        }

        // The daemon's own word when it is running, since a file on disk that failed to
        // parse is not loaded; existence on disk only when there is no daemon to ask.
        if case .read(let snapshot) = facts.socket, let daemon = snapshot.daemon {
            facts.enrichmentMissing = daemon.enrichment.filter { !$0.loaded }.map(\.name)
        } else {
            facts.enrichmentMissing = EnrichmentDatabase.allCases
                .filter { $0.installedPath == nil }.map(\.name)
        }

        if logLines > 0 {
            facts.logs = logPaths.map { tail(of: $0, lines: logLines) }
        }

        asked.wait()
        switch launchd.output {
        case nil: facts.job = .unknown
        case ""?: facts.job = .absent
        case let output?: facts.job = .present(LaunchdJob.parse(output))
        }
        return facts
    }

    /// The installed job's arguments, from its plist. Root-free: the plist is world-readable.
    static func installedArguments() -> [String] {
        guard let data = FileManager.default.contents(atPath: BeholderPaths.launchdPlist),
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any]
        else { return [] }
        return plist["ProgramArguments"] as? [String] ?? []
    }

    /// Whether any `.swift` file under a directory is newer than `date`. Stops at the first,
    /// as the `find -newer -print -quit` this replaced did.
    static func hasSwiftSource(under directory: String, newerThan date: Date) -> Bool {
        guard
            let walker = FileManager.default.enumerator(
                at: URL(fileURLWithPath: directory),
                includingPropertiesForKeys: [.contentModificationDateKey])
        else { return false }
        for case let url as URL in walker where url.pathExtension == "swift" {
            if let modified = try? url.resourceValues(forKeys: [.contentModificationDateKey])
                .contentModificationDate, modified > date
            {
                return true
            }
        }
        return false
    }

    /// The last lines of a log, each one cleaned.
    ///
    /// A log is text some other program wrote, and a daemon echoes hostnames and error
    /// strings that originated on the network, so this gets the same treatment as every
    /// other string an assistant is handed: no control characters, bounded length.
    static func tail(of path: String, lines: Int) -> LogTail {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            return LogTail(path: path, lines: [])
        }
        defer { try? handle.close() }
        // Only the end matters, and the log grows for weeks; seek rather than read it all.
        let window: UInt64 = 64 * 1024
        let size = (try? handle.seekToEnd()) ?? 0
        try? handle.seek(toOffset: size > window ? size - window : 0)
        let data = (try? handle.readToEnd()) ?? Data()
        var segments = String(decoding: data, as: UTF8.self)
            .split(separator: "\n", omittingEmptySubsequences: false)
        // Starting mid-file almost always means starting mid-line; that fragment would be
        // shown as if it were a whole line, so it is dropped.
        if size > window, !segments.isEmpty { segments.removeFirst() }
        let kept = segments.filter { !$0.isEmpty }.suffix(lines)
        return LogTail(
            path: path, lines: kept.map { MCPToolbox.cleaned(String($0), limit: 300) })
    }

    /// Written by one queue and read only after a semaphore orders the two; the box exists
    /// to say so to the compiler.
    private final class Asked: @unchecked Sendable {
        var output: String?
        var data = Data()
    }

    /// Asks launchd about the job. Returns the output; an empty string when launchd has no
    /// such job; nil when it could not be asked at all.
    ///
    /// This is the single subprocess the MCP server is allowed, and it is bounded the way
    /// `pfctl` is bounded in the daemon: an absolute path, never `PATH`; a fixed argument
    /// vector, never a shell; nothing from the caller reaches it; two seconds and then it
    /// is killed. Its output is only ever parsed. Without it an assistant cannot tell a
    /// crash loop from a pending approval, which is the first thing a broken install raises.
    static func askLaunchd(timeout: TimeInterval = 2) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "system/\(BeholderPaths.launchdLabel)"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice

        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        do {
            try process.run()
        } catch {
            return nil
        }

        // Drained while waiting. `launchctl print` can exceed a pipe's buffer, and a child
        // blocked writing to a full pipe never exits.
        let collected = Asked()
        let drained = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            collected.data = output.fileHandleForReading.readDataToEndOfFile()
            drained.signal()
        }
        if finished.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            _ = drained.wait(timeout: .now() + 1)
            return nil
        }
        drained.wait()
        // A missing job exits non-zero with nothing on stdout.
        if process.terminationStatus != 0 { return "" }
        return String(decoding: collected.data, as: UTF8.self)
    }

    // MARK: - Plain-text rendering

    /// The report as a person would read it in a terminal. `beholderd --diagnose` prints
    /// this, and `doctor.sh` includes it verbatim.
    ///
    /// The last line is `verdict: <name>`, machine-readable on purpose: `doctor.sh` acts on
    /// the verdict (opening Login Items for `awaitingApproval`), and matching a sentence of
    /// prose would break the first time the sentence was improved.
    public static func render(_ report: Report) -> String {
        var lines: [String] = [report.summary, ""]
        for finding in report.findings {
            let mark: String
            switch finding.severity {
            case .ok: mark = "ok     "
            case .note: mark = "note   "
            case .warning: mark = "WARNING"
            case .problem: mark = "PROBLEM"
            }
            lines.append("[\(mark)] \(finding.area): \(finding.message)")
            if let fix = finding.fix { lines.append("          fix: \(fix)") }
        }
        for log in report.logs {
            lines.append("")
            lines.append(log.isEmpty ? "\(log.path): empty" : "\(log.path):")
            for line in log.lines { lines.append("  \(line)") }
        }
        lines.append("")
        lines.append("verdict: \(report.verdict.rawValue)")
        return lines.joined(separator: "\n")
    }
}
