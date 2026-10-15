import Foundation
import Testing

@testable import BeholderCore

@Suite("Daemon diagnosis reaches the verdict doctor.sh used to")
struct DaemonDiagnosisTests {

    /// Shaped like `launchctl print system/com.beholder.daemon`: the keys that matter sit
    /// one tab in, and the nested coalition block repeats `state` two tabs in.
    private func output(
        state: String, pid: Int? = nil, runs: Int, exit: String = "0",
        signal: String? = nil
    ) -> String {
        var lines = [
            "system/com.beholder.daemon = {",
            "\tactive count = 0",
            "\tstate = \(state)",
            "\tprogram = /usr/local/libexec/beholderd",
        ]
        lines.append("\truns = \(runs)")
        if let pid { lines.append("\tpid = \(pid)") }
        lines.append("\tlast exit code = \(exit)")
        if let signal { lines.append("\tlast terminating signal = \(signal)") }
        lines.append("\tresource coalition = {")
        lines.append("\t\tstate = active")
        lines.append("\t}")
        lines.append("}")
        return lines.joined(separator: "\n")
    }

    private func facts(_ launchctl: String?) -> DaemonDiagnosis.Facts {
        var facts = DaemonDiagnosis.Facts()
        facts.job = launchctl.map { .present(DaemonDiagnosis.LaunchdJob.parse($0)) } ?? .absent
        return facts
    }

    @Test("Nested keys do not leak into the job")
    func nestedKeysIgnored() {
        let job = DaemonDiagnosis.LaunchdJob.parse(output(state: "not running", runs: 3))
        #expect(job.state == "not running", "the two-tab `state = active` must not win")
        #expect(job.runs == 3)
        #expect(job.pid == nil)
    }

    @Test("A recorded signal means a crash loop, whatever the logs say")
    func crashLoop() {
        var input = facts(output(state: "not running", runs: 1506, exit: "0", signal: "Killed: 9"))
        input.logs = [.init(path: "/var/log/beholderd.log", lines: [])]
        let report = DaemonDiagnosis.diagnose(input)
        #expect(report.verdict == .crashLooping)
        #expect(report.summary.contains("not waiting for approval"))
        #expect(report.findings.contains { $0.message.contains("1506") })
    }

    @Test("Never having run is a pending approval, not a crash")
    func awaitingApproval() {
        let report = DaemonDiagnosis.diagnose(facts(output(state: "not running", runs: 0)))
        #expect(report.verdict == .awaitingApproval)
    }

    @Test("Ran, stopped, no signal")
    func stopped() {
        let report = DaemonDiagnosis.diagnose(facts(output(state: "not running", runs: 4)))
        #expect(report.verdict == .stoppedAfterRunning)
    }

    @Test("A pid means running")
    func running() {
        let report = DaemonDiagnosis.diagnose(
            facts(output(state: "running", pid: 412, runs: 1)))
        #expect(report.verdict == .running)
    }

    @Test("No job and no plist is not installed; a plist without a job is a fault")
    func installation() {
        #expect(DaemonDiagnosis.diagnose(facts(nil)).verdict == .notInstalled)

        var orphaned = facts(nil)
        orphaned.plistInstalled = true
        let report = DaemonDiagnosis.diagnose(orphaned)
        #expect(report.verdict == .unknown)
        #expect(report.findings.contains { $0.severity == .problem })
    }

    @Test("A launchd that cannot be asked concludes nothing")
    func queryFailed() {
        var input = facts(nil)
        input.job = .unknown
        #expect(DaemonDiagnosis.diagnose(input).verdict == .unknown)
    }

    @Test("An anchor file that pf.conf does not name is called out with its fix")
    func anchorNotNamed() {
        var input = facts(output(state: "running", pid: 1, runs: 1))
        input.anchorFilePresent = true
        input.pfConfigurationNamesAnchor = false
        let report = DaemonDiagnosis.diagnose(input)
        let finding = report.findings.first { $0.area == "blocking" && $0.severity == .problem }
        #expect(finding?.fix == "sudo ./Scripts/install-pf-anchor.sh")
    }

    @Test("A binary older than the source is flagged; one newer is not")
    func staleBinary() {
        var input = facts(output(state: "running", pid: 1, runs: 1))
        input.sourceDirectory = "/src"
        input.sourceChecked = true
        input.staleBinaries = ["/old"]
        let stale = DaemonDiagnosis.diagnose(input).findings.filter { $0.area == "install" }
        #expect(stale.count == 1)
        #expect(stale.first?.message.contains("/old") == true)
    }

    @Test("Finding a newer source file stops at the first one, and an old tree has none")
    func sourceNewerThan() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("diagnosis-src-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try "".write(
            to: directory.appendingPathComponent("a.swift"), atomically: true, encoding: .utf8)

        #expect(DaemonDiagnosis.hasSwiftSource(under: directory.path, newerThan: .distantPast))
        #expect(!DaemonDiagnosis.hasSwiftSource(under: directory.path, newerThan: .distantFuture))
    }

    @Test("A live socket that cannot be read is a warning, not health")
    func socketAcceptsButUnreadable() {
        var input = facts(output(state: "running", pid: 1, runs: 1))
        input.socket = .unreadable("timed out")
        let socket = DaemonDiagnosis.diagnose(input).findings.first { $0.area == "socket" }
        #expect(socket?.severity == .warning)
    }

    /// Decided from the facts that cause it — the job's arguments and pf.conf — not from the
    /// wording of a log line, which a reworded message or a weeks-old refusal would fool.
    @Test("A --block install with no wired-in anchor is named as why it keeps exiting")
    func blockRefusalIsNamed() {
        var input = facts(output(state: "not running", runs: 1972))
        input.installedWithBlock = true
        input.anchorFilePresent = true
        input.pfConfigurationNamesAnchor = false
        let report = DaemonDiagnosis.diagnose(input)
        #expect(
            report.findings.contains {
                $0.area == "daemon" && $0.message.contains("exiting at startup")
                    && $0.fix == "sudo ./Scripts/install-pf-anchor.sh"
            })
        #expect(
            !report.findings.contains { $0.message == "Check the logs below." },
            "the cause is known, so the generic advice is not offered beside it")

        input.installedWithBlock = false
        #expect(
            !DaemonDiagnosis.diagnose(input).findings.contains {
                $0.message.contains("exiting at startup")
            }, "without --block the anchor cannot be why it stops")
    }

    @Test("The rendered report ends with a machine-readable verdict")
    func renderEndsWithVerdict() {
        let report = DaemonDiagnosis.diagnose(facts(output(state: "not running", runs: 0)))
        #expect(
            DaemonDiagnosis.render(report).hasSuffix("verdict: awaitingApproval"),
            "doctor.sh opens Login Items off this line; prose would break it")
    }

    @Test("A daemon publishing on the socket is capture working, whatever the installed job says")
    func foregroundDaemonIsRunning() {
        var input = facts(output(state: "not running", runs: 1972))
        input.socket = .read(
            FlowSnapshot(
                generatedAt: Date(), startedAt: Date(), interfaces: [], flows: [],
                statistics: WireStatistics()))
        let report = DaemonDiagnosis.diagnose(input)
        #expect(report.verdict == .running)
        #expect(!report.hasProblem, "a working capture is not a problem to fix")

        var uninstalled = DaemonDiagnosis.Facts()
        uninstalled.socket = input.socket
        #expect(DaemonDiagnosis.diagnose(uninstalled).verdict == .running)
    }

    @Test("A socket belonging to another user is named as that, not as one that answered")
    func forbiddenSocket() {
        var input = facts(output(state: "running", pid: 1, runs: 1))
        input.socket = .forbidden("/var/run/beholder.sock belongs to uid 0.")
        let socket = DaemonDiagnosis.diagnose(input).findings.first { $0.area == "socket" }
        #expect(socket?.message.contains("another user") == true)
        #expect(socket?.message.contains("accepts connections") == false)
    }

    /// The case pf.conf cannot show: the anchor named there but never loaded. The daemon's
    /// own exit status carries it, and needs no root to read.
    @Test("The --block refusal exit code is recognised even when pf.conf looks fine")
    func blockRefusalByExitCode() {
        var input = facts(
            output(state: "not running", runs: 12, exit: "78: Function not implemented"))
        input.installedWithBlock = true
        input.anchorFilePresent = true
        input.pfConfigurationNamesAnchor = true
        #expect(
            DaemonDiagnosis.diagnose(input).findings.contains {
                $0.message.contains("exiting at startup")
            })
        #expect(
            DaemonDiagnosis.LaunchdJob.parse(output(state: "x", runs: 1, exit: "(never exited)"))
                .lastExitStatus == nil)
    }

    @Test("A tail that starts mid-file drops the fragment it started in")
    func tailDropsPartialFirstLine() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("diagnosis-tail-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("log").path
        // 300 lines of 300 bytes (under the 300-character display limit with the newline):
        // the 64 KB window starts inside one of them, and asking for more lines than the
        // window holds is what used to let the fragment through.
        let line = String(repeating: "x", count: 299)
        try Array(repeating: line, count: 300).joined(separator: "\n")
            .write(toFile: path, atomically: true, encoding: .utf8)

        let tail = DaemonDiagnosis.tail(of: path, lines: 500)
        #expect(!tail.lines.isEmpty)
        #expect(tail.lines.allSatisfy { $0 == line }, "every line shown is a whole line")
    }

    @Test("Log lines are cleaned of control characters")
    func logsAreCleaned() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("diagnosis-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("log").path
        try "first\nhost \u{1B}[31mred\u{1B}[0m\nlast".write(
            toFile: path, atomically: true, encoding: .utf8)

        let tail = DaemonDiagnosis.tail(of: path, lines: 2)
        #expect(tail.lines.count == 2)
        #expect(!tail.lines.joined().contains("\u{1B}"))
        #expect(tail.lines.last == "last")
    }
}
