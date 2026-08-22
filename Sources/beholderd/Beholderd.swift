import BeholderCore
import Darwin
import Dispatch
import Foundation
import Security

// Phase 0 of Beholder: prove that capture works.
//
// This binary opens the interface carrying the default route and reports what it sees,
// once per second. It exists to answer three questions before any higher-level machinery
// is built on top: can we get at /dev/bpf, do we resolve the right interface when a VPN
// is up, and do we parse that interface's link layer correctly?
//
// The "parsed" column is the one that matters. If packets are arriving but the parsed
// count stays near zero, the link-layer assumption for that interface is wrong.
//
// Deliberately an `@main` type rather than a `main.swift`: top-level code in Swift 6 is
// `@MainActor`-isolated, which makes any dispatch-queue callback that touches top-level
// state trap at runtime.
@main
enum Beholderd {
    /// Objects that own dispatch sources have to outlive `main()`.
    ///
    /// `dispatchMain()` never returns, which means the compiler is free to release
    /// `main()`'s locals before it is even called. A released reporter takes its timer
    /// with it, and the process then sits in `dispatchMain()` forever, alive but silent —
    /// no output, no exit, no error. Holding the references here for the lifetime of the
    /// process removes the question entirely.
    ///
    /// Written once during startup, before any concurrency exists.
    private nonisolated(unsafe) static var retained: [AnyObject] = []

    /// The packet filter, held statically so that `atexit` can reach it.
    ///
    /// Every path out of this process has to release pf's reference and empty the block
    /// table, including the ones that call `exit` directly — both shutdown handlers do, and
    /// so does `fail()`. Registering one `atexit` hook covers all of them, where hanging the
    /// teardown off each exit point would cover whichever ones someone remembered.
    ///
    /// `SIGKILL` still runs nothing, which is what `make unblock` exists for.
    private nonisolated(unsafe) static var packetFilter: PacketFilter?

    static func main() {
        // Line-buffer stdout. Swift block-buffers it when it is a file rather than a
        // terminal, so under launchd every status line sat in a buffer and was lost when
        // the process exited — leaving a crash-looping daemon with two empty log files
        // and nothing whatsoever to diagnose from.
        setvbuf(stdout, nil, _IOLBF, 0)

        // A reader going away must never take the daemon with it.
        //
        // Writing to a socket whose peer has closed raises SIGPIPE, and the default
        // disposition is to terminate — so quitting the app could kill capture. The
        // per-socket SO_NOSIGPIPE set on each client is not a sufficient guard: when the
        // peer closes before the connection is accepted, setsockopt itself fails with
        // EINVAL, leaving the option unset on precisely the socket that needs it. Ignoring
        // the signal process-wide turns every such write into an EPIPE return value, which
        // the send path already handles by dropping the client.
        signal(SIGPIPE, SIG_IGN)

        note("starting: \(CommandLine.arguments.joined(separator: " "))")

        guard let options = Options.parse(Array(CommandLine.arguments.dropFirst())) else {
            print(Options.usage)
            exit(1)
        }

        // Reading history needs no capture and no root, so it is handled before
        // anything privileged is attempted.
        if options.history {
            HistoryCommands.run(options)
        }

        // Same reasoning: checking a block list reads a file and prints what it means.
        if options.checkBlocklist {
            exit(checkBlocklist(options))
        }

        if options.checkControlPin {
            exit(checkControlPin(options))
        }

        // The installer asks for these rather than carrying its own copy. Two files that
        // must contain the same pf rules and are edited in different languages will
        // eventually disagree, and the disagreement would show up as blocking that loads
        // without complaint and matches nothing.
        if options.printPFAnchor {
            print(PacketFilterPlan.anchorRuleset, terminator: "")
            exit(0)
        }
        if options.printPFConfiguration {
            print(PacketFilterPlan.mainConfigurationLines)
            exit(0)
        }

        if options.dumpSockets {
            SocketDump.run()
            exit(0)
        }

        // Flows are needed to draw the live view and to publish to the app. Without
        // either, packets are only counted, which is all the statistics view wants.
        let needsFlows = options.top || options.serve

        // Payload reading only has somewhere to go when flows are being tracked. Asked for
        // without --serve or --top it is reported rather than refused, since a run that
        // only counts packets has nothing the excerpts could attach to.
        let readCleartext = options.readsCleartext
        if options.readCleartext, !readCleartext {
            note("--read-cleartext has no effect without --serve or --top")
        }
        if readCleartext {
            print("Reading payload of unencrypted connections. Held in memory only:")
            print("nothing is written to the history database or to the transcript.")
            print("")
        }

        let measureQuality = options.measuresQuality
        if !options.measureQuality, needsFlows {
            note("not measuring round-trip time, retransmissions or jitter")
        }
        let monitor =
            needsFlows
            ? FlowMonitor(readCleartext: readCleartext, measureQuality: measureQuality) : nil

        // The one thing here that is not purely passive, so it announces itself the way payload
        // reading does — before anything happens, not in a log nobody reads afterwards.
        let probing = options.probes
        if options.probe, !probing {
            note("--probe has no effect without --serve or --top, or with --no-history")
        }
        if probing, let monitor {
            let targets =
                options.probeTargets.isEmpty ? Prober.defaultAnchors : options.probeTargets
            let instance = Prober(
                interval: options.probeInterval,
                anchors: targets,
                record: { [weak monitor] results in monitor?.recordProbes(results) }
            )

            print("Sending probes. Beholder is no longer only watching:")
            let named = instance.currentTargets().map {
                "\($0.address)\($0.kind == .gateway ? " (gateway)" : "")"
            }
            print(
                "every \(Int(options.probeInterval))s, one ICMP echo to "
                    + named.joined(separator: ", "))
            print("Nothing else is sent, and no traffic of anyone else's is altered.")
            print("")

            // Started by the monitor, which also owns it: it must be cancelled before the store
            // closes, and a local here would not survive dispatchMain().
            monitor.attach(prober: instance)
        }
        let packetHandler: PacketSink
        if let monitor {
            packetHandler = monitor.packetHandler()
        } else {
            packetHandler = { _, _, _ in }
        }
        let engine = CaptureEngine(
            snapshotLength: readCleartext
                ? CaptureEngine.cleartextSnapshotLength
                : CaptureEngine.defaultSnapshotLength,
            onPacket: packetHandler
        )

        let log = makeLog(options)
        if let log {
            print("Logging to \(log.url.path)")
        }

        // Armed before capture opens, so a machine that cannot enforce what it was asked to
        // enforce fails while the operator is still watching the terminal, rather than
        // capturing happily with blocking silently off.
        if options.block {
            let filter = PacketFilter(
                listPath: options.blocklistPath,
                managedListPath: options.managedBlocklistPath,
                log: log)
            // Registered *before* arming, not after.
            //
            // `arm()` enables pf and takes a reference partway through its work, so a failure
            // after that point — an unusable list, a pfctl command that exits non-zero — used
            // to exit without ever handing the reference back. Under launchd that is a crash
            // loop, and every iteration leaked another reference that nothing could ever
            // release, because the token died with the process that held it. Teardown is safe
            // to have registered for a filter that armed only partly: it releases what was
            // taken and skips what was not.
            packetFilter = filter
            retained.append(filter)
            atexit { Beholderd.packetFilter?.disarm() }

            do {
                let summary = try filter.arm()
                filter.installReloadHandler()

                print("Blocking. Beholder is no longer only watching:")
                print("\(summary), from \(options.blocklistPath)")
                print("Blocking is by destination, so it applies to every program on this")
                print("machine — and an address serving several names takes all of them.")
                print("Edit the list and `sudo kill -HUP \(getpid())` to reload it.")
                print("Blocking stops when this daemon does.")
                print("")
            } catch {
                fail("\((error as? PacketFilter.FilterError)?.description ?? "\(error)")")
            }
        }

        // The control socket. Opened after blocking is armed, so a client that connects the
        // instant it appears cannot find a daemon that has not finished deciding whether it
        // can enforce anything.
        if options.opensControlSocket {
            startControlServer(options)
        }

        var interfaces: [String] = []
        var followedInterface: String?

        if !options.selfTest {
            let resolved = resolveInterfaces(options)
            interfaces = resolved.interfaces
            followedInterface = resolved.followed
            for interface in interfaces {
                do {
                    try engine.start(interface: interface)
                } catch let error as CaptureError {
                    fail(error.description)
                } catch {
                    fail("\(error)")
                }
            }

            for statistics in engine.statistics() {
                note("capturing \(statistics.interfaceName) (\(statistics.linkLayer.name))")
            }
            print("")

            // Opening context, so a transcript read later explains its own conditions
            // rather than needing them remembered.
            log?.section(
                "RUN START",
                """
                Started:    \(formatTimestamp(Date()))
                Command:    \(CommandLine.arguments.joined(separator: " "))
                Interfaces: \(engine.statistics().map { "\($0.interfaceName) (\($0.linkLayer.name))" }.joined(separator: ", "))
                Following:  \(followedInterface ?? "no — interfaces named explicitly")
                Host:       \(ProcessInfo.processInfo.hostName)
                macOS:      \(ProcessInfo.processInfo.operatingSystemVersionString)
                """
            )
        } else {
            let path = options.top ? "live view" : "reporting loop"
            print("Self-test: running the \(path) with no interfaces.")
            print("")
        }

        retained.append(engine)

        if let monitor {
            if options.storeHistory, !options.selfTest {
                switch monitor.openStore(at: options.historyPath ?? FlowStore.defaultPath()) {
                case .success(let path):
                    note("recording history to \(path)")
                case .failure(let error):
                    FileHandle.standardError.write(
                        Data("beholderd: \(error); continuing without history.\n".utf8)
                    )
                }
            }
            note("starting the flow monitor")
            monitor.start()

            // Only supervise when Beholder chose the interface. An explicit interface
            // list is an instruction to stay put.
            //
            // The self-test supervises too, with nothing yet followed: reconcile() then
            // finds the real default route and tries to capture it, which without root
            // fails and records a failed transition. That exercises route lookup, the
            // failure path and transition recording without needing privilege.
            var supervisor: InterfaceSupervisor?
            if followedInterface != nil || options.selfTest {
                let pinned = interfaces.filter { $0 != followedInterface }
                let created = InterfaceSupervisor(
                    engine: engine,
                    pinned: pinned,
                    initiallyFollowing: followedInterface,
                    onChange: { [weak monitor] in monitor?.refreshLocalAddresses() }
                )
                created.start()
                supervisor = created
                retained.append(created)
            }

            if options.serve {
                let startedAt = Date()
                // Bound to a `let` so the snapshot closure captures an immutable value.
                let activeSupervisor = supervisor
                let server = FlowServer(path: options.socketPath) { [weak monitor, weak engine] in
                    guard let monitor, let engine else {
                        return FlowSnapshot(
                            generatedAt: Date(), startedAt: startedAt,
                            interfaces: [], flows: [], statistics: WireStatistics()
                        )
                    }
                    let statistics = engine.statistics()
                    return monitor.wireSnapshot(
                        startedAt: startedAt,
                        interfaces: statistics.map(\.interfaceName),
                        packetsCaptured: statistics.reduce(0) { $0 + $1.counters.packets },
                        packetsDropped: statistics.reduce(0) { $0 + UInt64($1.kernelDropped) },
                        transitions: activeSupervisor?.recordedTransitions().map(\.summary) ?? []
                    )
                }
                do {
                    try server.start()
                    note("publishing on \(options.socketPath)")
                    retained.append(server)
                } catch let error as UnixSocket.Failure {
                    // The terminal view still works, so this is a warning, not a failure.
                    FileHandle.standardError.write(
                        Data("beholderd: \(error.description); continuing without it.\n".utf8)
                    )
                } catch {
                    FileHandle.standardError.write(Data("beholderd: \(error)\n".utf8))
                }
            }

            let session = TopView(
                monitor: monitor,
                engine: engine,
                supervisor: supervisor,
                log: log,
                rendersToTerminal: options.top
            )
            session.installSignalHandlers()
            session.start(stopAfterTicks: options.selfTest ? 3 : nil)
            retained.append(monitor)
            retained.append(session)

            if !options.top {
                print("Serving. Ctrl-C to stop.")
            }
        } else {
            let reporter = StatisticsReporter(engine: engine)
            reporter.installSignalHandlers()
            reporter.start(stopAfterTicks: options.selfTest ? 3 : nil)
            retained.append(reporter)
        }

        note("startup complete; entering the run loop")
        dispatchMain()
    }

    /// Works out what to capture, and whether to keep following the default route.
    ///
    /// Naming interfaces explicitly is taken as an instruction, not a hint: if the user
    /// asked for `en0`, capture stays on `en0` even when routing moves elsewhere.
    /// Following only happens when the choice was left to Beholder.
    private static func resolveInterfaces(
        _ options: Options
    ) -> (interfaces: [String], followed: String?) {
        var interfaces = options.interfaces
        var followed: String?

        if interfaces.isEmpty {
            guard let route = RouteLookup.defaultRoute() else {
                fail("could not determine the default route.")
            }
            interfaces = [route.interfaceName]
            followed = route.interfaceName
            print("Default route leaves via \(route)")
        }

        if options.includeLoopback, !interfaces.contains("lo0") {
            interfaces.append("lo0")
        }
        return (interfaces, followed)
    }

    /// Opens the run transcript. Defaults to `logs/` beside the working directory so the
    /// file lands with the project rather than somewhere the user has to go looking.
    private static func makeLog(_ options: Options) -> RunLog? {
        guard options.logging else { return nil }
        let directory =
            options.logDirectory.map { URL(fileURLWithPath: $0) }
            ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("logs")

        guard let log = RunLog(directory: directory, startedAt: Date()) else {
            // Not fatal. Losing the transcript is a nuisance; refusing to capture
            // because of it would be worse.
            FileHandle.standardError.write(
                Data("beholderd: could not open a log in \(directory.path); continuing.\n".utf8)
            )
            return nil
        }
        return log
    }

    /// Opens the one channel into the daemon that changes something.
    ///
    /// A missing or unusable pin is a warning rather than a failure, and the asymmetry with
    /// `--block` is deliberate. Refusing to start when blocking cannot be enforced protects
    /// someone who believes a destination is unreachable. Refusing to start when the *app*
    /// cannot be authenticated would protect nobody — capture and any blocking already
    /// configured carry on perfectly well, and taking those down because a GUI cannot connect
    /// would be the larger harm. So it says so loudly and serves nothing.
    private static func startControlServer(_ options: Options) {
        let requirement: SecRequirement
        switch PeerAuthenticator.loadRequirement(at: options.controlPinPath) {
        case .unavailable(let reason):
            note("not opening the control socket: \(reason)")
            note("pin the app with: sudo ./Scripts/install-control-pin.sh")
            return
        case .loaded(let loaded):
            requirement = loaded
        }

        let server = ControlServer(path: options.controlSocketPath, requirement: requirement) {
            request in
            guard let filter = packetFilter else {
                // Answered rather than refused. "Blocking is not running" is a fact the app
                // needs in order to say something useful, and it is a different state from
                // "nothing is blocked" — the app draws a different screen for each.
                let reason =
                    "this daemon is running without --block, so nothing is being enforced"
                switch request.action {
                case .status:
                    return ControlResponse(
                        ok: true,
                        state: ControlState(isBlocking: false, entries: [], reason: reason))
                case .block, .unblock:
                    return .failure(reason)
                }
            }

            switch request.action {
            case .status:
                return ControlResponse(ok: true, state: filter.state())
            case .block:
                guard let destination = request.destination else {
                    return .failure("block needs a destination")
                }
                return filter.add(destination: destination, note: request.note)
            case .unblock:
                guard let destination = request.destination else {
                    return .failure("unblock needs a destination")
                }
                return filter.remove(destination: destination)
            }
        }

        do {
            try server.start()
            note("control socket on \(options.controlSocketPath)")
            retained.append(server)
        } catch let error as UnixSocket.Failure {
            // Capture is unaffected, so this is a warning. The app will say it cannot reach
            // the daemon, which is true and is the right thing for it to say.
            FileHandle.standardError.write(
                Data("beholderd: \(error.description); continuing without it.\n".utf8))
        } catch {
            FileHandle.standardError.write(Data("beholderd: \(error)\n".utf8))
        }
    }

    /// Reports whether the pinned peer identity loads, and whether a given app satisfies it.
    ///
    /// The bundle is taken from the positional arguments, which in this mode carry no
    /// interfaces — the command exits before any capture is set up.
    ///
    /// The satisfaction check is here rather than in `doctor.sh` because it has to be asked
    /// of the same API the daemon uses. Comparing `codesign` output to the pin file as text
    /// answers a different question, and would differ for exactly the pin this project plans
    /// for next.
    private static func checkControlPin(_ options: Options) -> Int32 {
        print("Pinned peer: \(options.controlPinPath)")

        let requirement: SecRequirement
        switch PeerAuthenticator.loadRequirement(at: options.controlPinPath) {
        case .unavailable(let reason):
            print("")
            print("Cannot be used: \(reason)")
            print("")
            print("Without it the daemon opens no control socket, and blocking can only")
            print("be changed by editing the block list and sending SIGHUP.")
            return 1
        case .loaded(let loaded):
            requirement = loaded
        }

        print("The requirement loads. Only a program matching it may change blocking.")

        guard let bundle = options.interfaces.first else { return 0 }
        print("")
        print("\(bundle)")

        switch PeerAuthenticator.satisfies(bundlePath: bundle, requirement: requirement) {
        case .satisfies:
            print("  satisfies the pin — this build may change what is blocked.")
            return 0

        case .doesNotSatisfy:
            print("  does NOT satisfy the pin, so it cannot change what is blocked.")
            print("  Rebuilding the app changes its identity; re-pin with:")
            print("    sudo ./Scripts/install-control-pin.sh")
            return 1

        case .unreadable(let reason):
            // Not a stale pin, and saying so would send someone to re-pin an app that is not
            // there. The pin above may be entirely correct for the copy they actually run.
            print("  could not be checked: \(reason).")
            print("  Nothing is wrong with the pin itself; there is no app at that path to")
            print("  compare it against. Name the one you run, or build it:")
            print("    beholderd --check-control-pin /Applications/Beholder.app")
            print("    make app")
            return 1
        }
    }

    /// Reports what the block lists would do, without doing any of it.
    ///
    /// Needs no root and touches pf not at all, so it is the way to check an edit before
    /// handing it to a daemon that will refuse to start on a list it cannot use.
    ///
    /// It reads **both** files, through the same `EnforcedBlockList.read` the daemon arms
    /// from. Previewing only the hand-edited list was a preview of something other than what
    /// gets enforced: anyone who had ever blocked a destination from the app was shown less
    /// than pf would hold, with no hint that a second file existed.
    private static func checkBlocklist(_ options: Options) -> Int32 {
        print("Block lists:")
        print("  \(options.blocklistPath)          (yours; never rewritten)")
        print("  \(options.managedBlocklistPath)   (the app's; rewritten by the daemon)")
        print("")

        // The daemon runs as root and refuses a file anything else can write. This check
        // often runs as you, on a draft that is not installed yet, so it applies the rule for
        // *this* user and warns about the stricter one rather than failing it — the check
        // would be useless exactly when it is most wanted.
        for path in [options.blocklistPath, options.managedBlocklistPath] {
            let asRoot = SecureFile.read(at: path)
            if case .insecure(let verdict) = asRoot {
                print("Note: \(path) is \(verdict.description).")
                print("      beholderd --block will refuse it until that is fixed.")
                print("")
            }
        }

        switch EnforcedBlockList.read(
            fixed: options.blocklistPath,
            managed: options.managedBlocklistPath,
            readerUID: geteuid())
        {
        case .failed(let path, let failure):
            switch failure {
            case .missing(let reason):
                print("Cannot read \(path): \(reason)")
            case .insecure(let verdict):
                print("Refusing \(path): \(verdict.description)")
            case .unusable(let problems):
                print("\(problems.count) line(s) in \(path) cannot be used:")
                for problem in problems {
                    print("  line \(problem.line): \(problem.text)")
                    print("    \(problem.reason)")
                }
                print("")
                print("beholderd --block refuses a list with unusable lines rather than")
                print("enforcing the part of it that happens to parse.")
            }
            return 1

        case .lists(let lists):
            let entries = lists.controlEntries
            guard !entries.isEmpty else {
                print("Nothing would be blocked.")
                return 0
            }
            print("Would block \(entries.count) destination(s):")
            let width = entries.map(\.destination.count).max() ?? 0
            for entry in entries {
                let padded = entry.destination.padding(
                    toLength: width, withPad: " ", startingAt: 0)
                let source = entry.isRemovable ? "app " : "list"
                let note = entry.note.map { "   # \($0)" } ?? ""
                print("  \(padded)  [\(source)]\(note)")
            }
            return 0
        }
    }

    /// A startup breadcrumb on stderr, which is never buffered.
    ///
    /// Startup is where a daemon fails, and it is exactly where buffered output is most
    /// likely to be lost. These cost nothing and turn "it exits immediately" into a line
    /// naming the step it got to.
    static func note(_ message: String) {
        FileHandle.standardError.write(Data("beholderd: \(message)\n".utf8))
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("beholderd: \(message)\n".utf8))
        exit(1)
    }
}
