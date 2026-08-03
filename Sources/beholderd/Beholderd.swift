import BeholderCore
import Darwin
import Dispatch
import Foundation

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

    static func main() {
        guard let options = Options.parse(Array(CommandLine.arguments.dropFirst())) else {
            print(Options.usage)
            exit(1)
        }

        // Reading history needs no capture and no root, so it is handled before
        // anything privileged is attempted.
        if options.history {
            HistoryCommands.run(options)
        }

        if options.dumpSockets {
            SocketDump.run()
            exit(0)
        }

        // Flows are needed to draw the live view and to publish to the app. Without
        // either, packets are only counted, which is all the statistics view wants.
        let needsFlows = options.top || options.serve
        let monitor = needsFlows ? FlowMonitor() : nil
        let packetHandler: PacketSink
        if let monitor {
            packetHandler = monitor.packetHandler()
        } else {
            packetHandler = { _, _, _ in }
        }
        let engine = CaptureEngine(onPacket: packetHandler)

        let log = makeLog(options)
        if let log {
            print("Logging to \(log.url.path)")
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
                print(
                    "Capturing \(statistics.interfaceName) — "
                        + "link type \(statistics.linkLayer.name)"
                )
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
                    print("Recording history to \(path)")
                case .failure(let error):
                    FileHandle.standardError.write(
                        Data("beholderd: \(error); continuing without history.\n".utf8)
                    )
                }
            }
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
                    print("Publishing on \(options.socketPath) — open Beholder.app to view")
                    retained.append(server)
                } catch let error as FlowServer.ServerError {
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

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("beholderd: \(message)\n".utf8))
        exit(1)
    }
}
