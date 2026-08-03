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

        if options.dumpSockets {
            SocketDump.run()
            exit(0)
        }

        // In --top mode the flow monitor consumes packets; otherwise they are only
        // counted, since Phase 0's statistics view has no use for them.
        let monitor = options.top ? FlowMonitor() : nil
        let packetHandler: PacketSink
        if let monitor {
            packetHandler = monitor.packetHandler()
        } else {
            packetHandler = { _, _, _ in }
        }
        let engine = CaptureEngine(onPacket: packetHandler)

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
        } else {
            let path = options.top ? "live view" : "reporting loop"
            print("Self-test: running the \(path) with no interfaces.")
            print("")
        }

        retained.append(engine)

        if let monitor {
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

            let view = TopView(monitor: monitor, engine: engine, supervisor: supervisor)
            view.installSignalHandlers()
            view.start(stopAfterTicks: options.selfTest ? 3 : nil)
            retained.append(monitor)
            retained.append(view)
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

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("beholderd: \(message)\n".utf8))
        exit(1)
    }
}
