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
    static func main() {
        guard let options = Options.parse(Array(CommandLine.arguments.dropFirst())) else {
            print(Options.usage)
            exit(1)
        }

        if options.dumpSockets {
            SocketDump.run()
            exit(0)
        }

        let engine = CaptureEngine { _, _ in }

        if !options.selfTest {
            for interface in resolveInterfaces(options) {
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
            print("Self-test: running the reporting loop with no interfaces.")
            print("")
        }

        let reporter = StatisticsReporter(engine: engine)
        reporter.installSignalHandlers()
        reporter.start(stopAfterTicks: options.selfTest ? 3 : nil)

        dispatchMain()
    }

    private static func resolveInterfaces(_ options: Options) -> [String] {
        var interfaces = options.interfaces

        if interfaces.isEmpty {
            guard let route = RouteLookup.defaultRoute() else {
                fail("could not determine the default route.")
            }
            interfaces = [route.interfaceName]
            print("Default route leaves via \(route)")
        }

        if options.includeLoopback, !interfaces.contains("lo0") {
            interfaces.append("lo0")
        }
        return interfaces
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("beholderd: \(message)\n".utf8))
        exit(1)
    }
}
