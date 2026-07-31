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
// count stays near zero, the link-layer assumption is wrong.

// MARK: - Arguments

struct Options {
    var interfaces: [String] = []
    var includeLoopback = false
    var dumpSockets = false

    static func parse(_ arguments: [String]) -> Options? {
        var options = Options()
        for argument in arguments {
            switch argument {
            case "--loopback", "-l":
                options.includeLoopback = true
            case "--sockets", "-s":
                options.dumpSockets = true
            case "--help", "-h":
                return nil
            default:
                guard !argument.hasPrefix("-") else {
                    FileHandle.standardError.write(
                        Data("beholderd: unknown option '\(argument)'\n".utf8)
                    )
                    return nil
                }
                options.interfaces.append(argument)
            }
        }
        return options
    }
}

let usage = """
    usage: beholderd [--loopback] [--sockets] [interface ...]

      interface    Interface(s) to capture. Defaults to the interface carrying the
                   default route, which with a VPN active is the tunnel, not en0.
      --loopback   Additionally capture lo0.
      --sockets    Dump the socket-to-process table and exit, instead of capturing.
                   Needs no root, but only reveals your own processes unless run as
                   root. Compare against: lsof -nP -i TCP
      --help       Show this message.

    Capture requires root: it reads /dev/bpf*, which is mode 0600 root:wheel.
    """

guard let options = Options.parse(Array(CommandLine.arguments.dropFirst())) else {
    print(usage)
    exit(1)
}

// MARK: - Socket table dump

if options.dumpSockets {
    let snapshot = Attributor.snapshot()
    let privilegeNote = geteuid() == 0
        ? ""
        : "; run as root to see other users' processes"

    print(
        """
        Examined \(snapshot.processesExamined) processes \
        (\(snapshot.inaccessibleProcesses) not inspectable\(privilegeNote)), \
        found \(snapshot.socketsFound) network sockets.
        """
    )
    print("")
    print(
        Column.left("PROCESS", 24) + Column.right("PID", 7) + "  "
            + Column.left("PROTO", 6) + Column.left("STATE", 12)
            + Column.left("LOCAL", 44) + "REMOTE"
    )

    let connections = snapshot.connections
        .map { key, entry in
            (
                name: entry.owner.name,
                pid: entry.owner.pid,
                proto: key.isTCP ? "TCP" : "UDP",
                state: entry.tcpState.map(String.init(describing:)) ?? "-",
                local: "\(key.local):\(key.localPort)",
                remote: "\(key.remote):\(key.remotePort)"
            )
        }
        .sorted { ($0.name.lowercased(), $0.local) < ($1.name.lowercased(), $1.local) }

    for row in connections {
        print(
            Column.left(row.name, 24) + Column.right(row.pid, 7) + "  "
                + Column.left(row.proto, 6) + Column.left(row.state, 12)
                + Column.left(row.local, 44) + row.remote
        )
    }

    let unconnected = snapshot.localPorts
        .map { key, entry in
            (name: entry.owner.name, pid: entry.owner.pid,
             proto: key.isTCP ? "TCP" : "UDP", port: key.port)
        }
        .sorted { ($0.port, $0.name) < ($1.port, $1.name) }

    if !unconnected.isEmpty {
        print("")
        print("Unconnected / listening sockets, matched by local port only:")
        for row in unconnected {
            print(
                Column.left(row.name, 24) + Column.right(row.pid, 7) + "  "
                    + Column.left(row.proto, 6) + "*:\(row.port)"
            )
        }
    }

    exit(0)
}

// MARK: - Interface selection

var interfaces = options.interfaces

if interfaces.isEmpty {
    guard let route = RouteLookup.defaultRoute() else {
        FileHandle.standardError.write(
            Data("beholderd: could not determine the default route.\n".utf8)
        )
        exit(1)
    }
    interfaces = [route.interfaceName]
    print("Default route leaves via \(route)")
}

if options.includeLoopback, !interfaces.contains("lo0") {
    interfaces.append("lo0")
}

// MARK: - Capture

// Phase 0 only counts; the parsed packets are discarded until the flow table lands.
let engine = CaptureEngine { _, _ in }

for interface in interfaces {
    do {
        try engine.start(interface: interface)
    } catch let error as CaptureError {
        FileHandle.standardError.write(Data("beholderd: \(error.description)\n".utf8))
        exit(1)
    } catch {
        FileHandle.standardError.write(Data("beholderd: \(error)\n".utf8))
        exit(1)
    }
}

for statistics in engine.statistics() {
    print("Capturing \(statistics.interfaceName) — link type \(statistics.linkLayer.name)")
}
print("")
print(
    Column.left("INTERFACE", 12) + Column.right("PKTS/S", 10)
        + Column.right("BYTES/S", 14) + Column.right("TOTAL", 14)
        + Column.right("PARSED", 12) + Column.right("NON-IP", 10)
        + Column.right("DROPPED", 10)
)

// MARK: - Reporting loop

let reportQueue = DispatchQueue(label: "com.beholder.report")
var previousCounters: [String: CaptureCounters] = [:]
var previousTimestamp = Date()

let timer = DispatchSource.makeTimerSource(queue: reportQueue)
timer.schedule(deadline: .now() + 1, repeating: 1.0)
timer.setEventHandler {
    let now = Date()
    let elapsed = now.timeIntervalSince(previousTimestamp)
    previousTimestamp = now
    guard elapsed > 0 else { return }

    for statistics in engine.statistics() {
        let current = statistics.counters
        let previous = previousCounters[statistics.interfaceName] ?? CaptureCounters()
        previousCounters[statistics.interfaceName] = current

        let packetRate = Double(current.packets - previous.packets) / elapsed
        let byteRate = Double(current.wireBytes - previous.wireBytes) / elapsed

        print(
            Column.left(statistics.interfaceName, 12)
                + Column.right(String(format: "%.0f", packetRate), 10)
                + Column.right(formatBytes(byteRate) + "/s", 14)
                + Column.right(formatBytes(Double(current.wireBytes)), 14)
                + Column.right(current.parsed, 12)
                + Column.right(current.nonIP, 10)
                + Column.right(statistics.kernelDropped, 10)
        )
    }
}
timer.resume()

// MARK: - Shutdown

func installSignalHandler(_ signalNumber: Int32) -> DispatchSourceSignal {
    signal(signalNumber, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: reportQueue)
    source.setEventHandler {
        print("\nStopping.")
        for statistics in engine.statistics() {
            let counters = statistics.counters
            print(
                """
                \(statistics.interfaceName): \(counters.packets) packets, \
                \(formatBytes(Double(counters.wireBytes))), \
                \(counters.parsed) parsed, \(counters.nonIP) non-IP, \
                \(counters.truncatedHeaders) truncated, \
                \(counters.otherFailures) other failures, \
                \(statistics.kernelDropped) dropped by kernel
                """
            )
        }
        engine.stopAll()
        exit(0)
    }
    source.resume()
    return source
}

let interruptSource = installSignalHandler(SIGINT)
let terminateSource = installSignalHandler(SIGTERM)

dispatchMain()
