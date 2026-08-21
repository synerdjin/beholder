import BeholderCore
import Foundation

struct Options {
    var interfaces: [String] = []
    var includeLoopback = false
    var dumpSockets = false
    var selfTest = false
    var top = false
    var logDirectory: String?
    var logging = true
    var serve = false
    var socketPath = WireProtocol.defaultSocketPath
    var history = false
    var historyHours = 24
    var historyMatch: String?
    var historyCSV = false
    var historyPath: String?
    var storeHistory = true
    var readCleartext = false
    var measureQuality = true
    var probe = false
    var probeTargets: [String] = []
    var probeInterval = 30.0

    /// Whether payload reading will actually happen.
    ///
    /// `readCleartext` alone is not the answer: payload has nowhere to go unless flows are
    /// being tracked. Derived in one place so the three consumers — the monitor, the
    /// snaplen, and the banner — cannot disagree about it, which would otherwise show up
    /// as a raised snaplen on a run that keeps nothing.
    var readsCleartext: Bool { readCleartext && (top || serve) }

    /// Whether quality will actually be measured.
    ///
    /// Like `readsCleartext`, measurement needs flows to attach itself to, so a run that
    /// only counts packets does none of it whatever the flag says. Derived in one place so
    /// the monitor and the banner cannot disagree.
    var measuresQuality: Bool { measureQuality && (top || serve) }

    /// Whether probes will actually be sent.
    ///
    /// Probing writes to the history database and nowhere else, so a run that is not
    /// storing history has nowhere to put the answers. Derived here so the banner and the
    /// prober cannot disagree about whether this machine is sending.
    var probes: Bool { probe && storeHistory && (top || serve) }

    static let usage = """
        usage: beholderd [--top] [--loopback] [--log DIR | --no-log]
                         [--sockets] [--self-test] [interface ...]

          interface     Interface(s) to capture. Defaults to the interface carrying the
                        default route, which with a VPN active is the tunnel, not en0.
          --top         Show a live table of connections by process, sorted by volume.
                        Without it, beholderd prints per-interface capture statistics.
          --loopback    Additionally capture lo0.
          --sockets     Dump the socket-to-process table and exit, instead of capturing.
                        Needs no root, but only reveals your own processes unless run as
                        root. Compare against: lsof -nP -i TCP
          --self-test   Run the reporting loop with no interfaces for a few seconds and
                        exit. Needs no root; exercises the timer and signal handling.
          --log DIR     Write the run transcript to DIR (default: ./logs). The log is
                        owned by the user who ran sudo and created mode 0600, since it
                        lists every host this machine contacted. The newest run is always
                        at DIR/latest.log.
          --no-log      Do not write a transcript.
          --serve       Publish snapshots on a Unix socket for Beholder.app to read.
                        Draws nothing, so it can be left running in the background; add
                        --top to also watch it in the terminal. The socket is owned by
                        the user who ran sudo and created mode 0600.
          --socket PATH Publish somewhere other than \(WireProtocol.defaultSocketPath).
          --no-history  Do not record finished connections to the history database.
          --probe       Also *send* a small ICMP echo to the default gateway and to a few
                        fixed addresses every 30 seconds. Off by default, and the one thing
                        here that is not purely passive: everything else watches traffic
                        somebody else asked for. It exists because two questions cannot be
                        answered any other way — whether the connection was working while
                        nobody was using it, and whether a problem is your own Wi-Fi or the
                        link beyond your router. Timing the first hop separately is the only
                        way to tell those apart.
          --probe-target ADDR
                        Probe this address instead of the built-in anchors. Repeatable.
          --probe-interval SECONDS
                        How often to probe (default 30).
          --no-quality  Do not measure round-trip time, retransmissions or jitter.
                        Measurement is on by default — unlike --read-cleartext it reads
                        only header fields the kernel has already handed over, and learns
                        nothing about what any connection carries. On by default for a
                        second reason too: it has to be running when the trouble happens,
                        and a switch flipped afterwards has nothing to say about a
                        connection that has already gone bad.
          --read-cleartext
                        Also keep the opening few kilobytes of connections that are not
                        encrypted, so Beholder.app can show what is actually being sent.
                        Off by default, and a real change in what this program holds:
                        without it Beholder keeps facts about traffic, and with it it
                        keeps some of the traffic. The bytes live in memory only, bounded
                        and released when a connection ends — never written to the history
                        database or the run transcript, and never sent over MCP. Raises
                        the capture snaplen, which costs a little more copying per packet.

        Querying history (needs no root if the database is yours):

          --history         Show what was recorded. Needs no capture running.
          --hours N         How far back to look (default 24).
          --match TEXT      Only connections matching an app, host, address, company
                            or network.
          --csv             Emit CSV instead of a summary.
          --history-db PATH Read a database somewhere other than the default.

          --help        Show this message.

        Capture requires root: it reads /dev/bpf*, which is mode 0600 root:wheel.
        """

    static func parse(_ arguments: [String]) -> Options? {
        var options = Options()
        var expectingLogDirectory = false
        var expectingSocketPath = false
        var expectingHours = false
        var expectingMatch = false
        var expectingHistoryPath = false
        var expectingProbeTarget = false
        var expectingProbeInterval = false

        for argument in arguments {
            if expectingProbeTarget {
                options.probeTargets.append(argument)
                expectingProbeTarget = false
                continue
            }
            if expectingProbeInterval {
                guard let seconds = Double(argument), seconds >= 5 else {
                    FileHandle.standardError.write(
                        Data("beholderd: --probe-interval needs at least 5 seconds\n".utf8)
                    )
                    return nil
                }
                options.probeInterval = seconds
                expectingProbeInterval = false
                continue
            }
            if expectingLogDirectory {
                options.logDirectory = argument
                expectingLogDirectory = false
                continue
            }
            if expectingSocketPath {
                options.socketPath = argument
                expectingSocketPath = false
                continue
            }
            if expectingHours {
                guard let hours = Int(argument), hours > 0 else {
                    FileHandle.standardError.write(
                        Data("beholderd: --hours needs a positive number\n".utf8)
                    )
                    return nil
                }
                options.historyHours = hours
                expectingHours = false
                continue
            }
            if expectingMatch {
                options.historyMatch = argument
                expectingMatch = false
                continue
            }
            if expectingHistoryPath {
                options.historyPath = argument
                expectingHistoryPath = false
                continue
            }
            switch argument {
            case "--log":
                expectingLogDirectory = true
            case "--socket":
                expectingSocketPath = true
            case "--hours":
                expectingHours = true
            case "--match":
                expectingMatch = true
            case "--history-db":
                expectingHistoryPath = true
            case "--serve":
                options.serve = true
            case "--history":
                options.history = true
            case "--csv":
                options.historyCSV = true
            case "--no-history":
                options.storeHistory = false
            case "--read-cleartext":
                options.readCleartext = true
            case "--no-quality":
                options.measureQuality = false
            case "--probe":
                options.probe = true
            case "--probe-target":
                expectingProbeTarget = true
            case "--probe-interval":
                expectingProbeInterval = true
            case "--no-log":
                options.logging = false
            case "--loopback", "-l":
                options.includeLoopback = true
            case "--sockets", "-s":
                options.dumpSockets = true
            case "--top", "-t":
                options.top = true
            case "--self-test":
                options.selfTest = true
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

        guard !expectingLogDirectory else {
            FileHandle.standardError.write(Data("beholderd: --log needs a directory\n".utf8))
            return nil
        }
        guard !expectingSocketPath else {
            FileHandle.standardError.write(Data("beholderd: --socket needs a path\n".utf8))
            return nil
        }
        guard !expectingHours else {
            FileHandle.standardError.write(Data("beholderd: --hours needs a number\n".utf8))
            return nil
        }
        guard !expectingMatch else {
            FileHandle.standardError.write(Data("beholderd: --match needs a search term\n".utf8))
            return nil
        }
        guard !expectingHistoryPath else {
            FileHandle.standardError.write(Data("beholderd: --history-db needs a path\n".utf8))
            return nil
        }
        guard !expectingProbeTarget else {
            FileHandle.standardError.write(
                Data("beholderd: --probe-target needs an address\n".utf8)
            )
            return nil
        }
        guard !expectingProbeInterval else {
            FileHandle.standardError.write(
                Data("beholderd: --probe-interval needs a number of seconds\n".utf8)
            )
            return nil
        }
        return options
    }
}
