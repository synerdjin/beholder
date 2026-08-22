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
    var block = false
    var blocklistPath = BlockList.defaultPath
    var checkBlocklist = false
    var printPFAnchor = false
    var printPFConfiguration = false
    var managedBlocklistPath = ControlProtocol.managedListPath
    var control = false
    var checkControlPin = false
    var checkControlPinBundle: String?
    var controlSocketPath = ControlProtocol.defaultSocketPath
    var controlPinPath = ControlProtocol.pinPath

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

    /// Whether the control socket should be opened.
    ///
    /// `--block` implies it: blocking that cannot be adjusted from the app is a firewall you
    /// have to edit a file and send a signal to change, which is the Phase A experience and
    /// not the one worth keeping. `--control` alone is also allowed, so the app can ask about
    /// blocking and be told it is not running rather than finding a socket missing and having
    /// to guess why.
    var opensControlSocket: Bool { control || block }

    /// Blocking, unlike everything else here, does not need flows.
    ///
    /// There is deliberately no `blocks` derived property gating this on `--serve` or
    /// `--top`: pf enforces in the kernel whether or not anything is watching, and a run
    /// that only counts packets still blocks exactly what it was asked to. Pretending
    /// otherwise would mean a flag that silently does nothing in one of the modes.

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
          --block       Block the destinations listed in the block list, instead of only
                        reporting them. Off by default, and the only thing Beholder does
                        that changes what this machine can reach — everything else here
                        observes. Needs root and a one-time `sudo ./Scripts/install-pf-anchor.sh`.
                        Blocking is by *destination*, never by process: pf matches
                        addresses, so a block applies to every program on the machine, and
                        an address serving several names takes all of them with it.
                        Blocking lasts as long as the daemon does — stopping it restores
                        everything. If it is killed outright, `make unblock` clears up.
          --blocklist PATH
                        Read the block list somewhere other than
                        \(BlockList.defaultPath). It must be owned by root and writable by
                        nobody else, because it decides what a root process adds to the
                        firewall.
          --check-blocklist
                        Parse the block list, print what it would block, and exit. Needs no
                        root and changes nothing. Exits non-zero if any line cannot be used.
          --control     Open the control socket so Beholder.app can change what is blocked.
                        Implied by --block. The socket is the only channel into the daemon
                        that changes anything: the publishing socket still accepts no
                        command at all. It admits a connection only from a program whose
                        code identity matches the one pinned by install-control-pin.sh —
                        file permissions cannot tell your app from anything else running as
                        you, and for a writer that distinction is the whole point.
          --control-socket PATH
          --control-pin PATH
                        Where the control socket lives, and where the peer's expected code
                        identity is pinned. Defaults: \(ControlProtocol.defaultSocketPath),
                        \(ControlProtocol.pinPath).
          --check-control-pin [APP]
                        Report whether the pinned peer identity can be loaded, and — given an
                        app bundle — whether that bundle satisfies it. Needs no root and opens
                        nothing. Rebuilding the app changes its identity, so this is the way
                        to tell a stale pin from a working one.
          --managed-blocklist PATH
                        Where to keep what the app blocks. Never the same file as
                        --blocklist: that one is written by a person and is not rewritten.
          --print-pf-anchor
          --print-pf-conf
                        Print the pf rules Beholder blocks with, and the lines /etc/pf.conf
                        needs for them to be evaluated. install-pf-anchor.sh writes what
                        these print rather than keeping a second copy that could drift.

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
        /// The flag whose value is expected next, and where to put it.
        ///
        /// One slot rather than a boolean per flag: they all do the same thing, and the
        /// failure mode of the old shape — adding the flag and forgetting its trailing
        /// "needs a value" guard — silently swallowed the argument instead of complaining.
        ///
        /// A closure rather than a key path because three of these fields are `String?` and
        /// the rest are `String`, and one slot has to be able to hold either.
        var pending: (flag: String, assign: (inout Options, String) -> Void)?
        var expectingHours = false
        var expectingProbeTarget = false
        var expectingProbeInterval = false

        for argument in arguments {
            if let slot = pending {
                slot.assign(&options, argument)
                pending = nil
                continue
            }
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
            switch argument {
            case "--log":
                pending = ("--log", { $0.logDirectory = $1 })
            case "--socket":
                pending = ("--socket", { $0.socketPath = $1 })
            case "--hours":
                expectingHours = true
            case "--match":
                pending = ("--match", { $0.historyMatch = $1 })
            case "--history-db":
                pending = ("--history-db", { $0.historyPath = $1 })
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
            case "--block":
                options.block = true
            case "--blocklist":
                pending = ("--blocklist", { $0.blocklistPath = $1 })
            case "--managed-blocklist":
                pending = ("--managed-blocklist", { $0.managedBlocklistPath = $1 })
            case "--control":
                options.control = true
            case "--check-control-pin":
                options.checkControlPin = true
            case "--control-socket":
                pending = ("--control-socket", { $0.controlSocketPath = $1 })
            case "--control-pin":
                pending = ("--control-pin", { $0.controlPinPath = $1 })
            case "--check-blocklist":
                options.checkBlocklist = true
            case "--print-pf-anchor":
                options.printPFAnchor = true
            case "--print-pf-conf":
                options.printPFConfiguration = true
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

        guard pending == nil else {
            let message = "beholderd: \(pending!.flag) needs a value\n"
            FileHandle.standardError.write(Data(message.utf8))
            return nil
        }
        guard !expectingHours else {
            FileHandle.standardError.write(Data("beholderd: --hours needs a number\n".utf8))
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
        guard options.managedBlocklistPath != options.blocklistPath else {
            // They are merged, and one of them is rewritten by the daemon. Pointing both at
            // one file would have the daemon regenerate the hand-edited list, comments and
            // all, the first time anything was blocked from the app.
            let message =
                "beholderd: --managed-blocklist must differ from --blocklist; the managed "
                + "one is rewritten and the other is not\n"
            FileHandle.standardError.write(Data(message.utf8))
            return nil
        }
        return options
    }
}
