import Foundation

struct Options {
    var interfaces: [String] = []
    var includeLoopback = false
    var dumpSockets = false
    var selfTest = false
    var top = false
    var logDirectory: String?
    var logging = true

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
          --help        Show this message.

        Capture requires root: it reads /dev/bpf*, which is mode 0600 root:wheel.
        """

    static func parse(_ arguments: [String]) -> Options? {
        var options = Options()
        var expectingLogDirectory = false

        for argument in arguments {
            if expectingLogDirectory {
                options.logDirectory = argument
                expectingLogDirectory = false
                continue
            }
            switch argument {
            case "--log":
                expectingLogDirectory = true
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
        return options
    }
}
