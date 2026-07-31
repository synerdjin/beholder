import Foundation

struct Options {
    var interfaces: [String] = []
    var includeLoopback = false
    var dumpSockets = false
    var selfTest = false

    static let usage = """
        usage: beholderd [--loopback] [--sockets] [--self-test] [interface ...]

          interface     Interface(s) to capture. Defaults to the interface carrying the
                        default route, which with a VPN active is the tunnel, not en0.
          --loopback    Additionally capture lo0.
          --sockets     Dump the socket-to-process table and exit, instead of capturing.
                        Needs no root, but only reveals your own processes unless run as
                        root. Compare against: lsof -nP -i TCP
          --self-test   Run the reporting loop with no interfaces for a few seconds and
                        exit. Needs no root; exercises the timer and signal handling.
          --help        Show this message.

        Capture requires root: it reads /dev/bpf*, which is mode 0600 root:wheel.
        """

    static func parse(_ arguments: [String]) -> Options? {
        var options = Options()
        for argument in arguments {
            switch argument {
            case "--loopback", "-l":
                options.includeLoopback = true
            case "--sockets", "-s":
                options.dumpSockets = true
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
        return options
    }
}
