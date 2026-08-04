import BeholderCore
import Darwin
import Foundation

/// Answers questions about captured traffic over MCP, so an assistant can be asked
/// "what did this laptop talk to overnight" rather than a person reading rows.
///
/// Unprivileged and read-only by construction: the history database is opened
/// `SQLITE_OPEN_READONLY`, no tool takes a path or a SQL string, not one byte is written to
/// the daemon's socket, and no subprocess is ever spawned.
///
/// `@main` on a type rather than top-level code, for the reason `Beholderd.swift` already
/// records: top-level code in Swift 6 is `@MainActor`-isolated, which makes any callback
/// touching top-level state trap at runtime. A stdio server is almost entirely callbacks.
@main
enum BeholderMCP {

    static func main() {
        var historyPath = FlowStore.defaultPath()
        var socketPath = WireProtocol.defaultSocketPath

        var expecting: String?
        for argument in CommandLine.arguments.dropFirst() {
            if let flag = expecting {
                switch flag {
                case "--history-db": historyPath = argument
                case "--socket": socketPath = argument
                default: break
                }
                expecting = nil
                continue
            }
            switch argument {
            case "--history-db", "--socket":
                expecting = argument
            case "--help", "-h":
                // To stdout is wrong for this binary in the general case, but --help is
                // never passed by a client — a human typed it, and there is no protocol
                // stream to corrupt.
                print(usage)
                exit(0)
            default:
                fail("unknown option '\(argument)'")
            }
        }
        if let expecting { fail("\(expecting) needs a value") }

        // SIGPIPE would otherwise kill the process outright the moment the client closes
        // its end mid-write, which looks like a crash to whoever is reading the logs. The
        // write path handles EPIPE as an ordinary end of session instead.
        signal(SIGPIPE, SIG_IGN)

        // One line, to stderr, every run. It is invisible to the model — stderr is not part
        // of the protocol stream — but it means the fact that this session can send network
        // history to an assistant is recorded in the client's MCP log rather than resting
        // on the user having read the README once.
        note(
            """
            beholder-mcp: serving read-only queries over \(historyPath). Results of tool \
            calls, including hostnames and process names, are sent to the assistant that \
            calls them.
            """
        )

        if geteuid() == 0 {
            // Not fatal — someone may have a genuine reason — but almost always a mistake
            // worth naming, because it silently reads the wrong user's data.
            note(
                """
                beholder-mcp: running as root. BeholderPaths then resolves to root's home, so \
                this will read /var/root's database rather than yours and is likely to report \
                an empty history. Run it as your own user.
                """
            )
        }

        let toolbox = MCPToolbox(historyPath: historyPath, socketPath: socketPath)
        StdioTransport(handler: toolbox.handler).run()
        exit(0)
    }

    static let usage = """
        usage: beholder-mcp [--history-db PATH] [--socket PATH]

        Serves Beholder's history database and live snapshot to an MCP client over stdio,
        so an assistant can answer questions about what this Mac has been talking to.

          --history-db PATH  Read a database other than the default
                             (\(FlowStore.defaultPath())).
          --socket PATH      Read live snapshots from somewhere other than
                             \(WireProtocol.defaultSocketPath).
          --help             Show this message.

        Register it with an assistant, which is what turns it on:

          claude mcp add beholder -- /usr/local/libexec/beholder-mcp

        It is read-only: the database is opened read-only, no tool accepts a path or a SQL
        string, nothing is written to the capture daemon, and no subprocess is spawned.

        Do not run it under sudo. It would read root's paths rather than yours, find an
        empty database, and hand an assistant's tool calls a root process for no benefit.
        """

    static func note(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }

    static func fail(_ message: String) -> Never {
        note("beholder-mcp: \(message)")
        note(usage)
        exit(1)
    }
}
