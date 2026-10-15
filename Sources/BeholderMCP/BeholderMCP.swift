import BeholderCore
import Darwin
import Foundation

/// Answers questions about captured traffic over MCP, so an assistant can be asked
/// "what did this laptop talk to overnight" rather than a person reading rows.
///
/// Unprivileged and read-only by construction: the history database is opened
/// `SQLITE_OPEN_READONLY`, no tool takes a path or a SQL string, and not one byte is written
/// to the daemon's socket.
///
/// One subprocess is spawned, and only by `beholder_doctor`: `/bin/launchctl print
/// system/com.beholder.daemon`, by absolute path, with a fixed argument vector, no shell, a
/// two-second limit, its output only parsed. It is the one way to tell a crash-looping
/// daemon from one macOS is holding back, and nothing a caller says reaches it.
///
/// `@main` on a type rather than top-level code, for the reason `Beholderd.swift` already
/// records: top-level code in Swift 6 is `@MainActor`-isolated, which makes any callback
/// touching top-level state trap at runtime. A stdio server is almost entirely callbacks.
@main
enum BeholderMCP {

    static func main() {
        var historyPath = FlowStore.defaultPath()
        var socketPath = WireProtocol.defaultSocketPath
        var allowPayload = false
        // From the environment rather than a flag a tool call could influence: it is set
        // where the server is registered, once, by the person who knows where the checkout is.
        var sourceDirectory = ProcessInfo.processInfo.environment["BEHOLDER_SOURCE_DIR"]
        if sourceDirectory?.isEmpty == true { sourceDirectory = nil }

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
            case "--allow-payload":
                allowPayload = true
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

        if allowPayload {
            // Said on every start, in the one place the client logs. This flag is the
            // difference between a server that cannot return the contents of traffic and
            // one that can, and it should never be a thing nobody remembers turning on.
            note(
                """
                beholder-mcp: --allow-payload is ON. The cleartext_excerpts tool can return \
                the opening bytes of unencrypted connections, when the daemon runs with \
                --read-cleartext. That can include credentials and personal messages, and \
                it is sent to the assistant that calls it.
                """
            )
        }

        let toolbox = MCPToolbox(
            historyPath: historyPath, socketPath: socketPath, allowPayload: allowPayload,
            sourceDirectory: sourceDirectory)
        StdioTransport(handler: toolbox.handler).run()
        exit(0)
    }

    static let usage = """
        usage: beholder-mcp [--history-db PATH] [--socket PATH] [--allow-payload]

        Serves Beholder's history database and live snapshot to an MCP client over stdio,
        so an assistant can answer questions about what this Mac has been talking to.

          --history-db PATH  Read a database other than the default
                             (\(FlowStore.defaultPath())).
          --socket PATH      Read live snapshots from somewhere other than
                             \(WireProtocol.defaultSocketPath).
          --allow-payload    Also offer the cleartext_excerpts tool, which can return the
                             opening bytes of unencrypted connections. Off by default, and
                             then the tool does not exist rather than refusing. Needs the
                             daemon to be running with --read-cleartext.
          --help             Show this message.

        Environment:
          BEHOLDER_SOURCE_DIR  A checkout of Beholder. With it, beholder_doctor can say
                               whether the installed binaries are older than the source.

        Register it with an assistant, which is what turns it on:

          claude mcp add beholder -- /usr/local/libexec/beholder-mcp

        It is read-only: the database is opened read-only, no tool accepts a path or a SQL
        string, and nothing is written to the capture daemon. The one subprocess is
        `launchctl print` for beholder_doctor, by absolute path with a fixed argument list.

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
