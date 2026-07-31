import BeholderCore
import Darwin
import Foundation

/// Prints the socket-to-process table, for validating attribution against `lsof`.
///
/// Runs without root, though libproc only reveals other users' processes to root, so an
/// unprivileged run sees a fraction of the machine.
enum SocketDump {
    static func run() {
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
                (
                    name: entry.owner.name, pid: entry.owner.pid,
                    proto: key.isTCP ? "TCP" : "UDP", port: key.port
                )
            }
            .sorted { ($0.port, $0.name) < ($1.port, $1.name) }

        guard !unconnected.isEmpty else { return }
        print("")
        print("Unconnected / listening sockets, matched by local port only:")
        for row in unconnected {
            print(
                Column.left(row.name, 24) + Column.right(row.pid, 7) + "  "
                    + Column.left(row.proto, 6) + "*:\(row.port)"
            )
        }
    }
}
