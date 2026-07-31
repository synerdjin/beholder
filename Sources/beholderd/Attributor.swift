import BeholderCore
import CBeholderShim
import Darwin
import Foundation

// MARK: - Identity types

struct ProcessOwner: Sendable, Hashable {
    let pid: pid_t
    let path: String

    var name: String {
        guard let last = path.split(separator: "/").last, !last.isEmpty else {
            return "pid \(pid)"
        }
        return String(last)
    }
}

/// A fully-connected socket: both ends known.
struct ConnectionKey: Hashable, Sendable {
    let isTCP: Bool
    let local: IPAddress
    let localPort: UInt16
    let remote: IPAddress
    let remotePort: UInt16
}

/// A socket identified by its local port alone. This is the fallback for unconnected UDP
/// sockets and wildcard binds, where the kernel reports no peer — common for DNS clients
/// and anything using `sendto`.
struct LocalPortKey: Hashable, Sendable {
    let isTCP: Bool
    let port: UInt16
}

// MARK: - Snapshot

/// One socket in the table: who owns it, and (for TCP) what state it is in.
struct SocketEntry: Sendable {
    let owner: ProcessOwner
    let tcpState: TCPState?

    /// Whether this socket can still be carrying the packets we are capturing.
    ///
    /// Dead sockets are kept in the snapshot so that `--sockets` can show them, but they
    /// are never used to attribute a packet: a CLOSED or TIME_WAIT socket's 5-tuple can
    /// be reused by a different process, and matching against it would confidently name
    /// the wrong program. UDP has no state, so it is always eligible.
    var carriesTraffic: Bool {
        tcpState?.canCarryTraffic ?? true
    }
}

struct SocketSnapshot: Sendable {
    fileprivate(set) var connections: [ConnectionKey: SocketEntry] = [:]
    fileprivate(set) var localPorts: [LocalPortKey: SocketEntry] = [:]

    /// Processes examined, and how many refused inspection. A large
    /// `inaccessibleProcesses` count when running as a normal user is expected: libproc
    /// only reveals other users' processes to root. If it is large while running as root,
    /// something is wrong.
    fileprivate(set) var processesExamined = 0
    fileprivate(set) var inaccessibleProcesses = 0
    fileprivate(set) var socketsFound = 0
    fileprivate(set) var capturedAt = Date()

    /// Resolves the process behind a captured packet.
    ///
    /// Tries the exact connection first, in both orientations — a captured packet may be
    /// inbound or outbound and the socket table always stores it local-end-first. Falls
    /// back to matching the local port alone, which is all that is available for
    /// unconnected UDP.
    func owner(for packet: ParsedPacket, localAddresses: Set<IPAddress>) -> ProcessOwner? {
        guard packet.transport.hasPorts else { return nil }
        let isTCP = packet.transport == .tcp

        // Work out which end is ours. If both or neither look local (loopback traffic,
        // or an interface address we have not refreshed yet), try both orientations.
        let sourceIsLocal = localAddresses.contains(packet.source)
        let destinationIsLocal = localAddresses.contains(packet.destination)

        var orientations: [(local: IPAddress, localPort: UInt16, remote: IPAddress, remotePort: UInt16)] = []
        if sourceIsLocal || !destinationIsLocal {
            orientations.append(
                (packet.source, packet.sourcePort, packet.destination, packet.destinationPort)
            )
        }
        if destinationIsLocal || !sourceIsLocal {
            orientations.append(
                (packet.destination, packet.destinationPort, packet.source, packet.sourcePort)
            )
        }

        for orientation in orientations {
            let key = ConnectionKey(
                isTCP: isTCP,
                local: orientation.local,
                localPort: orientation.localPort,
                remote: orientation.remote,
                remotePort: orientation.remotePort
            )
            if let entry = connections[key], entry.carriesTraffic { return entry.owner }
        }

        for orientation in orientations {
            let key = LocalPortKey(isTCP: isTCP, port: orientation.localPort)
            if let entry = localPorts[key], entry.carriesTraffic { return entry.owner }
        }

        return nil
    }
}

// MARK: - Attributor

/// Builds a map from socket endpoints to the processes that own them, by walking every
/// process's file descriptors via libproc.
///
/// This is a *poll*, and that is the fundamental limitation of the non-entitled approach:
/// a connection that opens and closes between two polls is never seen here. Beholder
/// mitigates this by polling faster while unattributed flows exist and by retaining
/// recently-departed sockets, but cannot eliminate it. Flows that stay unattributed are
/// reported as unknown rather than dropped.
///
/// Verified against `lsof -nP -i TCP` on a machine with ~1000 processes and ~160 TCP
/// connections: zero false positives, and every ESTABLISHED and CLOSE_WAIT connection
/// matched. The connections not reported were all ones `lsof` showed as CLOSED — though
/// not every CLOSED socket is omitted, so this is the kernel's behaviour rather than a
/// guarantee. Attribution therefore filters dead states explicitly in `owner(for:)`
/// rather than relying on them being absent.
enum Attributor {

    static func snapshot() -> SocketSnapshot {
        var snapshot = SocketSnapshot()

        guard let pids = listProcessIDs() else { return snapshot }
        snapshot.processesExamined = pids.count

        // Endpoints are collected first and paths resolved afterwards, so that
        // proc_pidpath is called once per process that actually holds a network socket
        // rather than once per process on the machine.
        var pendingConnections: [(key: ConnectionKey, pid: pid_t, state: TCPState?)] = []
        var pendingLocalPorts: [(key: LocalPortKey, pid: pid_t, state: TCPState?)] = []
        var pidsWithSockets = Set<pid_t>()

        for pid in pids where pid > 0 {
            guard let descriptors = listSocketDescriptors(of: pid) else {
                snapshot.inaccessibleProcesses += 1
                continue
            }

            for descriptor in descriptors {
                var endpoint = beholder_socket_endpoint()
                guard beholder_socket_endpoint_for_fd(pid, descriptor, &endpoint),
                    endpoint.valid
                else { continue }

                let family: IPAddress.Family = endpoint.is_ipv6 ? .v6 : .v4
                guard
                    let local = address(from: endpoint.local_addr, family: family),
                    let remote = address(from: endpoint.remote_addr, family: family)
                else { continue }

                snapshot.socketsFound += 1
                pidsWithSockets.insert(pid)

                let state = endpoint.is_tcp ? TCPState(rawValue: endpoint.tcp_state) : nil

                if endpoint.remote_port != 0 {
                    pendingConnections.append(
                        (
                            ConnectionKey(
                                isTCP: endpoint.is_tcp,
                                local: local,
                                localPort: endpoint.local_port,
                                remote: remote,
                                remotePort: endpoint.remote_port
                            ),
                            pid,
                            state
                        )
                    )
                } else if endpoint.local_port != 0 {
                    pendingLocalPorts.append(
                        (
                            LocalPortKey(isTCP: endpoint.is_tcp, port: endpoint.local_port),
                            pid,
                            state
                        )
                    )
                }
            }
        }

        var owners: [pid_t: ProcessOwner] = [:]
        owners.reserveCapacity(pidsWithSockets.count)
        for pid in pidsWithSockets {
            owners[pid] = ProcessOwner(pid: pid, path: executablePath(of: pid))
        }

        for pending in pendingConnections {
            guard let owner = owners[pending.pid] else { continue }
            snapshot.connections[pending.key] = SocketEntry(
                owner: owner, tcpState: pending.state
            )
        }
        // A connected socket is a better answer than a port-only match, so the port index
        // never overwrites an existing connection entry.
        for pending in pendingLocalPorts where snapshot.localPorts[pending.key] == nil {
            guard let owner = owners[pending.pid] else { continue }
            snapshot.localPorts[pending.key] = SocketEntry(
                owner: owner, tcpState: pending.state
            )
        }

        snapshot.capturedAt = Date()
        return snapshot
    }

    // MARK: libproc plumbing

    private static func listProcessIDs() -> [pid_t]? {
        let sizeNeeded = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard sizeNeeded > 0 else { return nil }

        // Headroom, because processes can be created between sizing and reading.
        let capacity = Int(sizeNeeded) / MemoryLayout<pid_t>.stride + 64
        var pids = [pid_t](repeating: 0, count: capacity)
        let written = proc_listpids(
            UInt32(PROC_ALL_PIDS), 0, &pids,
            Int32(capacity * MemoryLayout<pid_t>.stride)
        )
        guard written > 0 else { return nil }

        return Array(pids.prefix(Int(written) / MemoryLayout<pid_t>.stride))
    }

    /// Returns the socket file descriptors of a process, or nil if it cannot be inspected
    /// (it exited, or we lack the privilege to look).
    private static func listSocketDescriptors(of pid: pid_t) -> [Int32]? {
        let sizeNeeded = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard sizeNeeded > 0 else { return nil }

        let capacity = Int(sizeNeeded) / MemoryLayout<proc_fdinfo>.stride + 32
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
        let written = proc_pidinfo(
            pid, PROC_PIDLISTFDS, 0, &descriptors,
            Int32(capacity * MemoryLayout<proc_fdinfo>.stride)
        )
        guard written > 0 else { return nil }

        let count = Int(written) / MemoryLayout<proc_fdinfo>.stride
        return descriptors.prefix(count)
            .filter { $0.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) }
            .map(\.proc_fd)
    }

    private static func executablePath(of pid: pid_t) -> String {
        var buffer = [CChar](repeating: 0, count: Int(beholder_proc_pidpath_max_size))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return "" }
        return String(nullTerminated: buffer)
    }

    /// Converts the shim's fixed 16-byte address field, which Swift imports as a tuple.
    private static func address(
        from raw: (
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
        ),
        family: IPAddress.Family
    ) -> IPAddress? {
        withUnsafeBytes(of: raw) { bytes in
            guard let base = bytes.baseAddress else { return nil }
            switch family {
            case .v4:
                return IPAddress(v4NetworkOrder: base.loadUnaligned(as: UInt32.self))
            case .v6:
                return IPAddress(v6NetworkOrderBytes: base)
            }
        }
    }
}
