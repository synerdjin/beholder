import Darwin
import Foundation
import Testing

@testable import BeholderCore

/// A stand-in for the capture daemon: binds a real Unix socket, accepts one client, and
/// behaves as told. A real socket rather than a fake, because everything worth testing here
/// — the receive timeout, the framing, telling ENOENT from EACCES — is in the syscalls.
private final class FakeDaemon: @unchecked Sendable {
    enum Behaviour {
        /// Write these bytes and keep the connection open.
        case send(Data)
        /// Accept and say nothing at all. The case the deadline exists for.
        case silence
        /// Accept and immediately hang up.
        case hangUp
    }

    let path: String
    private let directory: String
    private var listener: Int32 = -1
    private var accepted: Int32 = -1
    private let lock = NSLock()

    init(behaviour: Behaviour) throws {
        directory = NSTemporaryDirectory() + "beholder-sock-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true
        )
        // Short, because sun_path is only 104 bytes on Darwin.
        path = directory + "/s"

        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, Darwin.listen(listener, 1) == 0 else {
            throw NSError(domain: "FakeDaemon", code: Int(errno))
        }

        let listenerCopy = listener
        DispatchQueue.global().async { [weak self] in
            let client = Darwin.accept(listenerCopy, nil, nil)
            guard client >= 0 else { return }
            switch behaviour {
            case .send(let payload):
                payload.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress else { return }
                    _ = Darwin.write(client, base, raw.count)
                }
                // Held open, so the reader sees a complete line rather than an EOF.
                self?.retain(client)
            case .silence:
                self?.retain(client)
            case .hangUp:
                close(client)
            }
        }
    }

    private func retain(_ descriptor: Int32) {
        lock.lock()
        accepted = descriptor
        lock.unlock()
    }

    func shutdown() {
        lock.lock()
        if accepted >= 0 { close(accepted) }
        lock.unlock()
        if listener >= 0 { close(listener) }
        try? FileManager.default.removeItem(atPath: directory)
    }
}

private func encodedSnapshot(version: Int = WireProtocol.version) throws -> Data {
    let snapshot = FlowSnapshot(
        version: version,
        generatedAt: Date(),
        startedAt: Date().addingTimeInterval(-60),
        interfaces: ["utun8"],
        flows: [],
        statistics: WireStatistics()
    )
    var data = try FlowSnapshot.encoder().encode(snapshot)
    data.append(0x0A)
    return data
}

@Suite("Snapshot client")
struct SnapshotClientTests {

    @Test("A published snapshot is read back")
    func readsASnapshot() throws {
        let daemon = try FakeDaemon(behaviour: .send(try encodedSnapshot()))
        defer { daemon.shutdown() }

        let snapshot = try SnapshotClient.readOne(from: daemon.path, deadline: 2)
        #expect(snapshot.interfaces == ["utun8"])
    }

    @Test("A silent daemon is given up on rather than waited for forever")
    func timesOutOnSilence() throws {
        // The point of the whole deadline. Without the per-read SO_RCVTIMEO this parks in
        // read() and no overall deadline can ever fire, because nothing returns to check
        // the clock — a single unanswerable tool call would hang the client's session.
        let daemon = try FakeDaemon(behaviour: .silence)
        defer { daemon.shutdown() }

        let started = Date()
        #expect(throws: SnapshotClient.Failure.self) {
            _ = try SnapshotClient.readOne(from: daemon.path, deadline: 0.8)
        }
        let elapsed = Date().timeIntervalSince(started)
        #expect(elapsed < 3, "it should give up near the deadline, not hang")
    }

    @Test("The default deadline outlasts the daemon's publishing interval")
    func defaultDeadlineIsGenerous() {
        // FlowServer publishes on a repeating one-second timer and sends nothing on accept,
        // so a freshly connected reader legitimately waits up to a second for the first
        // byte. Anything at or below that reports a healthy daemon as absent, sometimes.
        #expect(SnapshotClient.defaultDeadline > 1.0)
    }

    @Test("A socket that is not there is reported as not running")
    func absentSocketIsNotRunning() {
        // Deliberately short. A Unix socket path lives in `sun_path`, which is 104 bytes on
        // Darwin, and a full temporary-directory path plus a UUID already exceeds that —
        // the first version of this test tripped the length guard instead of the missing
        // file and asserted the wrong thing.
        let path = NSTemporaryDirectory() + "bh-\(UInt32.random(in: 0..<0xFFFF_FFFF)).sock"
        do {
            _ = try SnapshotClient.readOne(from: path, deadline: 1)
            Issue.record("connecting to a nonexistent socket should fail")
        } catch let failure as SnapshotClient.Failure {
            guard case .notRunning = failure else {
                Issue.record("expected .notRunning, got \(failure)")
                return
            }
            // The message has to be actionable: "not running" and "not yours" have
            // different fixes and used to be indistinguishable from a return code.
            #expect(failure.description.contains("not running"))
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test("A path too long for a Unix socket is refused by name")
    func overLongPathIsRefused() {
        // 104 bytes is the whole of sun_path on Darwin. Copying a longer path in would
        // truncate it and connect to some other socket entirely, so it is refused instead.
        let path = "/tmp/" + String(repeating: "x", count: 200) + ".sock"
        #expect(throws: SnapshotClient.Failure.self) {
            _ = try SnapshotClient.readOne(from: path, deadline: 1)
        }
    }

    @Test("A daemon that hangs up mid-message is a framing failure")
    func hangUpIsUnframed() throws {
        let daemon = try FakeDaemon(behaviour: .hangUp)
        defer { daemon.shutdown() }

        do {
            _ = try SnapshotClient.readOne(from: daemon.path, deadline: 1)
            Issue.record("a truncated stream should fail")
        } catch let failure as SnapshotClient.Failure {
            guard case .unframed = failure else {
                Issue.record("expected .unframed, got \(failure)")
                return
            }
        }
    }

    @Test("A daemon speaking another protocol version is refused clearly")
    func versionMismatch() throws {
        let daemon = try FakeDaemon(
            behaviour: .send(try encodedSnapshot(version: WireProtocol.version + 1))
        )
        defer { daemon.shutdown() }

        do {
            _ = try SnapshotClient.readOne(from: daemon.path, deadline: 2)
            Issue.record("a version mismatch should fail")
        } catch let failure as SnapshotClient.Failure {
            guard case .wrongVersion = failure else {
                Issue.record("expected .wrongVersion, got \(failure)")
                return
            }
            #expect(failure.description.contains("Rebuild"))
        }
    }

    @Test("Garbage on the socket is reported as undecodable, not as silence")
    func undecodable() throws {
        let daemon = try FakeDaemon(behaviour: .send(Data("{\"not\":\"a snapshot\"}\n".utf8)))
        defer { daemon.shutdown() }

        do {
            _ = try SnapshotClient.readOne(from: daemon.path, deadline: 2)
            Issue.record("undecodable input should fail")
        } catch let failure as SnapshotClient.Failure {
            guard case .undecodable = failure else {
                Issue.record("expected .undecodable, got \(failure)")
                return
            }
        }
    }
}
