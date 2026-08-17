import BeholderCore
import CBeholderShim
import Darwin
import Dispatch

// MARK: - Errors

enum CaptureError: Error, CustomStringConvertible {
    case createFailed(interface: String, message: String)
    case permissionDenied(interface: String)
    case activateFailed(interface: String, status: Int32, message: String)
    case unsupportedLinkLayer(interface: String, datalink: Int32)
    case filterFailed(interface: String, message: String)
    case noSelectableDescriptor(interface: String)

    var description: String {
        switch self {
        case .createFailed(let interface, let message):
            return "cannot open \(interface): \(message)"
        case .permissionDenied(let interface):
            return """
                permission denied opening \(interface). \
                Packet capture reads /dev/bpf*, which is root-only — run beholderd under sudo.
                """
        case .activateFailed(let interface, let status, let message):
            return "cannot activate capture on \(interface) (status \(status)): \(message)"
        case .unsupportedLinkLayer(let interface, let datalink):
            return """
                \(interface) uses unsupported link type \(datalink). Refusing to guess: \
                parsing with the wrong link type yields plausible but wrong output.
                """
        case .filterFailed(let interface, let message):
            return "cannot install BPF filter on \(interface): \(message)"
        case .noSelectableDescriptor(let interface):
            return "\(interface) provides no selectable file descriptor"
        }
    }
}

// MARK: - Counters

struct CaptureCounters: Sendable, Equatable {
    var packets: UInt64 = 0
    /// Accumulated from `pcap_pkthdr.len` — true wire size, never the truncated caplen.
    var wireBytes: UInt64 = 0
    var parsed: UInt64 = 0
    var nonIP: UInt64 = 0
    var truncatedHeaders: UInt64 = 0
    var otherFailures: UInt64 = 0

    /// Which wakeup actually delivered packets. Kept because the read source and the
    /// safety timer are redundant by design, and knowing which one does the work is the
    /// difference between "capture is healthy" and "capture only works by accident".
    var deliveringSourceWakeups: UInt64 = 0
    var deliveringTimerWakeups: UInt64 = 0
}

struct InterfaceStatistics: Sendable {
    let interfaceName: String
    let linkLayer: LinkLayer
    var counters: CaptureCounters

    /// Packets BPF has accepted for this handle, read or not. If this climbs while
    /// `counters.packets` stays at zero, packets are arriving but nothing is draining
    /// them — which is precisely what happens when immediate mode is off.
    var bpfReceived: UInt32
    /// Packets the kernel dropped because the buffer filled. Sustained non-zero values
    /// mean the reported numbers are an undercount.
    var kernelDropped: UInt32
    var interfaceDropped: UInt32
}

/// Which wakeup caused a drain, so we can tell the two mechanisms apart.
private enum DrainTrigger {
    case readSource
    case safetyTimer
}

/// Receives every parsed packet along with its transport payload.
///
/// **The payload buffer is only valid for the duration of the call.** It points into
/// libpcap's receive buffer, which is reused for the next packet the moment this returns.
/// Anything a handler needs from the payload — a hostname, a DNS answer — must be
/// extracted synchronously and copied; handing the buffer to another queue reads freed
/// memory. The `ParsedPacket` itself is a value and may be passed on freely.
typealias PacketSink = @Sendable (ParsedPacket, UnsafeRawBufferPointer, String) -> Void

// MARK: - Per-interface capture

/// Owns one `pcap_t` and the dispatch sources draining it.
///
/// All mutable state is confined to the engine's serial queue; `@unchecked Sendable` is
/// the honest annotation here, since the invariant is queue confinement rather than
/// immutability.
final class InterfaceCapture: @unchecked Sendable {
    let interfaceName: String
    let linkLayer: LinkLayer

    private let handle: OpaquePointer
    private let queue: DispatchQueue
    private let onPacket: PacketSink
    private var source: DispatchSourceRead?
    private var safetyTimer: DispatchSourceTimer?
    private var stopped = false

    fileprivate var counters = CaptureCounters()

    /// How many packets to pull per wakeup. Bounded so one busy interface cannot starve
    /// the others sharing the capture queue; the read source re-fires if more remain.
    private static let batchLimit: Int32 = 256

    private init(
        interfaceName: String,
        linkLayer: LinkLayer,
        handle: OpaquePointer,
        queue: DispatchQueue,
        onPacket: @escaping PacketSink
    ) {
        self.interfaceName = interfaceName
        self.linkLayer = linkLayer
        self.handle = handle
        self.queue = queue
        self.onPacket = onPacket
    }

    static func open(
        interfaceName: String,
        snapshotLength: Int32,
        bufferSize: Int32,
        filter: String,
        queue: DispatchQueue,
        onPacket: @escaping PacketSink
    ) throws -> InterfaceCapture {
        var errorBuffer = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        guard let handle = pcap_create(interfaceName, &errorBuffer) else {
            throw CaptureError.createFailed(
                interface: interfaceName, message: String(nullTerminated: errorBuffer)
            )
        }

        pcap_set_snaplen(handle, snapshotLength)
        // Promiscuous mode would capture other hosts' traffic on the LAN. Beholder is
        // about *this* machine, and sniffing the neighbours is both useless here and
        // a needless privacy overreach.
        pcap_set_promisc(handle, 0)
        pcap_set_timeout(handle, 100)
        pcap_set_buffer_size(handle, bufferSize)

        // Immediate mode is mandatory here, not an optimisation.
        //
        // A BPF descriptor's read timeout only applies to *blocking* reads. When the
        // descriptor is polled through kqueue — which is what a DispatchSource does — it
        // does not become readable until the store buffer fills. With a multi-megabyte
        // buffer and ordinary traffic that can take hours, so capture silently reports
        // zero packets forever while BPF quietly accumulates them. BIOCIMMEDIATE, which
        // this sets, makes each batch readable as soon as it arrives.
        pcap_set_immediate_mode(handle, 1)

        let status = pcap_activate(handle)
        if status < 0 {
            let message = String(cString: pcap_statustostr(status))
            pcap_close(handle)
            if status == PCAP_ERROR_PERM_DENIED {
                throw CaptureError.permissionDenied(interface: interfaceName)
            }
            throw CaptureError.activateFailed(
                interface: interfaceName, status: status, message: message
            )
        }

        let datalink = pcap_datalink(handle)
        guard let linkLayer = LinkLayer(datalink: datalink) else {
            pcap_close(handle)
            throw CaptureError.unsupportedLinkLayer(
                interface: interfaceName, datalink: datalink
            )
        }

        // Non-blocking, because the dispatch sources decide when we read.
        if pcap_setnonblock(handle, 1, &errorBuffer) < 0 {
            let message = String(nullTerminated: errorBuffer)
            pcap_close(handle)
            throw CaptureError.createFailed(interface: interfaceName, message: message)
        }

        // Drop non-IP frames in the kernel rather than waking userspace for ARP.
        var program = bpf_program()
        guard pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) == 0 else {
            let message = String(cString: pcap_geterr(handle))
            pcap_close(handle)
            throw CaptureError.filterFailed(interface: interfaceName, message: message)
        }
        let filterStatus = pcap_setfilter(handle, &program)
        pcap_freecode(&program)
        guard filterStatus == 0 else {
            let message = String(cString: pcap_geterr(handle))
            pcap_close(handle)
            throw CaptureError.filterFailed(interface: interfaceName, message: message)
        }

        let descriptor = pcap_get_selectable_fd(handle)
        guard descriptor >= 0 else {
            pcap_close(handle)
            throw CaptureError.noSelectableDescriptor(interface: interfaceName)
        }

        let capture = InterfaceCapture(
            interfaceName: interfaceName,
            linkLayer: linkLayer,
            handle: handle,
            queue: queue,
            onPacket: onPacket
        )

        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler { [weak capture] in capture?.drain(trigger: .readSource) }
        // Closing the pcap handle from the cancel handler guarantees it outlives any
        // in-flight event handler — closing it eagerly from stop() would race.
        source.setCancelHandler { pcap_close(handle) }
        capture.source = source
        source.resume()

        // Belt and braces. Readability notification on BPF descriptors has enough
        // platform-specific quirks that a monitoring tool should not depend on it alone;
        // a periodic drain bounds worst-case latency to half a second no matter what.
        // The counters record which mechanism actually delivers, so this cannot quietly
        // paper over a broken read source.
        let safetyTimer = DispatchSource.makeTimerSource(queue: queue)
        safetyTimer.schedule(deadline: .now() + 0.5, repeating: 0.5, leeway: .milliseconds(100))
        safetyTimer.setEventHandler { [weak capture] in capture?.drain(trigger: .safetyTimer) }
        capture.safetyTimer = safetyTimer
        safetyTimer.resume()

        return capture
    }

    /// Must run on the capture queue.
    private func drain(trigger: DrainTrigger) {
        guard !stopped else { return }
        let context = Unmanaged.passUnretained(self).toOpaque()
        let result = pcap_dispatch(
            handle,
            Self.batchLimit,
            packetCallback,
            context.assumingMemoryBound(to: UInt8.self)
        )

        if result > 0 {
            switch trigger {
            case .readSource: counters.deliveringSourceWakeups += 1
            case .safetyTimer: counters.deliveringTimerWakeups += 1
            }
        }
        // -1 is an error; -2 means pcap_breakloop() was called. Neither is recoverable
        // by retrying in place, so stop this interface and let the engine report it.
        if result < 0 {
            stopped = true
        }
    }

    fileprivate func consume(header: pcap_pkthdr, bytes: UnsafePointer<UInt8>) {
        counters.packets += 1
        counters.wireBytes += UInt64(header.len)

        let buffer = UnsafeRawBufferPointer(start: bytes, count: Int(header.caplen))
        switch PacketParser.parse(buffer, linkLayer: linkLayer, wireBytes: header.len) {
        case .success(let packet):
            counters.parsed += 1
            // The payload slice is handed straight through and is valid only until this
            // returns — see PacketSink. Clamped defensively even though the parser
            // already bounds the offset.
            let payloadStart = min(packet.payloadOffset, buffer.count)
            let payload = UnsafeRawBufferPointer(
                rebasing: buffer[payloadStart..<buffer.count]
            )
            onPacket(packet, payload, interfaceName)
        case .failure(let reason):
            switch reason {
            case .notIP:
                counters.nonIP += 1
            case .truncatedLinkLayer, .truncatedNetworkHeader, .truncatedTransportHeader:
                counters.truncatedHeaders += 1
            default:
                counters.otherFailures += 1
            }
        }
    }

    /// Must run on the capture queue.
    fileprivate func statistics() -> InterfaceStatistics {
        var stats = pcap_stat()
        var received: UInt32 = 0
        var kernelDropped: UInt32 = 0
        var interfaceDropped: UInt32 = 0
        if !stopped, pcap_stats(handle, &stats) == 0 {
            received = stats.ps_recv
            kernelDropped = stats.ps_drop
            interfaceDropped = stats.ps_ifdrop
        }
        return InterfaceStatistics(
            interfaceName: interfaceName,
            linkLayer: linkLayer,
            counters: counters,
            bpfReceived: received,
            kernelDropped: kernelDropped,
            interfaceDropped: interfaceDropped
        )
    }

    /// Must run on the capture queue.
    fileprivate func stop() {
        guard !stopped else { return }
        stopped = true
        safetyTimer?.cancel()
        safetyTimer = nil
        source?.cancel()
        source = nil
    }
}

/// pcap invokes a bare C function pointer, which cannot capture context, so the capture
/// object travels through the `user` argument.
private let packetCallback: pcap_handler = { user, header, bytes in
    guard let user, let header, let bytes else { return }
    let capture = Unmanaged<InterfaceCapture>
        .fromOpaque(UnsafeRawPointer(user))
        .takeUnretainedValue()
    capture.consume(header: header.pointee, bytes: bytes)
}

// MARK: - Engine

final class CaptureEngine: @unchecked Sendable {
    /// Enough to hold IP and TCP headers, a complete DNS answer, and a full TLS
    /// ClientHello, while leaving bulk payload in the kernel where it belongs.
    ///
    /// 512 was the earlier value and truncated some ClientHellos before their SNI
    /// extension, silently costing hostnames. The extra copy is a few hundred KB per
    /// second even on a busy link, and none of it is retained.
    static let defaultSnapshotLength: Int32 = 1024

    /// Used only under `--read-cleartext`, where the point is no longer to read a header
    /// but to read the message. 1024 leaves a full-MTU HTTP request truncated mid-headers,
    /// which is precisely the part worth seeing.
    ///
    /// This is the one setting that meaningfully raises what capture copies out of the
    /// kernel, which is why it is opt-in rather than simply raised for everyone.
    static let cleartextSnapshotLength: Int32 = 16384

    static let defaultBufferSize: Int32 = 4 * 1024 * 1024
    static let defaultFilter = "ip or ip6"

    private let queue = DispatchQueue(label: "com.beholder.capture", qos: .utility)
    private var captures: [String: InterfaceCapture] = [:]
    private let onPacket: PacketSink

    /// How much of each packet to copy out of the kernel. Fixed for the process lifetime,
    /// since `InterfaceSupervisor` re-opens capture whenever the route moves and every
    /// re-open must use the same value the run started with.
    private let snapshotLength: Int32

    init(snapshotLength: Int32 = CaptureEngine.defaultSnapshotLength, onPacket: @escaping PacketSink) {
        self.snapshotLength = snapshotLength
        self.onPacket = onPacket
    }

    /// Begins capturing on an interface. Returns silently if already capturing it.
    func start(interface: String) throws {
        try queue.sync {
            guard captures[interface] == nil else { return }
            captures[interface] = try InterfaceCapture.open(
                interfaceName: interface,
                snapshotLength: snapshotLength,
                bufferSize: Self.defaultBufferSize,
                filter: Self.defaultFilter,
                queue: queue,
                onPacket: onPacket
            )
        }
    }

    func stop(interface: String) {
        queue.sync {
            captures.removeValue(forKey: interface)?.stop()
        }
    }

    func stopAll() {
        queue.sync {
            for capture in captures.values { capture.stop() }
            captures.removeAll()
        }
    }

    var activeInterfaces: [String] {
        queue.sync { captures.keys.sorted() }
    }

    func statistics() -> [InterfaceStatistics] {
        queue.sync {
            captures.values
                .map { $0.statistics() }
                .sorted { $0.interfaceName < $1.interfaceName }
        }
    }
}
