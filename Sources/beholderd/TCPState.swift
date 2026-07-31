import CBeholderShim

/// TCP connection state as reported by libproc (`tcpsi_state`, the `TSI_S_*` values).
enum TCPState: Int32, Sendable, CustomStringConvertible {
    case closed = 0
    case listen = 1
    case synSent = 2
    case synReceived = 3
    case established = 4
    case closeWait = 5
    case finWait1 = 6
    case closing = 7
    case lastAck = 8
    case finWait2 = 9
    case timeWait = 10
    case reserved = 11

    var description: String {
        switch self {
        case .closed: return "CLOSED"
        case .listen: return "LISTEN"
        case .synSent: return "SYN_SENT"
        case .synReceived: return "SYN_RCVD"
        case .established: return "ESTABLISHED"
        case .closeWait: return "CLOSE_WAIT"
        case .finWait1: return "FIN_WAIT_1"
        case .closing: return "CLOSING"
        case .lastAck: return "LAST_ACK"
        case .finWait2: return "FIN_WAIT_2"
        case .timeWait: return "TIME_WAIT"
        case .reserved: return "RESERVED"
        }
    }

    /// Whether packets can still flow on this connection. Sockets past this point hold a
    /// 5-tuple that no longer describes live traffic, and reusing it for attribution
    /// risks pinning a new connection on whichever process happened to own the port last.
    var canCarryTraffic: Bool {
        switch self {
        case .closed, .listen, .timeWait, .reserved:
            return false
        default:
            return true
        }
    }
}
