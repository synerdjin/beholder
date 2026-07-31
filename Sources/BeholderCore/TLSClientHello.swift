import Foundation

/// Extracts the requested hostname from a TLS ClientHello's SNI extension.
///
/// This is the more dependable of the two hostname sources, because it names the host
/// for *this specific connection* rather than inferring it from a shared address. It has
/// two blind spots, both unavoidable:
///
/// - **Encrypted Client Hello** encrypts the SNI outright. That is the entire point of
///   the feature, and no host-side observer can undo it.
/// - **QUIC** (HTTP/3, which shows up as UDP port 443) carries its ClientHello inside
///   encrypted CRYPTO frames, so this parser does not apply. DNS covers that traffic
///   instead, provided DNS itself is in the clear.
public enum TLSClientHello {

    private static let handshakeRecord: UInt8 = 0x16
    private static let clientHelloType: UInt8 = 0x01
    private static let serverNameExtension: UInt16 = 0x0000
    private static let hostNameType: UInt8 = 0x00

    /// Returns the SNI hostname, or nil if this is not a ClientHello, carries no SNI, or
    /// was truncated by the capture snaplen before the extension could be read.
    public static func serverName(in buffer: UnsafeRawBufferPointer) -> String? {
        // TLS record header: type, version (2), length (2).
        guard buffer.count >= 5, buffer[0] == handshakeRecord else { return nil }

        var position = 5
        guard position < buffer.count, buffer[position] == clientHelloType else { return nil }

        position += 4  // handshake type (1) and length (3)
        position += 2  // client version
        position += 32  // random

        guard position < buffer.count else { return nil }
        let sessionIDLength = Int(buffer[position])
        position += 1 + sessionIDLength

        guard let cipherSuitesLength = uint16(buffer, position) else { return nil }
        position += 2 + Int(cipherSuitesLength)

        guard position < buffer.count else { return nil }
        let compressionMethodsLength = Int(buffer[position])
        position += 1 + compressionMethodsLength

        guard let extensionsLength = uint16(buffer, position) else { return nil }
        position += 2
        let extensionsEnd = min(position + Int(extensionsLength), buffer.count)

        while position + 4 <= extensionsEnd {
            guard
                let type = uint16(buffer, position),
                let length = uint16(buffer, position + 2)
            else { return nil }
            position += 4

            guard type == serverNameExtension else {
                position += Int(length)
                continue
            }

            // ServerNameList: list length (2), then entries of type (1), length (2), name.
            // Only host_name is defined, and only the first entry is ever used.
            guard position + 5 <= buffer.count, buffer[position + 2] == hostNameType else {
                return nil
            }
            guard let nameLength = uint16(buffer, position + 3) else { return nil }
            let nameStart = position + 5
            guard nameLength > 0, nameStart + Int(nameLength) <= buffer.count else {
                return nil
            }

            var bytes = [UInt8]()
            bytes.reserveCapacity(Int(nameLength))
            for offset in 0..<Int(nameLength) {
                bytes.append(buffer[nameStart + offset])
            }
            let name = String(decoding: bytes, as: UTF8.self)
            // A hostname of control characters means we mis-parsed, not that the server
            // is unusual. Refuse it rather than displaying garbage.
            return name.allSatisfy { !$0.isNewline && !$0.isWhitespace } ? name : nil
        }

        return nil
    }

    @inline(__always)
    private static func uint16(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= buffer.count else { return nil }
        return UInt16(bigEndian: buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
    }
}
