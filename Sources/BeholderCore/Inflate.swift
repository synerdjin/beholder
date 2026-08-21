import CBeholderShim
import Foundation

/// zlib, wrapped for one job: reading the front of a compressed stream that was cut short.
///
/// The general-purpose decompression APIs all want a whole stream and report a truncated
/// one as corrupt. An excerpt is a 4 KB prefix of a body that is usually much larger, so
/// truncation is not the exceptional case here — it is the normal one, and the only useful
/// answer is "here is how far it got". `inflate` is used directly for that reason: it
/// decompresses incrementally and says whether the stream ended or merely ran out.
public enum Inflate {

    public struct Result: Sendable, Equatable {
        public let bytes: [UInt8]
        /// True when the input ended before the compressed stream did — the ordinary case
        /// for an excerpt, and the caveat that has to reach the screen.
        public let isPartial: Bool
        /// True when decompression stopped at the output ceiling rather than at the end of
        /// the data. Compression ratios run to a thousand to one, so a 4 KB excerpt can
        /// describe megabytes; the ceiling is what keeps a hostile or merely enthusiastic
        /// body from being expanded in full on the main thread.
        public let hitLimit: Bool
    }

    /// What wraps the deflate stream.
    ///
    /// `zlib` and `gzip` are one case because the two differ only in their header and zlib
    /// can detect which is present. They are still named separately at the call site,
    /// because what an HTTP header claimed is worth keeping distinct from what was found.
    public enum Format: Sendable, Equatable {
        case gzipOrZlib
        /// No header at all. HTTP's `deflate` is specified as zlib-wrapped, but enough
        /// servers send it bare that a reader which only accepts the specified form fails
        /// on real traffic.
        case raw
    }

    public static let defaultLimit = 64 * 1024

    public static func decompress(
        _ input: [UInt8],
        format: Format,
        limit: Int = defaultLimit
    ) -> Result? {
        guard !input.isEmpty, limit > 0 else { return nil }

        var stream = z_stream()
        // 15 is the largest window; +32 asks zlib to read either header, and negative
        // means there is no header to read.
        let windowBits: Int32 = format == .raw ? -15 : 15 + 32
        guard
            inflateInit2_(
                &stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)
            ) == Z_OK
        else { return nil }
        defer { inflateEnd(&stream) }

        var output = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        var status = Z_OK
        var hitLimit = false

        var source = input
        source.withUnsafeMutableBufferPointer { buffer in
            stream.next_in = buffer.baseAddress
            stream.avail_in = uInt(buffer.count)

            while status == Z_OK {
                let produced = chunk.withUnsafeMutableBufferPointer { out -> Int in
                    stream.next_out = out.baseAddress
                    stream.avail_out = uInt(out.count)
                    status = inflate(&stream, Z_NO_FLUSH)
                    return out.count - Int(stream.avail_out)
                }

                guard produced > 0 else { break }
                let room = limit - output.count
                if produced >= room {
                    output.append(contentsOf: chunk[0..<room])
                    hitLimit = true
                    break
                }
                output.append(contentsOf: chunk[0..<produced])
            }
        }

        // Nothing came out and the data was rejected: this is not the format claimed, and
        // saying so lets the caller try the other one rather than showing an empty body.
        if output.isEmpty && status != Z_STREAM_END { return nil }

        return Result(
            bytes: output,
            isPartial: !hitLimit && status != Z_STREAM_END,
            hitLimit: hitLimit
        )
    }
}
