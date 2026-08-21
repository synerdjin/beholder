import Foundation
import Testing

@testable import BeholderCore

/// Real gzip, produced by a different implementation than the one reading it.
private let gzipped: [UInt8] = [
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xed, 0x8e,
        0xc1, 0x0d, 0xc2, 0x40, 0x0c, 0x04, 0x5b, 0xd9, 0x02, 0x10, 0x05, 0x50,
        0x41, 0x9e, 0x3c, 0xd2, 0x80, 0x49, 0xcc, 0x9d, 0x85, 0xb1, 0x4f, 0x67,
        0x07, 0x04, 0xd5, 0x73, 0xaf, 0xd4, 0xc0, 0x23, 0xdf, 0x59, 0xad, 0x66,
        0xa6, 0x79, 0xbe, 0xe2, 0xe6, 0xab, 0x70, 0x80, 0x3a, 0x23, 0x2b, 0x43,
        0x2c, 0xb9, 0x73, 0xa4, 0x58, 0x41, 0x25, 0xbd, 0x5f, 0x06, 0x95, 0x80,
        0xdb, 0x98, 0x02, 0xea, 0x03, 0xb3, 0xf9, 0x56, 0xea, 0xe0, 0x94, 0x28,
        0x5f, 0x69, 0xa0, 0x25, 0x37, 0x52, 0xfd, 0x20, 0x6a, 0x17, 0x7b, 0x04,
        0x24, 0x4f, 0x20, 0x5b, 0xd1, 0xb9, 0x71, 0x4a, 0xca, 0x8b, 0xf7, 0x93,
        0x63, 0xf1, 0x67, 0x1b, 0x86, 0xc0, 0x9b, 0x55, 0xcf, 0x98, 0x8e, 0x88,
        0x23, 0xe2, 0x1f, 0x23, 0x7e, 0x38, 0x1b, 0x45, 0xe6, 0x1e, 0x03, 0x00,
        0x00,
]

/// The same stream cut where an excerpt would cut it: mid-deflate, no end marker.
private let gzippedPrefix = Array(gzipped[0..<88])

/// The same data as bare deflate, with no zlib header — what a number of servers send
/// when they say `Content-Encoding: deflate`.
private let rawDeflate: [UInt8] = [
        0xed, 0x8e, 0xc1, 0x0d, 0xc2, 0x40, 0x0c, 0x04, 0x5b, 0xd9, 0x02, 0x10,
        0x05, 0x50, 0x41, 0x9e, 0x3c, 0xd2, 0x80, 0x49, 0xcc, 0x9d, 0x85, 0xb1,
        0x4f, 0x67, 0x07, 0x04, 0xd5, 0x73, 0xaf, 0xd4, 0xc0, 0x23, 0xdf, 0x59,
        0xad, 0x66, 0xa6, 0x79, 0xbe, 0xe2, 0xe6, 0xab, 0x70, 0x80, 0x3a, 0x23,
        0x2b, 0x43, 0x2c, 0xb9, 0x73, 0xa4, 0x58, 0x41, 0x25, 0xbd, 0x5f, 0x06,
        0x95, 0x80, 0xdb, 0x98, 0x02, 0xea, 0x03, 0xb3, 0xf9, 0x56, 0xea, 0xe0,
        0x94, 0x28, 0x5f, 0x69, 0xa0, 0x25, 0x37, 0x52, 0xfd, 0x20, 0x6a, 0x17,
        0x7b, 0x04, 0x24, 0x4f, 0x20, 0x5b, 0xd1, 0xb9, 0x71, 0x4a, 0xca, 0x8b,
        0xf7, 0x93, 0x63, 0xf1, 0x67, 0x1b, 0x86, 0xc0, 0x9b, 0x55, 0xcf, 0x98,
        0x8e, 0x88, 0x23, 0xe2, 0x1f, 0x23, 0x7e,
]

private let expected = "HTTP bodies are the interesting half: this one is long enough that gzip actually shrinks it, and repetitive enough to compress well. HTTP bodies are the interesting half: this one is long enough that gzip actually shrinks it, and repetitive enough to compress well. HTTP bodies are the interesting half: this one is long enough that gzip actually shrinks it, and repetitive enough to compress well. HTTP bodies are the interesting half: this one is long enough that gzip actually shrinks it, and repetitive enough to compress well. HTTP bodies are the interesting half: this one is long enough that gzip actually shrinks it, and repetitive enough to compress well. HTTP bodies are the interesting half: this one is long enough that gzip actually shrinks it, and repetitive enough to compress well. "

@Suite("Undoing a content encoding")
struct InflateTests {

    @Test("A whole gzip stream decompresses and is reported as whole")
    func wholeStream() throws {
        let result = try #require(Inflate.decompress(gzipped, format: .gzipOrZlib))
        #expect(String(decoding: result.bytes, as: UTF8.self) == expected)
        #expect(!result.isPartial)
        #expect(!result.hitLimit)
    }

    /// The case the wrapper exists for. A 4 KB excerpt of a larger body is a truncated
    /// stream, and the general-purpose APIs report that as corrupt rather than returning
    /// the prefix — which would leave the reader showing nothing for every body worth
    /// looking at.
    @Test("A stream cut short yields what it got, and says it was cut short")
    func truncatedStream() throws {
        let result = try #require(Inflate.decompress(gzippedPrefix, format: .gzipOrZlib))
        #expect(result.isPartial, "no end marker was reached")
        #expect(!result.bytes.isEmpty, "the prefix is the readable part")
        #expect(expected.hasPrefix(String(decoding: result.bytes, as: UTF8.self)))
    }

    @Test("Bare deflate is read when the zlib wrapper is absent")
    func rawStream() throws {
        #expect(Inflate.decompress(rawDeflate, format: .gzipOrZlib) == nil, "no header to find")
        let result = try #require(Inflate.decompress(rawDeflate, format: .raw))
        #expect(String(decoding: result.bytes, as: UTF8.self) == expected)
    }

    /// Compression ratios run to a thousand to one, so an excerpt can describe far more
    /// than it holds. The ceiling is what keeps that off the main thread.
    @Test("Decompression stops at the ceiling and says so")
    func ceiling() throws {
        let result = try #require(Inflate.decompress(gzipped, format: .gzipOrZlib, limit: 64))
        #expect(result.hitLimit)
        #expect(result.bytes.count == 64)
    }

    @Test("Data that is not compressed at all is declined")
    func notCompressed() {
        #expect(Inflate.decompress(Array("plain text, no stream here".utf8), format: .gzipOrZlib) == nil)
        #expect(Inflate.decompress([], format: .gzipOrZlib) == nil)
    }
}
