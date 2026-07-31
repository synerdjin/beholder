extension String {
    /// Builds a `String` from a null-terminated C character buffer.
    ///
    /// The C interfaces Beholder calls (`inet_ntop`, `if_indextoname`, pcap's error
    /// buffer) all write into fixed-size `[CChar]` arrays. `String(cString:)` is
    /// deprecated for that shape because it reads to the terminator with no bound; this
    /// truncates at the terminator explicitly and never runs past the array.
    public init(nullTerminated buffer: [CChar]) {
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        self = String(decoding: bytes, as: UTF8.self)
    }
}
