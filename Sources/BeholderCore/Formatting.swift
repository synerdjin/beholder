import Foundation

/// Counts with a correctly pluralised noun.
///
/// "1 connections" is the kind of small wrongness that makes a tool feel unfinished, and
/// it appears wherever a normally-large count happens to be one. Generic over integer
/// width because these counts arrive as both `Int` and `UInt64`.
///
/// In Core because it had reached four copies — the app, the daemon, the DNS preview, and
/// a fourth spelled out by hand five times inside `ReliabilityReport`'s prose. Every copy
/// that lacked the `plural:` parameter grew a hand-written clause beside it for the first
/// irregular noun it met, which is how "1 authority" and "2 authoritys" both become
/// possible in the same program.
public func pluralised(
    _ count: some BinaryInteger, _ singular: String, plural: String? = nil
) -> String {
    let noun = count == 1 ? singular : (plural ?? singular + "s")
    return "\(count) \(noun)"
}

/// The same, when the noun is already written and only the verb has to agree.
public func agreeing(_ count: some BinaryInteger, _ singular: String, _ plural: String) -> String {
    count == 1 ? singular : plural
}
