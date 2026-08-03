import Foundation

/// Column formatting for the terminal output.
///
/// Swift's `String(format:)` does not reliably honour width specifiers on `%@`
/// conversions, which silently produces ragged columns, so padding is done directly.
enum Column {
    static func left(_ text: String, _ width: Int) -> String {
        text.count >= width
            ? String(text.prefix(width))
            : text + String(repeating: " ", count: width - text.count)
    }

    static func right(_ text: String, _ width: Int) -> String {
        text.count >= width
            ? String(text.prefix(width))
            : String(repeating: " ", count: width - text.count) + text
    }

    static func right(_ value: some BinaryInteger, _ width: Int) -> String {
        right(String(value), width)
    }
}

/// Counts with a correctly pluralised noun. "1 connections" is the kind of small
/// wrongness that makes a tool feel unfinished, and it shows up wherever a count that is
/// usually large happens to be one.
func pluralised(_ count: some BinaryInteger, _ singular: String, plural: String? = nil) -> String {
    let noun = count == 1 ? singular : (plural ?? singular + "s")
    return "\(count) \(noun)"
}

/// Full local date, time and zone.
///
/// Reports get copied out of a terminal and read days later, often alongside a commit
/// log. A bare time-of-day makes two runs indistinguishable, so every report stamps the
/// date too.
func formatTimestamp(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss zzz"
    return formatter.string(from: date)
}

func formatDuration(_ seconds: TimeInterval) -> String {
    let total = Int(seconds.rounded())
    let hours = total / 3600
    let minutes = (total % 3600) / 60
    let secs = total % 60
    if hours > 0 { return String(format: "%dh %02dm %02ds", hours, minutes, secs) }
    if minutes > 0 { return String(format: "%dm %02ds", minutes, secs) }
    return String(format: "%ds", secs)
}

func formatBytes(_ bytes: Double) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var value = bytes
    var unitIndex = 0
    while value >= 1024, unitIndex < units.count - 1 {
        value /= 1024
        unitIndex += 1
    }
    return unitIndex == 0
        ? String(format: "%.0f %@", value, units[unitIndex])
        : String(format: "%.1f %@", value, units[unitIndex])
}
