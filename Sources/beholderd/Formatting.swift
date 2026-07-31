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
