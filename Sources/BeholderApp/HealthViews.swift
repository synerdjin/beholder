import AppKit
import BeholderCore
import SwiftUI

/// The key the "Show technical details" setting is stored under. Off by default: the
/// numbers are for whoever goes looking, and the words are for everyone.
let showTechnicalDetailKey = "showTechnicalDetail"

extension HealthRating {
    /// Colour is never the only signal — each rating has its own symbol shape too, so the
    /// scale reads the same to someone who cannot tell green from orange.
    var color: Color {
        switch self {
        case .unmeasured: return .secondary
        case .good: return .green
        case .fair: return .yellow
        case .poor: return .red
        }
    }

    var symbol: String {
        switch self {
        case .unmeasured: return "questionmark.circle.fill"
        case .good: return "checkmark.circle.fill"
        case .fair: return "exclamationmark.circle.fill"
        case .poor: return "xmark.octagon.fill"
        }
    }
}

/// A rating as a small capsule: symbol, word, colour.
struct RatingBadge: View {
    let rating: HealthRating

    var body: some View {
        Badge(
            text: rating.label,
            symbol: rating.symbol,
            tint: rating == .unmeasured ? .secondary : rating.color,
            help: rating == .unmeasured
                ? "Not enough has been measured to say. Not the same as good."
                : "Rated against Beholder's fixed scale; see the README, \"Reading the Overview\"."
        )
    }
}

/// Three coloured bands with a marker at the measured value.
///
/// Shows *where* a figure sits, not only which band it fell in, so "just over the line"
/// and "far past it" look different. With no value the bands are drawn grey and carry no
/// marker: an empty scale, not a green one.
struct ScaleBar: View {
    let value: Double?
    let bands: HealthScale.Bands

    var body: some View {
        GeometryReader { geometry in
            let width = geometry.size.width
            let maximum = bands.displayMaximum
            let goodEnd = width * bands.good / maximum
            let fairEnd = width * bands.fair / maximum
            let measured = value != nil

            ZStack(alignment: .leading) {
                HStack(spacing: 2) {
                    band(.good, measured).frame(width: max(goodEnd - 1, 0))
                    band(.fair, measured).frame(width: max(fairEnd - goodEnd - 2, 0))
                    band(.poor, measured)
                }
                if let value {
                    let position = min(max(value / maximum, 0), 1) * width
                    Capsule()
                        .fill(Color.primary)
                        .frame(width: 3, height: 14)
                        .offset(x: min(max(position - 1.5, 0), width - 3))
                }
            }
            .frame(height: 14)
        }
        .frame(height: 14)
        .accessibilityElement()
        .accessibilityLabel(value.map { _ in bands.rate(value).label } ?? "Not measured")
    }

    private func band(_ rating: HealthRating, _ measured: Bool) -> some View {
        RoundedRectangle(cornerRadius: 3)
            .fill((measured ? rating.color : Color.secondary).opacity(measured ? 0.35 : 0.15))
            .frame(height: 8)
    }
}

/// A command to run in a terminal, with a copy button.
///
/// Shared by every screen that has to hand the user something needing root. The app cannot
/// run it — it holds no privilege, by design — so the next best thing is a command that can
/// be pasted as it stands.
struct CommandBox: View {
    let command: String

    var body: some View {
        HStack(spacing: 8) {
            Text(command)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy the command")
        }
        .padding(10)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }
}

enum ProjectCommand {
    /// The app bundle lives at `<project>/.build/Beholder.app`, so the project root is
    /// two levels up. Showing the real path means the command can be pasted as-is
    /// instead of being adjusted for wherever the user happens to be.
    static var projectRoot: String? {
        let root = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let makefile = root.appendingPathComponent("Makefile")
        return FileManager.default.fileExists(atPath: makefile.path) ? root.path : nil
    }

    /// `make <target>`, prefixed with a `cd` into the project when it can be found.
    static func make(_ target: String) -> String {
        guard let projectRoot else { return "make \(target)" }
        return "cd \(projectRoot) && make \(target)"
    }
}
