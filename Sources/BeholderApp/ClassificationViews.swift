import BeholderCore
import SwiftUI

/// Grouping choice and the filter for connections nothing could identify.
struct GroupingBar: View {
    @Binding var grouping: Grouping
    @Binding var unidentifiedOnly: Bool
    let snapshot: FlowSnapshot

    private var unidentifiedCount: Int {
        snapshot.flows.filter { !$0.isIdentified }.count
    }

    var body: some View {
        HStack(spacing: 12) {
            Picker("Group", selection: $grouping) {
                ForEach(Grouping.allCases) { option in
                    Text(option.rawValue).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()

            Toggle(isOn: $unidentifiedOnly) {
                // The count travels with the control. Without it a filter that removes
                // nothing is indistinguishable from a filter that does not work — which
                // is exactly how the previous one read.
                Text("Only unidentified (\(unidentifiedCount))")
                    .foregroundStyle(unidentifiedCount == 0 ? .secondary : .primary)
            }
            .toggleStyle(.checkbox)
            .disabled(unidentifiedCount == 0 && !unidentifiedOnly)
            .help(
                "Connections with no hostname, no known company and no known network — "
                    + "an address and a port and nothing else. Usually local or "
                    + "carrier-internal addresses that no database can describe. Narrowing "
                    + "to these is not a claim that any of them is suspicious."
            )

            Spacer()

            Text("\(snapshot.flows.count - unidentifiedCount) of \(pluralised(snapshot.flows.count, "connection")) identified")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}

/// What is known about a host, shown beside it.
///
/// Two independent facts, never merged. The operator comes from a tracker database and is
/// evidence about *who*; the naming signal comes from the hostname itself and is evidence
/// about what the operator *called it*. Neither is a verdict — `api.anthropic.com` and
/// `browser-intake-us5-datadoghq.com` are both an app talking to its vendor over TLS, and
/// only the person using the machine can say which they mind.
struct ClassificationBadges: View {
    let classification: HostClassification?

    var body: some View {
        if let classification, !classification.isEmpty {
            HStack(spacing: 4) {
                if let owner = classification.owner {
                    Badge(
                        text: owner,
                        symbol: "building.2",
                        tint: .secondary,
                        help: helpForOwner(classification)
                    )
                }
                // Only the first category: a host can carry five, and a row of five
                // badges is noise rather than information.
                if let category = classification.categories.first {
                    Badge(
                        text: category,
                        symbol: nil,
                        tint: .secondary,
                        help: classification.categories.count > 1
                            ? "Categories: " + classification.categories.joined(separator: ", ")
                            : "Category: \(category)"
                    )
                }
                if let signal = classification.namingSignal {
                    Badge(
                        text: signal,
                        symbol: "text.magnifyingglass",
                        tint: .orange,
                        help:
                            "The hostname contains \"\(signal)\", which operators "
                            + "conventionally use for data collection. This describes the "
                            + "name only — it is not a claim about what the connection does."
                    )
                }
            }
        }
    }

    private func helpForOwner(_ classification: HostClassification) -> String {
        var text = "Operated by \(classification.owner ?? "an unknown company")"
        if let matched = classification.matchedDomain {
            text += ", matched on \(matched)"
        }
        return text + ". Source: DuckDuckGo Tracker Radar."
    }
}

private struct Badge: View {
    let text: String
    let symbol: String?
    let tint: Color
    let help: String

    var body: some View {
        HStack(spacing: 2) {
            if let symbol {
                Image(systemName: symbol).font(.system(size: 8))
            }
            Text(text)
        }
        .font(.caption2)
        .foregroundStyle(tint)
        .padding(.horizontal, 5)
        .padding(.vertical, 1)
        .background(tint.opacity(0.12), in: Capsule())
        .help(help)
    }
}
