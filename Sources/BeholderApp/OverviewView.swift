import BeholderCore
import SwiftUI

/// The first screen: is the network all right, and if not, where is the trouble?
///
/// Written for someone who does not know what a round trip is. Every judgement it shows
/// comes from `HealthAssessment` in Core, where the thresholds are fixed and tested; this
/// view only lays it out. The measurements behind each sentence are one click away, and
/// fully visible with "Show technical details" on.
struct OverviewView: View {
    let snapshot: FlowSnapshot
    let health: HealthModel
    let openQuality: () -> Void
    let openConnections: () -> Void

    @AppStorage(showTechnicalDetailKey) private var showTechnicalDetail = false

    private var assessment: HealthAssessment {
        HealthAssessment.make(statistics: snapshot.statistics, probes: health.probes)
    }

    var body: some View {
        let assessment = self.assessment
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                StatusCard(assessment: assessment, startedAt: snapshot.startedAt)

                if !assessment.hasProbes {
                    ProbeOffer()
                }

                ForEach(assessment.findings) { finding in
                    FindingRow(
                        finding: finding,
                        showTechnicalDetail: showTechnicalDetail,
                        window: finding.area == .localNetwork || finding.area == .internet
                            ? "Last 15 minutes of probes."
                            : "Since capture started."
                    )
                }

                HStack {
                    Toggle("Show technical details", isOn: $showTechnicalDetail)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                    Spacer()
                    Button("Connection quality in detail", action: openQuality)
                    Button("Which apps are talking", action: openConnections)
                }
                .font(.caption)
            }
            .padding(16)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }
}

/// The verdict, as large as the screen allows, with the caveats that qualify it directly
/// beneath — never on another screen, because a rating read without its coverage is a
/// rating misread.
private struct StatusCard: View {
    let assessment: HealthAssessment
    let startedAt: Date

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: assessment.overall.symbol)
                .font(.system(size: 40))
                .foregroundStyle(assessment.overall.color)
            VStack(alignment: .leading, spacing: 6) {
                Text(assessment.headline)
                    .font(.title2.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(
                    "Watching since \(startedAt.formatted(date: .omitted, time: .shortened)) "
                        + "(\(startedAt.formatted(.relative(presentation: .named))))."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                if let note = assessment.coverageNote {
                    Label(note, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .background(assessment.overall.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

private struct FindingRow: View {
    let finding: HealthFinding
    let showTechnicalDetail: Bool
    let window: String

    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(finding.area.title).font(.headline)
                Spacer()
                RatingBadge(rating: finding.rating)
            }
            if let bands = finding.bands {
                ScaleBar(value: finding.value, bands: bands)
            }
            Text(finding.sentence)
                .fixedSize(horizontal: false, vertical: true)
            if let aside = finding.aside {
                Label(aside, systemImage: "info.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if showTechnicalDetail {
                technical
            }

            DisclosureGroup("What does this mean?", isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(finding.area.explanation)
                    if !showTechnicalDetail { technical }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 4)
            }
            .font(.caption)
        }
        .padding(12)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    private var technical: some View {
        Text("\(finding.detail) \(window)")
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Offers `--probe` without starting it.
///
/// Probing is the one part of Beholder that sends traffic, so it stays opt-in and is
/// started by a person in a terminal, not by a button in an unprivileged app. What the card
/// can do is say plainly what it would answer, which no passive measurement can.
private struct ProbeOffer: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Find out whether a problem is your Wi-Fi or your internet provider",
                systemImage: "scope")
                .font(.headline)
            Text(
                "Beholder can ping your router and a few public servers (1.1.1.1, 8.8.8.8, "
                    + "9.9.9.9) every 30 seconds. Comparing the two shows where trouble starts. "
                    + "This is off by default because it is the only part of Beholder that "
                    + "sends anything. To turn it on, stop Beholder and start it with:"
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            CommandBox(command: ProjectCommand.make("probe"))
        }
        .padding(12)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}
