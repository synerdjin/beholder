import BeholderCore
import SwiftUI

/// The blocking screen.
///
/// It has more explanation on it than any other view here, and that is deliberate rather
/// than apologetic. Every other tab reports what happened; this one changes what the machine
/// can reach, and the two things most likely to surprise someone — that a block applies to
/// every program, and that one address often serves many names — are invisible in a list of
/// addresses. Somewhere to read them is cheaper than finding out.
struct BlockingView: View {
    @Bindable var model: BlockingModel

    @State private var destination = ""
    @State private var note = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            switch model.state {
            case .unknown:
                waiting("Asking the daemon what it is blocking…")

            case .unreachable(let reason):
                notice(
                    title: "Cannot reach the daemon's control socket",
                    detail: reason,
                    remedy: """
                        The control socket only opens when the daemon runs with --block (or \
                        --control), and only when a peer identity has been pinned:

                            sudo ./Scripts/install-pf-anchor.sh
                            sudo ./Scripts/install-control-pin.sh
                            make block
                        """)

            case .notEnforcing(let reason):
                // Not the same as an empty list, and it gets its own screen for that reason:
                // "nothing is blocked" would be a lie about a daemon that is not checking.
                notice(
                    title: "Nothing is being enforced",
                    detail: reason,
                    remedy: """
                        Blocking is off unless the daemon was started with --block. Anything \
                        listed below is what *would* be blocked, not what is.

                            make block
                        """)

            case .enforcing:
                list
            }

            Spacer(minLength: 0)
            if case .enforcing = model.state { composer }
        }
        .task {
            await model.refresh()
        }
    }

    // MARK: - Pieces

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Label("Blocking", systemImage: "hand.raised")
                    .font(.headline)
                Spacer()
                if model.isBusy { ProgressView().controlSize(.small) }
                Button {
                    Task { await model.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .help("Ask the daemon what it is blocking now")
            }

            Text(
                "Blocking applies to every program on this machine — pf matches addresses, "
                    + "not processes. One address often serves many names, so blocking a "
                    + "shared address takes everything behind it with it."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
    }

    private var list: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let error = model.actionError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if model.entries.isEmpty {
                // Enforcing and empty. A real state, and a different one from not enforcing.
                VStack(alignment: .leading, spacing: 6) {
                    Text("Blocking is running, and nothing is blocked.")
                        .font(.callout)
                    Text("Add a destination below, or from any connection's context menu.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12)
            } else {
                List {
                    ForEach(model.entries) { entry in
                        row(entry)
                    }
                }
                .listStyle(.inset)
            }
        }
    }

    private func row(_ entry: ControlEntry) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.destination)
                    .font(.system(.body, design: .monospaced))
                if let note = entry.note {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()

            if entry.isRemovable {
                Button("Unblock") {
                    Task { await model.unblock(entry.destination) }
                }
                .buttonStyle(.borderless)
                .disabled(model.isBusy)
            } else {
                // Shown, and not offered as a button that would fail. Root wrote it into the
                // block list; root takes it back.
                Text("from the block list")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help(
                        "This came from the root-owned block list, which Beholder never "
                            + "rewrites. Edit that file and reload the daemon to remove it.")
            }
        }
        .padding(.vertical, 2)
    }

    private var composer: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            HStack(spacing: 8) {
                TextField("Address or network, e.g. 93.184.216.34 or 10.0.0.0/8", text: $destination)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                TextField("Why (optional)", text: $note)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 200)
                Button("Block") {
                    let target = destination.trimmingCharacters(in: .whitespaces)
                    let reason = note.trimmingCharacters(in: .whitespaces)
                    Task {
                        await model.block(target, note: reason.isEmpty ? nil : reason)
                        if model.actionError == nil {
                            destination = ""
                            note = ""
                        }
                    }
                }
                .disabled(model.isBusy || destination.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            Text(
                "Host names are not accepted: pf matches addresses, and a name would fix one "
                    + "answer for a record that rotates."
            )
            .font(.caption2)
            .foregroundStyle(.secondary)
        }
        .padding(12)
    }

    private func waiting(_ message: String) -> some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(message).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
    }

    private func notice(title: String, detail: String, remedy: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: "info.circle")
                .font(.callout.weight(.medium))
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(remedy)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
        }
        .padding(.horizontal, 12)
    }
}
