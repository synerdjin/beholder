import BeholderCore
import Foundation

/// Reads the history database back out.
///
/// A separate read-only path rather than a mode of the running daemon: history is worth
/// querying precisely when capture is *not* running, and SQLite's WAL mode means a reader
/// never blocks the writer if it is.
enum HistoryCommands {

    static func run(_ options: Options) -> Never {
        let path = options.historyPath ?? FlowStore.defaultPath()

        guard FileManager.default.fileExists(atPath: path) else {
            print("No history database at \(path).")
            print("Run a capture first — history is written as connections finish.")
            exit(1)
        }

        let store: FlowStore
        do {
            store = try FlowStore(path: path)
        } catch {
            FileHandle.standardError.write(Data("beholderd: \(error)\n".utf8))
            exit(1)
        }
        defer { store.close() }

        let since = Date().addingTimeInterval(-Double(options.historyHours) * 3600)

        do {
            // State the window that was actually recorded. Without it an empty result is
            // ambiguous between "nothing happened" and "nothing was watching".
            if let coverage = try store.coverage() {
                print(
                    "History covers \(formatTimestamp(coverage.earliest)) "
                        + "to \(formatTimestamp(coverage.latest))."
                )
            } else {
                print("History is empty.")
                exit(0)
            }
            print(
                "Showing the last \(pluralised(options.historyHours, "hour"))"
                    + (options.historyMatch.map { ", matching \"\($0)\"" } ?? "") + "."
            )
            print("")

            if options.historyCSV {
                try printCSV(store: store, since: since, match: options.historyMatch)
            } else {
                try printSummary(store: store, since: since, match: options.historyMatch)
            }
        } catch {
            FileHandle.standardError.write(Data("beholderd: \(error)\n".utf8))
            exit(1)
        }
        exit(0)
    }

    private static func printSummary(store: FlowStore, since: Date, match: String?) throws {
        let totals = try store.processTotals(since: since)
        if !totals.isEmpty && match == nil {
            print("BY APPLICATION")
            print(
                Column.left("PROCESS", 30) + Column.right("CONNECTIONS", 13)
                    + Column.right("UP", 12) + Column.right("DOWN", 12)
            )
            for total in totals.prefix(25) {
                print(
                    Column.left(total.processName, 30)
                        + Column.right(total.flowCount, 13)
                        + Column.right(formatBytes(Double(total.bytesOut)), 12)
                        + Column.right(formatBytes(Double(total.bytesIn)), 12)
                )
            }
            print("")
        }

        let flows = try store.flows(since: since, matching: match, limit: 40)
        guard !flows.isEmpty else {
            print("No connections recorded in that window.")
            return
        }

        print("HEAVIEST CONNECTIONS")
        print(
            Column.left("WHEN", 21) + Column.left("PROCESS", 22)
                + Column.left("REMOTE", 42) + Column.right("UP", 11)
                + Column.right("DOWN", 11)
        )
        for flow in flows {
            print(
                Column.left(shortTimestamp(flow.lastSeen), 21)
                    + Column.left(flow.processName ?? "(unattributed)", 22)
                    + Column.left(flow.remoteDescription, 42)
                    + Column.right(formatBytes(Double(flow.bytesOut)), 11)
                    + Column.right(formatBytes(Double(flow.bytesIn)), 11)
            )
        }
    }

    /// CSV for taking the data elsewhere. Quoted and escaped properly, because hostnames
    /// and process names can contain commas and quotes.
    private static func printCSV(store: FlowStore, since: Date, match: String?) throws {
        let flows = try store.flows(since: since, matching: match, limit: 100_000)
        print(
            "first_seen,last_seen,process,transport,remote,port,host,country,"
                + "network,company,bytes_out,bytes_in"
        )
        let formatter = ISO8601DateFormatter()
        for flow in flows {
            let fields = [
                formatter.string(from: flow.firstSeen),
                formatter.string(from: flow.lastSeen),
                flow.processName ?? "",
                flow.transport,
                flow.remoteAddress,
                String(flow.remotePort),
                flow.hostName ?? "",
                flow.country ?? "",
                flow.networkOperator ?? "",
                flow.ownerCompany ?? "",
                String(flow.bytesOut),
                String(flow.bytesIn),
            ]
            print(fields.map(escapeCSV).joined(separator: ","))
        }
    }

    private static func escapeCSV(_ value: String) -> String {
        guard value.contains(",") || value.contains("\"") || value.contains("\n") else {
            return value
        }
        return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    private static func shortTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }
}
