// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Beholder",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "BeholderCore", targets: ["BeholderCore"]),
        .executable(name: "beholderd", targets: ["beholderd"]),

        // Declared explicitly, unlike BeholderApp which relies on SwiftPM's implicit
        // product: an MCP client configuration names this binary by absolute path, so
        // its name is part of the interface rather than an internal detail.
        .executable(name: "BeholderMCP", targets: ["BeholderMCP"]),
    ],
    targets: [
        // Re-exports the system C headers we need (pcap, libproc, route) plus a few
        // helpers for constructs Swift imports awkwardly. Links libpcap from the SDK.
        .target(
            name: "CBeholderShim",
            linkerSettings: [.linkedLibrary("pcap"), .linkedLibrary("sqlite3")]
        ),

        // All pure, testable logic: parsers, address types, flow aggregation.
        // Deliberately free of privilege and I/O so it can be unit-tested without root.
        .target(
            name: "BeholderCore",
            dependencies: ["CBeholderShim"]
        ),

        // The privileged capture daemon.
        .executableTarget(
            name: "beholderd",
            dependencies: ["BeholderCore", "CBeholderShim"]
        ),

        // The SwiftUI viewer. Runs unprivileged; it only reads the daemon's socket.
        // Scripts/build-app.sh wraps this binary in a .app bundle, which is what
        // MenuBarExtra and the Dock need. There is no Xcode project because none is
        // required: the bundle is a directory with an Info.plist in it.
        .executableTarget(
            name: "BeholderApp",
            dependencies: ["BeholderCore"]
        ),

        // Answers questions about the history database and the live snapshot over MCP,
        // so an assistant can be asked "what did this laptop talk to overnight" instead
        // of the user reading rows. Unprivileged and read-only by construction.
        //
        // A separate binary rather than a `beholderd --mcp` mode, because MCP's stdout
        // contract is absolute — nothing but JSON-RPC lines — and beholderd's stdout is
        // chatty by design: it prints a starting note before parsing arguments, prints
        // the usage on a bad flag, and prints status from every capture path. Sharing a
        // binary would make every future print() in that path a silent protocol
        // corruption whose only symptom is a parse error on the client's side.
        .executableTarget(
            name: "BeholderMCP",
            dependencies: ["BeholderCore"]
        ),

        .testTarget(
            name: "BeholderCoreTests",
            dependencies: ["BeholderCore"]
        ),
    ]
)
