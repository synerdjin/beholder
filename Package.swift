// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Beholder",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "BeholderCore", targets: ["BeholderCore"]),
        .executable(name: "beholderd", targets: ["beholderd"]),
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

        .testTarget(
            name: "BeholderCoreTests",
            dependencies: ["BeholderCore"]
        ),
    ]
)
