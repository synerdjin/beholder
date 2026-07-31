import Foundation
import Testing

@testable import BeholderCore

private let laptop = IPAddress(networkOrderBytes: [10, 5, 0, 2], family: .v4)!

private func flow(
    remoteLastOctet: UInt8,
    port: UInt16 = 443,
    owner: ProcessOwner?,
    bytes: UInt64 = 1000,
    localPort: UInt16 = 50000
) -> Flow {
    let remote = IPAddress(networkOrderBytes: [93, 184, 216, remoteLastOctet], family: .v4)!
    var value = Flow(
        key: FlowKey(
            transport: .tcp, local: laptop, localPort: localPort,
            remote: remote, remotePort: port
        ),
        interfaceName: "utun8",
        at: Date()
    )
    value.owner = owner
    value.bytesOut = bytes
    return value
}

private let shield = ProcessOwner(
    pid: 43840,
    path: "/Library/SystemExtensions/F83E70BA/com.nordvpn.macos.Shield.systemextension"
        + "/Contents/MacOS/com.nordvpn.macos.Shield"
)
private let browser = ProcessOwner(pid: 500, path: "/Applications/Safari.app/Safari")
private let mail = ProcessOwner(pid: 600, path: "/System/Applications/Mail.app/Mail")

@Suite("Transparent proxy detection")
struct ProxyDetectionTests {

    @Test("A system extension dominating traffic to many hosts is flagged")
    func dominantSystemExtensionIsFlagged() throws {
        var flows: [Flow] = []
        for index in 0..<30 {
            flows.append(
                flow(
                    remoteLastOctet: UInt8(index), owner: shield,
                    localPort: UInt16(50000 + index)
                )
            )
        }
        for index in 0..<10 {
            flows.append(
                flow(
                    remoteLastOctet: UInt8(100 + index), owner: browser,
                    localPort: UInt16(60000 + index)
                )
            )
        }

        let findings = ProxyDetection.findLikelyProxies(in: flows)
        let shieldFinding = try #require(findings.first { $0.owner == shield })

        #expect(shieldFinding.isSystemExtension)
        #expect(shieldFinding.flowCount == 30)
        #expect(shieldFinding.distinctRemoteHosts == 30)
        #expect(shieldFinding.advice.contains("transparent proxy"))
        // The user needs to be told what to actually do about it.
        #expect(shieldFinding.advice.contains("Disable"))
    }

    /// The check must not fire on ordinary applications, or the warning becomes noise
    /// and gets ignored precisely when it matters.
    @Test("A process talking to only a few hosts is not flagged")
    func fewHostsIsNotAProxy() {
        var flows: [Flow] = []
        // Mail dominates by flow count but only reaches three hosts — a busy client,
        // not a proxy.
        for index in 0..<30 {
            flows.append(
                flow(
                    remoteLastOctet: UInt8(index % 3), owner: mail,
                    localPort: UInt16(50000 + index)
                )
            )
        }
        for index in 0..<10 {
            flows.append(
                flow(
                    remoteLastOctet: UInt8(100 + index), owner: browser,
                    localPort: UInt16(60000 + index)
                )
            )
        }

        #expect(ProxyDetection.findLikelyProxies(in: flows).isEmpty)
    }

    @Test("A minority process is not flagged even with many hosts")
    func minorityShareIsNotAProxy() {
        var flows: [Flow] = []
        for index in 0..<10 {
            flows.append(
                flow(
                    remoteLastOctet: UInt8(index), owner: browser,
                    localPort: UInt16(50000 + index)
                )
            )
        }
        for index in 0..<30 {
            flows.append(
                flow(
                    remoteLastOctet: UInt8(100 + index), owner: mail,
                    localPort: UInt16(60000 + index)
                )
            )
        }
        let findings = ProxyDetection.findLikelyProxies(in: flows)
        #expect(!findings.contains { $0.owner == browser })
    }

    @Test("Too little data to judge produces no finding")
    func smallSamplesAreIgnored() {
        let flows = (0..<10).map {
            flow(remoteLastOctet: UInt8($0), owner: shield, localPort: UInt16(50000 + $0))
        }
        #expect(ProxyDetection.findLikelyProxies(in: flows).isEmpty)
    }

    @Test("Unattributed flows never trigger a finding")
    func unattributedFlowsAreIgnored() {
        let flows = (0..<40).map {
            flow(remoteLastOctet: UInt8($0), owner: nil, localPort: UInt16(50000 + $0))
        }
        #expect(ProxyDetection.findLikelyProxies(in: flows).isEmpty)
    }

    @Test(
        "System-extension paths are recognised",
        arguments: [
            ("/Library/SystemExtensions/ABC/x.systemextension/Contents/MacOS/x", true),
            ("/Applications/Foo.app/Contents/PlugIns/Bar.appex/Contents/MacOS/Bar", true),
            ("/Applications/Safari.app/Contents/MacOS/Safari", false),
            ("/usr/bin/curl", false),
        ]
    )
    func systemExtensionPaths(path: String, expected: Bool) {
        #expect(ProxyDetection.looksLikeSystemExtension(path) == expected)
    }
}
