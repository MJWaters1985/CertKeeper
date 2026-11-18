import Foundation
import Testing
@testable import CertKeeperCore

/// Real TLS connections to a local `openssl s_server`: the probe (Network.framework on macOS,
/// SwiftNIO on Linux) and the device API's trust decision.
/// Timeouts match the device API's 30 s: on a busy two-core CI runner, the first trust check (which
/// loads the system CA bundle) alongside the rest of the suite took longer than 10 s.
@Suite struct TLSTransportTests {
    struct Server {
        let process: TestProcess
        let port: Int
        let leafSHA256: String
        let dir: URL
        func stop() { process.stop(); try? FileManager.default.removeItem(at: dir) }
    }

    func start() throws -> Server {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-tls-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // RSA: macOS's LibreSSL s_server fails ECDSA handshakes.
        let (leaf, key) = try selfSigned(["device.example.com"], algorithm: .rsa2048)
        let (intermediate, _) = try selfSigned(["Test Intermediate"])
        let full = dir.appendingPathComponent("full.pem"), inter = dir.appendingPathComponent("inter.pem"), k = dir.appendingPathComponent("key.pem")
        try CertCrypto.joinPEMs([leaf, intermediate]).write(to: full, atomically: true, encoding: .utf8)
        try intermediate.write(to: inter, atomically: true, encoding: .utf8)
        try key.write(to: k, atomically: true, encoding: .utf8)
        let sha = try CertCrypto.summarize(pem: leaf).sha256

        for _ in 0..<5 {
            let port = Int.random(in: 30_000...60_000)
            var args = ["s_server", "-accept", String(port), "-cert", full.path, "-key", k.path, "-www", "-quiet"]
            #if os(Linux)
            args += ["-cert_chain", inter.path]  // OpenSSL 3 sends only what -cert_chain names; LibreSSL lacks it
            #endif
            let server = try TestProcess("/usr/bin/openssl", args)
            for _ in 0..<50 {
                if (try? runShell("echo | openssl s_client -connect 127.0.0.1:\(port) 2>/dev/null | grep -q BEGIN", path: "/usr/bin")) != nil {
                    return Server(process: server, port: port, leafSHA256: sha, dir: dir)
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            server.stop()
        }
        throw DeployError("s_server didn't start")
    }

    @Test func probeReadsTheServedChain() async throws {
        let server = try start()
        defer { server.stop() }
        let served = try await TLSProbe.fetchServed(endpoint: "127.0.0.1:\(server.port)", timeout: 30)
        #expect(served.chain.first?.sha256 == server.leafSHA256)
        #expect(served.chain.first?.dnsNames == ["device.example.com"])
        #if os(Linux)
        #expect(served.exact)
        #expect(served.chain.map(\.subject) == ["CN=device.example.com", "CN=Test Intermediate"], "exactly what was sent")
        #endif
    }

    @Test func pinnedCertificateIsAccepted() async throws {
        let server = try start()
        defer { server.stop() }
        let gate = TrustGate(pinned: DeviceAPI.formatFingerprint(server.leafSHA256))
        let raw = try await HTTPOverTLS.exchange(host: "127.0.0.1", port: UInt16(server.port),
                                                 request: Data("GET / HTTP/1.0\r\n\r\n".utf8), gate: gate, timeout: 30)
        #expect(String(decoding: raw.prefix(12), as: UTF8.self) == "HTTP/1.0 200")
        #expect(gate.rejectedFingerprint == nil)
    }

    @Test func untrustedUnpinnedCertificateIsRefused() async throws {
        let server = try start()
        defer { server.stop() }
        let gate = TrustGate(pinned: "")
        await #expect(throws: (any Error).self) {
            _ = try await HTTPOverTLS.exchange(host: "127.0.0.1", port: UInt16(server.port),
                                               request: Data("GET / HTTP/1.0\r\n\r\n".utf8), gate: gate, timeout: 30)
        }
        #expect(gate.rejectedFingerprint == server.leafSHA256, "the refused leaf's fingerprint is reported")
    }
}
