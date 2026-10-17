import Foundation
import Testing
@testable import CertKeeperCore

/// The Family Hub case: a custom app (python3 under family-hub-admin.service) serving TLS from PEM
/// files in /etc/family-hub/tls. A real `openssl s_server` stands in for the app.
@Suite(.serialized) struct GenericTLSTests {
    struct Host {
        let root: URL
        var bin: URL { root.appendingPathComponent("bin") }
        var tls: URL { root.appendingPathComponent("etc/family-hub/tls") }
        let server: Process
        let port: Int
        func cleanup() { server.terminate(); server.waitUntilExit(); try? FileManager.default.removeItem(at: root) }
    }

    /// Starts a TLS server on a free local port serving `served` (PEM, full chain) with `key`.
    func start(unit: String = "family-hub-admin.service", writeKey: Bool = true, servedOverride: (String, String)? = nil) throws -> Host {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ck-generic-\(UUID().uuidString)")
        let tls = root.appendingPathComponent("etc/family-hub/tls"), bin = root.appendingPathComponent("bin")
        try FileManager.default.createDirectory(at: tls, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        // RSA: macOS's LibreSSL s_server fails ECDSA handshakes (alert 40); hosts' OpenSSL 3 handles either.
        let (leaf, key) = try selfSigned(["family-hub.example.com"], algorithm: .rsa2048)
        let (inter, _) = try selfSigned(["Test Intermediate"])
        try CertCrypto.joinPEMs([leaf, inter]).write(to: tls.appendingPathComponent("fullchain.pem"), atomically: true, encoding: .utf8)
        try leaf.write(to: tls.appendingPathComponent("cert.pem"), atomically: true, encoding: .utf8)  // decoy: leaf only
        if writeKey { try key.write(to: tls.appendingPathComponent("privkey.pem"), atomically: true, encoding: .utf8) }
        let (servedCert, servedKey) = servedOverride ?? (CertCrypto.joinPEMs([leaf, inter]), key)
        let sc = root.appendingPathComponent("served-cert.pem"), sk = root.appendingPathComponent("served-key.pem")
        try servedCert.write(to: sc, atomically: true, encoding: .utf8)
        try servedKey.write(to: sk, atomically: true, encoding: .utf8)

        var lastError: Error?
        for _ in 0..<5 {
            let port = Int.random(in: 30_000...60_000)
            let server = Process()
            server.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            server.arguments = ["s_server", "-accept", String(port), "-cert", sc.path, "-key", sk.path, "-www", "-quiet"]
            server.standardOutput = FileHandle.nullDevice
            server.standardError = FileHandle.nullDevice
            server.standardInput = Pipe()
            try server.run()
            // wait until it accepts TLS
            for _ in 0..<50 {
                if (try? runShell("echo | openssl s_client -connect 127.0.0.1:\(port) 2>/dev/null | grep -q BEGIN", path: "/usr/bin")) != nil {
                    let tools = [
                        "ss": "#!/bin/sh\necho 'LISTEN 0 128 0.0.0.0:\(port) 0.0.0.0:* users:((\"python3\",pid=4242,fd=3))'",
                        "ps": "#!/bin/sh\ncase \"$*\" in *'comm= -p 4242'*) echo python3 ;; *'unit= -p 4242'*) echo '\(unit)' ;; esac",
                    ]
                    for (name, body) in tools {
                        try body.write(to: bin.appendingPathComponent(name), atomically: true, encoding: .utf8)
                        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin.appendingPathComponent(name).path)
                    }
                    return Host(root: root, server: server, port: port)
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            server.terminate()
            lastError = DeployError("s_server didn't start on \(port)")
        }
        throw lastError ?? DeployError("no port")
    }

    func discover(_ host: Host) throws -> Discovery.Report {
        Discovery.parse(try runShell(Discovery.script, path: host.bin.path, env: ["CK_ROOT": host.root.path]))
    }

    @Test func findsTheFilesTheServiceServes() throws {
        let host = try start()
        defer { host.cleanup() }
        let report = try discover(host)
        let ep = try #require(report.endpoints.first { $0.label.hasPrefix("TLS service on :\(host.port)") })
        #expect(ep.kind == .containerApp)
        #expect(ep.label == "TLS service on :\(host.port) (python3)")
        #expect(ep.certPath == host.tls.appendingPathComponent("fullchain.pem").path, "the full-chain file, not the leaf-only decoy")
        #expect(ep.keyPath == host.tls.appendingPathComponent("privkey.pem").path)
        #expect(ep.summary?.dnsNames == ["family-hub.example.com"])
        #expect(ep.options?["restart_target"] == "systemd:family-hub-admin.service")
        #expect(ep.options?["verify_port"] == String(host.port))
        #expect(ep.options?["file_owner"]?.isEmpty == false)
        #expect(ep.note == nil)
    }

    @Test func userSessionUnitsAreNeverRestartTargets() throws {
        let host = try start(unit: "user@1000.service")
        defer { host.cleanup() }
        let ep = try #require(try discover(host).endpoints.first { $0.label.hasPrefix("TLS service on :\(host.port)") })
        #expect(ep.options?["restart_target"] == nil)
        #expect(ep.note?.contains("No systemd service found to restart") == true)
    }

    @Test func missingKeyIsFlagged() throws {
        let host = try start(writeKey: false)
        defer { host.cleanup() }
        let ep = try #require(try discover(host).endpoints.first { $0.label.hasPrefix("TLS service on :\(host.port)") })
        #expect(ep.keyPath.isEmpty)
        #expect(ep.note?.contains("No matching private key") == true)
    }

    @Test func certificateNotInAnyFileIsWarned() throws {
        let other = try selfSigned(["somewhere-else.lan"], algorithm: .rsa2048)
        let host = try start(servedOverride: other)
        defer { host.cleanup() }
        let report = try discover(host)
        #expect(!report.endpoints.contains { $0.label.hasPrefix("TLS service on :\(host.port)") })
        #expect(report.warnings.contains { $0.contains("TLS on port \(host.port) (python3)") })
    }

    @MainActor @Test func adoptingDoesntCopyTheGenericMarker() throws {
        let host = try start()
        defer { host.cleanup() }
        let ep = try #require(try discover(host).endpoints.first { $0.label.hasPrefix("TLS service on :\(host.port)") })
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())
        let h = ManagedHost(name: "family-hub", address: "family-hub.example.com"); m.addHost(h)
        let d = m.adopt(ep, hostID: h.id)
        #expect(d.options["generic"] == nil)
        #expect(d.option(.restartTarget) == "systemd:family-hub-admin.service")
        #expect(d.verifyEndpoint == "family-hub.example.com:\(host.port)")
    }
}

@Suite struct GenericDedupTests {
    @Test func catchAllDuplicatesOfSpecificEntriesAreDropped() throws {
        let (pem, _) = try selfSigned(["kvm.lan"])
        let (other, _) = try selfSigned(["app.lan"])
        let output = """
        @@OS Linux
        @@ENDPOINT nginx|kvm|/etc/letsencrypt/live/kvm/fullchain.pem|/etc/letsencrypt/live/kvm/privkey.pem||
        \(pem)
        @@END
        @@ENDPOINT containerApp|TLS service on :443 (nginx)|/etc/letsencrypt/archive/kvm/fullchain1.pem|/k||cert_format=pem;generic=true|
        \(pem)
        @@END
        @@ENDPOINT containerApp|TLS service on :8443 (python3)|/opt/app/cert.pem|/opt/app/key.pem||cert_format=pem;generic=true|
        \(other)
        @@END
        """
        let labels = Discovery.parse(output).endpoints.map(\.label)
        #expect(labels == ["kvm", "TLS service on :8443 (python3)"], "same certificate behind a symlinked path is a duplicate")
    }
}
