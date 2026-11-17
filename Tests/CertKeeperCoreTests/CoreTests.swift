import Crypto
import Foundation
import SwiftASN1
import Testing
import X509
@testable import CertKeeperCore

// MARK: - Fixtures

/// Creates a self-signed certificate for `names`, returning (certPEM, keyPEM).
func selfSigned(_ names: [String], days: Int = 90, algorithm: KeyAlgorithm = .ecdsaP256) throws -> (String, String) {
    let keyPEM = try CertCrypto.generateKeyPEM(algorithm)
    let key = try Certificate.PrivateKey(pemEncoded: keyPEM)
    let dn = try DistinguishedName { CommonName(names[0]) }
    let now = Date()
    let cert = try Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: key.publicKey,
        notValidBefore: now.addingTimeInterval(-60),
        notValidAfter: now.addingTimeInterval(Double(days) * 86_400),
        issuer: dn,
        subject: dn,
        signatureAlgorithm: algorithm == .ecdsaP256 ? .ecdsaWithSHA256 : .sha256WithRSAEncryption,
        extensions: try Certificate.Extensions { SubjectAlternativeNames(names.map { .dnsName($0) }) },
        issuerPrivateKey: key
    )
    return (try cert.serializeAsPEM().pemString, keyPEM)
}

// MARK: - Crypto

@Suite struct CryptoTests {
    @Test(arguments: KeyAlgorithm.allCases)
    func csrRoundTrip(_ alg: KeyAlgorithm) throws {
        let keyPEM = try CertCrypto.generateKeyPEM(alg)
        let der = try CertCrypto.makeCSR(domains: ["example.com", "*.example.com"], keyPEM: keyPEM)
        let csr = try CertificateSigningRequest(derEncoded: Array(der))
        let key = try Certificate.PrivateKey(pemEncoded: keyPEM)
        #expect(csr.publicKey == key.publicKey)
        #expect(csr.publicKey.isValidSignature(csr.signature, for: csr))
        let sans = try csr.attributes.extensionRequest?.extensions.subjectAlternativeNames
        #expect(sans.map(Array.init) == [.dnsName("example.com"), .dnsName("*.example.com")])
    }

    @Test func longFirstDomainOmitsCN() throws {
        let long = String(repeating: "a", count: 60) + ".example.com"
        let der = try CertCrypto.makeCSR(domains: [long], keyPEM: try CertCrypto.generateKeyPEM(.ecdsaP256))
        let csr = try CertificateSigningRequest(derEncoded: Array(der))
        #expect(csr.subject.isEmpty)
    }

    @Test func summarizeAndKeyMatch() throws {
        let (cert, key) = try selfSigned(["a.example.com", "b.example.com"], days: 10)
        let s = try CertCrypto.summarize(pem: cert)
        #expect(s.dnsNames == ["a.example.com", "b.example.com"])
        #expect((9...10).contains(s.daysRemaining))
        #expect(s.sha256.count == 64)
        #expect(CertCrypto.keyMatches(certPEM: cert, keyPEM: key))
        #expect(!CertCrypto.keyMatches(certPEM: cert, keyPEM: try CertCrypto.generateKeyPEM(.ecdsaP256)))
    }

    @Test func splitsBundle() throws {
        let (a, _) = try selfSigned(["a.test"])
        let (b, _) = try selfSigned(["b.test"])
        let pems = CertCrypto.certificatePEMs(in: a + "\n" + b)
        #expect(pems.count == 2)
        #expect(try CertCrypto.summarize(pem: pems[1]).dnsNames == ["b.test"])
    }

    @Test func jwkThumbprintIsStable() throws {
        let key = P256.Signing.PrivateKey()
        let jwk = ACMEClient.jwk(for: key.publicKey)
        #expect(jwk["kty"] == "EC")
        #expect(jwk["x"]?.count == 43 && jwk["y"]?.count == 43)
        #expect(ACMEClient.thumbprint(for: key.publicKey) == ACMEClient.thumbprint(for: key.publicKey))
        #expect(ACMEClient.thumbprint(for: key.publicKey).count == 43)
    }

    @Test func base64URL() {
        #expect(Data([0xfb, 0xff]).base64URL == "-_8")
    }
}

// MARK: - Cloudflare

@Suite struct CloudflareTests {
    let zones = [
        CloudflareClient.Zone(id: "1", name: "example.com"),
        CloudflareClient.Zone(id: "2", name: "lab.example.com"),
        CloudflareClient.Zone(id: "3", name: "other.org"),
    ]

    @Test func picksMostSpecificZone() {
        #expect(CloudflareClient.zone(for: "_acme-challenge.nas.lab.example.com", in: zones)?.id == "2")
        #expect(CloudflareClient.zone(for: "_acme-challenge.www.example.com", in: zones)?.id == "1")
        #expect(CloudflareClient.zone(for: "*.other.org", in: zones)?.id == "3")
        #expect(CloudflareClient.zone(for: "notexample.com", in: zones) == nil)
    }
}

// MARK: - Discovery

@Suite struct DiscoveryTests {
    @Test func parsesEndpoints() throws {
        let (cert, _) = try selfSigned(["www.example.com"])
        let output = """
        @@OS Linux Debian GNU/Linux 12 (bookworm)
        @@ENDPOINT nginx|www.example.com|/etc/ssl/www.pem|/etc/ssl/www.key|
        \(cert)
        @@END
        @@WARN cannot read /etc/missing.pem
        @@ENDPOINT proxmox|pveproxy (custom)|/etc/pve/local/pveproxy-ssl.pem|/etc/pve/local/pveproxy-ssl.key|
        @@END
        @@ENDPOINT bogus|x|y|z|
        @@END
        """
        let report = Discovery.parse(output)
        #expect(report.os == "Linux Debian GNU/Linux 12 (bookworm)")
        #expect(report.endpoints.count == 2)
        #expect(report.endpoints[0].kind == .nginx)
        #expect(report.endpoints[0].summary?.dnsNames == ["www.example.com"])
        #expect(report.endpoints[1].summary == nil)
        #expect(report.warnings == ["cannot read /etc/missing.pem"])
    }

    @Test func matchesDeployments() {
        let eps = [
            DiscoveredEndpoint(kind: .nginx, label: "a", certPath: "/a.pem", keyPath: "", chainPath: "", summary: nil),
            DiscoveredEndpoint(kind: .nginx, label: "b", certPath: "/b.pem", keyPath: "", chainPath: "", summary: nil),
            DiscoveredEndpoint(kind: .truenas, label: "ui", certPath: "", keyPath: "", chainPath: "", summary: nil),
        ]
        var d = Deployment(certificateID: UUID(), hostID: UUID(), kind: .nginx)
        d.certPath = "/b.pem"
        #expect(Discovery.match(d, in: eps)?.label == "b")
        #expect(Discovery.match(Deployment(certificateID: UUID(), hostID: UUID(), kind: .truenas), in: eps)?.label == "ui")
    }

    /// Runs the real discovery script against a fake filesystem layout with a stub `nginx -T`.
    @Test func discoveryScriptFindsNginxCert() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-disc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (cert, _) = try selfSigned(["site.example.com"])
        try cert.write(to: dir.appendingPathComponent("site.pem"), atomically: true, encoding: .utf8)
        let nginx = dir.appendingPathComponent("nginx")
        try """
        #!/bin/sh
        cat <<EOF
        server {
            server_name site.example.com www.site.example.com;
            ssl_certificate "\(dir.path)/site.pem";
            ssl_certificate_key \(dir.path)/site.key; # comment
        }
        EOF
        """.write(to: nginx, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: nginx.path)

        let r = try runShell(Discovery.script, path: dir.path)
        let report = Discovery.parse(r)
        let ep = try #require(report.endpoints.first { $0.kind == .nginx })
        #expect(ep.label == "site.example.com www.site.example.com")
        #expect(ep.certPath == dir.path + "/site.pem")
        #expect(ep.keyPath == dir.path + "/site.key")
        #expect(ep.summary?.dnsNames == ["site.example.com"])
    }
}

// MARK: - Deploy scripts

@Suite struct DeployScriptTests {
    func issuedCert() throws -> (ManagedCertificate, String) {
        let (leaf, key) = try selfSigned(["www.example.com"])
        let (chain, _) = try selfSigned(["Fake Intermediate"])
        var c = ManagedCertificate(name: "www", domains: ["www.example.com"])
        c.leafPEM = leaf
        c.chainPEM = chain
        c.current = try CertCrypto.summarize(pem: leaf)
        return (c, key)
    }

    @Test(arguments: DeploymentKind.allCases)
    func templatesAreValidShell(_ kind: DeploymentKind) throws {
        let (c, key) = try issuedCert()
        let script = try DeployScripts.build(deployment: Deployment(certificateID: c.id, hostID: UUID(), kind: kind), certificate: c, keyPEM: key)
        let r = try runTool("/bin/sh", ["-n"], stdin: Data(SSHRunner.shielded(script).utf8))
        #expect(r.status == 0, "sh -n failed for \(kind)")
    }

    @Test func slug() throws {
        let c = ManagedCertificate(name: "x", domains: ["*.Lab.Example.com"])
        #expect(DeployScripts.slug(for: c) == "certkeeper_lab_example_com")
    }

    /// Executes the nginx template locally with a stub `nginx` binary to check install, backup and rollback.
    @Test(arguments: [true, false])
    func nginxInstallAndRollback(configTestPasses: Bool) throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString)")
        let bin = dir.appendingPathComponent("bin")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "#!/bin/sh\n[ \"$1\" = \"-t\" ] && exit \(configTestPasses ? 0 : 1)\nexit 0\n"
            .write(to: bin.appendingPathComponent("nginx"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin.appendingPathComponent("nginx").path)

        let certPath = dir.appendingPathComponent("site.crt").path
        let keyPath = dir.appendingPathComponent("site.key").path
        try "OLD CERT".write(toFile: certPath, atomically: true, encoding: .utf8)
        try "OLD KEY".write(toFile: keyPath, atomically: true, encoding: .utf8)

        let (c, key) = try issuedCert()
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .nginx)
        d.certPath = certPath
        d.keyPath = keyPath
        let script = try DeployScripts.build(deployment: d, certificate: c, keyPEM: key)

        let run = Result { try runShell(script, path: bin.path) }
        let ok = (try? run.get()) != nil
        #expect(ok == configTestPasses, "\(run)")
        let installed = try String(contentsOfFile: certPath, encoding: .utf8)
        let installedKey = try String(contentsOfFile: keyPath, encoding: .utf8)
        if configTestPasses {
            #expect(CertCrypto.certificatePEMs(in: installed).count == 2, "full chain installed")
            #expect(CertCrypto.keyMatches(certPEM: installed, keyPEM: installedKey))
            let backups = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".bak") }
            #expect(backups.count == 2)
        } else {
            #expect(installed == "OLD CERT")
            #expect(installedKey == "OLD KEY")
        }
    }
}

// MARK: - Policy

@Suite @MainActor struct PolicyTests {
    func model() -> AppModel {
        AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"), secrets: MemorySecretStore())
    }

    @Test func renewalStatus() throws {
        let m = model()
        var c = ManagedCertificate(name: "a", domains: ["a.example.com"])
        #expect(m.status(of: c) == .notIssued)

        let (fresh, _) = try selfSigned(["a.example.com"], days: 80)
        c.leafPEM = fresh
        c.current = try CertCrypto.summarize(pem: fresh)
        #expect(!m.needsIssuance(c))

        let (old, _) = try selfSigned(["a.example.com"], days: 20)
        c.leafPEM = old
        c.current = try CertCrypto.summarize(pem: old)
        #expect(m.needsIssuance(c))
        c.renewDaysBeforeExpiry = 10
        #expect(!m.needsIssuance(c))

        c.domains.append("b.example.com")
        #expect(m.status(of: c) == .domainsChanged)
    }

    @Test func deploymentNeedsRotationOnlyWhenFingerprintDiffers() throws {
        let m = model()
        let (pem, _) = try selfSigned(["a.example.com"])
        var c = ManagedCertificate(name: "a", domains: ["a.example.com"])
        c.leafPEM = pem
        c.current = try CertCrypto.summarize(pem: pem)
        m.addCertificate(c)
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .proxmox)
        m.addDeployment(d)
        #expect(m.needsDeployment(d))
        d.deployedSHA256 = c.current?.sha256
        #expect(!m.needsDeployment(d))
        d.enabled = false
        d.deployedSHA256 = "x"
        #expect(!m.needsDeployment(d))
    }

    @Test func adoptReusesMatchingCertificate() throws {
        let m = model()
        let (pem, _) = try selfSigned(["nas.example.com"])
        let ep = DiscoveredEndpoint(kind: .truenas, label: "Web UI", certPath: "", keyPath: "", chainPath: "",
                                    summary: try CertCrypto.summarize(pem: pem))
        let h1 = ManagedHost(name: "nas1", address: "10.0.0.2"), h2 = ManagedHost(name: "nas2", address: "10.0.0.3")
        m.addHost(h1); m.addHost(h2)
        let d1 = m.adopt(ep, hostID: h1.id)
        let d2 = m.adopt(ep, hostID: h2.id)
        #expect(m.inventory.certificates.count == 1)
        #expect(d1.certificateID == d2.certificateID)
        #expect(d1.verifyEndpoint == "nas.example.com:443")
    }

    @Test func persistsInventory() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = MemorySecretStore()
        let m = AppModel(fileURL: url, secrets: store)
        m.addHost(ManagedHost(name: "pve", address: "pve.lan"))
        let reloaded = AppModel(fileURL: url, secrets: store)
        #expect(reloaded.inventory.hosts.map(\.name) == ["pve"])
    }
}

@Suite struct TLSProbeTests {
    @Test func splitsEndpoints() {
        #expect(TLSProbe.split("nas.lan") == ("nas.lan", 443))
        #expect(TLSProbe.split("nas.lan:8443") == ("nas.lan", 8443))
        #expect(TLSProbe.split("https://nas.lan:9443/ui") == ("nas.lan", 9443))
        #expect(TLSProbe.split("[fd00::1]:8006") == ("fd00::1", 8006))
    }
}

// MARK: - Helpers

@discardableResult
func runShell(_ script: String, path: String, env: [String: String] = [:]) throws -> String {
    #if os(Linux)
    // Foundation's Process passes blocked signals on to children here; see CleanSpawn.
    let environment = ["PATH": "\(path):/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": FileManager.default.temporaryDirectory.path]
        .merging(env) { $1 }
    SSHRunner.ignoreSIGPIPE()
    let r = try CleanSpawn.run("/bin/sh", ["-s"], environment: environment, stdin: Data(SSHRunner.shielded(script).utf8))
    guard r.status == 0 else { throw DeployError("exit \(r.status): \(String(decoding: r.stderr, as: UTF8.self))") }
    return String(decoding: r.stdout, as: UTF8.self)
    #else
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = ["-s"]
    p.environment = ["PATH": "\(path):/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": FileManager.default.temporaryDirectory.path]
        .merging(env) { $1 }
    let input = Pipe(), output = Pipe(), err = Pipe()
    p.standardInput = input
    p.standardOutput = output
    p.standardError = err
    try p.run()
    SSHRunner.ignoreSIGPIPE(); try? input.fileHandleForWriting.write(contentsOf: Data(SSHRunner.shielded(script).utf8))
    try input.fileHandleForWriting.close()
    let out = output.fileHandleForReading.readDataToEndOfFile()
    let errOut = err.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard p.terminationStatus == 0 else {
        throw DeployError("exit \(p.terminationStatus): \(String(decoding: errOut, as: UTF8.self))")
    }
    return String(decoding: out, as: UTF8.self)
    #endif
}
