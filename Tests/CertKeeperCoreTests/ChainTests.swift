import Foundation
import Testing
@testable import CertKeeperCore

@Suite struct ChainTests {
    /// leaf + 3 intermediates, like the Let's Encrypt production download.
    func bundle() throws -> [String] {
        try ["pve.example.com", "YE1", "ISRG Root YE", "ISRG Root X2"].map { try selfSigned([$0]).0 }
    }

    /// Number of certificates OpenSSL reads from a PEM file.
    func opensslCount(_ pem: String) throws -> Int {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-chain-\(UUID().uuidString).pem")
        try pem.write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }
        let out = try runShell("openssl crl2pkcs7 -nocrl -certfile \(url.path) 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -c '^subject' || true", path: "/usr/bin")
        return Int(out.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
    }

    @Test func oldJoinWasBroken() throws {
        let pems = try bundle()
        let glued = pems.dropFirst().joined()  // what earlier builds stored
        #expect(glued.contains("-----END CERTIFICATE----------BEGIN CERTIFICATE-----"))
        #expect(try opensslCount(pems[0] + "\n" + glued) < 4)
    }

    @Test func issuedBundleSplitsIntoValidPEM() throws {
        let pems = try bundle()
        let download = pems.joined(separator: "\n")
        let (leaf, chain) = try #require(CertCrypto.splitIssuedBundle(download))
        #expect(try CertCrypto.summarize(pem: leaf).dnsNames == ["pve.example.com"])
        #expect(!chain.contains("----------"))
        var c = ManagedCertificate(name: "pve", domains: ["pve.example.com"])
        c.leafPEM = leaf
        c.chainPEM = chain
        #expect(try opensslCount(c.fullchainPEM!) == 4)
        #expect(try opensslCount(chain) == 3)
    }

    @Test func normalizeRepairsGluedChainsAndIsIdempotent() throws {
        let pems = try bundle()
        let glued = pems.dropFirst().joined()
        let fixed = CertCrypto.normalizePEMBundle(glued)
        #expect(try opensslCount(fixed) == 3)
        #expect(CertCrypto.normalizePEMBundle(fixed) == fixed)
        #expect(CertCrypto.certificatePEMs(in: fixed).map { try? CertCrypto.summarize(pem: $0).sha256 }
                == pems.dropFirst().map { try? CertCrypto.summarize(pem: $0).sha256 })
    }

    @MainActor @Test func loadingRepairsStoredChainsAndForcesRedeploy() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let pems = try bundle()
        var inv = Inventory()
        var c = ManagedCertificate(name: "pve.example.com", domains: ["pve.example.com"])
        c.leafPEM = pems[0]
        c.chainPEM = pems.dropFirst().joined()
        c.current = try CertCrypto.summarize(pem: pems[0])
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .proxmox)
        d.deployedSHA256 = c.current?.sha256  // leaf already live — would never redeploy on its own
        inv.certificates = [c]
        inv.deployments = [d]
        try InventoryFile.save(inv, to: url)

        let store = MemorySecretStore()
        let m = AppModel(fileURL: url, secrets: store)
        #expect(try opensslCount(m.inventory.certificates[0].chainPEM!) == 3)
        #expect(m.inventory.deployments[0].forceRedeploy)
        #expect(m.needsDeployment(m.inventory.deployments[0]))
        #expect(m.inventory.log.first?.message.contains("Repaired") == true)

        let again = AppModel(fileURL: url, secrets: store)
        #expect(again.inventory.deployments[0].forceRedeploy, "flag persists until a deploy succeeds")
        #expect(again.inventory.log.filter { $0.message.contains("Repaired") }.count == 1, "repair runs once")
    }
}
