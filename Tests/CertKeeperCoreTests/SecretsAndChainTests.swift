import Crypto
import Foundation
import SwiftASN1
import Testing
import X509
@testable import CertKeeperCore

@Suite @MainActor struct SecretMigrationTests {
    let password = "s3cret-pfx-Pw"

    /// An inventory as earlier builds wrote it: the .pfx password in the deployment's options and in
    /// the host's saved discovery results.
    func legacyInventory(at url: URL) throws -> (hostID: UUID, deploymentID: UUID, endpoint: DiscoveredEndpoint) {
        var inv = Inventory()
        let host = ManagedHost(name: "nas", address: "nas.example.com")
        let (pem, _) = try selfSigned(["nas.example.com"])
        var ep = DiscoveredEndpoint(kind: .containerApp, label: "App: jellyfin (Jellyfin HTTPS)", certPath: "/mnt/x/jf.p12",
                                    keyPath: "", chainPath: "", summary: try CertCrypto.summarize(pem: pem))
        ep.options = ["cert_format": "pkcs12", "pfx_password": password, "restart_target": "jellyfin"]
        var h = host
        h.lastDiscovery = [ep]
        let cert = ManagedCertificate(name: "nas.example.com", domains: ["nas.example.com"])
        var d = Deployment(certificateID: cert.id, hostID: host.id, kind: .containerApp)
        d.certPath = ep.certPath
        d.options = ["cert_format": "pkcs12", "pfx_password": password]
        inv.hosts = [h]
        inv.certificates = [cert]
        inv.deployments = [d]
        try InventoryFile.save(inv, to: url)
        return (host.id, d.id, ep)
    }

    @Test func movesPasswordsOutOfTheInventoryFile() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let (_, deploymentID, _) = try legacyInventory(at: url)
        let store = MemorySecretStore()
        let m = AppModel(fileURL: url, secrets: store)

        #expect(m.inventory.deployments[0].options["pfx_password"] == nil)
        #expect(m.inventory.hosts[0].lastDiscovery[0].options?["pfx_password"] == nil)
        #expect(m.inventory.hosts[0].lastDiscovery[0].options?["cert_format"] == "pkcs12", "other options kept")
        #expect(m.secret(.pfxPassword, for: deploymentID) == password)
        #expect(!(try String(contentsOf: url, encoding: .utf8)).contains(password), "file no longer contains it")
        #expect(m.inventory.log.contains { $0.message.contains("Moved passwords") })

        // A second launch has nothing left to move.
        let again = AppModel(fileURL: url, secrets: store)
        #expect(again.inventory.log.filter { $0.message.contains("Moved passwords") }.count == 1)
    }

    @Test func deployScriptGetsThePasswordFromTheStore() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let (_, deploymentID, _) = try legacyInventory(at: url)
        let m = AppModel(fileURL: url, secrets: MemorySecretStore())
        let d = try #require(m.inventory.deployments.first { $0.id == deploymentID })
        let (leaf, key) = try selfSigned(["nas.example.com"])
        var c = m.inventory.certificates[0]
        c.leafPEM = leaf
        c.chainPEM = ""
        let script = try DeployScripts.build(deployment: m.withSecrets(d), certificate: c, keyPEM: key)
        #expect(script.contains("CK_OPT_PFX_PASSWORD='\(password)'"))
        #expect(m.inventory.deployments[0].options["pfx_password"] == nil, "the stored deployment stays clean")
    }

    @Test func adoptingAfterRelaunchKeepsTheDiscoveredPassword() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let (hostID, deploymentID, _) = try legacyInventory(at: url)
        let m = AppModel(fileURL: url, secrets: MemorySecretStore())
        m.deleteDeployment(deploymentID)
        #expect(m.secret(.pfxPassword, for: deploymentID).isEmpty, "secret removed with its deployment")

        let saved = m.inventory.hosts[0].lastDiscovery[0]  // stripped copy, as the UI sees it
        let d = m.adopt(saved, hostID: hostID)
        #expect(d.options["pfx_password"] == nil)
        #expect(m.secret(.pfxPassword, for: d.id) == password)
    }

    @Test func freshDiscoveryNeverStoresThePassword() throws {
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())
        let host = ManagedHost(name: "nas", address: "nas.lan"); m.addHost(host)
        let (pem, _) = try selfSigned(["nas.example.com"])
        var ep = DiscoveredEndpoint(kind: .containerApp, label: "jf", certPath: "/x.p12", keyPath: "", chainPath: "",
                                    summary: try CertCrypto.summarize(pem: pem))
        ep.options = ["cert_format": "pkcs12", "pfx_password": password]
        let d = m.adopt(ep, hostID: host.id)
        #expect(d.options["pfx_password"] == nil)
        #expect(m.secret(.pfxPassword, for: d.id) == password)
    }
}

@Suite struct ChainCompletenessTests {
    struct Issued { let summary: CertificateSummary; let key: Certificate.PrivateKey; let name: DistinguishedName }

    func issue(_ cn: String, by issuer: Issued?, isCA: Bool) throws -> Issued {
        let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let name = try DistinguishedName { CommonName(cn) }
        let cert = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: key.publicKey,
            notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(86_400 * 30),
            issuer: issuer?.name ?? name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                if isCA { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) }
                else { SubjectAlternativeNames([.dnsName(cn)]) }
            },
            issuerPrivateKey: issuer?.key ?? key)
        return Issued(summary: try CertCrypto.summarize(pem: try cert.serializeAsPEM().pemString), key: key, name: name)
    }

    @Test func detectsMissingIntermediate() throws {
        let root = try issue("ISRG Root Test", by: nil, isCA: true)
        let intermediate = try issue("YE1 Test", by: root, isCA: true)
        let leaf = try issue("pve.example.com", by: intermediate, isCA: false)

        #expect(!TLSProbe.chainIsComplete([leaf.summary]), "leaf only — what the glued chain produced")
        #expect(TLSProbe.chainIsComplete([leaf.summary, intermediate.summary]))
        #expect(TLSProbe.chainIsComplete([leaf.summary, intermediate.summary, root.summary]))
        #expect(!TLSProbe.chainIsComplete([leaf.summary, root.summary]), "wrong certificate sent")
        #expect(TLSProbe.chainIsComplete([root.summary]), "self-signed needs nothing else")
        #expect(!TLSProbe.chainIsComplete([]))
    }

    @Test func oldDeploymentsDecodeWithUnknownChainState() throws {
        let json = #"{"id":"\#(UUID())","certificateID":"\#(UUID())","hostID":"\#(UUID())","kind":"nginx"}"#
        let d = try JSONDecoder().decode(Deployment.self, from: Data(json.utf8))
        #expect(d.servedChainComplete == nil)
    }
}

@Suite @MainActor struct PreflightTests {
    @Test func flagsIssuedCertificatesWithoutKeys() async throws {
        let store = MemorySecretStore()
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: store)
        let (pem, key) = try selfSigned(["a.example.com"])
        var withKey = ManagedCertificate(name: "a.example.com", domains: ["a.example.com"])
        withKey.leafPEM = pem
        var withoutKey = ManagedCertificate(name: "b.example.com", domains: ["b.example.com"])
        withoutKey.leafPEM = pem
        let notIssued = ManagedCertificate(name: "c.example.com", domains: ["c.example.com"])
        [withKey, withoutKey, notIssued].forEach(m.addCertificate)
        try store.set(key, for: .certificateKey(withKey.id))

        await m.preflightSecrets()
        let entry = try #require(m.inventory.log.first { $0.message.contains("Private keys missing") })
        #expect(entry.detail == "b.example.com", "only issued certificates whose key is gone")
    }

    @Test func quietWhenEverythingIsPresent() async throws {
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())
        await m.preflightSecrets()
        #expect(m.inventory.log.isEmpty)
    }
}
