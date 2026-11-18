import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct ConfigTransferTests {
    /// A populated model: a managed cert with a key, a monitored cert, a password host, a pfx secret.
    func populated() throws -> (AppModel, MemorySecretStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-xfer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = MemorySecretStore()
        let m = AppModel(fileURL: dir.appendingPathComponent("inventory.json"), secrets: store)
        var host = ManagedHost(name: "nas", address: "nas.lan")
        host.passwordLogin = true
        m.addHost(host)
        let (leaf, key) = try selfSigned(["nas.example.com"])
        var c = ManagedCertificate(name: "nas.example.com", domains: ["nas.example.com"])
        c.leafPEM = leaf
        c.current = try CertCrypto.summarize(pem: leaf)
        m.addCertificate(c)
        var mon = ManagedCertificate(name: "unifi.example.com", domains: ["unifi.example.com"])
        mon.external = true
        m.addCertificate(mon)
        var d = Deployment(certificateID: c.id, hostID: host.id, kind: .containerApp)
        d.options = ["cert_format": "pkcs12"]
        m.addDeployment(d)
        m.inventory.settings.acmeEmail = "me@example.com"
        try store.set("cf-token", for: .cloudflareToken)
        try store.set("acme-key", for: .acmeAccountKey)
        try store.set(key, for: .certificateKey(c.id))
        try store.set("host-pw", for: .hostPassword(host.id))
        try store.set("pfx-pw", for: .deploymentSecret(d.id, "pfx_password"))
        m.log(.info, "something happened")
        return (m, store, dir)
    }

    func freshModel() -> (AppModel, MemorySecretStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-xfer-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = MemorySecretStore()
        let m = AppModel(fileURL: dir.appendingPathComponent("inventory.json"), secrets: store)
        m.log(.info, "existing history")
        return (m, store, dir)
    }

    @Test func withoutSecretsTheFileHoldsNone() throws {
        let (m, _, dir) = try populated()
        defer { try? FileManager.default.removeItem(at: dir) }
        let data = try m.exportConfiguration(password: nil)
        let text = String(decoding: data, as: UTF8.self)
        for secret in ["cf-token", "acme-key", "host-pw", "pfx-pw", "PRIVATE KEY"] {
            #expect(!text.contains(secret), "\(secret) must not be in the file")
        }
        let file = try ConfigTransfer.read(data)
        #expect(file.secrets == nil)
        #expect(file.inventory.log.isEmpty, "the activity log isn't exported")
        #expect(file.inventory.hosts.count == 1 && file.inventory.certificates.count == 2 && file.inventory.deployments.count == 1)

        let (target, store, tdir) = freshModel()
        defer { try? FileManager.default.removeItem(at: tdir) }
        try target.importConfiguration(file, secrets: [])
        #expect(target.inventory.settings.acmeEmail == "me@example.com")
        #expect(target.inventory.certificates.first { $0.name == "unifi.example.com" }?.isMonitored == true)
        #expect(store.count == 0)
        let entry = try #require(target.inventory.log.first)
        #expect(entry.message == "Imported configuration" && entry.level == .warning)
        #expect(entry.detail?.contains("No private key for: nas.example.com") == true)
        #expect(entry.detail?.contains("No password for: nas") == true)
        #expect(target.inventory.log.contains { $0.message == "existing history" }, "log is kept")
    }

    @Test func secretsRoundTripWithThePassword() throws {
        let (m, source, dir) = try populated()
        defer { try? FileManager.default.removeItem(at: dir) }
        let data = try m.exportConfiguration(password: "correct horse")
        let text = String(decoding: data, as: UTF8.self)
        #expect(!text.contains("cf-token") && !text.contains("PRIVATE KEY"), "secrets are encrypted")
        let file = try ConfigTransfer.read(data)
        #expect(file.secrets?.count == 5)

        let secrets = try ConfigTransfer.decryptSecrets(file, password: "correct horse")
        #expect(secrets.count == 5)
        let (target, store, tdir) = freshModel()
        defer { try? FileManager.default.removeItem(at: tdir) }
        let backup = try target.importConfiguration(file, secrets: secrets)
        #expect(FileManager.default.fileExists(atPath: backup.path), "previous configuration saved")
        let cert = try #require(target.inventory.certificates.first { $0.name == "nas.example.com" })
        let host = try #require(target.inventory.hosts.first)
        let d = try #require(target.inventory.deployments.first)
        #expect(store.get(.cloudflareToken) == "cf-token")
        #expect(store.get(.acmeAccountKey) == "acme-key")
        #expect(store.get(.certificateKey(cert.id)) == source.get(.certificateKey(cert.id)))
        #expect(store.get(.hostPassword(host.id)) == "host-pw")
        #expect(target.secret(.pfxPassword, for: d.id) == "pfx-pw")
        #expect(target.inventory.log.first?.level == .success)
    }

    @Test func wrongPasswordAndTamperingAreRejected() throws {
        let (m, _, dir) = try populated()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = try ConfigTransfer.read(try m.exportConfiguration(password: "correct horse"))
        #expect(throws: ConfigTransfer.TransferError.wrongPassword) { try ConfigTransfer.decryptSecrets(file, password: "wrong horse") }
        var tampered = file
        var bytes = Data(base64Encoded: tampered.secrets!.sealed)!
        bytes[bytes.count / 2] ^= 0xFF
        tampered.secrets!.sealed = bytes.base64EncodedString()
        #expect(throws: ConfigTransfer.TransferError.wrongPassword) { try ConfigTransfer.decryptSecrets(tampered, password: "correct horse") }
    }

    @Test func rejectsShortPasswordsOtherFilesAndNewerVersions() throws {
        let (m, _, dir) = try populated()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(throws: ConfigTransfer.TransferError.passwordTooShort) { try m.exportConfiguration(password: "short") }
        #expect(throws: ConfigTransfer.TransferError.notAConfiguration) { try ConfigTransfer.read(Data(#"{"hosts":[]}"#.utf8)) }
        let data = try m.exportConfiguration(password: nil)
        var json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        json["version"] = 99
        #expect(throws: ConfigTransfer.TransferError.unsupportedVersion(99)) {
            try ConfigTransfer.read(try JSONSerialization.data(withJSONObject: json))
        }
    }

    @Test func secretsForUnknownItemsAreIgnored() throws {
        let (m, _, dir) = try populated()
        defer { try? FileManager.default.removeItem(at: dir) }
        var file = try ConfigTransfer.read(try m.exportConfiguration(password: "correct horse"))
        file.inventory.hosts = []  // the host password no longer belongs to anything in the file
        let secrets = try ConfigTransfer.decryptSecrets(file, password: "correct horse")
        #expect(secrets.count == 4)
    }

    /// PBKDF2-HMAC-SHA256 test vector from RFC 7914 §11 (first 32 bytes), so files exported before the
    /// switch to swift-crypto's PBKDF2 still decrypt.
    @Test func keyDerivationMatchesRFC7914() throws {
        let key = try ConfigTransfer.deriveKey(password: "passwd", salt: Data("salt".utf8), iterations: 1)
        let hex = key.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
        #expect(hex == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
    }
}
