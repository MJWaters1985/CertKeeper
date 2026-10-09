import Foundation
import Testing
@testable import CertKeeperCore

/// Mimics a TrueNAS SMB-share dataset (aclmode=restricted): changing permission bits is refused,
/// including `cp -p`, even for root.
@Suite struct ACLDatasetTests {
    struct Env {
        let dir: URL
        var bin: URL { dir.appendingPathComponent("bin") }
        var share: URL { dir.appendingPathComponent("Share") }
    }

    func makeEnv(nginxTestPasses: Bool = true) throws -> Env {
        let env = Env(dir: FileManager.default.temporaryDirectory.appendingPathComponent("ck-acl-\(UUID().uuidString)"))
        try FileManager.default.createDirectory(at: env.bin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: env.share, withIntermediateDirectories: true)
        let tools = [
            "chmod": "#!/bin/sh\necho \"chmod: changing permissions of '$2': Operation not permitted\" >&2\nexit 1",
            "cp": "#!/bin/sh\nfor a; do [ \"$a\" = -p ] && { echo \"cp: preserving permissions: Operation not permitted\" >&2; exit 1; }; done\nexec /bin/cp \"$@\"",
            "nginx": "#!/bin/sh\n[ \"$1\" = -t ] && exit \(nginxTestPasses ? 0 : 1)\nexit 0",
        ]
        for (name, body) in tools {
            let url = env.bin.appendingPathComponent(name)
            try body.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }
        return env
    }

    func issued(_ name: String) throws -> (ManagedCertificate, String) {
        let (leaf, key) = try selfSigned([name])
        var c = ManagedCertificate(name: name, domains: [name])
        c.leafPEM = leaf
        c.chainPEM = ""
        return (c, key)
    }

    @Test func replacesExistingFilesWithoutChangingPermissions() throws {
        let env = try makeEnv()
        defer { try? FileManager.default.removeItem(at: env.dir) }
        let crt = env.share.appendingPathComponent("Cert/nas_waters_tk.crt"), key = env.share.appendingPathComponent("Cert/NAS.key")
        try FileManager.default.createDirectory(at: crt.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "OLD CERT".write(to: crt, atomically: true, encoding: .utf8)
        try "OLD KEY".write(to: key, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o664], ofItemAtPath: crt.path)

        let (c, keyPEM) = try issued("nas.example.com")
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .containerApp)
        d.certPath = crt.path
        d.keyPath = key.path
        let out = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: keyPEM), path: env.bin.path)
        #expect(out.contains("installed \(crt.path)"))
        #expect(CertCrypto.keyMatches(certPEM: try String(contentsOf: crt, encoding: .utf8), keyPEM: try String(contentsOf: key, encoding: .utf8)))
        #expect(try FileManager.default.attributesOfItem(atPath: crt.path)[.posixPermissions] as? Int == 0o664, "existing mode kept")
        let backups = try FileManager.default.contentsOfDirectory(atPath: crt.deletingLastPathComponent().path).filter { $0.hasSuffix(".bak") }
        #expect(backups.count == 2)
    }

    @Test func newPfxFileSucceedsWhenChmodIsRefused() throws {
        let env = try makeEnv()
        defer { try? FileManager.default.removeItem(at: env.dir) }
        let (c, keyPEM) = try issued("nas.example.com")
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .containerApp)
        d.certPath = env.share.appendingPathComponent("Media/nas.example.com.p12").path
        d.options = ["cert_format": "pkcs12", "pfx_password": "pw"]
        _ = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: keyPEM), path: env.bin.path)
        let probed = try runShell(Discovery.probeScript(path: d.certPath, pkcs12: true, password: "pw"), path: env.bin.path)
        #expect(try CertCrypto.summarize(pem: probed).sha256 == CertCrypto.summarize(pem: c.leafPEM!).sha256)
    }

    @Test func rollbackRestoresContentsInPlace() throws {
        let env = try makeEnv(nginxTestPasses: false)
        defer { try? FileManager.default.removeItem(at: env.dir) }
        let crt = env.share.appendingPathComponent("site.crt"), key = env.share.appendingPathComponent("site.key")
        try "OLD CERT".write(to: crt, atomically: true, encoding: .utf8)
        try "OLD KEY".write(to: key, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: key.path)
        let inode = try FileManager.default.attributesOfItem(atPath: key.path)[.systemFileNumber] as? Int

        let (c, keyPEM) = try issued("site.example.com")
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .nginx)
        d.certPath = crt.path
        d.keyPath = key.path
        #expect(throws: DeployError.self) { try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: keyPEM), path: env.bin.path) }
        #expect(try String(contentsOf: crt, encoding: .utf8) == "OLD CERT")
        #expect(try String(contentsOf: key, encoding: .utf8) == "OLD KEY")
        let attrs = try FileManager.default.attributesOfItem(atPath: key.path)
        #expect(attrs[.posixPermissions] as? Int == 0o640)
        #expect(attrs[.systemFileNumber] as? Int == inode, "same file, so its ACL is untouched")
        #expect(try FileManager.default.contentsOfDirectory(atPath: env.share.path).filter { $0.hasSuffix(".bak") }.isEmpty)
    }
}
