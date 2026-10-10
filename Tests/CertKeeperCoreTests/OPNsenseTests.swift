import Foundation
import Testing
@testable import CertKeeperCore

@Suite struct OPNsenseTests {
    /// The line the discovery PHP prints for the firewall in this setup (ACME Client cert, GUI on 443).
    @Test func parsesDiscoveryWithPortAndACMENote() throws {
        let (pem, _) = try selfSigned(["opnsense.example.com"])
        let note = "Issued by OPNsense's ACME Client plugin. Once CertKeeper has deployed, turn off this certificate's automatic renewal in Services > ACME Client > Certificates."
        let output = "@@ENDPOINT opnsense|Web GUI (opnsense.example.com (ACME Client))||||verify_port=443|\(note)\n\(pem)\n@@END\n"
        let ep = try #require(Discovery.parse(output).endpoints.first)
        #expect(ep.kind == .opnsense)
        #expect(ep.label == "Web GUI (opnsense.example.com (ACME Client))")
        #expect(ep.options?["verify_port"] == "443")
        #expect(ep.note == note)
        #expect(ep.summary?.dnsNames == ["opnsense.example.com"])
    }

    @Test func nonACMECertificateHasNoNote() throws {
        let (pem, _) = try selfSigned(["fw.lan"])
        let ep = try #require(Discovery.parse("@@ENDPOINT opnsense|Web GUI (Web GUI TLS certificate)||||verify_port=8443|\n\(pem)\n@@END\n").endpoints.first)
        #expect(ep.note == nil)
        #expect(ep.options?["verify_port"] == "8443")
    }

    @MainActor @Test func adoptUsesTheGUIPort() throws {
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())
        let host = ManagedHost(name: "opnsense", address: "opnsense.example.com"); m.addHost(host)
        let (pem, _) = try selfSigned(["opnsense.example.com"])
        var ep = DiscoveredEndpoint(kind: .opnsense, label: "Web GUI (x)", certPath: "", keyPath: "", chainPath: "",
                                    summary: try CertCrypto.summarize(pem: pem))
        ep.options = ["verify_port": "8443"]
        let d = m.adopt(ep, hostID: host.id)
        #expect(d.verifyEndpoint == "opnsense.example.com:8443")
        #expect(d.options.isEmpty, "the port is used for verification, not passed to the script")
    }

    @Test func deployScriptVerifiesBeforeRestartingAndRestoresOnFailure() throws {
        let (leaf, key) = try selfSigned(["opnsense.example.com"])
        var c = ManagedCertificate(name: "opnsense.example.com", domains: ["opnsense.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        let script = try DeployScripts.build(deployment: Deployment(certificateID: c.id, hostID: UUID(), kind: .opnsense),
                                             certificate: c, keyPEM: key)
        let backup = try #require(script.range(of: "cp -p /conf/config.xml \"$BACKUP\""))
        let write = try #require(script.range(of: "write_config("))
        let verify = try #require(script.range(of: "new OPNsense\\Trust\\Cert()"))
        let restore = try #require(script.range(of: "cp -p \"$BACKUP\" /conf/config.xml"))
        let restart = try #require(script.range(of: "configctl webgui restart"))
        #expect(backup.lowerBound < write.lowerBound)
        #expect(write.lowerBound < verify.lowerBound)
        #expect(verify.lowerBound < restore.lowerBound && restore.lowerBound < restart.lowerBound,
                "verification and rollback come before the GUI restart")
        #expect(script.contains("'@attributes' => ['uuid' => ck_uuid()]"))
    }
}
