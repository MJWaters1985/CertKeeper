import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct AdoptionTests {
    func model() -> AppModel {
        AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"), secrets: MemorySecretStore())
    }

    func endpoint(_ names: [String], kind: DeploymentKind = .containerApp, path: String = "/mnt/app/cert.pem") throws -> DiscoveredEndpoint {
        let (pem, _) = try selfSigned(names)
        return DiscoveredEndpoint(kind: kind, label: "app", certPath: path, keyPath: path + ".key", chainPath: "",
                                  summary: try CertCrypto.summarize(pem: pem))
    }

    @Test func wildcardMatching() {
        #expect(AppModel.name("*.example.com", covers: "nas.example.com"))
        #expect(AppModel.name("NAS.example.com", covers: "nas.EXAMPLE.com"))
        #expect(!AppModel.name("*.example.com", covers: "www.nas.example.com"), "wildcards cover one label only")
        #expect(!AppModel.name("*.example.com", covers: "example.com"))
        #expect(!AppModel.name("*.nas.example.com", covers: "*.example.com"))
        #expect(AppModel.name("*.example.com", covers: "*.example.com"))
    }

    /// The reported setup: managed cert for nas.example.com; apps carry nas + www.nas.
    @Test func narrowerCertIsNotPickedAutomatically() throws {
        let m = model()
        let host = ManagedHost(name: "nas", address: "nas.example.com"); m.addHost(host)
        let ui = ManagedCertificate(name: "nas.example.com", domains: ["nas.example.com"]); m.addCertificate(ui)
        let jf = try endpoint(["nas.example.com", "www.nas.example.com"], path: "/mnt/jf.pfx")
        #expect(m.automaticAdoptionTarget(for: jf) == nil)
        #expect(m.coverage(of: ui, for: AppModel.dnsNames(of: jf)) == .missing(["www.nas.example.com"]))

        // After adding www to the managed cert, both apps attach to it and nothing new is created.
        m.inventory.certificates[0].domains.append("www.nas.example.com")
        let d1 = m.adopt(jf, hostID: host.id)
        let d2 = m.adopt(try endpoint(["www.nas.example.com", "nas.example.com"], path: "/mnt/qb.pem"), hostID: host.id)
        #expect(m.inventory.certificates.count == 1)
        #expect(d1.certificateID == ui.id && d2.certificateID == ui.id)
    }

    @Test func prefersExactThenFewestExtraNames() throws {
        let m = model()
        let wildcard = ManagedCertificate(name: "wild", domains: ["*.example.com"])
        let broad = ManagedCertificate(name: "broad", domains: ["nas.example.com", "a.example.com", "b.example.com"])
        let narrow = ManagedCertificate(name: "narrow", domains: ["nas.example.com", "a.example.com"])
        [wildcard, broad, narrow].forEach(m.addCertificate)
        let ep = try endpoint(["nas.example.com"])
        #expect(m.adoptionCandidates(for: ep).map(\.name) == ["wild", "narrow", "broad"])

        let exact = ManagedCertificate(name: "exact", domains: ["nas.example.com"])
        m.addCertificate(exact)
        #expect(m.automaticAdoptionTarget(for: ep)?.name == "exact")
    }

    @Test func explicitTargets() throws {
        let m = model()
        let host = ManagedHost(name: "nas", address: "nas.lan"); m.addHost(host)
        let ui = ManagedCertificate(name: "nas", domains: ["nas.example.com"]); m.addCertificate(ui)
        let ep = try endpoint(["nas.example.com", "www.nas.example.com"])
        // Attaching to a cert that lacks a name is allowed when chosen explicitly.
        #expect(m.adopt(ep, hostID: host.id, target: .existing(ui.id)).certificateID == ui.id)
        m.deleteDeployment(m.inventory.deployments[0].id)
        // .new always creates one, even when an exact match exists.
        let exact = ManagedCertificate(name: "both", domains: ["nas.example.com", "www.nas.example.com"]); m.addCertificate(exact)
        let d = m.adopt(ep, hostID: host.id, target: .new)
        #expect(d.certificateID != exact.id)
        #expect(m.inventory.certificates.count == 3)
    }

    @Test func truenasNginxIsHidden() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-tn-nginx-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (pem, _) = try selfSigned(["nas.example.com"])
        try pem.write(to: dir.appendingPathComponent("ui.pem"), atomically: true, encoding: .utf8)
        for (name, body) in [
            ("nginx", "#!/bin/sh\necho 'server { server_name localhost; ssl_certificate \(dir.path)/ui.pem; ssl_certificate_key \(dir.path)/ui.key; }' | tr ';' '\\n' | sed 's/$/;/'"),
            ("midclt", "#!/bin/sh\nexit 1"),
        ] {
            try body.write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.appendingPathComponent(name).path)
        }
        let withMidclt = Discovery.parse(try runShell(Discovery.script, path: dir.path))
        #expect(!withMidclt.endpoints.contains { $0.kind == .nginx })

        try FileManager.default.removeItem(at: dir.appendingPathComponent("midclt"))
        let plain = Discovery.parse(try runShell(Discovery.script, path: dir.path))
        #expect(plain.endpoints.contains { $0.kind == .nginx }, "same nginx is found on a non-TrueNAS host")
    }
}
