import Foundation
import SwiftASN1
import Testing
@testable import CertKeeperCore

/// Fake Pi-hole v6 host: `pihole-FTL --config KEY [VALUE]` backed by a key=value file, plus
/// recording `systemctl` and an optional fake `docker` for containerized Pi-hole.
struct FakePihole {
    let dir: URL
    var bin: URL { dir.appendingPathComponent("bin") }
    var etc: URL { dir.appendingPathComponent("etc-pihole") }
    var tls: URL { etc.appendingPathComponent("tls.pem") }
    var log: String { (try? String(contentsOf: dir.appendingPathComponent("calls.log"), encoding: .utf8)) ?? "" }

    init(native: Bool = true, docker: Bool = false, port: String = "80o,443os,[::]:80o,[::]:443os") throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-pihole-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: etc, withIntermediateDirectories: true)
        let conf = dir.appendingPathComponent("pihole.conf")
        let tlsKey = docker ? "/etc/pihole/tls.pem" : tls.path
        try "webserver.tls.cert=\"\(tlsKey)\"\nwebserver.domain=\"pi.hole\"\nwebserver.port=\"\(port)\"\n"
            .write(to: conf, atomically: true, encoding: .utf8)
        let log = dir.appendingPathComponent("calls.log").path
        let ftl = """
        #!/bin/sh
        [ "$1" = --config ] || exit 1
        if [ $# -ge 3 ]; then echo "set $2=$3" >> \(log); exit 0; fi
        sed -n "s/^$2=//p" \(conf.path)
        """
        var tools = ["systemctl": "#!/bin/sh\necho \"systemctl $*\" >> \(log)\n"]
        if native { tools["pihole-FTL"] = ftl }
        try ftl.write(to: dir.appendingPathComponent("ftl-impl"), atomically: true, encoding: .utf8)
        if docker {
            tools["docker"] = """
            #!/bin/sh
            case "$1" in
              ps) echo "pihole pihole/pihole:2026.09.0"; echo "web nginx:latest" ;;
              exec) shift 3; exec sh \(dir.path)/ftl-impl "$@" ;;
              inspect) printf '/etc/pihole %s\\n/etc/dnsmasq.d %s/dnsmasq\\n' "\(etc.path)" "\(dir.path)" ;;
              port) [ "$3" = 443/tcp ] && echo "0.0.0.0:8443" ;;
              restart) echo "docker restart $2" >> \(log) ;;
            esac
            """
        }
        for (name, body) in tools {
            let url = bin.appendingPathComponent(name)
            try body.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }
    }

    /// Writes a tls.pem the way FTL does: private key, then certificate.
    func installSelfSigned(_ name: String = "pi.hole") throws {
        let (cert, key) = try selfSigned([name])
        try (key + cert).write(to: tls, atomically: true, encoding: .utf8)
    }

    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

@Suite struct PiholeTests {
    func issued(_ names: [String]) throws -> (ManagedCertificate, String) {
        let (leaf, key) = try selfSigned(names)
        let (chain, _) = try selfSigned(["Fake Intermediate"])
        var c = ManagedCertificate(name: names[0], domains: names)
        c.leafPEM = leaf
        c.chainPEM = chain
        return (c, key)
    }

    @Test func discoversNativePihole() throws {
        let ph = try FakePihole()
        defer { ph.cleanup() }
        try ph.installSelfSigned()
        let report = Discovery.parse(try runShell(Discovery.script, path: ph.bin.path))
        let ep = try #require(report.endpoints.first { $0.kind == .pihole })
        #expect(ep.label == "Web UI (pi.hole)")
        #expect(ep.certPath == ph.tls.path)
        #expect(ep.summary?.dnsNames == ["pi.hole"], "cert read past the key block")
        #expect(ep.options?["verify_port"] == "443")
        #expect(ep.options?["pihole_set_domain"] == "true")
        #expect(ep.note == nil)
    }

    @Test func notesWhenHTTPSIsOff() throws {
        let ph = try FakePihole(port: "80o,[::]:80o")
        defer { ph.cleanup() }
        try ph.installSelfSigned()
        let ep = try #require(Discovery.parse(try runShell(Discovery.script, path: ph.bin.path)).endpoints.first { $0.kind == .pihole })
        #expect(ep.note?.contains("HTTPS is not enabled") == true)
        #expect(ep.options?["verify_port"] == nil)
    }

    @Test func discoversDockerPihole() throws {
        let ph = try FakePihole(native: false, docker: true)
        defer { ph.cleanup() }
        try ph.installSelfSigned()
        let report = Discovery.parse(try runShell(Discovery.script, path: ph.bin.path))
        let eps = report.endpoints.filter { $0.kind == .pihole }
        #expect(eps.count == 1, "only the pihole image, not other containers")
        let ep = try #require(eps.first)
        #expect(ep.certPath == ph.tls.path, "container path mapped to the host volume")
        #expect(ep.options?["restart_target"] == "pihole")
        #expect(ep.options?["verify_port"] == "8443", "published host port")
    }

    @Test func deployWritesKeyAndChainSetsDomainAndRestarts() throws {
        let ph = try FakePihole()
        defer { ph.cleanup() }
        try ph.installSelfSigned()
        let (c, key) = try issued(["pihole.example.com"])
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .pihole)
        d.certPath = ph.tls.path
        let out = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: ph.bin.path)
        #expect(out.contains("restarted pihole-FTL"))
        #expect(ph.log.contains("set webserver.domain=pihole.example.com"))
        #expect(ph.log.contains("systemctl restart pihole-FTL"))

        let written = try String(contentsOf: ph.tls, encoding: .utf8)
        let docs = try PEMDocument.parseMultiple(pemString: written)
        #expect(docs.map(\.discriminator) == ["PRIVATE KEY", "CERTIFICATE", "CERTIFICATE"], "key, leaf, intermediate")
        #expect(CertCrypto.keyMatches(certPEM: written, keyPEM: docs[0].pemString))

        // The rotation check reads the combined file the same way.
        let probed = try runShell(Discovery.probeScript(path: ph.tls.path, pkcs12: false), path: ph.bin.path)
        #expect(try CertCrypto.summarize(pem: probed).sha256 == c.current?.sha256 ?? CertCrypto.summarize(pem: c.leafPEM!).sha256)
    }

    @Test func wildcardOrOptOutLeavesDomainAlone() throws {
        let ph = try FakePihole()
        defer { ph.cleanup() }
        try ph.installSelfSigned()
        let (wild, key) = try issued(["*.example.com", "example.com"])
        var d = Deployment(certificateID: wild.id, hostID: UUID(), kind: .pihole)
        d.certPath = ph.tls.path
        _ = try runShell(try DeployScripts.build(deployment: d, certificate: wild, keyPEM: key), path: ph.bin.path)
        #expect(!ph.log.contains("set webserver.domain"))

        let (c, key2) = try issued(["pihole.example.com"])
        var d2 = Deployment(certificateID: c.id, hostID: UUID(), kind: .pihole)
        d2.certPath = ph.tls.path
        d2.options = ["pihole_set_domain": "false"]
        _ = try runShell(try DeployScripts.build(deployment: d2, certificate: c, keyPEM: key2), path: ph.bin.path)
        #expect(!ph.log.contains("set webserver.domain"))
    }

    @Test func dockerDeployRestartsContainer() throws {
        let ph = try FakePihole(native: false, docker: true)
        defer { ph.cleanup() }
        try ph.installSelfSigned()
        let (c, key) = try issued(["pihole.example.com"])
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .pihole)
        d.certPath = ph.tls.path
        d.options = ["restart_target": "pihole"]
        let out = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: ph.bin.path)
        #expect(out.contains("restarted container pihole"))
        #expect(ph.log.contains("set webserver.domain=pihole.example.com"), "set through docker exec")
        #expect(ph.log.contains("docker restart pihole"))
        #expect(!ph.log.contains("systemctl"))
    }

    @MainActor @Test func adoptSetsVerifyEndpointFromPort() throws {
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"), secrets: MemorySecretStore())
        let host = ManagedHost(name: "pi-hole", address: "pi-hole.example.com"); m.addHost(host)
        let (pem, _) = try selfSigned(["pi.hole"])
        var ep = DiscoveredEndpoint(kind: .pihole, label: "Web UI (pi.hole)", certPath: "/etc/pihole/tls.pem",
                                    keyPath: "/etc/pihole/tls.pem", chainPath: "", summary: try CertCrypto.summarize(pem: pem))
        ep.options = ["pihole_set_domain": "true", "verify_port": "443"]
        let d = m.adopt(ep, hostID: host.id)
        #expect(d.verifyEndpoint == "pi-hole.example.com:443")
        #expect(d.flag(.piholeSetDomain))
        #expect(m.isManaged(ep, hostID: host.id))
    }
}
