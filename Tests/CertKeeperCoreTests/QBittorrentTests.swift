import Foundation
import Testing
@testable import CertKeeperCore

/// Fake Ubuntu host with qBittorrent: `ps`, `getent`, `systemctl` and optionally `docker` are stubs.
struct FakeQBHost {
    let dir: URL
    var bin: URL { dir.appendingPathComponent("bin") }
    var home: URL { dir.appendingPathComponent("home/alice") }
    var log: String { (try? String(contentsOf: dir.appendingPathComponent("calls.log"), encoding: .utf8)) ?? "" }

    init(running: Bool, unit: String = "qbittorrent-nox@alice.service", profile: String? = nil,
         dockerMounts: String? = nil) throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-qb-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        let log = dir.appendingPathComponent("calls.log").path
        let args = "/usr/bin/qbittorrent-nox" + (profile.map { " --profile=\($0)" } ?? "")
        var tools = [
            "ps": """
            #!/bin/sh
            case "$*" in
              *pid=,user=,args=*) \(running ? "echo '  4242 alice     \(args)'; echo '  5151 911      /usr/bin/qbittorrent-nox --webui-port=8080'" : ":") ;;
              *"unit= -p 4242"*) echo "\(unit)" ;;
              *"unit= -p 5151"*) echo "docker-0123abcd.scope" ;;
            esac
            """,
            "getent": """
            #!/bin/sh
            if [ $# -ge 2 ]; then [ "$2" = alice ] && echo "alice:x:1000:1000::\(home.path):/bin/bash"; exit 0; fi
            echo "root:x:0:0:root:\(dir.path)/root:/bin/bash"
            echo "alice:x:1000:1000::\(home.path):/bin/bash"
            echo "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
            """,
            "systemctl": """
            #!/bin/sh
            echo "systemctl $*" >> \(log)
            [ "$1" = cat ] && [ "$2" = qbittorrent-nox@alice.service ] && exit 0
            [ "$1" = cat ] && exit 1
            exit 0
            """,
        ]
        if let dockerMounts {
            tools["docker"] = """
            #!/bin/sh
            case "$1" in
              ps) echo "qbittorrent lscr.io/linuxserver/qbittorrent:latest"; echo "web nginx:latest" ;;
              inspect) printf '%s\\n' "\(dockerMounts)" ;;
              port) [ "$3" = 8080/tcp ] && echo "0.0.0.0:18080" ;;
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

    func writeConf(at conf: URL, cert: String, key: String, enabled: Bool = true, port: Int = 8080) throws {
        try FileManager.default.createDirectory(at: conf.deletingLastPathComponent(), withIntermediateDirectories: true)
        try """
        [Preferences]
        WebUI\\Address=*
        WebUI\\HTTPS\\CertificatePath=\(cert)
        WebUI\\HTTPS\\Enabled=\(enabled)
        WebUI\\HTTPS\\KeyPath=\(key)
        WebUI\\Port=\(port)
        """.write(to: conf, atomically: true, encoding: .utf8)
    }

    func writeCert(_ path: String, names: [String] = ["bt.example.com"]) throws {
        let url = URL(fileURLWithPath: path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try selfSigned(names).0.write(to: url, atomically: true, encoding: .utf8)
    }

    func discover() throws -> Discovery.Report { Discovery.parse(try runShell(Discovery.script, path: bin.path)) }
    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

@Suite struct QBittorrentTests {
    @Test func findsRunningServiceAndItsUnit() throws {
        let host = try FakeQBHost(running: true)
        defer { host.cleanup() }
        let cert = host.home.appendingPathComponent("certs/bt.crt").path
        try host.writeCert(cert)
        try host.writeConf(at: host.home.appendingPathComponent(".config/qBittorrent/qBittorrent.conf"),
                           cert: cert, key: host.home.appendingPathComponent("certs/bt.key").path, port: 8443)
        let report = try host.discover()
        let eps = report.endpoints.filter { $0.label.contains("qBittorrent") }
        #expect(eps.count == 1, "container process and home-folder fallback don't duplicate it")
        let ep = try #require(eps.first)
        #expect(ep.kind == .containerApp)
        #expect(ep.label == "qBittorrent Web UI (alice)")
        #expect(ep.certPath == cert)
        #expect(ep.summary?.dnsNames == ["bt.example.com"])
        #expect(ep.options?["restart_target"] == "systemd:qbittorrent-nox@alice.service")
        #expect(ep.options?["verify_port"] == "8443")
        #expect(ep.options?["file_owner"]?.isEmpty == false)
        #expect(ep.note == nil)
    }

    @Test func usesProfileFolder() throws {
        // --profile points outside the home folder
        let profile = FileManager.default.temporaryDirectory.appendingPathComponent("ck-qbprof-\(UUID().uuidString)/srv/qbt")
        defer { try? FileManager.default.removeItem(at: profile.deletingLastPathComponent().deletingLastPathComponent()) }
        let host2 = try FakeQBHost(running: true, profile: profile.path)
        defer { host2.cleanup() }
        let cert = profile.appendingPathComponent("ssl/cert.pem").path
        try host2.writeCert(cert)
        try host2.writeConf(at: profile.appendingPathComponent("qBittorrent/config/qBittorrent.conf"),
                            cert: cert, key: profile.appendingPathComponent("ssl/key.pem").path)
        let ep = try #require(try host2.discover().endpoints.first { $0.label.contains("qBittorrent") })
        #expect(ep.certPath == cert)
    }

    @Test func findsStoppedInstallInHomeFolders() throws {
        let host = try FakeQBHost(running: false)
        defer { host.cleanup() }
        let cert = host.home.appendingPathComponent("certs/bt.crt").path
        try host.writeCert(cert)
        try host.writeConf(at: host.home.appendingPathComponent(".config/qBittorrent/qBittorrent.conf"),
                           cert: cert, key: host.home.appendingPathComponent("certs/bt.key").path, enabled: false)
        let ep = try #require(try host.discover().endpoints.first { $0.label.contains("qBittorrent") })
        #expect(ep.options?["restart_target"] == "systemd:qbittorrent-nox@alice.service", "unit found with systemctl cat")
        #expect(ep.note?.contains("HTTPS is turned off") == true)
    }

    @Test func warnsWhenHTTPSHasNoFiles() throws {
        let host = try FakeQBHost(running: true)
        defer { host.cleanup() }
        try host.writeConf(at: host.home.appendingPathComponent(".config/qBittorrent/qBittorrent.conf"), cert: "", key: "")
        let report = try host.discover()
        #expect(!report.endpoints.contains { $0.label.contains("qBittorrent") })
        #expect(report.warnings.contains { $0.contains("no certificate files configured") })
    }

    @Test func findsDockerContainerAndMapsPaths() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-qbd-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let config = dir.appendingPathComponent("appdata/qbittorrent")
        let host = try FakeQBHost(running: false, dockerMounts: "/config \(config.path)\n/downloads \(dir.path)/downloads")
        defer { host.cleanup() }
        try host.writeCert(config.appendingPathComponent("ssl/cert.pem").path)
        try host.writeConf(at: config.appendingPathComponent("qBittorrent/qBittorrent.conf"),
                           cert: "/config/ssl/cert.pem", key: "/config/ssl/key.pem")
        let ep = try #require(try host.discover().endpoints.first { $0.label.contains("qBittorrent") })
        #expect(ep.label == "qBittorrent Web UI (container qbittorrent)")
        #expect(ep.certPath == config.appendingPathComponent("ssl/cert.pem").path)
        #expect(ep.keyPath == config.appendingPathComponent("ssl/key.pem").path)
        #expect(ep.options?["restart_target"] == "qbittorrent")
        #expect(ep.options?["verify_port"] == "18080", "published host port")
    }

    @Test func deployRestartsSystemdUnit() throws {
        let host = try FakeQBHost(running: true)
        defer { host.cleanup() }
        let cert = host.home.appendingPathComponent("certs/bt.crt").path, key = host.home.appendingPathComponent("certs/bt.key").path
        try host.writeCert(cert)
        try "old key".write(toFile: key, atomically: true, encoding: .utf8)
        let (leaf, keyPEM) = try selfSigned(["bt.example.com"])
        var c = ManagedCertificate(name: "bt.example.com", domains: ["bt.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .containerApp)
        d.certPath = cert
        d.keyPath = key
        d.options = ["restart_target": "systemd:qbittorrent-nox@alice.service"]
        let out = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: keyPEM), path: host.bin.path)
        #expect(out.contains("restarted qbittorrent-nox@alice.service"))
        #expect(host.log.contains("systemctl restart qbittorrent-nox@alice.service"))
        #expect(CertCrypto.keyMatches(certPEM: try String(contentsOfFile: cert, encoding: .utf8),
                                      keyPEM: try String(contentsOfFile: key, encoding: .utf8)))
    }
}
