import Foundation
import Testing
@testable import CertKeeperCore

/// A GL.iNet KVM-style host: the web UI is a second nginx started with its own -p/-c, serving
/// certbot-style symlinked files. /proc is faked; the "master" is a real child process.
struct FakeKVM {
    let dir: URL
    var bin: URL { dir.appendingPathComponent("bin") }
    var proc: URL { dir.appendingPathComponent("proc") }
    var prefix: String { dir.appendingPathComponent("etc/kvmd/nginx").path }
    var conf: String { dir.appendingPathComponent("etc/kvmd/nginx-kvmd.conf").path }
    var live: URL { dir.appendingPathComponent("etc/letsencrypt/live/basement-kvm.example.com") }
    var log: String { (try? String(contentsOf: dir.appendingPathComponent("calls.log"), encoding: .utf8)) ?? "" }

    init(configTestPasses: Bool = true) throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-kvm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: URL(fileURLWithPath: prefix), withIntermediateDirectories: true)
        let log = dir.appendingPathComponent("calls.log").path
        // nginx -T only knows the kvmd instance; the default config has no TLS.
        let nginx = """
        #!/bin/sh
        echo "nginx $*" >> \(log)
        case "$*" in
          *"-c \(conf) -T"*)
            echo "server {"
            echo "    listen 443 ssl;"
            echo "    ssl_certificate \(live.path)/fullchain.pem;"
            echo "    ssl_certificate_key \(live.path)/privkey.pem;"
            echo "}" ;;
          *-T*) echo "server { listen 80; }" ;;
          *-t*) exit \(configTestPasses ? 0 : 1) ;;
        esac
        """
        try nginx.write(to: bin.appendingPathComponent("nginx"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin.appendingPathComponent("nginx").path)

        // certbot layout: live/ symlinks into archive/
        let archive = dir.appendingPathComponent("etc/letsencrypt/archive/basement-kvm.example.com")
        try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: live, withIntermediateDirectories: true)
        let (cert, key) = try selfSigned(["basement-kvm.example.com"])
        try cert.write(to: archive.appendingPathComponent("fullchain1.pem"), atomically: true, encoding: .utf8)
        try key.write(to: archive.appendingPathComponent("privkey1.pem"), atomically: true, encoding: .utf8)
        for (link, target) in [("fullchain.pem", "fullchain1.pem"), ("privkey.pem", "privkey1.pem")] {
            try FileManager.default.createSymbolicLink(atPath: live.appendingPathComponent(link).path,
                                                       withDestinationPath: "../../archive/basement-kvm.example.com/\(target)")
        }
    }

    /// Registers `pid` in the fake /proc with an nginx process title.
    func addProcess(_ pid: Int32, _ title: String) throws {
        let d = proc.appendingPathComponent(String(pid))
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        try title.write(to: d.appendingPathComponent("cmdline"), atomically: true, encoding: .utf8)
    }

    func masterTitle() -> String {
        "nginx: master process /usr/sbin/nginx -p \(prefix) -c \(conf) -g pid /run/kvmd/nginx.pid; user root; error_log stderr;"
    }

    var env: [String: String] { ["CK_PROC": proc.path] }
    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

/// A real child process standing in for the nginx master, so we can see the HUP arrive.
func spawnSleeper() throws -> TestProcess {
    try TestProcess("/bin/sleep", ["60"])
}

@Suite struct NginxInstanceTests {
    @Test func discoversSeparateInstance() throws {
        let kvm = try FakeKVM()
        defer { kvm.cleanup() }
        try kvm.addProcess(1120, kvm.masterTitle())
        try kvm.addProcess(1121, "nginx: worker process")
        let report = Discovery.parse(try runShell(Discovery.script, path: kvm.bin.path, env: kvm.env))
        let ep = try #require(report.endpoints.first { $0.kind == .nginx })
        #expect(ep.certPath == kvm.live.path + "/fullchain.pem")
        #expect(ep.keyPath == kvm.live.path + "/privkey.pem")
        #expect(ep.label.contains("[\(kvm.conf)]"))
        #expect(ep.summary?.dnsNames == ["basement-kvm.example.com"], "read through the symlink")
        #expect(ep.options?["nginx_conf"] == kvm.conf)
        #expect(ep.options?["nginx_prefix"] == kvm.prefix)
        #expect(kvm.log.contains("-p \(kvm.prefix) -c \(kvm.conf) -T"))
    }

    @Test func relativeCertPathsResolveAgainstConfigDirectory() throws {
        let kvm = try FakeKVM()
        defer { kvm.cleanup() }
        try kvm.addProcess(1120, kvm.masterTitle())
        try """
        #!/bin/sh
        case "$*" in *-T*) printf 'server {\\n ssl_certificate ssl/server.crt;\\n ssl_certificate_key ssl/server.key;\\n}\\n' ;; esac
        """.write(to: kvm.bin.appendingPathComponent("nginx"), atomically: true, encoding: .utf8)
        let ep = try #require(Discovery.parse(try runShell(Discovery.script, path: kvm.bin.path, env: kvm.env)).endpoints.first { $0.kind == .nginx })
        let confDir = (kvm.conf as NSString).deletingLastPathComponent
        #expect(ep.certPath == confDir + "/ssl/server.crt")
    }

    func deploy(_ kvm: FakeKVM) throws -> (ManagedCertificate, String, Deployment) {
        let (leaf, key) = try selfSigned(["basement-kvm.example.com"])
        var c = ManagedCertificate(name: "basement-kvm.example.com", domains: ["basement-kvm.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .nginx)
        d.certPath = kvm.live.path + "/fullchain.pem"
        d.keyPath = kvm.live.path + "/privkey.pem"
        d.options = ["nginx_conf": kvm.conf, "nginx_prefix": kvm.prefix]
        return (c, key, d)
    }

    @Test func deployTestsAndReloadsThatInstanceOnly() throws {
        let kvm = try FakeKVM()
        defer { kvm.cleanup() }
        let master = try spawnSleeper()
        let other = try spawnSleeper()   // a system nginx master that must not be touched
        defer { other.terminate() }
        try kvm.addProcess(master.processIdentifier, kvm.masterTitle())
        try kvm.addProcess(other.processIdentifier, "nginx: master process /usr/sbin/nginx -g daemon off;")

        let (c, key, d) = try deploy(kvm)
        let out = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: kvm.bin.path, env: kvm.env)
        #expect(out.contains("master pid \(master.processIdentifier)"))
        #expect(kvm.log.contains("nginx -p \(kvm.prefix) -c \(kvm.conf) -t"))
        master.waitUntilExit()
        #expect(master.exitSignal == SIGHUP)
        #expect(other.isRunning)

        // written through the certbot symlinks
        let installed = try String(contentsOfFile: d.certPath, encoding: .utf8)
        #expect(CertCrypto.keyMatches(certPEM: installed, keyPEM: try String(contentsOfFile: d.keyPath, encoding: .utf8)))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: d.certPath).hasSuffix("fullchain1.pem"), "symlink kept")
        let probed = try runShell(Discovery.probeScript(path: d.certPath, pkcs12: false), path: kvm.bin.path)
        #expect(try CertCrypto.summarize(pem: probed).sha256 == CertCrypto.summarize(pem: c.leafPEM!).sha256)
    }

    @Test func failedConfigTestRollsBackWithoutSignalling() throws {
        let kvm = try FakeKVM(configTestPasses: false)
        defer { kvm.cleanup() }
        let master = try spawnSleeper()
        defer { master.terminate() }
        try kvm.addProcess(master.processIdentifier, kvm.masterTitle())
        let before = try String(contentsOfFile: kvm.live.path + "/fullchain.pem", encoding: .utf8)
        let (c, key, d) = try deploy(kvm)
        #expect(throws: DeployError.self) {
            try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: kvm.bin.path, env: kvm.env)
        }
        #expect(try String(contentsOfFile: d.certPath, encoding: .utf8) == before)
        #expect(master.isRunning)
    }

    @Test func notRunningIsReportedAsFailure() throws {
        let kvm = try FakeKVM()
        defer { kvm.cleanup() }
        let (c, key, d) = try deploy(kvm)
        #expect(throws: DeployError.self) {
            try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: kvm.bin.path, env: kvm.env)
        }
    }
}
