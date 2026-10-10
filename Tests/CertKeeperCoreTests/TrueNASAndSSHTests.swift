import Foundation
import Testing
@testable import CertKeeperCore

/// A fake `midclt` backed by a JSON state file, implementing the middleware calls CertKeeper uses.
let fakeMidclt = #"""
#!/usr/bin/env python3
import json, os, sys
STATE = os.environ["FAKE_TRUENAS_STATE"]
s = json.load(open(STATE))
STYLE = os.environ.get("FAKE_MIDCLT_STYLE", "new")
args = sys.argv[2:]
if args and args[0] in ("-h", "--help"):
    print("usage: midclt call [-h] [-j] [-jp {description,percent}] method [args ...]\n  -j, --job" if STYLE == "new"
          else "usage: midclt call [-h] [-job] [-jp {description,percent}] method [args ...]\n  -job")
    sys.exit(0)
if args and args[0].startswith("-"):
    allowed = ("-j", "--job") if STYLE == "new" else ("-job",)
    if args[0] not in allowed:
        print("midclt: error: unrecognized arguments: " + args[0], file=sys.stderr)
        sys.exit(2)
    args = args[1:]
method, params = args[0], [json.loads(a) if a[:1] in "[{0123456789" else a for a in args[1:]]
s.setdefault("calls", []).append(method)

def match(c, flt):
    for field, op, val in flt:
        v = c.get(field)
        if op == "=" and v != val: return False
        if op == "!=" and v == val: return False
        if op == "^" and not str(v).startswith(val): return False
    return True

def out(x):
    json.dump(s, open(STATE, "w"))
    print(json.dumps(x))
    sys.exit(0)

if method == "certificate.create":
    p = params[0]
    s["next_id"] += 1
    s["certs"].append({"id": s["next_id"], "name": p["name"], "certificate": p["certificate"]})
    out(s["certs"][-1])
if method == "certificate.query":
    rows = [c for c in s["certs"] if match(c, params[0] if params else [])]
    if len(params) > 1 and params[1].get("get"):
        out(rows[0])
    out(rows)
if method == "certificate.delete":
    s["certs"] = [c for c in s["certs"] if c["id"] != params[0]]
    out(True)
if method == "system.general.config":
    out({"ui_certificate": {"id": s["ui"]}})
if method == "system.general.update":
    s["ui"] = params[0]["ui_certificate"]
    out({})
if method == "system.general.ui_restart":
    out(None)
if method == "app.query":
    out([{"name": n, "config": cfg, "active_workloads": s.get("workloads", {}).get(n, {})} for n, cfg in s["apps"].items()])
if method == "app.redeploy":
    s.setdefault("redeployed", []).append(params[0])
    out({})
if method == "app.update":
    if params[0] in s.get("fail_updates", []):
        json.dump(s, open(STATE, "w"))
        print("[EFAULT] update failed", file=sys.stderr)
        sys.exit(1)
    s["apps"][params[0]] = params[1]["values"]
    out({})
print("unknown method " + method, file=sys.stderr)
sys.exit(1)
"""#

struct FakeTrueNAS {
    let dir: URL
    var stateURL: URL { dir.appendingPathComponent("state.json") }

    var style = "new"

    init(state: [String: Any], style: String = "new") throws {
        self.style = style
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-truenas-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let midclt = dir.appendingPathComponent("midclt")
        try fakeMidclt.write(to: midclt, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: midclt.path)
        try JSONSerialization.data(withJSONObject: state).write(to: stateURL)
    }

    var state: [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(contentsOf: stateURL))) as? [String: Any] ?? [:]
    }
    var certIDs: [Int] { (state["certs"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? Int }.sorted() }
    func appCert(_ app: String) -> Int? {
        ((state["apps"] as? [String: Any])?[app] as? [String: Any]).flatMap { ($0["network"] as? [String: Any])?["certificate_id"] as? Int }
    }

    func run(_ script: String) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-s"]
        p.environment = ["PATH": "\(dir.path):/usr/bin:/bin", "FAKE_TRUENAS_STATE": stateURL.path, "FAKE_MIDCLT_STYLE": style,
                         "TMPDIR": FileManager.default.temporaryDirectory.path]
        let input = Pipe(), output = Pipe(), err = Pipe()
        p.standardInput = input; p.standardOutput = output; p.standardError = err
        try p.run()
        SSHRunner.ignoreSIGPIPE(); try? input.fileHandleForWriting.write(contentsOf: Data(SSHRunner.shielded(script).utf8))
        try input.fileHandleForWriting.close()
        let out = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let errText = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw DeployError("exit \(p.terminationStatus)\n\(out)\n\(errText)") }
        return out
    }

    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

@Suite struct TrueNASAppTests {
    /// certs: 1 = older CertKeeper import (UI + nextcloud), 2 = manual cert (minio),
    ///        3 = even older CertKeeper import (unused); plex has TLS off.
    func scenario(failUpdates: [String] = [], style: String = "new") throws -> FakeTrueNAS {
        try FakeTrueNAS(state: [
            "next_id": 3,
            "ui": 1,
            "certs": [
                ["id": 1, "name": "certkeeper_www_example_com_20260101000000", "certificate": ""],
                ["id": 2, "name": "manual-wildcard", "certificate": ""],
                ["id": 3, "name": "certkeeper_www_example_com_20251001000000", "certificate": ""],
            ],
            "apps": [
                "nextcloud": ["network": ["certificate_id": 1, "web_port": 30027]],
                "minio": ["network": ["certificate_id": 2]],
                "plex": ["network": ["certificate_id": NSNull()]],
            ],
            "fail_updates": failUpdates,
        ], style: style)
    }

    func script(apps: String, ui: Bool = true) throws -> String {
        let (leaf, key) = try selfSigned(["www.example.com"])
        var c = ManagedCertificate(name: "www", domains: ["www.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .truenas)
        d.options = ["truenas_apps": apps, "truenas_ui": ui ? "true" : "false"]
        return try DeployScripts.build(deployment: d, certificate: c, keyPEM: key)
    }

    @Test(arguments: ["new", "old"])
    func repointsAppsAndPrunesUnreferencedCerts(midcltStyle: String) throws {
        let nas = try scenario(style: midcltStyle)
        defer { nas.cleanup() }
        let out = try nas.run(try script(apps: "minio"))
        #expect(nas.state["ui"] as? Int == 4)
        #expect(nas.appCert("nextcloud") == 4, "older CertKeeper copy is repointed automatically")
        #expect(nas.appCert("minio") == 4, "named app is switched from the manual cert")
        #expect(nas.appCert("plex") == nil, "apps with TLS off are left alone")
        #expect(nas.certIDs == [2, 4], "old CertKeeper imports deleted, manual cert kept")
        #expect(out.contains("web UI restart scheduled"))
        // other settings in the app config survive the update
        let nc = (nas.state["apps"] as? [String: Any])?["nextcloud"] as? [String: Any]
        #expect((nc?["network"] as? [String: Any])?["web_port"] as? Int == 30027)
    }

    @Test func appsOnlyLeavesUIAlone() throws {
        let nas = try scenario()
        defer { nas.cleanup() }
        _ = try nas.run(try script(apps: "", ui: false))
        #expect(nas.state["ui"] as? Int == 1)
        #expect(nas.appCert("nextcloud") == 4)
        #expect(nas.certIDs == [1, 2, 4], "cert 1 is kept because the UI still uses it")
    }

    @Test func failedAppUpdateKeepsItsCertificateAndFails() throws {
        let nas = try scenario(failUpdates: ["nextcloud"])
        defer { nas.cleanup() }
        #expect(throws: DeployError.self) { try nas.run(try script(apps: "")) }
        #expect(nas.appCert("nextcloud") == 1)
        #expect(nas.certIDs.contains(1), "never delete a cert an app still references")
        #expect(!nas.certIDs.contains(3))
    }

    @Test func unknownNamedAppFails() throws {
        let nas = try scenario()
        defer { nas.cleanup() }
        #expect(throws: DeployError.self) { try nas.run(try script(apps: "jellyfin")) }
    }

    @Test func discoveryListsUIAndApps() throws {
        let (pem, _) = try selfSigned(["nas.example.com"])
        let nas = try FakeTrueNAS(state: [
            "next_id": 2, "ui": 1,
            "certs": [["id": 1, "name": "ui-cert", "certificate": pem], ["id": 2, "name": "app-cert", "certificate": pem]],
            "apps": ["nextcloud": ["network": ["certificate_id": 2]], "plex": ["network": ["certificate_id": NSNull()]]],
        ])
        defer { nas.cleanup() }
        let report = Discovery.parse(try nas.run(Discovery.script))
        let truenas = report.endpoints.filter { $0.kind == .truenas }
        #expect(truenas.map(\.certPath) == ["ui", "app:nextcloud"])
        #expect(truenas.allSatisfy { $0.summary?.dnsNames == ["nas.example.com"] })
    }
}

@Suite @MainActor struct TrueNASModelTests {
    func model() -> AppModel {
        AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"))
    }

    @Test func adoptingUIAndAppsMergesIntoOneDeployment() throws {
        let m = model()
        let (pem, _) = try selfSigned(["nas.example.com"])
        let s = try CertCrypto.summarize(pem: pem)
        let host = ManagedHost(name: "nas", address: "nas.lan")
        m.addHost(host)
        let app = DiscoveredEndpoint(kind: .truenas, label: "App: nextcloud", certPath: "app:nextcloud", keyPath: "", chainPath: "", summary: s)
        let ui = DiscoveredEndpoint(kind: .truenas, label: "Web UI", certPath: "ui", keyPath: "", chainPath: "", summary: s)
        m.adopt(app, hostID: host.id)
        #expect(m.inventory.deployments.first?.flag(.truenasUI) == false)
        #expect(m.isManaged(app, hostID: host.id))
        #expect(!m.isManaged(ui, hostID: host.id))
        m.adopt(ui, hostID: host.id)
        m.adopt(DiscoveredEndpoint(kind: .truenas, label: "App: minio", certPath: "app:minio", keyPath: "", chainPath: "", summary: s), hostID: host.id)
        #expect(m.inventory.deployments.count == 1)
        let d = try #require(m.inventory.deployments.first)
        #expect(d.flag(.truenasUI))
        #expect(d.truenasApps == ["nextcloud", "minio"])
    }

    @Test func relevantEndpointsCoverUIAndNamedApps() {
        let s = CertificateSummary(subject: "", issuer: "", serial: "", notBefore: .now, notAfter: .now, dnsNames: [], sha256: "a")
        let eps = [
            DiscoveredEndpoint(kind: .truenas, label: "UI", certPath: "ui", keyPath: "", chainPath: "", summary: s),
            DiscoveredEndpoint(kind: .truenas, label: "nc", certPath: "app:nextcloud", keyPath: "", chainPath: "", summary: s),
        ]
        var d = Deployment(certificateID: UUID(), hostID: UUID(), kind: .truenas)
        d.options = ["truenas_apps": "nextcloud, gone"]
        let r = Discovery.relevantEndpoints(for: d, in: eps)
        #expect(r.map(\.certPath) == ["ui", "app:nextcloud", "app:gone"])
        #expect(r.last?.summary == nil, "missing app shows up as not deployed")
    }

    @Test func oldInventoryWithoutNewFieldsStillLoads() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let hostID = UUID(), certID = UUID()
        let legacy = """
        {"hosts":[{"id":"\(hostID)","name":"pve","address":"pve.lan","port":22,"username":"root","identityFile":"","useSudo":false,"notes":"","lastDiscovery":[]}],
         "certificates":[],"deployments":[{"id":"\(UUID())","certificateID":"\(certID)","hostID":"\(hostID)","kind":"proxmox","certPath":"","keyPath":"","chainPath":"","verifyEndpoint":"","enabled":true}],
         "settings":{"acmeEmail":"","useStaging":true,"renewDaysBeforeExpiry":30,"checkIntervalHours":12,"autoDeploy":true,"dnsPropagationTimeout":300,"acceptedTermsOfService":false},
         "log":[],"acmeAccounts":{}}
        """
        try legacy.write(to: url, atomically: true, encoding: .utf8)
        let m = AppModel(fileURL: url)
        #expect(m.loadError == nil)
        #expect(m.inventory.hosts.first?.passwordLogin == false)
        #expect(m.inventory.deployments.first?.options == [:])
    }

    @Test func unreadableInventoryIsMovedAsideNotOverwritten() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("inventory.json")
        try "{ not json".write(to: url, atomically: true, encoding: .utf8)
        let m = AppModel(fileURL: url)
        #expect(m.loadError != nil)
        m.addHost(ManagedHost(name: "x", address: "x"))
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        let backup = try #require(files.first { $0.contains("unreadable") })
        #expect(try String(contentsOf: dir.appendingPathComponent(backup), encoding: .utf8) == "{ not json")
    }
}

@Suite struct ContainerAppTests {
    @Test func installsFilesAndRestartsContainer() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString)")
        let bin = dir.appendingPathComponent("bin")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = dir.appendingPathComponent("docker.log").path
        try """
        #!/bin/sh
        echo "$@" >> \(log)
        [ "$1" = inspect ] && [ "$4" = proxy ] && exit 0
        [ "$1" = restart ] && exit 0
        exit 1
        """.write(to: bin.appendingPathComponent("docker"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin.appendingPathComponent("docker").path)

        let (leaf, key) = try selfSigned(["proxy.example.com"])
        var c = ManagedCertificate(name: "proxy", domains: ["proxy.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .containerApp)
        d.certPath = dir.appendingPathComponent("certs/fullchain.pem").path
        d.keyPath = dir.appendingPathComponent("certs/privkey.pem").path
        d.options = ["restart_target": "proxy"]
        let out = try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: bin.path)
        #expect(out.contains("restarted container proxy"))
        #expect(try String(contentsOfFile: log, encoding: .utf8).contains("restart proxy"))
        #expect(CertCrypto.keyMatches(certPEM: try String(contentsOfFile: d.certPath, encoding: .utf8),
                                      keyPEM: try String(contentsOfFile: d.keyPath, encoding: .utf8)))
        let mode = try FileManager.default.attributesOfItem(atPath: d.keyPath)[.posixPermissions] as? Int
        #expect(mode == 0o600)
    }
}

@Suite struct PasswordAuthTests {
    @Test func askpassOnlyAnswersPasswordPrompts() {
        let id = UUID()
        let env = [AskPass.hostVariable: id.uuidString]
        let lookup: (UUID) -> String? = { $0 == id ? "s3cret" : nil }
        #expect(AskPass.response(prompt: "root@nas's password: ", environment: env, lookup: lookup) == "s3cret")
        #expect(AskPass.response(prompt: "(root@nas) Password:", environment: env, lookup: lookup) == "s3cret")
        #expect(AskPass.response(prompt: "Enter passphrase for key '/x': ", environment: env, lookup: lookup) == nil)
        #expect(AskPass.response(prompt: "Are you sure you want to continue connecting (yes/no)?", environment: env, lookup: lookup) == nil)
        #expect(AskPass.response(prompt: "password:", environment: [:], lookup: lookup) == nil)
    }

    /// Uses a fake ssh that records its arguments, environment and stdin.
    func fakeSSH(sudoNeedsPassword: Bool) throws -> (SSHRunner, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-ssh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let ssh = dir.appendingPathComponent("ssh")
        try """
        #!/bin/sh
        for last; do :; done
        if [ "$last" = "sudo -n true" ]; then exit \(sudoNeedsPassword ? 1 : 0); fi
        { echo "ARGS $*"; echo "ASKPASS ${SSH_ASKPASS:-none} ${SSH_ASKPASS_REQUIRE:-none} ${CK_ASKPASS_HOST:-none}"; echo "REMOTE $last"; cat; } > \(dir.path)/capture
        """.write(to: ssh, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: ssh.path)
        var runner = SSHRunner(askpassPath: "/Applications/CertKeeper.app/Contents/MacOS/CertKeeper")
        runner.sshPath = ssh.path
        runner.passwordLookup = { _ in "s3cret" }
        return (runner, dir)
    }

    @Test func passwordLoginAndSudoPassword() async throws {
        let (runner, dir) = try fakeSSH(sudoNeedsPassword: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var host = ManagedHost(name: "nas-\(UUID())", address: "nas.lan", username: "admin")
        host.passwordLogin = true
        host.useSudo = true
        _ = try await runner.run("echo hi", on: host)
        let capture = try String(contentsOf: dir.appendingPathComponent("capture"), encoding: .utf8)
        #expect(capture.contains("BatchMode=no"))
        #expect(capture.contains("ASKPASS /Applications/CertKeeper.app/Contents/MacOS/CertKeeper force \(host.id.uuidString)"))
        #expect(capture.contains("REMOTE sudo -k -S -p '' sh -s"))
        #expect(capture.contains("REMOTE sudo -k -S -p '' sh -s\ns3cret\n{\necho hi\n} </dev/null"))
        #expect(!capture.contains("ARGS") || !capture.components(separatedBy: "\n")[0].contains("s3cret"), "password never in argv")
    }

    @Test func nopasswdSudoNeverSendsPassword() async throws {
        let (runner, dir) = try fakeSSH(sudoNeedsPassword: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        var host = ManagedHost(name: "pve-\(UUID())", address: "pve.lan")
        host.useSudo = true
        _ = try await runner.run("echo hi", on: host)
        let capture = try String(contentsOf: dir.appendingPathComponent("capture"), encoding: .utf8)
        #expect(capture.contains("REMOTE sudo -n sh -s\n{\necho hi\n} </dev/null"))
        #expect(!capture.contains("s3cret"))
        #expect(capture.contains("BatchMode=yes"), "password login is off for this host")
        #expect(capture.contains("ASKPASS none none none"))
    }
}


/// Recreates apps that terminate TLS themselves (Jellyfin with a .pfx, qBittorrent with PEM files).
@Suite struct AppInternalTLSTests {
    func pfx(_ certPEM: String, _ keyPEM: String, at url: URL, password: String = "") throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let c = dir.appendingPathComponent("tmp-cert.pem"), k = dir.appendingPathComponent("tmp-key.pem")
        try certPEM.write(to: c, atomically: true, encoding: .utf8)
        try keyPEM.write(to: k, atomically: true, encoding: .utf8)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["pkcs12", "-export", "-out", url.path, "-inkey", k.path, "-in", c.path, "-passout", "pass:\(password)"]
        try p.run(); p.waitUntilExit()
        try FileManager.default.removeItem(at: c); try FileManager.default.removeItem(at: k)
        #expect(p.terminationStatus == 0)
    }

    func write(_ text: String, _ url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: url, atomically: true, encoding: .utf8)
    }

    @Test func discoversJellyfinAndQBittorrentCertificates() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ck-apps-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let jf = root.appendingPathComponent("ix-apps/jellyfin/config")
        let qb = root.appendingPathComponent("ix-apps/qbittorrent/config")
        let (jfCert, jfKey) = try selfSigned(["jellyfin.example.com"])
        let (qbCert, _) = try selfSigned(["qbit.example.com"])
        try pfx(jfCert, jfKey, at: jf.appendingPathComponent("ssl/jellyfin.pfx"))
        try write("""
        <?xml version="1.0" encoding="utf-8"?>
        <NetworkConfiguration>
          <EnableHttps>true</EnableHttps>
          <InternalHttpsPort>8920</InternalHttpsPort>
          <CertificatePath>/config/ssl/jellyfin.pfx</CertificatePath>
          <CertificatePassword />
        </NetworkConfiguration>
        """, jf.appendingPathComponent("config/network.xml"))
        try write(qbCert, qb.appendingPathComponent("ssl/cert.pem"))
        try write("""
        [Preferences]
        WebUI\\HTTPS\\Enabled=true
        WebUI\\HTTPS\\CertificatePath=/config/ssl/cert.pem
        WebUI\\HTTPS\\KeyPath=/config/ssl/key.pem
        WebUI\\Port=30024
        """, qb.appendingPathComponent("qBittorrent/qBittorrent.conf"))

        let (uiPEM, _) = try selfSigned(["nas.example.com"])
        let nas = try FakeTrueNAS(state: [
            "next_id": 1, "ui": 1,
            "certs": [["id": 1, "name": "ui", "certificate": uiPEM]],
            "apps": ["jellyfin": ["network": ["web_port": 30013]], "qbittorrent": [:] as [String: Any], "plex": [:] as [String: Any]],
            "workloads": [
                "jellyfin": [
                    "container_details": [["volume_mounts": [
                        ["source": jf.path, "destination": "/config"],
                        ["source": root.appendingPathComponent("media").path, "destination": "/media"],
                    ]]],
                    "used_ports": [["container_port": 8920, "host_ports": [["host_port": 30014, "host_ip": "0.0.0.0"]]]],
                ],
                "qbittorrent": ["container_details": [["volume_mounts": [["source": qb.path, "destination": "/config/"]]]]],
            ],
        ])
        defer { nas.cleanup() }

        let report = Discovery.parse(try nas.run(Discovery.script))
        let apps = report.endpoints.filter { $0.kind == .containerApp }
        let jfEP = try #require(apps.first { $0.label.contains("Jellyfin") })
        #expect(jfEP.certPath == jf.path + "/ssl/jellyfin.pfx")
        #expect(jfEP.summary?.dnsNames == ["jellyfin.example.com"], "certificate read out of the .pfx")
        #expect(jfEP.options?["cert_format"] == "pkcs12")
        #expect(jfEP.options?["restart_target"] == "jellyfin")
        #expect(jfEP.options?["verify_port"] == "30014", "container port 8920 mapped to host port")
        #expect(jfEP.note == nil)

        let qbEP = try #require(apps.first { $0.label.contains("qBittorrent") })
        #expect(qbEP.certPath == qb.path + "/ssl/cert.pem")
        #expect(qbEP.keyPath == qb.path + "/ssl/key.pem")
        #expect(qbEP.summary?.dnsNames == ["qbit.example.com"])
        #expect(qbEP.options?["cert_format"] == "pem")
        #expect(qbEP.options?["verify_port"] == "30024")

        #expect(report.warnings.contains { $0.hasPrefix("app plex:") })
        #expect(!report.warnings.contains { $0.hasPrefix("app jellyfin:") || $0.hasPrefix("app qbittorrent:") })
    }

    @MainActor @Test func adoptingCarriesFormatRestartAndPort() throws {
        let m = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"))
        let (pem, _) = try selfSigned(["jellyfin.example.com"])
        let host = ManagedHost(name: "nas", address: "nas.example.com")
        m.addHost(host)
        var ep = DiscoveredEndpoint(kind: .containerApp, label: "App: jellyfin (Jellyfin HTTPS)", certPath: "/mnt/x/jellyfin.pfx",
                                    keyPath: "", chainPath: "", summary: try CertCrypto.summarize(pem: pem))
        ep.options = ["cert_format": "pkcs12", "restart_target": "jellyfin", "verify_port": "30014", "file_owner": "568:568"]
        let d = m.adopt(ep, hostID: host.id)
        #expect(d.isPKCS12)
        #expect(d.option(.restartTarget) == "jellyfin")
        #expect(d.option(.fileOwner) == "568:568")
        #expect(d.options["verify_port"] == nil)
        #expect(d.verifyEndpoint == "nas.example.com:30014")
        #expect(m.isManaged(ep, hostID: host.id))
    }

    @Test func pkcs12DeployWritesPfxAndRedeploysApp() throws {
        let nas = try FakeTrueNAS(state: ["next_id": 0, "ui": 0, "certs": [], "apps": ["jellyfin": [:] as [String: Any]]])
        defer { nas.cleanup() }
        let target = nas.dir.appendingPathComponent("config/ssl/jellyfin.pfx")
        try write("old", target)
        let (leaf, key) = try selfSigned(["jellyfin.example.com"])
        var c = ManagedCertificate(name: "jf", domains: ["jellyfin.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .containerApp)
        d.certPath = target.path
        d.options = ["cert_format": "pkcs12", "restart_target": "jellyfin"]
        let out = try nas.run(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key))
        #expect(out.contains("redeployed TrueNAS app jellyfin"))
        #expect((nas.state["redeployed"] as? [String]) == ["jellyfin"])
        // Read it back the same way the rotation check does.
        let probed = try nas.run(Discovery.probeScript(path: target.path, pkcs12: true))
        #expect(try CertCrypto.summarize(pem: probed).sha256 == CertCrypto.summarize(pem: leaf).sha256)
        #expect(FileManager.default.fileExists(atPath: target.path + ".certkeeper-" ) == false)
    }
}
