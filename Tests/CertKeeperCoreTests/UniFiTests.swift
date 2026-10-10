import Foundation
import Testing
@testable import CertKeeperCore

/// A UniFi OS Server host under a fake root: rootless podman volume in /home/uosserver, plus stubs for
/// runuser/podman/systemctl/id that record what they're asked to do.
struct FakeUOS {
    let root: URL
    var bin: URL { root.appendingPathComponent("bin") }
    var dir: URL { root.appendingPathComponent("home/uosserver/.local/share/containers/storage/volumes/uosserver_data/_data/unifi-core/config") }
    var log: String { (try? String(contentsOf: root.appendingPathComponent("calls.log"), encoding: .utf8)) ?? "" }

    init(inContainerRestartWorks: Bool = true) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("ck-uos-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let (cert, key) = try selfSigned(["unifi.local"])
        try cert.write(to: dir.appendingPathComponent("unifi-core.crt"), atomically: true, encoding: .utf8)
        try key.write(to: dir.appendingPathComponent("unifi-core.key"), atomically: true, encoding: .utf8)
        let log = root.appendingPathComponent("calls.log").path
        let tools = [
            "runuser": "#!/bin/sh\necho \"runuser $*\" >> \(log)\nwhile [ \"$1\" != -- ]; do shift; done; shift\nexec \"$@\"",
            "podman": "#!/bin/sh\necho \"podman $* XDG=$XDG_RUNTIME_DIR\" >> \(log)\nexit \(inContainerRestartWorks ? 0 : 125)",
            "systemctl": "#!/bin/sh\necho \"systemctl $*\" >> \(log)\nexit 0",
            "id": "#!/bin/sh\necho 1001",
        ]
        for (name, body) in tools {
            let url = bin.appendingPathComponent(name)
            try body.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }
    }

    var env: [String: String] { ["CK_ROOT": root.path] }
    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

@Suite struct UniFiTests {
    @Test func discoversUniFiOSServerVolume() throws {
        let uos = try FakeUOS()
        defer { uos.cleanup() }
        let report = Discovery.parse(try runShell(Discovery.script, path: uos.bin.path, env: uos.env))
        let ep = try #require(report.endpoints.first { $0.kind == .unifiOS })
        #expect(ep.label == "UniFi OS Server (unifi-core)")
        #expect(ep.certPath == uos.dir.path + "/unifi-core.crt")
        #expect(ep.options?["unifi_dir"] == uos.dir.path)
        #expect(ep.options?["verify_port"] == "11443")
        #expect(ep.summary?.dnsNames == ["unifi.local"])
    }

    @Test func consoleLayoutStillFoundOnPort443() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ck-udm-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let dir = root.appendingPathComponent("data/unifi-core/config")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try selfSigned(["udm.lan"]).0.write(to: dir.appendingPathComponent("unifi-core.crt"), atomically: true, encoding: .utf8)
        let ep = try #require(Discovery.parse(try runShell(Discovery.script, path: "/usr/bin", env: ["CK_ROOT": root.path]))
            .endpoints.first { $0.kind == .unifiOS })
        #expect(ep.label == "UniFi OS console (unifi-core)")
        #expect(ep.options?["verify_port"] == nil)
    }

    func deploy(_ uos: FakeUOS) throws -> (ManagedCertificate, String, String) {
        let (leaf, key) = try selfSigned(["unifi.example.com"])
        var c = ManagedCertificate(name: "unifi.example.com", domains: ["unifi.example.com"])
        c.leafPEM = leaf
        c.chainPEM = ""
        var d = Deployment(certificateID: c.id, hostID: UUID(), kind: .unifiOS)
        d.options = ["unifi_dir": uos.dir.path]
        return (c, key, try DeployScripts.build(deployment: d, certificate: c, keyPEM: key))
    }

    @Test func restartsUnifiCoreInsideTheRootlessContainer() throws {
        let uos = try FakeUOS()
        defer { uos.cleanup() }
        let (c, key, script) = try deploy(uos)
        let out = try runShell(script, path: uos.bin.path, env: uos.env)
        #expect(out.contains("restarted unifi-core inside the uosserver container"))
        let owner = try FileManager.default.attributesOfItem(atPath: uos.root.appendingPathComponent("home/uosserver").path)[.ownerAccountName] as? String
        #expect(uos.log.contains("runuser -u \(owner ?? "?") -- env XDG_RUNTIME_DIR=/run/user/1001 podman exec uosserver systemctl restart unifi-core"),
                "runs podman as the volume's owner with its runtime dir")
        #expect(!uos.log.contains("systemctl restart uosserver"))
        let crt = try String(contentsOf: uos.dir.appendingPathComponent("unifi-core.crt"), encoding: .utf8)
        #expect(crt.contains(c.leafPEM!.trimmingCharacters(in: .whitespacesAndNewlines)))
        #expect(CertCrypto.keyMatches(certPEM: crt, keyPEM: try String(contentsOf: uos.dir.appendingPathComponent("unifi-core.key"), encoding: .utf8)))
        _ = key
    }

    @Test func fallsBackToRestartingTheService() throws {
        let uos = try FakeUOS(inContainerRestartWorks: false)
        defer { uos.cleanup() }
        let out = try runShell(try deploy(uos).2, path: uos.bin.path, env: uos.env)
        #expect(out.contains("restarted the uosserver service"))
        #expect(uos.log.contains("systemctl cat uosserver.service"))
        #expect(uos.log.contains("systemctl restart uosserver"))
    }

    @Test func missingFolderFailsClearly() throws {
        let uos = try FakeUOS()
        defer { uos.cleanup() }
        var d = Deployment(certificateID: UUID(), hostID: UUID(), kind: .unifiOS)
        d.options = ["unifi_dir": "/nonexistent/unifi-core/config"]
        let (leaf, key) = try selfSigned(["u"])
        var c = ManagedCertificate(name: "u", domains: ["u"]); c.leafPEM = leaf; c.chainPEM = ""
        #expect(throws: DeployError.self) {
            try runShell(try DeployScripts.build(deployment: d, certificate: c, keyPEM: key), path: uos.bin.path, env: uos.env)
        }
    }
}

@Suite struct PipeSafetyTests {
    /// A remote script that exits early closes ssh's stdin while CertKeeper is still writing; that used
    /// to raise SIGPIPE and kill the app. Same code path, with a local process standing in for ssh.
    @Test func earlyExitWithLargeInputDoesNotCrash() async throws {
        SSHRunner.ignoreSIGPIPE()
        let big = String(repeating: "echo filler line to overflow the pipe buffer\n", count: 25_000)  // ~1 MB
        let r = try await SSHRunner.execute("/bin/sh", ["-c", "exit 3"], stdin: big, timeout: 30)
        #expect(r.status == 3)
    }
}

@Suite struct StdinShieldTests {
    /// What hid UniFi OS Server: a command that reads stdin swallows the rest of a script piped to `sh -s`.
    let script = """
    echo before
    cat > /dev/null
    echo after
    """

    @Test func unshieldedScriptLosesEverythingAfterAStdinReader() async throws {
        SSHRunner.ignoreSIGPIPE()
        let r = try await SSHRunner.execute("/bin/sh", ["-s"], stdin: script, timeout: 30)
        #expect(r.stdout.contains("before"))
        #expect(!r.stdout.contains("after"), "reproduces the bug: the rest of the script was eaten")
    }

    @Test func shieldedScriptRunsCompletely() async throws {
        SSHRunner.ignoreSIGPIPE()
        let r = try await SSHRunner.execute("/bin/sh", ["-s"], stdin: SSHRunner.shielded(script), timeout: 30)
        #expect(r.stdout == "before\nafter\n")
        #expect(r.status == 0)
    }

    @Test func shieldedKeepsHeredocsTrapsAndExitCodes() async throws {
        SSHRunner.ignoreSIGPIPE()
        let s = """
        set -eu
        trap 'echo cleaned' EXIT
        cat <<'X'
        heredoc text
        X
        exit 7
        """
        let r = try await SSHRunner.execute("/bin/sh", ["-s"], stdin: SSHRunner.shielded(s), timeout: 30)
        #expect(r.stdout == "heredoc text\ncleaned\n")
        #expect(r.status == 7)
    }
}
