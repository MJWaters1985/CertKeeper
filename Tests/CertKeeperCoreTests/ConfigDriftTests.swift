import Foundation
import Testing
@testable import CertKeeperCore

@Suite struct ConfigDriftTests {
    let kvmConf = "/etc/kvmd/nginx-kvmd.conf"

    func endpoint(_ kind: DeploymentKind, _ path: String, conf: String? = nil) -> DiscoveredEndpoint {
        var ep = DiscoveredEndpoint(kind: kind, label: "x", certPath: path, keyPath: path + ".key", chainPath: "", summary: nil)
        if let conf { ep.options = ["nginx_conf": conf, "nginx_prefix": "/etc/kvmd/nginx"] }
        return ep
    }

    func kvmDeployment(_ path: String) -> Deployment {
        var d = Deployment(certificateID: UUID(), hostID: UUID(), kind: .nginx)
        d.certPath = path
        d.options = ["nginx_conf": kvmConf, "nginx_prefix": "/etc/kvmd/nginx"]
        return d
    }

    /// The basement KVM after its config reset: the kvmd nginx now reads the vendor's files.
    @Test func reportsMovedPath() throws {
        let d = kvmDeployment("/etc/letsencrypt/live/basement-kvm.example.com/fullchain.pem")
        let found = [endpoint(.nginx, "/etc/kvmd/user/ssl/server.crt", conf: kvmConf),
                     endpoint(.nginx, "/etc/ssl/other.pem")]  // the system nginx, a different instance
        let usage = try #require(Discovery.configStillUses(d, in: found))
        #expect(!usage.inUse)
        #expect(usage.current == ["/etc/kvmd/user/ssl/server.crt"], "only the same nginx instance counts")
    }

    @Test func stillInUse() throws {
        let d = kvmDeployment("/etc/kvmd/user/ssl/server.crt")
        let usage = try #require(Discovery.configStillUses(d, in: [endpoint(.nginx, "/etc/kvmd/user/ssl/server.crt", conf: kvmConf)]))
        #expect(usage.inUse)
    }

    @Test func unknownWhenTheServerWasntFound() {
        let d = kvmDeployment("/etc/kvmd/user/ssl/server.crt")
        #expect(Discovery.configStillUses(d, in: [endpoint(.nginx, "/etc/ssl/other.pem")]) == nil, "no false alarm")
        #expect(Discovery.configStillUses(d, in: []) == nil)
    }

    @Test func apacheAndOtherKinds() throws {
        var a = Deployment(certificateID: UUID(), hostID: UUID(), kind: .apache)
        a.certPath = "/etc/ssl/old.pem"
        let usage = try #require(Discovery.configStillUses(a, in: [endpoint(.apache, "/etc/ssl/new.pem")]))
        #expect(!usage.inUse && usage.current == ["/etc/ssl/new.pem"])
        #expect(Discovery.configStillUses(Deployment(certificateID: UUID(), hostID: UUID(), kind: .proxmox), in: []) == nil)
    }

    @Test func attentionSurvivesSaveAndOldFilesDecode() throws {
        var d = kvmDeployment("/x")
        d.attention = "nginx no longer reads /x"
        let data = try JSONEncoder().encode(d)
        #expect(try JSONDecoder().decode(Deployment.self, from: data).attention == d.attention)
        let old = #"{"id":"\#(UUID())","certificateID":"\#(UUID())","hostID":"\#(UUID())","kind":"nginx"}"#
        #expect(try JSONDecoder().decode(Deployment.self, from: Data(old.utf8)).attention == nil)
    }
}
