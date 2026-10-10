import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct HostHealthTests {
    let model: AppModel
    let host = ManagedHost(name: "nas", address: "nas.lan")
    let issued: ManagedCertificate
    let pending = ManagedCertificate(name: "new", domains: ["new.example.com"])

    init() throws {
        model = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())
        let (pem, _) = try selfSigned(["nas.example.com"])
        var c = ManagedCertificate(name: "nas", domains: ["nas.example.com"])
        c.leafPEM = pem
        c.current = try CertCrypto.summarize(pem: pem)
        issued = c
        model.addHost(host)
        model.addCertificate(issued)
        model.addCertificate(pending)
    }

    @discardableResult
    func add(current: Bool = true, cert: ManagedCertificate? = nil, _ tweak: (inout Deployment) -> Void = { _ in }) -> Deployment {
        let c = cert ?? issued
        var d = Deployment(certificateID: c.id, hostID: host.id, kind: .nginx)
        if current { d.deployedSHA256 = c.current?.sha256 }
        tweak(&d)
        model.addDeployment(d)
        return d
    }

    @Test func unmanagedHost() {
        #expect(model.health(ofHost: host.id) == .init(level: .unmanaged, summary: "No managed deployments"))
    }

    @Test func allCurrent() {
        add(); add()
        #expect(model.health(ofHost: host.id) == .init(level: .current, summary: "All 2 deployments current"))
    }

    @Test func singleCurrent() {
        add()
        #expect(model.health(ofHost: host.id).summary == "1 deployment current")
    }

    @Test func outOfDateAndIncompleteChainWarn() {
        add(); add(current: false); add { $0.servedChainComplete = false }
        let h = model.health(ofHost: host.id)
        #expect(h.level == .warning)
        #expect(h.summary == "1 out of date, 1 with an incomplete chain (of 3 deployments)")
    }

    @Test func problemsOutrankEverything() {
        add(current: false)
        add { $0.attention = "nginx no longer reads /x" }
        add { $0.lastError = "SSH failed" }
        let h = model.health(ofHost: host.id)
        #expect(h.level == .problem)
        #expect(h.summary.hasPrefix("2 need attention, 1 out of date"))
    }

    @Test func awaitingIssuanceIsPendingNotAWarning() {
        add(); add(current: false, cert: pending)
        let h = model.health(ofHost: host.id)
        #expect(h.level == .pending)
        #expect(h.summary == "1 awaiting issuance (of 2 deployments)")
    }

    @Test func disabledDeploymentsDontCount() {
        add()
        add(current: false) { $0.enabled = false }
        add { $0.enabled = false; $0.attention = "ignored" }
        #expect(model.health(ofHost: host.id) == .init(level: .current, summary: "1 deployment current"))
    }

    @Test func otherHostsDontLeakIn() {
        let other = ManagedHost(name: "pve", address: "pve.lan")
        model.addHost(other)
        var d = Deployment(certificateID: issued.id, hostID: other.id, kind: .proxmox)
        d.attention = "broken"
        model.addDeployment(d)
        add()
        #expect(model.health(ofHost: host.id).level == .current)
        #expect(model.health(ofHost: other.id).level == .problem)
    }

    @Test func stateOrderMatchesTheBadges() {
        let d = add(current: false) { $0.lastError = "x"; $0.attention = "y" }
        #expect(model.state(of: d) == .attention("y"), "attention wins over an error")
        let e = add(current: false) { $0.lastError = "x" }
        #expect(model.state(of: e) == .error("x"))
        let p = add(current: false, cert: pending)
        #expect(model.state(of: p) == .awaitingIssuance)
    }
}
