import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct MonitorOnlyTests {
    let store = MemorySecretStore()
    let model: AppModel
    let host = ManagedHost(name: "unifi", address: "certkeeper-test.invalid")

    init() {
        model = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: store)
        model.addHost(host)
    }

    func endpoint(days: Int = 60) throws -> DiscoveredEndpoint {
        let (pem, _) = try selfSigned(["unifi.example.com"], days: days)
        var ep = DiscoveredEndpoint(kind: .unifiOS, label: "UniFi OS Server (unifi-core)", certPath: "/v/unifi-core.crt",
                                    keyPath: "/v/unifi-core.key", chainPath: "", summary: try CertCrypto.summarize(pem: pem))
        ep.options = ["unifi_dir": "/v", "verify_port": "11443"]
        return ep
    }

    @Test func adoptAsMonitorOnly() throws {
        let d = model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        let cert = try #require(model.certificate(d.certificateID))
        #expect(cert.isMonitored)
        #expect(cert.current != nil, "starts from what discovery saw")
        #expect(d.verifyEndpoint == "certkeeper-test.invalid:11443")
        #expect(!model.needsIssuance(cert), "never issued by CertKeeper")
        #expect(!model.needsDeployment(d), "never deployed by CertKeeper")
        // A second monitored endpoint with the same names shares the certificate.
        let d2 = model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        #expect(d2.certificateID == d.certificateID)
    }

    @Test func automaticAdoptionNeverPicksAMonitoredCertificate() throws {
        model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        let ep = try endpoint()
        #expect(model.automaticAdoptionTarget(for: ep) == nil)
    }

    @Test func deploymentStatesFollowTheServedCertificate() throws {
        let d = model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        func set(_ notAfter: Date?, chain: Bool? = true) -> AppModel.DeploymentState {
            let i = model.inventory.deployments.firstIndex { $0.id == d.id }!
            model.inventory.deployments[i].deployedNotAfter = notAfter
            model.inventory.deployments[i].servedChainComplete = chain
            return model.state(of: model.inventory.deployments[i])
        }
        let day = 86_400.0
        #expect(set(nil) == .notCheckedYet)
        #expect(set(Date().addingTimeInterval(60 * day + 600)) == .watching(days: 60))
        #expect(set(Date().addingTimeInterval(10 * day + 600)) == .expiringSoon(days: 10), "default warning window is 14 days")
        #expect(set(Date().addingTimeInterval(-day)) == .expired)
        #expect(set(Date().addingTimeInterval(60 * day), chain: false) == .incompleteChain)
        _ = set(Date().addingTimeInterval(10 * day + 600))
        #expect(model.health(ofHost: host.id).level == .warning)
        _ = set(Date().addingTimeInterval(-day))
        #expect(model.health(ofHost: host.id).level == .problem)
    }

    @Test func switchingToMonitorOnlyDiscardsTheIssuedCopy() throws {
        let (leaf, key) = try selfSigned(["unifi.example.com"])
        var c = ManagedCertificate(name: "unifi.example.com", domains: ["unifi.example.com"])
        c.leafPEM = leaf
        c.current = try CertCrypto.summarize(pem: leaf)
        model.addCertificate(c)
        try store.set(key, for: .certificateKey(c.id))
        var d = Deployment(certificateID: c.id, hostID: host.id, kind: .unifiOS)
        d.deployedSHA256 = "old"; d.forceRedeploy = true
        model.addDeployment(d)

        model.setMonitorOnly(c.id, true)
        let m = try #require(model.certificate(c.id))
        #expect(m.isMonitored && m.leafPEM == nil && m.current == nil)
        #expect(store.get(.certificateKey(c.id)) == nil, "private key discarded")
        #expect(model.inventory.deployments[0].deployedSHA256 == nil && !model.inventory.deployments[0].forceRedeploy)
        #expect(model.state(of: model.inventory.deployments[0]) == .notCheckedYet)

        model.setMonitorOnly(c.id, false)
        #expect(model.needsIssuance(try #require(model.certificate(c.id))), "back to managed: CertKeeper issues a fresh one")
    }

    @Test func deployIsANoOpForMonitoredCertificates() async throws {
        let d = model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        await model.deploy(d.id)
        #expect(!model.inventory.log.contains { $0.message.hasPrefix("Deploying") })
    }

    @Test func emptyEndpointReadsTheHostInsteadOfTLS() async throws {
        let d = model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        let i = model.inventory.deployments.firstIndex { $0.id == d.id }!
        model.inventory.deployments[i].verifyEndpoint = ""
        await model.check(d.id)
        let after = model.inventory.deployments[i]
        #expect(after.lastError?.hasPrefix("Couldn't read the certificate on unifi:") == true, "went over SSH, not TLS")
        #expect(after.lastError?.contains("Couldn't reach") == false)
    }

    @Test func unreachableEndpointIsReportedNotSilentlyIgnored() async throws {
        let d = model.adopt(try endpoint(), hostID: host.id, target: .monitor)
        await model.check(d.id)
        let after = try #require(model.inventory.deployments.first { $0.id == d.id })
        #expect(after.lastError?.contains("Couldn't reach certkeeper-test.invalid:11443") == true)
        #expect(after.lastError?.contains("clear the deployment's TLS endpoint") == true, "suggests the host fallback")
        #expect(model.inventory.log.contains { $0.message.contains("monitor check failed") })
        if case .error = model.state(of: after) {} else { Issue.record("expected an error state") }
    }
}
