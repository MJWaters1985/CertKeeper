import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct BusyGuardTests {
    let model = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())

    /// An issued certificate deployed to an unreachable host (.invalid never resolves), with no key stored:
    /// any operation that actually runs leaves a trace (a log entry or lastChecked).
    func setUp() throws -> Deployment {
        let host = ManagedHost(name: "fw", address: "certkeeper-test.invalid")
        model.addHost(host)
        let (pem, _) = try selfSigned(["fw.example.com"])
        var c = ManagedCertificate(name: "fw", domains: ["fw.example.com"])
        c.leafPEM = pem
        c.current = try CertCrypto.summarize(pem: pem)
        model.addCertificate(c)
        let d = Deployment(certificateID: c.id, hostID: host.id, kind: .opnsense)
        model.addDeployment(d)
        return d
    }

    @Test func checkIsSkippedWhileTheDeploymentIsBusy() async throws {
        let d = try setUp()
        await model.withBusy(d.id) { await model.check(d.id) }
        #expect(model.inventory.deployments[0].lastChecked == nil, "no check ran")
        #expect(model.inventory.log.isEmpty)
    }

    @Test func deployIsSkippedWhileAnotherIsRunning() async throws {
        let d = try setUp()
        await model.withBusy(d.id) { await model.deploy(d.id) }
        #expect(model.inventory.log.isEmpty, "the second deploy never started")
    }

    @Test func issuanceIsSkippedWhileTheCertificateIsBusy() async throws {
        let d = try setUp()
        await model.withBusy(d.certificateID) { await model.issue(d.certificateID) }
        #expect(model.inventory.log.isEmpty)
    }

    @Test func checksStillRunWhenIdle() async throws {
        let d = try setUp()
        await model.check(d.id)  // fails: the host doesn't exist
        #expect(model.inventory.deployments[0].lastChecked != nil)
        #expect(model.inventory.log.contains { $0.message.contains("Check failed") })
        #expect(!model.busy.contains(d.id), "busy marker released afterwards")
    }

    @Test func deployStartsWhenIdleAndReleasesTheMarker() async throws {
        // Fails at the missing key, before the follow-up check (performCheck, which bypasses the guard
        // because the deploy already holds the marker). This only proves the deploy starts and cleans up.
        let d = try setUp()
        await model.deploy(d.id)
        #expect(model.inventory.log.contains { $0.message.hasPrefix("Deploy failed") })
        #expect(!model.busy.contains(d.id))
    }
}
