import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct SidebarSortTests {
    let model = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())

    @Test func hostsSortLikeFinder() {
        for name in ["pve.example.com", "Office-KVM", "kvm10", "basement-kvm", "kvm2", "nas.example.com"] {
            model.addHost(ManagedHost(name: name, address: name))
        }
        #expect(model.sortedHosts.map(\.name) == ["basement-kvm", "kvm2", "kvm10", "nas.example.com", "Office-KVM", "pve.example.com"])
        #expect(model.inventory.hosts.first?.name == "pve.example.com", "stored order is unchanged")
    }

    @Test func certificatesSortAndTiesKeepTheirOrder() {
        let a = ManagedCertificate(name: "unifi.example.com", domains: ["unifi.example.com"])
        let b = ManagedCertificate(name: "nas.example.com", domains: ["nas.example.com"])
        let c1 = ManagedCertificate(name: "dup", domains: ["one"])
        let c2 = ManagedCertificate(name: "dup", domains: ["two"])
        [a, c1, b, c2].forEach(model.addCertificate)
        #expect(model.sortedCertificates.map(\.id) == [c1.id, c2.id, b.id, a.id])
    }
}
