import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct LogRetentionTests {
    let model = AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"),
                         secrets: MemorySecretStore())

    func entry(daysAgo: Double, _ message: String) -> LogEntry {
        var e = LogEntry(.info, message)
        e.date = Date().addingTimeInterval(-daysAgo * 86_400)
        return e
    }

    @Test func defaultKeepsNinetyDays() {
        model.inventory.log = [entry(daysAgo: 1, "recent"), entry(daysAgo: 89, "edge"), entry(daysAgo: 91, "old"), entry(daysAgo: 400, "ancient")]
        model.pruneLog()
        #expect(model.inventory.log.map(\.message) == ["recent", "edge"])
    }

    @Test func customRetentionAndLoggingPrunes() {
        model.inventory.settings.logRetentionDays = 7
        model.inventory.log = [entry(daysAgo: 3, "keep"), entry(daysAgo: 8, "drop")]
        model.log(.info, "new")
        #expect(model.inventory.log.map(\.message) == ["new", "keep"])
    }

    @Test func entryCapStillApplies() {
        model.inventory.log = (0..<1_200).map { entry(daysAgo: Double($0) / 100, "e\($0)") }  // all within 12 days
        model.pruneLog()
        #expect(model.inventory.log.count == 1_000)
        #expect(model.inventory.log.first?.message == "e0", "newest kept")
    }

    @Test func valuesAreClamped() {
        var s = AppSettings()
        #expect(s.effectiveLogRetentionDays == 90)
        s.logRetentionDays = 0
        #expect(s.effectiveLogRetentionDays == 1)
        s.logRetentionDays = 5_000
        #expect(s.effectiveLogRetentionDays == 365)
    }

    @Test func settingsFromEarlierVersionsDecode() throws {
        let old = #"{"acmeEmail":"","useStaging":true,"renewDaysBeforeExpiry":30,"checkIntervalHours":12,"autoDeploy":true,"dnsPropagationTimeout":300,"acceptedTermsOfService":true}"#
        let s = try JSONDecoder().decode(AppSettings.self, from: Data(old.utf8))
        #expect(s.logRetentionDays == nil && s.effectiveLogRetentionDays == 90)
    }
}
