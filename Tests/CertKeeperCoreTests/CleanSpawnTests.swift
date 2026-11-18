import Foundation
import Testing
@testable import CertKeeperCore

@Suite struct CleanSpawnTests {
    /// Many children at once, each launched from Dispatch's shared pool and fed more input than a pipe
    /// holds. When the launcher fed input from that same pool, the blocked launches used up its
    /// threads and every child waited for input forever.
    @Test func manyChildrenStartedFromThePoolAllFinish() {
        SSHRunner.ignoreSIGPIPE()
        let input = Data(repeating: UInt8(ascii: "x"), count: 100_000)
        let group = DispatchGroup()
        let results = Results()
        for _ in 0..<96 {
            DispatchQueue.global().async(group: group) {
                let r = try? CleanSpawn.run("/bin/sh", ["-c", "wc -c"], stdin: input, timeout: 60)
                results.add(r.map { String(decoding: $0.stdout, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) })
            }
        }
        #expect(group.wait(timeout: .now() + 60) == .success, "all finish")
        #expect(results.all.count == 96)
        #expect(results.all.allSatisfy { $0 == "100000" }, "each child read all of its input")
    }

    @Test func timeoutStopsAChildThatNeverExits() throws {
        let start = Date()
        let r = try CleanSpawn.run("/bin/sleep", ["30"], timeout: 1)
        #expect(Date().timeIntervalSince(start) < 10)
        #expect(r.status == SIGTERM, "ended by the timeout's SIGTERM")
    }

    final class Results: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [String?] = []
        func add(_ v: String?) { lock.lock(); values.append(v); lock.unlock() }
        var all: [String?] { lock.lock(); defer { lock.unlock() }; return values }
    }
}
