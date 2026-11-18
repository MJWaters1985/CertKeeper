import Foundation

/// Runs a local tool to completion (through CleanSpawn; see there for why not Process).
public enum LocalCommand {
    public struct Output: Sendable {
        public var status: Int32
        public var stdout: Data
        public var stderr: Data
        public var succeeded: Bool { status == 0 }
    }

    public static func run(_ path: String, _ args: [String], environment: [String: String]? = nil,
                           stdin: Data = Data(), timeout: TimeInterval = 120) throws -> Output {
        SSHRunner.ignoreSIGPIPE()
        let r = try CleanSpawn.run(path, args, environment: environment, stdin: stdin, timeout: timeout)
        return Output(status: r.status, stdout: r.stdout, stderr: r.stderr)
    }
}
