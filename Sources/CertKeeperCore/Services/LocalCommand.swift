import Foundation

/// Runs a local tool to completion: CleanSpawn on Linux (see there for why), Process on macOS.
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
        #if os(Linux)
        let r = try CleanSpawn.run(path, args, environment: environment, stdin: stdin, timeout: timeout)
        return Output(status: r.status, stdout: r.stdout, stderr: r.stderr)
        #else
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        if let environment { p.environment = environment }
        let input = Pipe(), output = Pipe(), errors = Pipe()
        p.standardInput = input
        p.standardOutput = output
        p.standardError = errors
        try p.run()
        let collected = Collected()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async { collected.setErr(errors.fileHandleForReading.readDataToEndOfFile()); group.leave() }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { if p.isRunning { p.terminate() } }
        try? input.fileHandleForWriting.write(contentsOf: stdin)
        try? input.fileHandleForWriting.close()
        let out = output.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        group.wait()
        return Output(status: p.terminationStatus, stdout: out, stderr: collected.err)
        #endif
    }

    #if !os(Linux)
    private final class Collected: @unchecked Sendable {
        private let lock = NSLock()
        private var e = Data()
        func setErr(_ d: Data) { lock.lock(); e = d; lock.unlock() }
        var err: Data { lock.lock(); defer { lock.unlock() }; return e }
    }
    #endif
}
