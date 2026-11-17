import Foundation
@testable import CertKeeperCore

// Child processes for tests. On Linux, Foundation's Process passes the launching thread's blocked
// signals on to the child (see CleanSpawn), so a test server couldn't be stopped and a stand-in
// nginx master would never see its HUP. Linux uses CleanSpawn; macOS keeps Process.

/// Runs a tool to completion and returns its exit status and output.
func runTool(_ path: String, _ args: [String], environment: [String: String]? = nil, stdin: Data = Data()) throws -> (status: Int32, stdout: Data, stderr: Data) {
    SSHRunner.ignoreSIGPIPE()
    #if os(Linux)
    let r = try CleanSpawn.run(path, args, environment: environment, stdin: stdin)
    return (r.status, r.stdout, r.stderr)
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
    // Read both streams concurrently so neither can fill up and stall the tool.
    var errData = Data()
    let reader = Thread { errData = errors.fileHandleForReading.readDataToEndOfFile() }
    reader.start()
    try? input.fileHandleForWriting.write(contentsOf: stdin)
    try? input.fileHandleForWriting.close()
    let out = output.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    while reader.isExecuting { Thread.sleep(forTimeInterval: 0.01) }
    return (p.terminationStatus, out, errData)
    #endif
}

/// A long-running child (a TLS server, a stand-in nginx master) with its output discarded.
final class TestProcess: @unchecked Sendable {
    #if os(Linux)
    let processIdentifier: Int32
    private var exitSignalValue: Int32?
    private var reaped = false

    init(_ path: String, _ args: [String]) throws { processIdentifier = try CleanSpawn.launch(path, args) }

    var isRunning: Bool {
        guard !reaped else { return false }
        var status: Int32 = 0
        guard waitpid(processIdentifier, &status, WNOHANG) == processIdentifier else { return true }
        record(status)
        return false
    }

    func waitUntilExit() {
        guard !reaped else { return }
        var status: Int32 = 0
        while waitpid(processIdentifier, &status, 0) == -1 && errno == EINTR {}
        record(status)
    }

    /// The signal that ended the process, if one did.
    var exitSignal: Int32? { exitSignalValue }

    func terminate() { if !reaped { kill(processIdentifier, SIGTERM) } }

    private func record(_ status: Int32) {
        reaped = true
        let signal = status & 0x7f
        exitSignalValue = signal == 0 ? nil : signal
    }
    #else
    private let process = Process()

    init(_ path: String, _ args: [String]) throws {
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.standardInput = Pipe()
        try process.run()
    }

    var processIdentifier: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }
    func waitUntilExit() { process.waitUntilExit() }
    var exitSignal: Int32? { process.terminationReason == .uncaughtSignal ? process.terminationStatus : nil }
    func terminate() { process.terminate() }
    #endif

    func stop() { terminate(); waitUntilExit() }
}
