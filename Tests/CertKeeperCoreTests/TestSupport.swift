import Foundation
@testable import CertKeeperCore

// Child processes for tests go through CleanSpawn, as CertKeeper's own do: Foundation's Process
// passes the launching thread's blocked signals on to the child on Linux, so a test server couldn't
// be stopped and a stand-in nginx master would never see its HUP.

/// Runs a tool to completion and returns its exit status and output.
func runTool(_ path: String, _ args: [String], environment: [String: String]? = nil, stdin: Data = Data()) throws -> (status: Int32, stdout: Data, stderr: Data) {
    SSHRunner.ignoreSIGPIPE()
    let r = try CleanSpawn.run(path, args, environment: environment, stdin: stdin)
    return (r.status, r.stdout, r.stderr)
}

/// A long-running child (a TLS server, a stand-in nginx master) with its output discarded.
final class TestProcess: @unchecked Sendable {
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

    func stop() { terminate(); waitUntilExit() }

    private func record(_ status: Int32) {
        reaped = true
        let signal = status & 0x7f
        exitSignalValue = signal == 0 ? nil : signal
    }
}
