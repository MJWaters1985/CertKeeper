import Foundation

/// Runs commands on remote hosts using the system OpenSSH client, so ~/.ssh/config,
/// ssh-agent, hardware keys and known_hosts all work as they do in Terminal.
///
/// Scripts are sent on stdin to `sh -s`, which avoids remote quoting problems.
public struct SSHRunner: Sendable {
    public struct Result: Sendable {
        public let status: Int32
        public let stdout: String
        public let stderr: String
        public var succeeded: Bool { status == 0 }
    }

    public struct SSHError: LocalizedError {
        public let message: String
        public let result: Result?
        public var errorDescription: String? { message }
    }

    public var sshPath = "/usr/bin/ssh"
    public var connectTimeout = 15
    /// Executable ssh calls (via SSH_ASKPASS) to obtain a login password. It must answer using
    /// `AskPass.response(prompt:environment:)` — the CertKeeper app binary does this when launched
    /// with CK_ASKPASS_HOST set.
    public var askpassPath: String?
    /// Looks up a host's stored password. Injectable for tests.
    public var passwordLookup: @Sendable (UUID) -> String? = { Keychain.get(.hostPassword($0)) }

    /// `sh -s` reads its script from stdin, and dash (Ubuntu/Debian's /bin/sh) reads a pipe ahead in
    /// blocks, so any command in the script that also reads stdin swallows the rest of the script,
    /// which then silently never runs (that hid UniFi OS Server from discovery). A brace group must be
    /// read completely before it runs, and `</dev/null` gives every command inside an empty stdin.
    public static func shielded(_ script: String) -> String {
        "{\n\(script)\n} </dev/null\n"
    }

    /// Writing to a pipe whose reader has exited raises SIGPIPE, which kills the process by default.
    /// A remote script that exits early (e.g. a failed precondition) closes ssh's stdin while a large
    /// script is still being written, so processes driving SSHRunner must ignore it. Idempotent.
    public static func ignoreSIGPIPE() { signal(SIGPIPE, SIG_IGN) }

    public init(askpassPath: String? = nil) {
        self.askpassPath = askpassPath
    }

    static var controlDirectory: URL {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("CertKeeper", isDirectory: true)
    }

    func usesPasswordLogin(_ host: ManagedHost) -> Bool {
        host.passwordLogin && askpassPath != nil && passwordLookup(host.id) != nil
    }

    func arguments(for host: ManagedHost, remoteCommand: String) -> [String] {
        var args: [String] = []
        if usesPasswordLogin(host) {
            args += [
                "-o", "BatchMode=no",
                "-o", "PreferredAuthentications=publickey,keyboard-interactive,password",
                "-o", "NumberOfPasswordPrompts=1",
            ]
        } else {
            args += ["-o", "BatchMode=yes"]
        }
        args += [
            "-o", "ConnectTimeout=\(connectTimeout)",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=15",
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=\(Self.controlDirectory.path)/cm-%C",
            "-o", "ControlPersist=60",
            "-p", String(host.port),
        ]
        if !host.identityFile.isEmpty {
            args += ["-i", (host.identityFile as NSString).expandingTildeInPath, "-o", "IdentitiesOnly=yes"]
        }
        let target = host.username.isEmpty ? host.address : "\(host.username)@\(host.address)"
        args += [target, remoteCommand]
        return args
    }

    func environment(for host: ManagedHost) -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        if usesPasswordLogin(host), let askpassPath {
            env["SSH_ASKPASS"] = askpassPath
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env[AskPass.hostVariable] = host.id.uuidString
        }
        return env
    }

    /// Runs `script` with `sh` on the host, elevated through sudo when the host asks for it.
    public func run(_ script: String, on host: ManagedHost, privileged: Bool = true, timeout: TimeInterval = 300) async throws -> Result {
        try? FileManager.default.createDirectory(at: Self.controlDirectory, withIntermediateDirectories: true)
        var remote = "sh -s"
        var input = Self.shielded(script)
        if privileged && host.useSudo {
            if let password = passwordLookup(host.id), try await !passwordlessSudo(host) {
                // -k forces a prompt even with cached credentials, so the first stdin line is always
                // consumed as the password and never reaches sh. NOPASSWD was ruled out above.
                remote = "sudo -k -S -p '' sh -s"
                input = password + "\n" + Self.shielded(script)
            } else {
                remote = "sudo -n sh -s"
            }
        }
        return try await Self.execute(sshPath, arguments(for: host, remoteCommand: remote),
                                      environment: environment(for: host), stdin: input, timeout: timeout)
    }

    /// Whether `sudo -n` works for this host's user (cached per host for the session).
    func passwordlessSudo(_ host: ManagedHost) async throws -> Bool {
        if let cached = SudoCache.shared.get(host) { return cached }
        let r = try await Self.execute(sshPath, arguments(for: host, remoteCommand: "sudo -n true"),
                                       environment: environment(for: host), stdin: "", timeout: 60)
        if r.status == 255 {
            throw SSHError(message: "SSH to \(host.name) failed: \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))", result: r)
        }
        SudoCache.shared.set(host, r.succeeded)
        return r.succeeded
    }

    /// Like `run`, but throws when the script exits non-zero.
    public func runChecked(_ script: String, on host: ManagedHost, privileged: Bool = true, timeout: TimeInterval = 300) async throws -> Result {
        let r = try await run(script, on: host, privileged: privileged, timeout: timeout)
        guard r.succeeded else {
            let detail = [r.stderr, r.stdout].map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }.joined(separator: "\n")
            throw SSHError(message: "Remote command on \(host.name) failed (exit \(r.status))\n\(detail)", result: r)
        }
        return r
    }

    static func execute(_ path: String, _ args: [String], environment: [String: String]? = nil, stdin: String, timeout: TimeInterval) async throws -> Result {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args
            if let environment { process.environment = environment }
            let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
            process.standardInput = inPipe
            process.standardOutput = outPipe
            process.standardError = errPipe

            let group = DispatchGroup()
            var outData = Data(), errData = Data()
            group.enter()
            DispatchQueue.global().async { outData = outPipe.fileHandleForReading.readDataToEndOfFile(); group.leave() }
            group.enter()
            DispatchQueue.global().async { errData = errPipe.fileHandleForReading.readDataToEndOfFile(); group.leave() }

            process.terminationHandler = { p in
                group.notify(queue: .global()) {
                    continuation.resume(returning: Result(
                        status: p.terminationStatus,
                        stdout: String(decoding: outData, as: UTF8.self),
                        stderr: String(decoding: errData, as: UTF8.self)
                    ))
                }
            }
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
                return
            }
            DispatchQueue.global().async {
                // If the remote side exits before reading everything, this fails with EPIPE rather than
                // crashing, provided SIGPIPE is ignored (see SSHRunner.ignoreSIGPIPE).
                try? inPipe.fileHandleForWriting.write(contentsOf: Data(stdin.utf8))
                try? inPipe.fileHandleForWriting.close()
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                if process.isRunning { process.terminate() }
            }
        }
    }
}

/// Remembers whether each host allows `sudo -n`, keyed by the settings that affect it.
final class SudoCache: @unchecked Sendable {
    static let shared = SudoCache()
    private let lock = NSLock()
    private var values: [String: Bool] = [:]
    private func key(_ h: ManagedHost) -> String { "\(h.id)|\(h.username)|\(h.address)|\(h.port)" }
    func get(_ h: ManagedHost) -> Bool? { lock.lock(); defer { lock.unlock() }; return values[key(h)] }
    func set(_ h: ManagedHost, _ v: Bool) { lock.lock(); values[key(h)] = v; lock.unlock() }
    func reset() { lock.lock(); values.removeAll(); lock.unlock() }
}

/// SSH_ASKPASS responder. ssh runs the askpass program with the prompt as its argument and reads
/// the answer from stdout; CertKeeper's own binary plays that role when CK_ASKPASS_HOST is set.
public enum AskPass {
    public static let hostVariable = "CK_ASKPASS_HOST"

    /// Returns the password for password prompts only — never for passphrases or host-key questions.
    public static func response(prompt: String, environment: [String: String],
                                lookup: (UUID) -> String? = { Keychain.get(.hostPassword($0)) }) -> String? {
        guard let raw = environment[hostVariable], let id = UUID(uuidString: raw) else { return nil }
        let p = prompt.lowercased()
        guard p.contains("password"), !p.contains("passphrase") else { return nil }
        return lookup(id)
    }
}

/// Shell quoting helper for values interpolated into remote scripts.
public func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}
