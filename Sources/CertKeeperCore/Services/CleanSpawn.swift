#if os(Linux)
import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Starts child processes on Linux with a clean signal state, in place of Foundation's `Process`.
///
/// On Linux, `Process` hands each child the signal mask of the thread that launched it, and
/// Dispatch's worker threads block nearly every signal. A child started from async code therefore
/// can't be stopped with SIGTERM, and tools that rely on signals (`timeout` uses SIGALRM) never fire.
/// This launcher uses posix_spawn with an empty mask and default dispositions (SIGPIPE included,
/// which CertKeeper itself ignores), and creates its pipes close-on-exec so no other child holds
/// them open. macOS's `Process` already does both.
enum CleanSpawn {
    struct Output {
        /// The exit code, or the signal number when a signal ended the process (as `Process` reports).
        var status: Int32
        var stdout: Data
        var stderr: Data
    }

    struct SpawnError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Runs `path` to completion, feeding it `stdin` and collecting its output. After `timeout` it
    /// gets SIGTERM, then SIGKILL two seconds later if it's still running.
    static func run(_ path: String, _ args: [String], environment: [String: String]? = nil, directory: String? = nil,
                    stdin: Data = Data(), timeout: TimeInterval? = nil) throws -> Output {
        // Pipes are made and the child spawned under one lock: between pipe() and FD_CLOEXEC a
        // concurrent spawn could otherwise inherit them and hold them open.
        spawnLock.lock()
        var fds: [Int32] = []
        let input: (read: Int32, write: Int32), output: (read: Int32, write: Int32), errors: (read: Int32, write: Int32)
        let pid: pid_t
        do {
            input = try makePipe(); fds += [input.read, input.write]
            output = try makePipe(); fds += [output.read, output.write]
            errors = try makePipe(); fds += [errors.read, errors.write]
            pid = try spawn(path, args, environment: environment, directory: directory,
                            stdio: (input.read, output.write, errors.write))
        } catch {
            spawnLock.unlock()
            fds.forEach { close($0) }
            throw error
        }
        close(input.read); close(output.write); close(errors.write)
        spawnLock.unlock()

        let group = DispatchGroup()
        let collected = Collected()
        group.enter()
        DispatchQueue.global().async { collected.setOut(readAll(output.read)); close(output.read); group.leave() }
        group.enter()
        DispatchQueue.global().async { collected.setErr(readAll(errors.read)); close(errors.read); group.leave() }
        DispatchQueue.global().async {
            // A child that exits without reading everything makes this fail with EPIPE, which is fine
            // because CertKeeper ignores SIGPIPE (SSHRunner.ignoreSIGPIPE).
            writeAll(input.write, stdin)
            close(input.write)
        }

        let state = ExitState()
        if let timeout {
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                guard state.signalIfRunning(pid, SIGTERM) else { return }
                DispatchQueue.global().asyncAfter(deadline: .now() + 2) { _ = state.signalIfRunning(pid, SIGKILL) }
            }
        }
        // Wait for the exit without reaping, so the timeout can't signal a recycled PID, then reap.
        var info = siginfo_t()
        while waitid(P_PID, id_t(pid), &info, WEXITED | WNOWAIT) == -1 && errno == EINTR {}
        state.markExited()
        var raw: Int32 = 0
        while waitpid(pid, &raw, 0) == -1 && errno == EINTR {}
        group.wait()
        // Decoded by hand: Swift doesn't import the WIFEXITED family of macros.
        let signal = raw & 0x7f
        let status = signal == 0 ? (raw >> 8) & 0xff : signal
        return Output(status: status, stdout: collected.out, stderr: collected.err)
    }

    /// Starts a long-running process with stdin, stdout and stderr on /dev/null; the caller stops it
    /// with `kill` and reaps it with `waitpid`.
    static func launch(_ path: String, _ args: [String], environment: [String: String]? = nil) throws -> pid_t {
        spawnLock.lock()
        defer { spawnLock.unlock() }
        let null = open("/dev/null", O_RDWR | O_CLOEXEC)
        guard null >= 0 else { throw SpawnError(message: "Couldn't open /dev/null: \(String(cString: strerror(errno)))") }
        defer { close(null) }
        return try spawn(path, args, environment: environment, directory: nil, stdio: (null, null, null))
    }

    private static func spawn(_ path: String, _ args: [String], environment: [String: String]?, directory: String?,
                              stdio: (Int32, Int32, Int32)) throws -> pid_t {
        var actions = posix_spawn_file_actions_t()
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        // dup2 onto 0/1/2 clears close-on-exec for those three only.
        posix_spawn_file_actions_adddup2(&actions, stdio.0, 0)
        posix_spawn_file_actions_adddup2(&actions, stdio.1, 1)
        posix_spawn_file_actions_adddup2(&actions, stdio.2, 2)
        #if canImport(Glibc)
        // Nothing else open in this process reaches the child, whether or not it was close-on-exec.
        // (musl has no closefrom; there the close-on-exec pipes made under spawnLock have to do.)
        posix_spawn_file_actions_addclosefrom_np(&actions, 3)
        #endif
        if let directory { posix_spawn_file_actions_addchdir_np(&actions, directory) }

        var attributes = posix_spawnattr_t()
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        var noneBlocked = sigset_t()
        sigemptyset(&noneBlocked)
        posix_spawnattr_setsigmask(&attributes, &noneBlocked)
        var allDefault = sigset_t()
        sigfillset(&allDefault)
        sigdelset(&allDefault, SIGKILL)
        sigdelset(&allDefault, SIGSTOP)
        posix_spawnattr_setsigdefault(&attributes, &allDefault)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF))

        let env = (environment ?? ProcessInfo.processInfo.environment).map { "\($0.key)=\($0.value)" }
        let argv = ([path] + args).map { strdup($0) } + [nil]
        let envp = env.map { strdup($0) } + [nil]
        defer { (argv + envp).forEach { free($0) } }

        var pid: pid_t = 0
        var result = posix_spawn(&pid, path, &actions, &attributes, argv, envp)
        // ETXTBSY: a just-written script is still open for writing in some other child for a moment.
        for _ in 0..<20 where result == ETXTBSY {
            usleep(10_000)
            result = posix_spawn(&pid, path, &actions, &attributes, argv, envp)
        }
        guard result == 0 else {
            throw SpawnError(message: "Couldn't start \(path): \(String(cString: strerror(result)))")
        }
        return pid
    }

    private static let spawnLock = NSLock()

    /// A close-on-exec pipe. Call with `spawnLock` held. (Swift doesn't see glibc's pipe2.)
    private static func makePipe() throws -> (read: Int32, write: Int32) {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else {
            throw SpawnError(message: "Couldn't create a pipe: \(String(cString: strerror(errno)))")
        }
        _ = fcntl(fds[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(fds[1], F_SETFD, FD_CLOEXEC)
        return (fds[0], fds[1])
    }

    private static func readAll(_ fd: Int32) -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n > 0 { data.append(contentsOf: buffer[0..<n]) }
            else if n == 0 || errno != EINTR { return data }
        }
    }

    private static func writeAll(_ fd: Int32, _ data: Data) {
        data.withUnsafeBytes { raw in
            guard var p = raw.baseAddress else { return }
            var left = raw.count
            while left > 0 {
                let n = write(fd, p, left)
                if n > 0 { p += n; left -= n }
                else if n == -1 && errno == EINTR { continue }
                else { return }
            }
        }
    }

    private final class Collected: @unchecked Sendable {
        private let lock = NSLock()
        private var o = Data(), e = Data()
        func setOut(_ d: Data) { lock.lock(); o = d; lock.unlock() }
        func setErr(_ d: Data) { lock.lock(); e = d; lock.unlock() }
        var out: Data { lock.lock(); defer { lock.unlock() }; return o }
        var err: Data { lock.lock(); defer { lock.unlock() }; return e }
    }

    /// Signals the child only while it hasn't been reaped, so a recycled PID is never hit.
    private final class ExitState: @unchecked Sendable {
        private let lock = NSLock()
        private var exited = false
        func markExited() { lock.lock(); exited = true; lock.unlock() }
        func signalIfRunning(_ pid: pid_t, _ signal: Int32) -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard !exited else { return false }
            kill(pid, signal)
            return true
        }
    }
}
#endif
