import CertKeeperCore
import Foundation
import Hummingbird
import HummingbirdTLS
import Logging
import ServiceLifecycle

enum Server {
    static let version = "1.0.0"

    static func run(_ config: ServerConfig) async throws {
        SSHRunner.ignoreSIGPIPE()
        try FileManager.default.createDirectory(at: config.configDirectory, withIntermediateDirectories: true)
        InventoryFile.directoryOverride = config.configDirectory
        UserEntry.ensure(config)
        ServerState.print("CertKeeper \(version) starting; configuration in \(config.configDirectory.path)")

        let (key, keySource) = try SecretsKey.load(config)
        let secrets: EncryptedFileSecretStore
        do {
            secrets = try EncryptedFileSecretStore(url: config.secretsFile, key: key)
        } catch is EncryptedFileSecretStore.DecryptionFailed {
            throw ConfigError("""
                \(config.secretsFile.path) can't be decrypted with the key from \(keySource). \
                If CERTKEEPER_SECRET_KEY was added, changed or removed, set it back to what it was.
                """)
        }
        let executable = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let model = await MainActor.run {
            AppModel(fileURL: config.inventoryFile, secrets: secrets, askpassPath: executable)
        }
        if let problem = await MainActor.run(body: { model.loadError }) { ServerState.print("warning: \(problem)") }
        let auth = try Auth(usersFile: config.usersFile)
        let tls = try ServerTLS(config: config)
        if let problem = tls.startupProblem {
            ServerState.print("error: the web interface's certificate couldn't be loaded, so it's using its self-signed one until the files are fixed: \(problem)")
        }
        let state = ServerState(config: config, model: model, auth: auth, tls: tls,
                                sshPublicKey: SSHKeys.ensure(config), secretsKeySource: keySource)
        await MainActor.run {
            // Activity goes to standard output too, so it shows in the container's (TrueNAS app's) logs.
            model.onLog = { entry in
                ServerState.print("\(entry.level.rawValue): \(entry.message)" + (entry.level == .error ? (entry.detail.map { " — " + $0 } ?? "") : ""))
            }
        }
        await state.syncServerCertificate()
        if config.schedule {
            await MainActor.run { model.startScheduler() }
        } else {
            ServerState.print("warning: CERTKEEPER_SCHEDULE=off: no automatic rotation passes")
        }

        if let code = auth.setupCode {
            ServerState.print("""

                ============================================================
                  CertKeeper isn't set up yet. Open the web interface and
                  enter this one-time setup code to create your account:

                      \(code)
                ============================================================

                """)
        }
        if let s = tls.status {
            ServerState.print("Web interface on https://\(config.host):\(config.port) (\(s.mode.rawValue) certificate \(s.subject))")
        }

        let router = Router(context: AppContext.self)
        router.add(middleware: SecurityHeadersMiddleware())
        if let web = Bundle.module.resourceURL?.appendingPathComponent("Web").path {
            router.add(middleware: FileMiddleware(web, cacheControl: .init([(MediaType(type: .any), [.noCache])]), searchForIndexHtml: true))
        }
        API.addRoutes(to: router, server: state)

        var logger = Logger(label: "CertKeeper")
        logger.logLevel = .warning
        let app = Application(
            router: router,
            server: try .tls(.http1(), tlsConfiguration: tls.configuration()),
            configuration: .init(address: .hostname(config.host, port: config.port), serverName: "CertKeeper"),
            services: [BackgroundService(state: state)],
            logger: logger)
        try await app.runService()
        ServerState.print("CertKeeper stopped")
    }
}

/// Every minute: pick up renewed certificates for the web interface. At shutdown: wait for running
/// operations (see ServerState.drain).
struct BackgroundService: Service {
    let state: ServerState

    func run() async throws {
        let ticker = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                if Task.isCancelled { break }
                await state.syncServerCertificate()
            }
        }
        try? await gracefulShutdown()
        ticker.cancel()
        ServerState.print("Shutting down")
        await state.drain()
    }
}

/// The container's SSH identity: an ed25519 key in $HOME/.ssh, created on first start. Hosts trust
/// CertKeeper by listing its public key in authorized_keys. Only managed when HOME is the
/// configuration folder (as in the container), never a developer's own ~/.ssh.
enum SSHKeys {
    static func ensure(_ config: ServerConfig) -> String? {
        guard let home = ProcessInfo.processInfo.environment["HOME"],
              URL(fileURLWithPath: home).standardizedFileURL.path == config.configDirectory.standardizedFileURL.path else { return nil }
        let dir = URL(fileURLWithPath: home).appendingPathComponent(".ssh")
        let key = dir.appendingPathComponent("id_ed25519"), pub = dir.appendingPathComponent("id_ed25519.pub")
        if !FileManager.default.fileExists(atPath: key.path) {
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let r = try LocalCommand.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "certkeeper", "-f", key.path])
                guard r.succeeded else {
                    ServerState.print("warning: couldn't create an SSH key: \(String(decoding: r.stderr, as: UTF8.self))")
                    return nil
                }
                ServerState.print("Created the SSH key \(key.path)")
            } catch {
                ServerState.print("warning: couldn't create an SSH key: \(error.localizedDescription)")
                return nil
            }
        }
        return (try? String(contentsOf: pub, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// OpenSSH refuses to run for a uid without a passwd entry ("No user exists for uid"), and the
/// TrueNAS install form lets people run the app as any uid. When the image has no entry for the
/// current uid, CertKeeper writes passwd/group files that include it and has its child processes
/// (ssh, ssh-keygen) read them through nss_wrapper, so nothing in the image needs to be writable.
enum UserEntry {
    static func ensure(_ config: ServerConfig) {
        let uid = getuid(), gid = getgid()
        guard getpwuid(uid) == nil else { return }
        let dir = config.configDirectory.appendingPathComponent(".nss", isDirectory: true)
        let passwd = dir.appendingPathComponent("passwd"), group = dir.appendingPathComponent("group")
        let home = ProcessInfo.processInfo.environment["HOME"] ?? config.configDirectory.path
        let systemPasswd = (try? String(contentsOfFile: "/etc/passwd", encoding: .utf8)) ?? ""
        var systemGroup = (try? String(contentsOfFile: "/etc/group", encoding: .utf8)) ?? ""
        if getgrgid(gid) == nil { systemGroup += "certkeeper:x:\(gid):\n" }
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try FileSecurity.writePrivate(Data((systemPasswd + "certkeeper:x:\(uid):\(gid):CertKeeper:\(home):/usr/sbin/nologin\n").utf8), to: passwd)
            try FileSecurity.writePrivate(Data(systemGroup.utf8), to: group)
        } catch {
            ServerState.print("warning: uid \(uid) has no user entry and one couldn't be written (\(error.localizedDescription)); SSH won't work")
            return
        }
        setenv("LD_PRELOAD", "libnss_wrapper.so", 1)
        setenv("NSS_WRAPPER_PASSWD", passwd.path, 1)
        setenv("NSS_WRAPPER_GROUP", group.path, 1)
        ServerState.print("uid \(uid) has no user entry in the image; SSH uses one from \(dir.path)")
    }
}
