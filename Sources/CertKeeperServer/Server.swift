import CertKeeperCore
import Foundation
import Hummingbird
import HummingbirdTLS
import Logging
import ServiceLifecycle

enum Server {
    static let version = "0.1.0"

    static func run(_ config: ServerConfig) async throws {
        SSHRunner.ignoreSIGPIPE()
        try FileManager.default.createDirectory(at: config.configDirectory, withIntermediateDirectories: true)
        InventoryFile.directoryOverride = config.configDirectory
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
            AppModel(fileURL: config.inventoryFile, secrets: secrets, askpassPath: executable, passwordInEnvironment: true)
        }
        if let problem = await MainActor.run(body: { model.loadError }) { ServerState.print("warning: \(problem)") }
        let auth = try Auth(usersFile: config.usersFile)
        let tls = try ServerTLS(config: config)
        let state = ServerState(config: config, model: model, auth: auth, tls: tls,
                                sshPublicKey: SSHKeys.ensure(config), secretsKeySource: keySource)
        await state.syncServerCertificate()
        await MainActor.run { model.startScheduler() }

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
