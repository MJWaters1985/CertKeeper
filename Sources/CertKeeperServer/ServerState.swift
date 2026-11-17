import CertKeeperCore
import Foundation
import Hummingbird

/// Shared server state: the model, sign-in, the web interface's certificate and shutdown.
final class ServerState: @unchecked Sendable {
    struct Settings: Codable {
        /// The managed certificate the web interface serves, renewed with the rest (nil = self-signed).
        var serverCertificateID: UUID?
    }

    let config: ServerConfig
    let model: AppModel
    let auth: Auth
    let tls: ServerTLS
    let sshPublicKey: String?
    let secretsKeySource: String

    private let lock = NSLock()
    private var accepting = true
    private var settings: Settings

    init(config: ServerConfig, model: AppModel, auth: Auth, tls: ServerTLS, sshPublicKey: String?, secretsKeySource: String) {
        self.config = config
        self.model = model
        self.auth = auth
        self.tls = tls
        self.sshPublicKey = sshPublicKey
        self.secretsKeySource = secretsKeySource
        settings = (try? JSONDecoder().decode(Settings.self, from: Data(contentsOf: config.serverSettingsFile))) ?? Settings()
    }

    var serverCertificateID: UUID? { lock.lock(); defer { lock.unlock() }; return settings.serverCertificateID }

    private func saveSettings(_ s: Settings) throws {
        lock.lock(); settings = s; lock.unlock()
        try FileSecurity.writePrivate(try JSONEncoder().encode(s), to: config.serverSettingsFile)
    }

    // MARK: - Operations

    func checkAccepting() throws {
        lock.lock(); defer { lock.unlock() }
        if !accepting { throw HTTPError(.serviceUnavailable, message: "CertKeeper is shutting down") }
    }

    private func stopAccepting() {
        lock.lock(); accepting = false; lock.unlock()
    }

    /// Starts a long operation in the background, unless the server is shutting down.
    func start(_ operation: @escaping @MainActor @Sendable (AppModel) async -> Void) async throws {
        try checkAccepting()
        let model = self.model
        Task { @MainActor in await operation(model) }
    }

    @MainActor func log(_ level: LogEntry.Level, _ message: String) {
        model.log(level, message)
        Self.print("\(level.rawValue): \(message)")
    }

    static func print(_ line: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        FileHandle.standardOutput.write(Data("\(stamp) \(line)\n".utf8))
    }

    /// At shutdown: refuse new operations, stop the schedule and wait (up to `limit`) for running
    /// ones, so no install is cut off halfway. A deployment that still gets interrupted stays out of
    /// date and is redeployed by the first rotation pass after the restart.
    func drain(limit: TimeInterval = 170) async {
        stopAccepting()
        await MainActor.run { model.stopScheduler() }
        let deadline = Date().addingTimeInterval(limit)
        var announced = false
        while Date() < deadline {
            let running = await MainActor.run { model.busy.count + (model.maintenanceRunning ? 1 : 0) }
            if running == 0 { return }
            if !announced {
                Self.print("Waiting for \(running) running operation\(running == 1 ? "" : "s") to finish before stopping")
                announced = true
            }
            try? await Task.sleep(for: .seconds(1))
        }
        Self.print("Stopping with operations still running; the next rotation pass will redeploy anything left out of date")
    }

    // MARK: - The web interface's own certificate

    func setServerCertificate(_ id: UUID?) async throws {
        if tls.platformProvided {
            throw HTTPError(.conflict, message: "The certificate comes from the install settings (CERTKEEPER_TLS_CERT); change it there")
        }
        if let id {
            let ok = await MainActor.run { model.certificate(id).map { !$0.isMonitored } ?? false }
            guard ok else { throw HTTPError(.badRequest, message: "Pick a certificate CertKeeper issues") }
        }
        var s = settings
        s.serverCertificateID = id
        try saveSettings(s)
        await syncServerCertificate()
    }

    func certificateDeleted(_ id: UUID) async {
        if serverCertificateID == id { try? await setServerCertificate(nil) }
    }

    /// Installs the chosen certificate for the web interface whenever it's (re)issued, and picks up
    /// changed certificate files. Runs every minute and after changes.
    func syncServerCertificate() async {
        if !tls.platformProvided {
            if let id = serverCertificateID {
                let material = await MainActor.run { () -> (String, String, String, String)? in
                    guard let cert = model.certificate(id), let current = cert.current, let full = cert.fullchainPEM,
                          let key = model.secrets.get(.certificateKey(id)) else { return nil }
                    return (cert.name, current.sha256, full, key)
                }
                if let (name, sha, full, key) = material, tls.managedLeafSHA256 != sha {
                    do {
                        try tls.installManaged(fullchainPEM: full, keyPEM: key)
                        await log(.success, "The web interface now uses \(name) (SHA-256 \(sha.prefix(16))…)")
                    } catch {
                        await log(.error, "Couldn't install \(name) for the web interface: \(error.localizedDescription)")
                    }
                }
            } else if FileManager.default.fileExists(atPath: tls.managedCertificateFile.path) {
                do {
                    try tls.removeManaged()
                    await log(.info, "The web interface is back on its self-signed certificate")
                } catch {
                    await log(.error, "Couldn't switch the web interface's certificate: \(error.localizedDescription)")
                }
            }
        }
        do {
            if try tls.reload() { Self.print("Loaded a new certificate for the web interface") }
        } catch {
            await log(.error, "The web interface's certificate files couldn't be loaded: \(error.localizedDescription)")
        }
    }

    // MARK: - Snapshot

    @MainActor func snapshot() -> Snapshot {
        let busy = model.busy
        let certificates = model.sortedCertificates.map { c -> CertDTO in
            var stripped = c
            stripped.leafPEM = nil
            stripped.chainPEM = nil
            return CertDTO(certificate: stripped, status: StatusDTO(model.status(of: c)), busy: busy.contains(c.id),
                           renewalWindow: model.renewalWindow(for: c), hasKey: model.secrets.get(.certificateKey(c.id)) != nil)
        }
        let hosts = model.sortedHosts.map { h -> HostDTO in
            let health = model.health(ofHost: h.id)
            let endpoints = h.lastDiscovery.map { ep in
                EndpointDTO(id: ep.id, managed: model.isManaged(ep, hostID: h.id),
                            automatic: model.automaticAdoptionTarget(for: ep)?.id,
                            candidates: model.adoptionCandidates(for: ep).map {
                                CandidateDTO(id: $0.id, name: $0.name, coverage: Self.describe(model.coverage(of: $0, for: AppModel.dnsNames(of: ep))))
                            })
            }
            return HostDTO(host: h, health: HealthDTO(level: Self.level(health.level), summary: health.summary), busy: busy.contains(h.id),
                           hasPassword: model.hasHostPassword(h.id), endpoints: endpoints)
        }
        let deployments = model.inventory.deployments.map { d in
            DeploymentDTO(deployment: d, state: StatusDTO(model.state(of: d)), busy: busy.contains(d.id),
                          hasPfxPassword: !model.secret(.pfxPassword, for: d.id).isEmpty)
        }
        return Snapshot(
            version: Server.version, settings: model.inventory.settings,
            hasCloudflareToken: model.secrets.get(.cloudflareToken) != nil,
            maintenanceRunning: model.maintenanceRunning, lastMaintenance: model.lastMaintenance, loadError: model.loadError,
            certificates: certificates, hosts: hosts, deployments: deployments, log: Array(model.inventory.log.prefix(300)),
            server: ServerInfo(username: auth.username, tls: tls.status, tlsPlatformProvided: tls.platformProvided,
                               serverCertificateID: serverCertificateID, sshPublicKey: sshPublicKey,
                               configDirectory: config.configDirectory.path, secretsKeySource: secretsKeySource))
    }

    static func level(_ l: AppModel.HostHealth.Level) -> String {
        switch l {
        case .unmanaged: "unmanaged"
        case .current: "current"
        case .pending: "pending"
        case .warning: "warning"
        case .problem: "problem"
        }
    }

    static func describe(_ c: AppModel.Coverage) -> String {
        switch c {
        case .exact: "same names"
        case .covers(let extra): extra == 0 ? "covers every name" : "covers every name, plus \(extra) more"
        case .missing(let names): "doesn't cover \(names.joined(separator: ", "))"
        }
    }
}

// MARK: - Snapshot types

struct Snapshot: Encodable {
    var version: String
    var settings: AppSettings
    var hasCloudflareToken: Bool
    var maintenanceRunning: Bool
    var lastMaintenance: Date?
    var loadError: String?
    var certificates: [CertDTO]
    var hosts: [HostDTO]
    var deployments: [DeploymentDTO]
    var log: [LogEntry]
    var server: ServerInfo
}

struct ServerInfo: Encodable {
    var username: String?
    var tls: ServerTLS.Status?
    var tlsPlatformProvided: Bool
    var serverCertificateID: UUID?
    var sshPublicKey: String?
    var configDirectory: String
    var secretsKeySource: String
}

/// A status as `kind` (the case name) plus its days or message.
struct StatusDTO: Encodable {
    var kind: String
    var days: Int?
    var detail: String?

    init(_ s: AppModel.CertStatus) {
        switch s {
        case .notIssued: kind = "notIssued"
        case .valid(let d): kind = "valid"; days = d
        case .renewDue(let d): kind = "renewDue"; days = d
        case .expired: kind = "expired"
        case .domainsChanged: kind = "domainsChanged"
        }
    }

    init(_ s: AppModel.DeploymentState) {
        switch s {
        case .disabled: kind = "disabled"
        case .attention(let m): kind = "attention"; detail = m
        case .error(let m): kind = "error"; detail = m
        case .awaitingIssuance: kind = "awaitingIssuance"
        case .outOfDate: kind = "outOfDate"
        case .incompleteChain: kind = "incompleteChain"
        case .current: kind = "current"
        case .notCheckedYet: kind = "notCheckedYet"
        case .watching(let d): kind = "watching"; days = d
        case .expiringSoon(let d): kind = "expiringSoon"; days = d
        case .expired: kind = "expired"
        }
    }
}

struct CertDTO: Encodable {
    var certificate: ManagedCertificate
    var status: StatusDTO
    var busy: Bool
    var renewalWindow: Int
    var hasKey: Bool
}

struct HealthDTO: Encodable { var level: String; var summary: String }
struct CandidateDTO: Encodable { var id: UUID; var name: String; var coverage: String }
struct EndpointDTO: Encodable { var id: String; var managed: Bool; var automatic: UUID?; var candidates: [CandidateDTO] }

struct HostDTO: Encodable {
    var host: ManagedHost
    var health: HealthDTO
    var busy: Bool
    var hasPassword: Bool
    /// Per discovered endpoint (same order as host.lastDiscovery): what adopting it would do.
    var endpoints: [EndpointDTO]
}

struct DeploymentDTO: Encodable {
    var deployment: Deployment
    var state: StatusDTO
    var busy: Bool
    var hasPfxPassword: Bool
}
