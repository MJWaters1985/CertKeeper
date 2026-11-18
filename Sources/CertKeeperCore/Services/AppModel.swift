import Foundation
import Observation

/// Owns the inventory and runs issuance, deployment, discovery and the periodic rotation pass.
@MainActor
@Observable
public final class AppModel {
    public var inventory: Inventory {
        didSet { persist() }
    }
    /// IDs (certificates, deployments, hosts) with an operation in flight.
    public private(set) var busy: Set<UUID> = []
    public private(set) var maintenanceRunning = false
    public private(set) var lastMaintenance: Date?
    public var loadError: String?

    @ObservationIgnored private let ssh: SSHRunner
    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private var schedulerTask: Task<Void, Never>?
    @ObservationIgnored public let secrets: SecretStore
    /// Secret options found by discovery this session, by endpoint ID — never written to the inventory.
    @ObservationIgnored private var discoveredSecrets: [String: [String: String]] = [:]

    /// - Parameter askpassPath: The executable ssh runs to answer password prompts (see `AskPass`).
    public init(fileURL: URL = InventoryFile.url, secrets: SecretStore, askpassPath: String? = Bundle.main.executablePath) {
        self.fileURL = fileURL
        self.secrets = secrets
        var ssh = SSHRunner(askpassPath: askpassPath)
        ssh.passwordLookup = { [secrets] in secrets.get(.hostPassword($0)) }
        self.ssh = ssh
        do {
            inventory = try InventoryFile.load(from: fileURL)
            repairChains()
            moveSecretsOutOfInventory()
            pruneLog()
        } catch {
            // Never let a file we can't read be overwritten by an empty inventory: move it aside first.
            let backup = fileURL.deletingPathExtension()
                .appendingPathExtension("unreadable-\(Int(Date().timeIntervalSince1970)).json")
            try? FileManager.default.moveItem(at: fileURL, to: backup)
            inventory = Inventory()
            loadError = "Could not read the inventory (\(error.localizedDescription)). It was moved to \(backup.path) and CertKeeper started empty."
        }
    }

    /// Earlier builds stored intermediates glued together without newlines, which strict PEM
    /// parsers reject and most others truncate to the leaf. Re-flow them and redeploy everywhere they went.
    private func repairChains() {
        var repaired: [String] = []
        for i in inventory.certificates.indices {
            guard let chain = inventory.certificates[i].chainPEM, !chain.isEmpty else { continue }
            let fixed = CertCrypto.normalizePEMBundle(chain)
            guard fixed != chain else { continue }
            inventory.certificates[i].chainPEM = fixed
            repaired.append(inventory.certificates[i].name)
            let id = inventory.certificates[i].id
            for j in inventory.deployments.indices where inventory.deployments[j].certificateID == id {
                inventory.deployments[j].forceRedeploy = true
            }
        }
        if !repaired.isEmpty {
            log(.warning, "Repaired malformed certificate chains; affected deployments will be redeployed",
                detail: repaired.joined(separator: ", "))
        }
    }

    /// Earlier builds stored secret options (the .pfx password) in the inventory file and in saved
    /// discovery results. Move them into the secret store.
    private func moveSecretsOutOfInventory() {
        var moved = 0
        for i in inventory.deployments.indices {
            for key in DeploymentOption.secrets {
                guard let value = inventory.deployments[i].options[key.rawValue] else { continue }
                if !value.isEmpty {
                    do { try secrets.set(value, for: .deploymentSecret(inventory.deployments[i].id, key.rawValue)) }
                    catch { log(.error, "Could not move a password into the secret store", detail: error.localizedDescription); continue }
                    moved += 1
                }
                inventory.deployments[i].options[key.rawValue] = nil
            }
        }
        for i in inventory.hosts.indices where inventory.hosts[i].lastDiscovery.contains(where: Self.hasSecrets) {
            inventory.hosts[i].lastDiscovery = inventory.hosts[i].lastDiscovery.map(stashSecrets)
            moved += 1
        }
        if moved > 0 { log(.info, "Moved passwords from the inventory file into the secret store") }
    }

    static func hasSecrets(_ ep: DiscoveredEndpoint) -> Bool {
        DeploymentOption.secrets.contains { ep.options?[$0.rawValue] != nil }
    }

    /// Keeps a discovered endpoint's secret options in memory for adoption and strips them from what gets saved.
    private func stashSecrets(_ ep: DiscoveredEndpoint) -> DiscoveredEndpoint {
        var ep = ep
        for key in DeploymentOption.secrets {
            if let value = ep.options?.removeValue(forKey: key.rawValue), !value.isEmpty {
                discoveredSecrets[ep.id, default: [:]][key.rawValue] = value
            }
        }
        return ep
    }

    public func secret(_ key: DeploymentOption, for deploymentID: UUID) -> String {
        secrets.get(.deploymentSecret(deploymentID, key.rawValue)) ?? ""
    }

    public func setSecret(_ value: String, _ key: DeploymentOption, for deploymentID: UUID) throws {
        if value.isEmpty { secrets.delete(.deploymentSecret(deploymentID, key.rawValue)) }
        else { try secrets.set(value, for: .deploymentSecret(deploymentID, key.rawValue)) }
    }

    /// A copy of the deployment with its secret options filled in, for building scripts. Never stored.
    func withSecrets(_ d: Deployment) -> Deployment {
        var d = d
        for key in DeploymentOption.secrets {
            let value = secret(key, for: d.id)
            if !value.isEmpty { d.options[key.rawValue] = value }
        }
        return d
    }

    private func removeDeployments(where predicate: (Deployment) -> Bool) {
        for d in inventory.deployments where predicate(d) {
            for key in DeploymentOption.secrets { secrets.delete(.deploymentSecret(d.id, key.rawValue)) }
        }
        inventory.deployments.removeAll(where: predicate)
    }

    private func persist() {
        do { try InventoryFile.save(inventory, to: fileURL) }
        catch { loadError = "Could not save inventory: \(error.localizedDescription)" }
    }

    // MARK: - Lookup helpers

    /// Name order as Finder sorts: case-insensitive, numbers compared numerically ("kvm2" before "kvm10").
    static func byName(_ a: String, _ b: String) -> Bool {
        a.localizedStandardCompare(b) == .orderedAscending
    }

    /// Certificates and hosts in alphabetical order, for the sidebar. Ties keep their stored order.
    public var sortedCertificates: [ManagedCertificate] {
        inventory.certificates.enumerated()
            .sorted { Self.byName($0.element.name, $1.element.name) || ($0.element.name.localizedStandardCompare($1.element.name) == .orderedSame && $0.offset < $1.offset) }
            .map(\.element)
    }

    public var sortedHosts: [ManagedHost] {
        inventory.hosts.enumerated()
            .sorted { Self.byName($0.element.name, $1.element.name) || ($0.element.name.localizedStandardCompare($1.element.name) == .orderedSame && $0.offset < $1.offset) }
            .map(\.element)
    }

    public func host(_ id: UUID) -> ManagedHost? { inventory.hosts.first { $0.id == id } }
    public func certificate(_ id: UUID) -> ManagedCertificate? { inventory.certificates.first { $0.id == id } }
    public func deployments(for certID: UUID) -> [Deployment] { inventory.deployments.filter { $0.certificateID == certID } }
    public func deployments(onHost hostID: UUID) -> [Deployment] { inventory.deployments.filter { $0.hostID == hostID } }

    func updateCertificate(_ id: UUID, _ body: (inout ManagedCertificate) -> Void) {
        guard let i = inventory.certificates.firstIndex(where: { $0.id == id }) else { return }
        body(&inventory.certificates[i])
    }

    func updateDeployment(_ id: UUID, _ body: (inout Deployment) -> Void) {
        guard let i = inventory.deployments.firstIndex(where: { $0.id == id }) else { return }
        body(&inventory.deployments[i])
    }

    func updateHost(_ id: UUID, _ body: (inout ManagedHost) -> Void) {
        guard let i = inventory.hosts.firstIndex(where: { $0.id == id }) else { return }
        body(&inventory.hosts[i])
    }

    /// Hard cap on log entries, a backstop behind the age limit in Settings.
    static let maxLogEntries = 1000

    public func log(_ level: LogEntry.Level, _ message: String, detail: String? = nil) {
        let entry = LogEntry(level, message, detail: detail)
        inventory.log.insert(entry, at: 0)
        pruneLog()
        onLog?(entry)
    }

    /// Called for every new log entry (the server copies them to its standard output).
    @ObservationIgnored public var onLog: ((LogEntry) -> Void)?

    /// Drops entries older than the configured retention, and any beyond the hard cap.
    public func pruneLog(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-Double(inventory.settings.effectiveLogRetentionDays) * 86_400)
        var kept = inventory.log.filter { $0.date >= cutoff }
        if kept.count > Self.maxLogEntries { kept.removeLast(kept.count - Self.maxLogEntries) }
        if kept.count != inventory.log.count { inventory.log = kept }
    }

    /// Marks `id` as in progress for the duration of `body`. Operations on the same certificate or
    /// deployment check `busy` first, so a rotation pass never overlaps a deploy the user started.
    func withBusy<T>(_ id: UUID, _ body: () async throws -> T) async rethrows -> T {
        busy.insert(id)
        defer { busy.remove(id) }
        return try await body()
    }

    // MARK: - Configuration export / import

    public func exportConfiguration(password: String?) throws -> Data {
        try ConfigTransfer.export(inventory, secrets: secrets, password: password)
    }

    /// Replaces the configuration with `file`'s. The current inventory is saved next to the live one
    /// first (no secrets in it). Secrets from the file go to the secret store; existing secrets for
    /// items the file doesn't cover are left alone. The activity log is kept. Returns the backup.
    @discardableResult
    public func importConfiguration(_ file: ConfigTransfer.File, secrets imported: [(SecretItem, String)]) throws -> URL {
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let backup = fileURL.deletingLastPathComponent().appendingPathComponent("inventory.before-import-\(stamp).json")
        try InventoryFile.save(inventory, to: backup)
        for (item, value) in imported { try secrets.set(value, for: item) }

        var next = file.inventory
        next.log = inventory.log
        discoveredSecrets = [:]
        SudoCache.shared.reset()
        inventory = next

        let missingKeys = inventory.certificates.filter { !$0.isMonitored && $0.leafPEM != nil && secrets.get(.certificateKey($0.id)) == nil }
        let missingPasswords = inventory.hosts.filter { ($0.passwordLogin || $0.useSudo) && secrets.get(.hostPassword($0.id)) == nil }
        var detail = "\(inventory.hosts.count) hosts, \(inventory.certificates.count) certificates, \(inventory.deployments.count) deployments; "
            + "\(imported.count) secret(s) restored. Previous configuration saved to \(backup.lastPathComponent)."
        if !missingKeys.isEmpty { detail += "\nNo private key for: \(missingKeys.map(\.name).joined(separator: ", ")) — reissue before deploying." }
        if !missingPasswords.isEmpty { detail += "\nNo password for: \(missingPasswords.map(\.name).joined(separator: ", ")) — re-enter it if the host needs one." }
        log(missingKeys.isEmpty && missingPasswords.isEmpty ? .success : .warning, "Imported configuration", detail: detail)
        return backup
    }

    // MARK: - Mutations used by the UI

    public func addHost(_ host: ManagedHost) { inventory.hosts.append(host) }

    public func deleteHost(_ id: UUID) {
        secrets.delete(.hostPassword(id))
        removeDeployments { $0.hostID == id }
        inventory.hosts.removeAll { $0.id == id }
    }

    public func addCertificate(_ cert: ManagedCertificate) { inventory.certificates.append(cert) }

    public func deleteCertificate(_ id: UUID) {
        removeDeployments { $0.certificateID == id }
        inventory.certificates.removeAll { $0.id == id }
        secrets.delete(.certificateKey(id))
    }

    public func addDeployment(_ d: Deployment) { inventory.deployments.append(d) }
    public func deleteDeployment(_ id: UUID) { removeDeployments { $0.id == id } }

    // MARK: - Renewal policy

    /// Days before expiry to renew — or, for a monitored certificate, to warn that the system renewing
    /// it seems to have stopped (14 by default, since such systems usually renew around 30).
    public func renewalWindow(for cert: ManagedCertificate) -> Int {
        cert.renewDaysBeforeExpiry ?? (cert.isMonitored ? Self.defaultMonitorWindow : inventory.settings.renewDaysBeforeExpiry)
    }

    public static let defaultMonitorWindow = 14

    public enum CertStatus: Equatable {
        case notIssued, valid(days: Int), renewDue(days: Int), expired, domainsChanged
    }

    public func status(of cert: ManagedCertificate) -> CertStatus {
        if cert.isMonitored {
            guard let cur = cert.current else { return .notIssued }  // shown as "not checked yet"
            if cur.isExpired { return .expired }
            if cur.daysRemaining <= renewalWindow(for: cert) { return .renewDue(days: cur.daysRemaining) }
            return .valid(days: cur.daysRemaining)
        }
        guard let cur = cert.current, cert.leafPEM != nil else { return .notIssued }
        if Set(cur.dnsNames.map { $0.lowercased() }) != Set(cert.domains.map { $0.lowercased() }) { return .domainsChanged }
        if cur.isExpired { return .expired }
        if cur.daysRemaining <= renewalWindow(for: cert) { return .renewDue(days: cur.daysRemaining) }
        return .valid(days: cur.daysRemaining)
    }

    public func needsIssuance(_ cert: ManagedCertificate) -> Bool {
        if cert.isMonitored { return false }
        if case .valid = status(of: cert) { return false }
        return true
    }

    /// A deployment is out of date when the service isn't confirmed to be serving the current certificate.
    public func needsDeployment(_ d: Deployment) -> Bool {
        guard d.enabled, let cert = certificate(d.certificateID), !cert.isMonitored, let cur = cert.current else { return false }
        return d.forceRedeploy || d.deployedSHA256 != cur.sha256
    }

    /// One deployment's state, most urgent first. Shared by the deployment badges and the host indicators.
    public enum DeploymentState: Equatable {
        case disabled
        case attention(String)
        case error(String)
        case awaitingIssuance
        case outOfDate
        case incompleteChain
        case current
        // Monitor-only deployments:
        case notCheckedYet
        case watching(days: Int)
        case expiringSoon(days: Int)
        case expired
    }

    public func state(of d: Deployment) -> DeploymentState {
        if !d.enabled { return .disabled }
        if let attention = d.attention { return .attention(attention) }
        if let error = d.lastError { return .error(error) }
        if let cert = certificate(d.certificateID), cert.isMonitored {
            guard let notAfter = d.deployedNotAfter else { return .notCheckedYet }
            let days = Int(floor(notAfter.timeIntervalSinceNow / 86_400))
            if notAfter < Date() { return .expired }
            if days <= renewalWindow(for: cert) { return .expiringSoon(days: days) }
            if d.servedChainComplete == false { return .incompleteChain }
            return .watching(days: days)
        }
        if certificate(d.certificateID)?.current == nil { return .awaitingIssuance }
        if needsDeployment(d) { return .outOfDate }
        if d.servedChainComplete == false { return .incompleteChain }
        return .current
    }

    /// Roll-up of a host's enabled deployments for the sidebar.
    public struct HostHealth: Equatable {
        public enum Level: Int, Comparable {
            case unmanaged, current, pending, warning, problem
            public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
        }
        public var level: Level
        public var summary: String
    }

    public func health(ofHost hostID: UUID) -> HostHealth {
        let states = deployments(onHost: hostID).map(state(of:)).filter { $0 != .disabled }
        guard !states.isEmpty else { return HostHealth(level: .unmanaged, summary: "No managed deployments") }
        func count(_ match: (DeploymentState) -> Bool) -> Int { states.filter(match).count }
        let problems = count {
            switch $0 { case .attention, .error, .expired: return true; default: return false }
        }
        let outOfDate = count { $0 == .outOfDate }
        let expiring = count { if case .expiringSoon = $0 { return true }; return false }
        let chain = count { $0 == .incompleteChain }
        let awaiting = count { $0 == .awaitingIssuance }
        let unchecked = count { $0 == .notCheckedYet }
        let total = states.count
        let noun = total == 1 ? "deployment" : "deployments"

        var parts: [String] = []
        if problems > 0 { parts.append("\(problems) need\(problems == 1 ? "s" : "") attention") }
        if outOfDate > 0 { parts.append("\(outOfDate) out of date") }
        if expiring > 0 { parts.append("\(expiring) monitored expiring soon") }
        if chain > 0 { parts.append("\(chain) with an incomplete chain") }
        if awaiting > 0 { parts.append("\(awaiting) awaiting issuance") }
        if unchecked > 0 { parts.append("\(unchecked) not checked yet") }
        let level: HostHealth.Level = problems > 0 ? .problem : (outOfDate + chain + expiring > 0 ? .warning : (awaiting + unchecked > 0 ? .pending : .current))
        let summary = parts.isEmpty
            ? (total == 1 ? "1 deployment current" : "All \(total) deployments current")
            : "\(parts.joined(separator: ", ")) (of \(total) \(noun))"
        return HostHealth(level: level, summary: summary)
    }

    // MARK: - Issuance

    public func issue(_ certID: UUID) async {
        guard let cert = certificate(certID), !busy.contains(certID) else { return }
        await withBusy(certID) {
            log(.info, "Requesting certificate for \(cert.domains.joined(separator: ", "))",
                detail: inventory.settings.useStaging ? "Let's Encrypt STAGING" : "Let's Encrypt production")
            do {
                let issued = try await performIssuance(cert)
                updateCertificate(certID) {
                    $0.leafPEM = issued.leaf
                    $0.chainPEM = issued.chain
                    $0.current = issued.summary
                    $0.lastIssued = Date()
                    $0.lastError = nil
                }
                log(.success, "Issued \(cert.name)",
                    detail: "Expires \(issued.summary.notAfter.formatted()) · SHA-256 \(issued.summary.sha256.prefix(16))…")
            } catch {
                updateCertificate(certID) { $0.lastError = error.localizedDescription }
                log(.error, "Issuance failed for \(cert.name)", detail: error.localizedDescription)
            }
        }
    }

    struct Issued { let leaf: String; let chain: String; let summary: CertificateSummary }

    private func performIssuance(_ cert: ManagedCertificate) async throws -> Issued {
        let settings = inventory.settings
        guard settings.acceptedTermsOfService else {
            throw DeployError("Accept the Let's Encrypt Subscriber Agreement in Settings first")
        }
        guard let cfToken = secrets.get(.cloudflareToken), !cfToken.isEmpty else {
            throw DeployError("No Cloudflare API token configured (Settings › Cloudflare)")
        }
        let domains = cert.domains.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        guard !domains.isEmpty else { throw DeployError("Certificate has no domains") }

        let accountKey: String
        if let k = secrets.get(.acmeAccountKey) { accountKey = k } else {
            accountKey = ACMEClient.newAccountKeyPEM()
            try secrets.set(accountKey, for: .acmeAccountKey)
        }
        let dirKey = settings.directoryURL.absoluteString
        let acme = try ACMEClient(
            directoryURL: settings.directoryURL,
            accountKeyPEM: accountKey,
            accountURL: inventory.acmeAccounts[dirKey].flatMap(URL.init(string:))
        )
        let accountURL = try await acme.ensureAccount(email: settings.acmeEmail)
        inventory.acmeAccounts[dirKey] = accountURL.absoluteString

        let (order, orderURL) = try await acme.newOrder(domains: domains)

        // Collect pending dns-01 challenges, grouped by record name (a wildcard and its apex share one).
        var pending: [(authz: URL, challenge: ACMEClient.Challenge, recordName: String, value: String)] = []
        for authzURL in order.authorizations {
            let authz = try await acme.authorization(at: authzURL)
            if authz.status == "valid" { continue }
            guard let ch = authz.challenges.first(where: { $0.type == "dns-01" }), let token = ch.token else {
                throw ACMEClient.ACMEError.noDNSChallenge(authz.identifier.value)
            }
            pending.append((authzURL, ch, "_acme-challenge.\(authz.identifier.value)", await acme.dnsTXTValue(token: token)))
        }

        let cf = CloudflareClient(token: cfToken)
        var created: [CloudflareClient.CreatedRecord] = []
        do {
            if !pending.isEmpty {
                let zones = try await cf.listZones()
                for p in pending {
                    guard let zone = CloudflareClient.zone(for: p.recordName, in: zones) else {
                        throw DeployError("No Cloudflare zone accessible to this token contains \(p.recordName)")
                    }
                    created.append(try await cf.createTXT(zone: zone, name: p.recordName, content: p.value))
                }
                log(.info, "Published \(created.count) DNS challenge record(s); waiting for propagation")
                let grouped = Dictionary(grouping: pending, by: \.recordName).mapValues { Set($0.map(\.value)) }
                for (name, values) in grouped {
                    try await DNSPropagation.waitFor(name: name, expected: values, timeout: TimeInterval(settings.dnsPropagationTimeout))
                }
                try await Task.sleep(for: .seconds(5))
                for p in pending { try await acme.respond(to: p.challenge) }
                for p in pending { _ = try await acme.waitForAuthorization(p.authz) }
                log(.info, "Domain validation passed")
            }
        } catch {
            await cleanup(created, cf)
            throw error
        }
        await cleanup(created, cf)

        let keyPEM = try CertCrypto.generateKeyPEM(cert.keyAlgorithm)
        let csr = try CertCrypto.makeCSR(domains: domains, keyPEM: keyPEM)
        let final = try await acme.finalize(order: order, orderURL: orderURL, csrDER: csr)
        guard let certURL = final.certificate else { throw DeployError("Order is valid but has no certificate URL") }
        let bundle = try await acme.downloadCertificate(certURL)
        guard let (leaf, chain) = CertCrypto.splitIssuedBundle(bundle) else {
            throw DeployError("Downloaded certificate bundle was empty")
        }
        guard CertCrypto.keyMatches(certPEM: leaf, keyPEM: keyPEM) else {
            throw DeployError("Issued certificate does not match the generated key")
        }
        try secrets.set(keyPEM, for: .certificateKey(cert.id))
        return Issued(leaf: leaf, chain: chain, summary: try CertCrypto.summarize(pem: leaf))
    }

    private func cleanup(_ records: [CloudflareClient.CreatedRecord], _ cf: CloudflareClient) async {
        for r in records {
            do { try await cf.deleteRecord(r) }
            catch { log(.warning, "Could not remove TXT record \(r.name)", detail: error.localizedDescription) }
        }
    }

    // MARK: - Deployment

    public func deploy(_ deploymentID: UUID) async {
        guard let d = inventory.deployments.first(where: { $0.id == deploymentID }),
              let cert = certificate(d.certificateID), !cert.isMonitored, let host = host(d.hostID),
              !busy.contains(deploymentID) else { return }
        await withBusy(deploymentID) {
            let label = "\(cert.name) → \(host.name) (\(d.kind.displayName))"
            do {
                guard let key = secrets.get(.certificateKey(cert.id)) else {
                    throw DeployError("The private key for \(cert.name) is missing — issue the certificate again")
                }
                log(.info, "Deploying \(label)")
                let detail: String
                if d.kind == .deviceAPI || host.isDeviceAPI {
                    guard d.kind == .deviceAPI, host.isDeviceAPI else {
                        throw DeployError("Device (HTTPS API) deployments need a host whose connection is Device API, and the other way round")
                    }
                    guard let chain = cert.fullchainPEM else { throw DeployError("\(cert.name) hasn't been issued yet") }
                    let installed = try await deviceAPI(for: host).install(chainPEM: chain, keyPEM: key)
                    detail = installed.map { "Device reports \($0.subject), expires \($0.notAfter)" } ?? ""
                } else {
                    let script = try DeployScripts.build(deployment: withSecrets(d), certificate: cert, keyPEM: key)
                    detail = try await ssh.runChecked(script, on: host, timeout: 300).stdout
                }
                updateDeployment(deploymentID) { $0.lastDeployed = Date(); $0.lastError = nil; $0.forceRedeploy = false }
                log(.success, "Deployed \(label)", detail: detail.trimmingCharacters(in: .whitespacesAndNewlines))
                // Give services that restart asynchronously a moment before verifying.
                try? await Task.sleep(for: .seconds([.truenas, .unifiOS, .opnsense, .containerApp, .pihole].contains(d.kind) ? 8 : 2))
                await performCheck(deploymentID, logResult: true)  // already marked busy by this deploy
            } catch {
                updateDeployment(deploymentID) { $0.lastError = error.localizedDescription }
                log(.error, "Deploy failed: \(label)", detail: error.localizedDescription)
            }
        }
    }

    /// Reads what the host (and, if configured, its TLS endpoint) is actually using and records it.
    /// Checks what a deployment's host is actually serving. Skipped while the deployment is busy,
    /// e.g. being deployed, since its state is about to change.
    public func check(_ deploymentID: UUID, logResult: Bool = false) async {
        guard !busy.contains(deploymentID) else { return }
        await withBusy(deploymentID) { await performCheck(deploymentID, logResult: logResult) }
    }

    func performCheck(_ deploymentID: UUID, logResult: Bool) async {
        guard let d = inventory.deployments.first(where: { $0.id == deploymentID }),
              let host = host(d.hostID) else { return }
        if let cert = certificate(d.certificateID), cert.isMonitored {
            await checkMonitored(d, cert: cert, host: host, logResult: logResult)
            return
        }
        do {
            var found: CertificateSummary?
            var onDisk: CertificateSummary?
            var fileMissing = false
            if d.kind == .deviceAPI || host.isDeviceAPI {
                // Ask the device what it serves; the TLS probe below confirms it from the outside.
                let info = try await deviceAPI(for: host).info()
                updateHost(host.id) { $0.lastSeen = Date() }
                if d.verifyEndpoint.isEmpty, let served = try? await TLSProbe.fetchLeaf(endpoint: deviceEndpoint(host)) {
                    found = served
                } else if d.verifyEndpoint.isEmpty {
                    throw DeployError("Couldn't connect to \(deviceEndpoint(host)) (the device reports \(info.subject))")
                }
            } else if d.kind.usesFilePaths {
                let probe = Discovery.probeScript(path: d.certPath, pkcs12: d.isPKCS12, password: secret(.pfxPassword, for: d.id))
                let r = try await ssh.run(probe, on: host, timeout: 60)
                if r.status == 255 {
                    throw SSHRunner.SSHError(message: "SSH to \(host.name) failed: \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))", result: r)
                }
                fileMissing = !r.succeeded
                found = try? CertCrypto.summarize(pem: r.stdout)
                onDisk = found
            } else {
                let report = try await Discovery.run(on: host, ssh: ssh)
                let current = certificate(d.certificateID)?.current?.sha256
                let summaries = Discovery.relevantEndpoints(for: d, in: report.endpoints).map(\.summary)
                // Every target must have the current cert; report the first one that doesn't.
                found = summaries.first { $0?.sha256 != current } ?? summaries.first ?? nil
            }
            var chainComplete: Bool?
            if !d.verifyEndpoint.isEmpty {
                var probe: TLSProbe.Served?
                var probeError: Error?
                // UniFi OS Server can take a minute to come back after a full service restart.
                let attempts = d.kind == .unifiOS ? 12 : 4
                for attempt in 0..<attempts {
                    do {
                        probe = try await TLSProbe.fetchServed(endpoint: d.verifyEndpoint)
                        probeError = nil
                    } catch {
                        probeError = error
                    }
                    if probe?.chain.first?.sha256 == certificate(d.certificateID)?.current?.sha256 { break }
                    if attempt < attempts - 1 { try? await Task.sleep(for: .seconds(5)) }
                }
                if probe == nil, let probeError {
                    log(.warning, "Couldn't check what \(d.verifyEndpoint) is serving",
                        detail: "\(probeError.localizedDescription)\nUsing the certificate found on \(host.name) instead.")
                }
                let chain = probe?.chain ?? []
                if let served = chain.first {
                    chainComplete = probe?.exact == true ? TLSProbe.chainIsComplete(chain) : nil
                    if chainComplete == false && d.servedChainComplete != false {
                        log(.warning, "\(host.name): \(d.verifyEndpoint) sends an incomplete certificate chain",
                            detail: "Only \(chain.count) certificate(s) sent and none issued \(served.subject). Browsers often cope; curl, apps and some phones will reject it. Redeploying usually fixes it.")
                    }
                    if let found, found.sha256 != served.sha256 {
                        log(.warning, "\(host.name): \(d.verifyEndpoint) serves a different certificate than the one on disk",
                            detail: "disk \(found.sha256.prefix(16))… vs served \(served.sha256.prefix(16))… — the service may need a restart")
                    }
                    found = served
                }
            }
            // A server whose config moved to other files would otherwise be redeployed every pass.
            var attention: String?? = .none  // .none = unchanged
            if d.kind == .nginx || d.kind == .apache,
               fileMissing || (onDisk != nil && found != nil && onDisk?.sha256 != found?.sha256) {
                let report = try await Discovery.run(on: host, ssh: ssh)
                if let usage = Discovery.configStillUses(d, in: report.endpoints) {
                    if usage.inUse {
                        attention = .some(nil)
                    } else {
                        let server = d.kind == .nginx ? "nginx\(d.option(.nginxConf).isEmpty ? "" : " [\(d.option(.nginxConf))]")" : "Apache"
                        attention = .some("\(server) no longer reads \(d.certPath); it now uses \(usage.current.joined(separator: ", ")). "
                            + "Automatic deploys are paused: update this deployment's paths, or adopt the new entry from Discover.")
                    }
                }
            } else if d.attention != nil, found?.sha256 == certificate(d.certificateID)?.current?.sha256 {
                attention = .some(nil)
            }
            if case .some(let message) = attention, let message, message != d.attention {
                log(.error, "\(host.name): deployment needs attention", detail: message)
            }
            updateDeployment(deploymentID) {
                $0.lastChecked = Date()
                $0.lastError = nil  // a successful check supersedes an earlier failure
                if case .some(let a) = attention { $0.attention = a }
                if let chainComplete { $0.servedChainComplete = chainComplete }
                $0.deployedSHA256 = found?.sha256
                $0.deployedNotAfter = found?.notAfter
            }
            if logResult, let cert = certificate(d.certificateID) {
                if found?.sha256 == cert.current?.sha256 {
                    log(.success, "Verified \(cert.name) is live on \(host.name)")
                } else {
                    log(.warning, "\(host.name) is not presenting the current \(cert.name) certificate",
                        detail: found.map { "Found \($0.subject), expires \($0.notAfter.formatted())" } ?? "No certificate found")
                }
            }
        } catch {
            updateDeployment(deploymentID) { $0.lastError = error.localizedDescription; $0.lastChecked = Date() }
            log(.error, "Check failed on \(host.name)", detail: error.localizedDescription)
        }
    }

    /// Monitor only: watch what the TLS endpoint serves, or — when the deployment has no endpoint (a
    /// service CertKeeper can't reach) — the certificate discovery finds in use on the host.
    /// An endpoint that's set but unreachable is an error; it never silently switches to the host.
    private func checkMonitored(_ d: Deployment, cert: ManagedCertificate, host: ManagedHost, logResult: Bool) async {
        func fail(_ message: String) {
            if d.lastError != message { log(.warning, "\(host.name): monitor check failed", detail: message) }
            updateDeployment(d.id) { $0.lastError = message; $0.lastChecked = Date() }
        }
        let leaf: CertificateSummary
        var chainComplete: Bool?
        if d.verifyEndpoint.isEmpty {
            do {
                let report = try await Discovery.run(on: host, ssh: ssh)
                guard let found = Discovery.relevantEndpoints(for: d, in: report.endpoints).compactMap(\.summary).first else {
                    return fail("Discovery on \(host.name) didn't find the \(d.kind.displayName) certificate")
                }
                leaf = found
            } catch {
                return fail("Couldn't read the certificate on \(host.name): \(error.localizedDescription)")
            }
        } else {
            var served: TLSProbe.Served?
            var failure: Error?
            for attempt in 0..<3 {
                do { served = try await TLSProbe.fetchServed(endpoint: d.verifyEndpoint); failure = nil; break }
                catch { failure = error }
                if attempt < 2 { try? await Task.sleep(for: .seconds(3)) }
            }
            guard let served, let first = served.chain.first else {
                return fail("Couldn't reach \(d.verifyEndpoint): \(failure?.localizedDescription ?? "no certificate presented")"
                    + ". If this service isn't reachable from CertKeeper, clear the deployment's TLS endpoint to read the certificate on the host instead.")
            }
            leaf = first
            if served.exact { chainComplete = TLSProbe.chainIsComplete(served.chain) }
        }
        let window = renewalWindow(for: cert)
        let previousDays = d.deployedNotAfter.map { Int(floor($0.timeIntervalSinceNow / 86_400)) }
        updateDeployment(d.id) {
            $0.lastChecked = Date()
            $0.lastError = nil
            $0.deployedSHA256 = leaf.sha256
            $0.deployedNotAfter = leaf.notAfter
            $0.servedChainComplete = chainComplete  // nil when read from the host: can't judge what's sent
        }
        updateCertificate(cert.id) { $0.current = leaf; $0.lastError = nil }
        if leaf.isExpired {
            log(.error, "\(cert.name) on \(host.name) has expired", detail: "Expired \(leaf.notAfter.formatted()). The system that renews it has stopped.")
        } else if leaf.daysRemaining <= window, previousDays.map({ $0 > window }) ?? true {
            log(.warning, "\(cert.name) on \(host.name) expires in \(leaf.daysRemaining) days",
                detail: "It's monitored, not renewed by CertKeeper. The system that renews it (e.g. the device's own ACME client) seems to have stopped.")
        } else if logResult {
            log(.success, "\(host.name) serves \(cert.name) (monitored)", detail: "Expires \(leaf.notAfter.formatted()) · issued by \(leaf.issuer)")
        }
    }

    /// Switches a certificate between managed (CertKeeper issues and deploys it) and monitor only.
    /// Going monitor-only discards CertKeeper's issued copy and its private key.
    public func setMonitorOnly(_ certID: UUID, _ monitored: Bool) {
        guard let cert = certificate(certID), cert.isMonitored != monitored else { return }
        updateCertificate(certID) {
            $0.external = monitored ? true : nil
            $0.leafPEM = nil
            $0.chainPEM = nil
            $0.current = nil
            $0.lastIssued = nil
            $0.lastError = nil
        }
        if monitored { secrets.delete(.certificateKey(certID)) }
        for d in deployments(for: certID) {
            updateDeployment(d.id) {
                $0.forceRedeploy = false
                $0.attention = nil
                $0.lastError = nil
                $0.deployedSHA256 = nil
                $0.deployedNotAfter = nil
                $0.servedChainComplete = nil
            }
        }
        log(.info, monitored ? "\(cert.name) is now monitor only" : "\(cert.name) is now managed by CertKeeper",
            detail: monitored ? "CertKeeper won't issue or deploy it; its deployments watch what each endpoint serves."
                              : "CertKeeper will issue and deploy it on the next rotation pass.")
    }

    // MARK: - Discovery

    public func discover(_ hostID: UUID) async {
        guard let host = host(hostID) else { return }
        await withBusy(hostID) {
            if host.isDeviceAPI {
                do {
                    let endpoint = try await discoverDevice(host)
                    updateHost(hostID) { $0.lastSeen = Date(); $0.lastDiscovery = [endpoint] }
                    log(.info, "Discovered the web interface certificate on \(host.name)", detail: endpoint.note)
                } catch {
                    log(.error, "Discovery failed on \(host.name)", detail: error.localizedDescription)
                }
                return
            }
            do {
                let report = try await Discovery.run(on: host, ssh: ssh)
                updateHost(hostID) {
                    $0.lastSeen = Date()
                    $0.lastDiscovery = report.endpoints.map(stashSecrets)
                    if $0.notes.isEmpty { $0.notes = report.os }
                }
                log(.info, "Discovered \(report.endpoints.count) certificate(s) on \(host.name)",
                    detail: ([report.os] + report.warnings).filter { !$0.isEmpty }.joined(separator: "\n"))
            } catch {
                log(.error, "Discovery failed on \(host.name)", detail: error.localizedDescription)
            }
        }
    }

    public func testConnection(_ hostID: UUID) async -> String {
        guard let host = host(hostID) else { return "Unknown host" }
        if host.isDeviceAPI {
            do {
                let info = try await deviceAPI(for: host).info()
                updateHost(hostID) { $0.lastSeen = Date() }
                return "Connected · token accepted · serving \(info.isSelfSigned ? "a self-signed" : "an installed") certificate for \(info.dnsNames.joined(separator: ", ")), expires \(info.notAfter)"
            } catch {
                return error.localizedDescription
            }
        }
        do {
            let r = try await ssh.runChecked("id -un; uname -sr", on: host, timeout: 30)
            updateHost(hostID) { $0.lastSeen = Date() }
            return "Connected as \(r.stdout.split(whereSeparator: \.isNewline).joined(separator: " · "))"
        } catch {
            return error.localizedDescription
        }
    }

    /// Which managed certificate an adopted endpoint should use.
    public enum AdoptTarget: Hashable {
        /// The best existing match (see `adoptionCandidates`), or a new certificate if none covers the names.
        case automatic
        case existing(UUID)
        case new
        /// Watch this endpoint's certificate without managing it (see `ManagedCertificate.external`).
        case monitor
    }

    /// How well a managed certificate fits a discovered endpoint's names.
    public enum Coverage: Comparable {
        /// Same set of names.
        case exact
        /// Covers every name (directly or by wildcard) and has `extra` other names.
        case covers(extra: Int)
        /// Doesn't cover these names — attaching would serve a certificate without them.
        case missing([String])

        var rank: (Int, Int) {
            switch self {
            case .exact: (0, 0)
            case .covers(let extra): (1, extra)
            case .missing(let names): (2, names.count)
            }
        }

        public static func < (a: Coverage, b: Coverage) -> Bool { a.rank < b.rank }
    }

    /// DNS names on a discovered certificate, without IP addresses.
    public static func dnsNames(of endpoint: DiscoveredEndpoint) -> [String] {
        (endpoint.summary?.dnsNames ?? []).filter { name in
            !name.contains(":") && !name.allSatisfy { $0.isNumber || $0 == "." }
        }
    }

    /// Whether certificate name `pattern` (possibly `*.example.com`) is valid for `name`.
    public static func name(_ pattern: String, covers name: String) -> Bool {
        let p = pattern.lowercased(), n = name.lowercased()
        if p == n { return true }
        guard p.hasPrefix("*."), !n.hasPrefix("*."), let dot = n.firstIndex(of: ".") else { return false }
        return n[n.index(after: dot)...] == p.dropFirst(2)
    }

    public func coverage(of cert: ManagedCertificate, for names: [String]) -> Coverage {
        let have = Set(cert.domains.map { $0.lowercased() })
        let want = Set(names.map { $0.lowercased() })
        if have == want { return .exact }
        let missing = names.filter { n in !cert.domains.contains { Self.name($0, covers: n) } }
        if !missing.isEmpty { return .missing(missing) }
        return .covers(extra: have.subtracting(want).count)
    }

    /// Managed certificates that cover all of the endpoint's names, best fit first
    /// (exact match, then fewest extra names).
    public func adoptionCandidates(for endpoint: DiscoveredEndpoint) -> [ManagedCertificate] {
        let names = Self.dnsNames(of: endpoint)
        guard !names.isEmpty else { return [] }
        return inventory.certificates.filter { !$0.isMonitored }
            .map { ($0, coverage(of: $0, for: names)) }
            .filter { if case .missing = $0.1 { return false }; return true }
            .sorted { $0.1 < $1.1 }
            .map(\.0)
    }

    /// The certificate `.automatic` would pick, or nil when it would create a new one.
    public func automaticAdoptionTarget(for endpoint: DiscoveredEndpoint) -> ManagedCertificate? {
        adoptionCandidates(for: endpoint).first
    }

    /// Brings a discovered certificate under management and links a deployment to it. By default it
    /// reuses the best-fitting managed certificate (same names, or one that already covers them —
    /// including by wildcard) and only creates a new certificate when none fits.
    @discardableResult
    public func adopt(_ endpoint: DiscoveredEndpoint, hostID: UUID, target: AdoptTarget = .automatic) -> Deployment {
        let names = Self.dnsNames(of: endpoint)
        let certID: UUID
        switch target {
        case .existing(let id) where certificate(id) != nil:
            certID = id
        case .automatic where automaticAdoptionTarget(for: endpoint) != nil:
            certID = automaticAdoptionTarget(for: endpoint)!.id
        case .monitor:
            if let existing = inventory.certificates.first(where: {
                $0.isMonitored && Set($0.domains.map { $0.lowercased() }) == Set(names.map { $0.lowercased() }) && !names.isEmpty
            }) {
                certID = existing.id
            } else {
                var c = ManagedCertificate(name: names.first ?? endpoint.label, domains: names)
                c.external = true
                c.current = endpoint.summary
                addCertificate(c)
                certID = c.id
            }
        default:
            let c = ManagedCertificate(name: names.first ?? endpoint.label, domains: names)
            addCertificate(c)
            certID = c.id
        }
        if endpoint.kind == .truenas,
           let i = inventory.deployments.firstIndex(where: { $0.hostID == hostID && $0.kind == .truenas && $0.certificateID == certID }) {
            // Fold the UI / an additional app into the existing TrueNAS deployment for this certificate.
            if let app = Discovery.truenasApp(endpoint) {
                let apps = inventory.deployments[i].truenasApps
                if !apps.contains(app) { inventory.deployments[i].options[DeploymentOption.truenasApps.rawValue] = (apps + [app]).joined(separator: ",") }
            } else {
                inventory.deployments[i].options[DeploymentOption.truenasUI.rawValue] = "true"
            }
            return inventory.deployments[i]
        }
        var d = Deployment(certificateID: certID, hostID: hostID, kind: endpoint.kind)
        if endpoint.kind == .truenas, let app = Discovery.truenasApp(endpoint) {
            d.options[DeploymentOption.truenasUI.rawValue] = "false"
            d.options[DeploymentOption.truenasApps.rawValue] = app
        }
        d.certPath = endpoint.kind.usesFilePaths ? endpoint.certPath : ""
        d.keyPath = endpoint.keyPath
        d.chainPath = endpoint.chainPath
        d.deployedSHA256 = endpoint.summary?.sha256
        d.deployedNotAfter = endpoint.summary?.notAfter
        d.lastChecked = Date()
        let secretKeys = Set(DeploymentOption.secrets.map(\.rawValue))
        for (key, value) in endpoint.options ?? [:]
        where key != DeploymentOption.verifyPort.rawValue && key != "monitor_suggested" && key != "generic" && !value.isEmpty {
            if secretKeys.contains(key) { try? secrets.set(value, for: .deploymentSecret(d.id, key)) }
            else { d.options[key] = value }
        }
        for (key, value) in discoveredSecrets[endpoint.id] ?? [:] {
            try? secrets.set(value, for: .deploymentSecret(d.id, key))
        }
        if target == .monitor && endpoint.options?["monitor_suggested"] == "true" {
            // The device renews this certificate itself, and discovery found the file it serves: read
            // that over SSH. Its TLS port may not be reachable from CertKeeper (UniFi OS Server's 11443
            // resets direct connections), and an endpoint can still be added in the editor.
            d.verifyEndpoint = ""
        } else if let h = host(hostID) {
            if let port = endpoint.options?[DeploymentOption.verifyPort.rawValue], !port.isEmpty {
                d.verifyEndpoint = "\(h.address):\(port)"
            } else {
                d.verifyEndpoint = "\(names.first(where: { !$0.hasPrefix("*") }) ?? h.address):443"
            }
        }
        addDeployment(d)
        return d
    }

    /// Whether a discovered endpoint is already covered by a deployment on that host.
    public func isManaged(_ endpoint: DiscoveredEndpoint, hostID: UUID) -> Bool {
        deployments(onHost: hostID).contains { d in
            guard d.kind == endpoint.kind else { return false }
            if d.kind.usesFilePaths { return d.certPath == endpoint.certPath }
            if d.kind == .truenas {
                if let app = Discovery.truenasApp(endpoint) { return d.truenasApps.contains(app) }
                return d.flag(.truenasUI)
            }
            return true
        }
    }

    // MARK: - Device API hosts

    /// For a Device API host the stored "password" is its API token.
    func deviceAPI(for host: ManagedHost) throws -> DeviceAPI {
        try DeviceAPI(host: host, token: secrets.get(.hostPassword(host.id)) ?? "")
    }

    func deviceEndpoint(_ host: ManagedHost) -> String { "\(host.address):\(host.port)" }

    /// The device's web interface as a discovered endpoint, so it can be adopted like any other.
    func discoverDevice(_ host: ManagedHost) async throws -> DiscoveredEndpoint {
        let info = try await deviceAPI(for: host).info()
        let summary = try? await TLSProbe.fetchLeaf(endpoint: deviceEndpoint(host))
        var note = info.isSelfSigned
            ? "Serving the device's self-signed certificate"
            : "Serving an installed certificate from \(info.issuer)"
        if let summary, summary.sha256 != info.sha256 {
            note += ". What CertKeeper sees (\(summary.sha256.prefix(16))…) differs from what the device reports (\(info.sha256.prefix(16))…)"
        }
        return DiscoveredEndpoint(kind: .deviceAPI, label: "Web interface", certPath: "", keyPath: "", chainPath: "",
                                  summary: summary, options: [DeploymentOption.verifyPort.rawValue: String(host.port)], note: note)
    }

    /// The fingerprint of whatever certificate the device presents right now, for pinning.
    public func fetchFingerprint(address: String, port: Int) async throws -> String {
        try await TLSProbe.fetchLeaf(endpoint: "\(address):\(port)").sha256
    }

    public func setHostPassword(_ password: String?, for hostID: UUID) throws {
        if let password, !password.isEmpty { try secrets.set(password, for: .hostPassword(hostID)) }
        else { secrets.delete(.hostPassword(hostID)) }
        SudoCache.shared.reset()
    }

    public func hasHostPassword(_ hostID: UUID) -> Bool { secrets.get(.hostPassword(hostID)) != nil }

    // MARK: - Rotation pass

    /// Renews what's due and pushes certificates to every deployment that isn't serving the current one.
    public func runMaintenance() async {
        guard !maintenanceRunning else { return }
        maintenanceRunning = true
        defer { maintenanceRunning = false; lastMaintenance = Date() }
        log(.info, "Rotation pass started")

        for cert in inventory.certificates where cert.autoRenew && needsIssuance(cert) {
            await issue(cert.id)
        }
        for d in inventory.deployments where d.enabled {
            await check(d.id)
        }
        if inventory.settings.autoDeploy {
            for d in inventory.deployments where needsDeployment(d) && d.attention == nil {
                await deploy(d.id)
            }
        }
        let blocked = inventory.deployments.filter { $0.enabled && $0.attention != nil }.count
        let outstanding = inventory.deployments.filter { needsDeployment($0) && $0.attention == nil }.count
        var problems: [String] = []
        if outstanding > 0 { problems.append("\(outstanding) deployment(s) still out of date") }
        if blocked > 0 { problems.append("\(blocked) deployment(s) need attention") }
        let monitoredTrouble = inventory.deployments.filter {
            switch state(of: $0) { case .expiringSoon, .expired: return true; default: return false }
        }.count
        if monitoredTrouble > 0 { problems.append("\(monitoredTrouble) monitored certificate(s) expiring or expired") }
        log(problems.isEmpty ? .success : .warning,
            "Rotation pass finished",
            detail: problems.isEmpty ? "Everything is current" : problems.joined(separator: "; "))
    }

    /// Reads every secret the inventory refers to once at startup, so missing keys are flagged early
    /// rather than during an unattended renewal.
    public func preflightSecrets() async {
        var items: [SecretItem] = [.cloudflareToken, .acmeAccountKey]
        items += inventory.hosts.map { .hostPassword($0.id) }
        items += inventory.deployments.flatMap { d in DeploymentOption.secrets.map { .deploymentSecret(d.id, $0.rawValue) } }
        let issued = inventory.certificates.filter { $0.leafPEM != nil }
        items += issued.map { .certificateKey($0.id) }
        let store = secrets
        let found = await Task.detached { items.map { store.get($0) != nil } }.value
        let missingKeys = zip(items, found).compactMap { item, ok -> String? in
            guard !ok, case .certificateKey(let id) = item else { return nil }
            return issued.first { $0.id == id }?.name
        }
        if !missingKeys.isEmpty {
            log(.error, "Private keys are missing for these certificates; they can't be deployed until they're issued again",
                detail: missingKeys.joined(separator: ", "))
        }
    }

    /// Stops the periodic rotation pass (at shutdown). A pass already running finishes its current step.
    public func stopScheduler() {
        schedulerTask?.cancel()
        schedulerTask = nil
    }

    public func startScheduler() {
        schedulerTask?.cancel()
        schedulerTask = Task { [weak self] in
            await self?.preflightSecrets()
            try? await Task.sleep(for: .seconds(30))
            while !Task.isCancelled {
                guard let self else { return }
                await self.runMaintenance()
                let hours = max(1, self.inventory.settings.checkIntervalHours)
                try? await Task.sleep(for: .seconds(hours * 3600))
            }
        }
    }
}
