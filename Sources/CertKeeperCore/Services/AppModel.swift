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

    @ObservationIgnored private let ssh = SSHRunner(askpassPath: Bundle.main.executablePath)
    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private var schedulerTask: Task<Void, Never>?
    @ObservationIgnored public let secrets: SecretStore
    /// Secret options found by discovery this session, by endpoint ID — never written to the inventory.
    @ObservationIgnored private var discoveredSecrets: [String: [String: String]] = [:]

    public init(fileURL: URL = InventoryFile.url, secrets: SecretStore = KeychainStore()) {
        self.fileURL = fileURL
        self.secrets = secrets
        do {
            inventory = try InventoryFile.load(from: fileURL)
            repairChains()
            moveSecretsOutOfInventory()
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
                    catch { log(.error, "Could not move a password into the Keychain", detail: error.localizedDescription); continue }
                    moved += 1
                }
                inventory.deployments[i].options[key.rawValue] = nil
            }
        }
        for i in inventory.hosts.indices where inventory.hosts[i].lastDiscovery.contains(where: Self.hasSecrets) {
            inventory.hosts[i].lastDiscovery = inventory.hosts[i].lastDiscovery.map(stashSecrets)
            moved += 1
        }
        if moved > 0 { log(.info, "Moved passwords from the inventory file into the Keychain") }
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

    public func log(_ level: LogEntry.Level, _ message: String, detail: String? = nil) {
        inventory.log.insert(LogEntry(level, message, detail: detail), at: 0)
        if inventory.log.count > 1000 { inventory.log.removeLast(inventory.log.count - 1000) }
    }

    /// Marks `id` as in progress for the duration of `body`. Operations on the same certificate or
    /// deployment check `busy` first, so a rotation pass never overlaps a deploy the user started.
    func withBusy<T>(_ id: UUID, _ body: () async throws -> T) async rethrows -> T {
        busy.insert(id)
        defer { busy.remove(id) }
        return try await body()
    }

    // MARK: - Mutations used by the UI

    public func addHost(_ host: ManagedHost) { inventory.hosts.append(host) }

    public func deleteHost(_ id: UUID) {
        Keychain.delete(.hostPassword(id))
        removeDeployments { $0.hostID == id }
        inventory.hosts.removeAll { $0.id == id }
    }

    public func addCertificate(_ cert: ManagedCertificate) { inventory.certificates.append(cert) }

    public func deleteCertificate(_ id: UUID) {
        removeDeployments { $0.certificateID == id }
        inventory.certificates.removeAll { $0.id == id }
        Keychain.delete(.certificateKey(id))
    }

    public func addDeployment(_ d: Deployment) { inventory.deployments.append(d) }
    public func deleteDeployment(_ id: UUID) { removeDeployments { $0.id == id } }

    // MARK: - Renewal policy

    public func renewalWindow(for cert: ManagedCertificate) -> Int {
        cert.renewDaysBeforeExpiry ?? inventory.settings.renewDaysBeforeExpiry
    }

    public enum CertStatus: Equatable {
        case notIssued, valid(days: Int), renewDue(days: Int), expired, domainsChanged
    }

    public func status(of cert: ManagedCertificate) -> CertStatus {
        guard let cur = cert.current, cert.leafPEM != nil else { return .notIssued }
        if Set(cur.dnsNames.map { $0.lowercased() }) != Set(cert.domains.map { $0.lowercased() }) { return .domainsChanged }
        if cur.isExpired { return .expired }
        if cur.daysRemaining <= renewalWindow(for: cert) { return .renewDue(days: cur.daysRemaining) }
        return .valid(days: cur.daysRemaining)
    }

    public func needsIssuance(_ cert: ManagedCertificate) -> Bool {
        if case .valid = status(of: cert) { return false }
        return true
    }

    /// A deployment is out of date when the service isn't confirmed to be serving the current certificate.
    public func needsDeployment(_ d: Deployment) -> Bool {
        guard d.enabled, let cert = certificate(d.certificateID), let cur = cert.current else { return false }
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
    }

    public func state(of d: Deployment) -> DeploymentState {
        if !d.enabled { return .disabled }
        if let attention = d.attention { return .attention(attention) }
        if let error = d.lastError { return .error(error) }
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
        let problems = count { if case .attention = $0 { return true }; if case .error = $0 { return true }; return false }
        let outOfDate = count { $0 == .outOfDate }
        let chain = count { $0 == .incompleteChain }
        let awaiting = count { $0 == .awaitingIssuance }
        let total = states.count
        let noun = total == 1 ? "deployment" : "deployments"

        var parts: [String] = []
        if problems > 0 { parts.append("\(problems) need\(problems == 1 ? "s" : "") attention") }
        if outOfDate > 0 { parts.append("\(outOfDate) out of date") }
        if chain > 0 { parts.append("\(chain) with an incomplete chain") }
        if awaiting > 0 { parts.append("\(awaiting) awaiting issuance") }
        let level: HostHealth.Level = problems > 0 ? .problem : (outOfDate + chain > 0 ? .warning : (awaiting > 0 ? .pending : .current))
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
        guard let cfToken = Keychain.get(.cloudflareToken), !cfToken.isEmpty else {
            throw DeployError("No Cloudflare API token configured (Settings › Cloudflare)")
        }
        let domains = cert.domains.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        guard !domains.isEmpty else { throw DeployError("Certificate has no domains") }

        let accountKey: String
        if let k = Keychain.get(.acmeAccountKey) { accountKey = k } else {
            accountKey = ACMEClient.newAccountKeyPEM()
            try Keychain.set(accountKey, for: .acmeAccountKey)
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
        try Keychain.set(keyPEM, for: .certificateKey(cert.id))
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
              let cert = certificate(d.certificateID), let host = host(d.hostID),
              !busy.contains(deploymentID) else { return }
        await withBusy(deploymentID) {
            let label = "\(cert.name) → \(host.name) (\(d.kind.displayName))"
            do {
                guard let key = Keychain.get(.certificateKey(cert.id)) else {
                    throw DeployError("Private key for \(cert.name) is missing from the Keychain — reissue the certificate")
                }
                let script = try DeployScripts.build(deployment: withSecrets(d), certificate: cert, keyPEM: key)
                log(.info, "Deploying \(label)")
                let result = try await ssh.runChecked(script, on: host, timeout: 300)
                updateDeployment(deploymentID) { $0.lastDeployed = Date(); $0.lastError = nil; $0.forceRedeploy = false }
                log(.success, "Deployed \(label)", detail: result.stdout.trimmingCharacters(in: .whitespacesAndNewlines))
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
        do {
            var found: CertificateSummary?
            var onDisk: CertificateSummary?
            var fileMissing = false
            if d.kind.usesFilePaths {
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

    // MARK: - Discovery

    public func discover(_ hostID: UUID) async {
        guard let host = host(hostID) else { return }
        await withBusy(hostID) {
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
        return inventory.certificates
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
        for (key, value) in endpoint.options ?? [:] where key != DeploymentOption.verifyPort.rawValue && !value.isEmpty {
            if secretKeys.contains(key) { try? secrets.set(value, for: .deploymentSecret(d.id, key)) }
            else { d.options[key] = value }
        }
        for (key, value) in discoveredSecrets[endpoint.id] ?? [:] {
            try? secrets.set(value, for: .deploymentSecret(d.id, key))
        }
        if let h = host(hostID) {
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

    public func setHostPassword(_ password: String?, for hostID: UUID) throws {
        if let password, !password.isEmpty { try Keychain.set(password, for: .hostPassword(hostID)) }
        else { Keychain.delete(.hostPassword(hostID)) }
        SudoCache.shared.reset()
    }

    public func hasHostPassword(_ hostID: UUID) -> Bool { Keychain.get(.hostPassword(hostID)) != nil }

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
        log(problems.isEmpty ? .success : .warning,
            "Rotation pass finished",
            detail: problems.isEmpty ? "Everything is current" : problems.joined(separator: "; "))
    }

    /// Reads every secret the app owns once, so any Keychain access prompt appears at launch while
    /// someone is at the Mac — not during an unattended renewal — and missing keys are flagged early.
    public func preflightSecrets() async {
        var items: [Keychain.Item] = [.cloudflareToken, .acmeAccountKey]
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
            log(.error, "Private keys missing from the Keychain — these certificates can't be deployed until reissued",
                detail: missingKeys.joined(separator: ", "))
        }
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
