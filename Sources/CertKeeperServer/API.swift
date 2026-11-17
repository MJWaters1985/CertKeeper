import CertKeeperCore
import Foundation
import Hummingbird
import NIOCore

/// The JSON API behind the web interface. Every model access happens on the main actor, where
/// AppModel lives. Long operations (issue, deploy, check, discover, rotation pass) start in the
/// background and return 202; the page polls /api/state to follow them.
enum API {
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    static func json<T: Encodable>(_ value: T, status: HTTPResponse.Status = .ok) throws -> Response {
        let data = try encoder.encode(value)
        return Response(status: status, headers: [.contentType: "application/json"], body: .init(byteBuffer: ByteBuffer(bytes: data)))
    }

    static func accepted() throws -> Response { try json(["started": true], status: .accepted) }

    static func id(_ context: AppContext, _ name: String = "id") throws -> UUID {
        guard let id = UUID(uuidString: try context.parameters.require(name)) else {
            throw HTTPError(.badRequest, message: "Bad \(name)")
        }
        return id
    }

    static func badRequest(_ message: String) -> HTTPError { HTTPError(.badRequest, message: message) }

    // MARK: - Routes

    static func addRoutes(to router: Router<AppContext>, server: ServerState) {
        let auth = server.auth
        router.get("healthz") { _, _ in "ok" }

        let api = router.group("api").add(middleware: SessionMiddleware(auth: auth))

        // Session
        api.get("session") { _, context in
            try json(SessionInfo(signedIn: context.username != nil, username: context.username, needsSetup: auth.needsSetup))
        }
        api.post("setup") { request, context in
            let input = try await request.decode(as: SetupInput.self, context: context)
            do {
                let token = try auth.setUp(code: input.code, username: input.username, password: input.password)
                await server.log(.info, "Administrator account \"\(input.username)\" created")
                var response = try json(SessionInfo(signedIn: true, username: input.username, needsSetup: false))
                response.setCookie(SessionMiddleware.cookie(token))
                return response
            } catch let e as Auth.AuthError { throw badRequest(e.message) }
        }
        api.post("login") { request, context in
            let input = try await request.decode(as: LoginInput.self, context: context)
            do {
                let token = try auth.logIn(username: input.username, password: input.password, from: context.remoteAddress)
                var response = try json(SessionInfo(signedIn: true, username: input.username, needsSetup: false))
                response.setCookie(SessionMiddleware.cookie(token))
                return response
            } catch let e as Auth.AuthError {
                if e.retryAfter != nil { throw HTTPError(.tooManyRequests, message: e.message) }
                await server.log(.warning, "Failed sign-in for \"\(input.username)\" from \(context.remoteAddress)")
                throw HTTPError(.unauthorized, message: e.message)
            }
        }
        api.post("logout") { _, context in
            if let token = context.sessionToken { auth.logOut(token) }
            var response = try json(SessionInfo(signedIn: false, username: nil, needsSetup: false))
            response.setCookie(SessionMiddleware.expiredCookie())
            return response
        }
        api.post("password") { request, context in
            let input = try await request.decode(as: PasswordInput.self, context: context)
            do {
                try auth.changePassword(current: input.current, new: input.new, keeping: context.sessionToken ?? "")
            } catch let e as Auth.AuthError { throw badRequest(e.message) }
            await server.log(.info, "Administrator password changed; other sessions were signed out")
            return try json(["ok": true])
        }

        // State
        api.get("state") { _, _ in try json(await server.snapshot()) }
        api.get("log") { _, _ in try json(await MainActor.run { server.model.inventory.log }) }
        api.delete("log") { _, _ in
            await MainActor.run { server.model.inventory.log.removeAll() }
            return try json(["ok": true])
        }

        // Settings
        api.put("settings") { request, context in
            let input = try await request.decode(as: AppSettings.self, context: context)
            await MainActor.run { server.model.inventory.settings = input }
            return try json(["ok": true])
        }
        api.put("cloudflare") { request, context in
            let input = try await request.decode(as: TokenInput.self, context: context)
            let token = input.token.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !token.isEmpty else { throw badRequest("Paste the API token") }
            try await MainActor.run { try server.model.secrets.set(token, for: .cloudflareToken) }
            return try json(["ok": true])
        }
        api.delete("cloudflare") { _, _ in
            await MainActor.run { server.model.secrets.delete(.cloudflareToken) }
            return try json(["ok": true])
        }
        api.post("cloudflare/verify") { request, context in
            let input = try await request.decode(as: TokenInput.self, context: context)
            let stored = await MainActor.run { server.model.secrets.get(.cloudflareToken) }
            let token = input.token.isEmpty ? (stored ?? "") : input.token.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !token.isEmpty else { throw badRequest("No Cloudflare token is saved") }
            do {
                let v = try await CloudflareClient(token: token).verifyToken()
                let zones = (try? await CloudflareClient(token: token).listZones().map(\.name)) ?? []
                return try json(VerifyResult(ok: true, message: "Token is \(v.status)", zones: zones))
            } catch {
                return try json(VerifyResult(ok: false, message: error.localizedDescription, zones: []))
            }
        }
        api.put("server-certificate") { request, context in
            let input = try await request.decode(as: ServerCertificateInput.self, context: context)
            try await server.setServerCertificate(input.certificateID)
            return try json(["ok": true])
        }

        // Rotation pass
        api.post("maintenance") { _, _ in
            try await server.start { await $0.runMaintenance() }
            return try accepted()
        }

        // Certificates
        api.post("certificates") { request, context in
            let input = try await request.decode(as: CertificateInput.self, context: context)
            let cert = try await MainActor.run { () -> ManagedCertificate in
                var cert = ManagedCertificate(name: "", domains: [])
                try input.apply(to: &cert)
                server.model.addCertificate(cert)
                if input.monitorOnly == true { server.model.setMonitorOnly(cert.id, true) }
                return cert
            }
            return try json(["id": cert.id], status: .created)
        }
        api.put("certificates/:id") { request, context in
            let id = try id(context)
            let input = try await request.decode(as: CertificateInput.self, context: context)
            try await MainActor.run {
                guard let i = server.model.inventory.certificates.firstIndex(where: { $0.id == id }) else { throw HTTPError(.notFound) }
                var cert = server.model.inventory.certificates[i]
                try input.apply(to: &cert)
                server.model.inventory.certificates[i] = cert
                if let monitor = input.monitorOnly, monitor != cert.isMonitored { server.model.setMonitorOnly(id, monitor) }
            }
            return try json(["ok": true])
        }
        api.delete("certificates/:id") { _, context in
            let id = try id(context)
            try await MainActor.run {
                guard !server.model.busy.contains(id) else { throw HTTPError(.conflict, message: "It's busy; try again when it's done") }
                server.model.deleteCertificate(id)
            }
            await server.certificateDeleted(id)
            return try json(["ok": true])
        }
        api.post("certificates/:id/issue") { _, context in
            let id = try id(context)
            try await server.start { await $0.issue(id) }
            return try accepted()
        }
        api.post("certificates/:id/export") { request, context in
            let id = try id(context)
            let input = try await request.decode(as: ExportInput.self, context: context)
            guard let format = CertExport.Format(rawValue: input.format) else { throw badRequest("Unknown format") }
            let (cert, key) = try await MainActor.run { () -> (ManagedCertificate, String) in
                guard let cert = server.model.certificate(id) else { throw HTTPError(.notFound) }
                guard let key = server.model.secrets.get(.certificateKey(id)) else {
                    throw badRequest("\(cert.name) has no private key here")
                }
                return (cert, key)
            }
            do {
                let files = try CertExport.files(for: cert, keyPEM: key, format: format, password: input.password, legacy: input.legacy ?? false)
                await server.log(.info, "Exported \(cert.name) (\(format.title))")
                return try json(files.map { FileDTO(name: $0.name, data: $0.data.base64EncodedString(), secret: $0.secret) })
            } catch {
                throw badRequest(error.localizedDescription)
            }
        }

        // Hosts
        api.post("hosts") { request, context in
            let input = try await request.decode(as: HostInput.self, context: context)
            let host = try await MainActor.run { () -> ManagedHost in
                var host = ManagedHost(name: "", address: "")
                try input.apply(to: &host, model: server.model)
                server.model.addHost(host)
                return host
            }
            return try json(["id": host.id], status: .created)
        }
        api.put("hosts/:id") { request, context in
            let id = try id(context)
            let input = try await request.decode(as: HostInput.self, context: context)
            try await MainActor.run {
                guard let i = server.model.inventory.hosts.firstIndex(where: { $0.id == id }) else { throw HTTPError(.notFound) }
                var host = server.model.inventory.hosts[i]
                try input.apply(to: &host, model: server.model)
                server.model.inventory.hosts[i] = host
            }
            return try json(["ok": true])
        }
        api.delete("hosts/:id") { _, context in
            let id = try id(context)
            try await MainActor.run {
                guard !server.model.busy.contains(id) else { throw HTTPError(.conflict, message: "It's busy; try again when it's done") }
                server.model.deleteHost(id)
            }
            return try json(["ok": true])
        }
        api.post("hosts/:id/test") { _, context in
            let id = try id(context)
            try server.checkAccepting()
            let message = await server.model.testConnection(id)
            return try json(["message": message])
        }
        api.post("hosts/:id/discover") { _, context in
            let id = try id(context)
            try await server.start { await $0.discover(id) }
            return try accepted()
        }
        api.post("hosts/:id/adopt") { request, context in
            let hostID = try id(context)
            let input = try await request.decode(as: AdoptInput.self, context: context)
            let deployment = try await MainActor.run { () -> Deployment in
                guard let host = server.model.host(hostID), let ep = host.lastDiscovery.first(where: { $0.id == input.endpointID }) else {
                    throw HTTPError(.notFound, message: "That discovered certificate is gone; discover again")
                }
                let target: AppModel.AdoptTarget
                switch input.target {
                case "automatic": target = .automatic
                case "new": target = .new
                case "monitor": target = .monitor
                case "existing":
                    guard let c = input.certificateID else { throw badRequest("Pick a certificate") }
                    target = .existing(c)
                default: throw badRequest("Unknown target")
                }
                return server.model.adopt(ep, hostID: hostID, target: target)
            }
            try? await server.start { await $0.check(deployment.id) }
            return try json(["deploymentID": deployment.id, "certificateID": deployment.certificateID], status: .created)
        }
        api.post("fingerprint") { request, context in
            let input = try await request.decode(as: FingerprintInput.self, context: context)
            do {
                let sha = try await server.model.fetchFingerprint(address: input.address, port: input.port)
                return try json(["sha256": DeviceAPI.formatFingerprint(sha)])
            } catch {
                throw badRequest(error.localizedDescription)
            }
        }

        // Deployments
        api.post("deployments") { request, context in
            let input = try await request.decode(as: DeploymentInput.self, context: context)
            let d = try await MainActor.run { () -> Deployment in
                guard server.model.certificate(input.certificateID) != nil, server.model.host(input.hostID) != nil else {
                    throw badRequest("Pick a certificate and a host")
                }
                var d = Deployment(certificateID: input.certificateID, hostID: input.hostID, kind: input.kind)
                try input.apply(to: &d, model: server.model)
                server.model.addDeployment(d)
                return d
            }
            try? await server.start { await $0.check(d.id) }
            return try json(["id": d.id], status: .created)
        }
        api.put("deployments/:id") { request, context in
            let id = try id(context)
            let input = try await request.decode(as: DeploymentInput.self, context: context)
            try await MainActor.run {
                guard let i = server.model.inventory.deployments.firstIndex(where: { $0.id == id }) else { throw HTTPError(.notFound) }
                var d = server.model.inventory.deployments[i]
                if d.certificateID != input.certificateID { d.deployedSHA256 = nil }
                d.certificateID = input.certificateID
                d.hostID = input.hostID
                d.kind = input.kind
                try input.apply(to: &d, model: server.model)
                d.attention = nil  // edited: let the next pass try again
                server.model.inventory.deployments[i] = d
            }
            return try json(["ok": true])
        }
        api.delete("deployments/:id") { _, context in
            let id = try id(context)
            try await MainActor.run {
                guard !server.model.busy.contains(id) else { throw HTTPError(.conflict, message: "It's busy; try again when it's done") }
                server.model.deleteDeployment(id)
            }
            return try json(["ok": true])
        }
        api.post("deployments/:id/deploy") { _, context in
            let id = try id(context)
            try await server.start { await $0.deploy(id) }
            return try accepted()
        }
        api.post("deployments/:id/check") { _, context in
            let id = try id(context)
            try await server.start { await $0.check(id, logResult: true) }
            return try accepted()
        }

        // Configuration transfer
        api.post("config/export") { request, context in
            let input = try await request.decode(as: ConfigExportInput.self, context: context)
            if let p = input.password, !p.isEmpty, p.count < 10 { throw badRequest("Use a password of at least 10 characters") }
            let data = try await MainActor.run { try server.model.exportConfiguration(password: input.password.flatMap { $0.isEmpty ? nil : $0 }) }
            await server.log(.info, "Configuration exported\(input.password?.isEmpty == false ? " with secrets" : "")")
            return try json(FileDTO(name: "CertKeeper-configuration.json", data: data.base64EncodedString(), secret: input.password?.isEmpty == false))
        }
        api.post("config/import") { request, context in
            let input = try await request.decode(as: ConfigImportInput.self, context: context)
            guard let data = Data(base64Encoded: input.file) else { throw badRequest("That file couldn't be read") }
            let file: ConfigTransfer.File
            do { file = try ConfigTransfer.read(data) } catch { throw badRequest(error.localizedDescription) }
            var secrets: [(Keychain.Item, String)] = []
            if file.secrets != nil, let password = input.password, !password.isEmpty {
                do { secrets = try ConfigTransfer.decryptSecrets(file, password: password) } catch { throw badRequest(error.localizedDescription) }
            }
            let summary = ImportSummary(exportedAt: file.exportedAt, hosts: file.inventory.hosts.count,
                                        certificates: file.inventory.certificates.count, deployments: file.inventory.deployments.count,
                                        secretsInFile: file.secrets?.count ?? 0, secretsImported: secrets.count, message: nil)
            guard input.confirm == true else { return try json(summary) }
            try server.checkAccepting()
            let imported = secrets
            let message = try await MainActor.run { () -> String in
                guard server.model.busy.isEmpty, !server.model.maintenanceRunning else {
                    throw HTTPError(.conflict, message: "Wait for the running operations to finish")
                }
                let backup = try server.model.importConfiguration(file, secrets: imported)
                return (server.model.inventory.log.first?.detail ?? "Imported").replacingOccurrences(of: backup.lastPathComponent, with: backup.path)
            }
            var done = summary
            done.message = message
            return try json(done)
        }
    }
}

// MARK: - Inputs

struct SetupInput: Decodable { var code: String; var username: String; var password: String }
struct LoginInput: Decodable { var username: String; var password: String }
struct PasswordInput: Decodable { var current: String; var new: String }
struct TokenInput: Decodable { var token: String }
struct ServerCertificateInput: Decodable { var certificateID: UUID? }
struct ExportInput: Decodable { var format: String; var password: String?; var legacy: Bool? }
struct AdoptInput: Decodable { var endpointID: String; var target: String; var certificateID: UUID? }
struct FingerprintInput: Decodable { var address: String; var port: Int }
struct ConfigExportInput: Decodable { var password: String? }
struct ConfigImportInput: Decodable { var file: String; var password: String?; var confirm: Bool? }

struct CertificateInput: Decodable {
    var name: String
    var domains: [String]
    var keyAlgorithm: KeyAlgorithm?
    var renewDaysBeforeExpiry: Int?
    var autoRenew: Bool?
    var monitorOnly: Bool?

    func apply(to cert: inout ManagedCertificate) throws {
        let domains = self.domains.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        guard !domains.isEmpty else { throw API.badRequest("Add at least one domain name") }
        if let bad = domains.first(where: { !Self.validName($0) }) { throw API.badRequest("\"\(bad)\" isn't a valid domain name") }
        cert.domains = Array(NSOrderedSet(array: domains)) as? [String] ?? domains
        let name = self.name.trimmingCharacters(in: .whitespaces)
        cert.name = name.isEmpty ? domains[0] : name
        if let keyAlgorithm { cert.keyAlgorithm = keyAlgorithm }
        if let days = renewDaysBeforeExpiry, !(1...60).contains(days) { throw API.badRequest("Renew between 1 and 60 days before expiry") }
        cert.renewDaysBeforeExpiry = renewDaysBeforeExpiry
        if let autoRenew { cert.autoRenew = autoRenew }
    }

    static func validName(_ s: String) -> Bool {
        let labels = (s.hasPrefix("*.") ? String(s.dropFirst(2)) : s).split(separator: ".", omittingEmptySubsequences: false)
        return labels.count >= 2 && labels.allSatisfy { l in
            !l.isEmpty && l.count <= 63 && !l.hasPrefix("-") && !l.hasSuffix("-")
                && l.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
        }
    }
}

struct HostInput: Decodable {
    var name: String
    var address: String
    var port: Int?
    var username: String?
    var identityFile: String?
    var useSudo: Bool?
    var passwordLogin: Bool?
    var notes: String?
    var connection: HostConnection?
    var apiPinnedSHA256: String?
    /// nil: keep the stored password; "": remove it; otherwise replace it.
    var password: String?

    @MainActor func apply(to host: inout ManagedHost, model: AppModel) throws {
        let address = self.address.trimmingCharacters(in: .whitespaces)
        guard !address.isEmpty else { throw API.badRequest("Enter the host's address") }
        guard !address.hasPrefix("-"), !address.contains(where: { $0.isWhitespace }) else { throw API.badRequest("That address isn't valid") }
        host.address = address
        let name = self.name.trimmingCharacters(in: .whitespaces)
        host.name = name.isEmpty ? address : name
        if let port { guard (1...65535).contains(port) else { throw API.badRequest("Port must be 1–65535") }; host.port = port }
        if let username {
            guard !username.hasPrefix("-") else { throw API.badRequest("That username isn't valid") }
            host.username = username.trimmingCharacters(in: .whitespaces)
        }
        if let identityFile { host.identityFile = identityFile.trimmingCharacters(in: .whitespaces) }
        if let useSudo { host.useSudo = useSudo }
        if let notes { host.notes = notes }
        if let connection { host.connection = connection }
        if let apiPinnedSHA256 { host.apiPinnedSHA256 = DeviceAPI.normalizeFingerprint(apiPinnedSHA256) }
        if let password {
            try model.setHostPassword(password.isEmpty ? nil : password, for: host.id)
        }
        host.passwordLogin = (passwordLogin ?? host.passwordLogin) && model.hasHostPassword(host.id)
        if host.isDeviceAPI {
            host.passwordLogin = false
            host.useSudo = false
        }
    }
}

struct DeploymentInput: Decodable {
    var certificateID: UUID
    var hostID: UUID
    var kind: DeploymentKind
    var certPath: String?
    var keyPath: String?
    var chainPath: String?
    var verifyEndpoint: String?
    var enabled: Bool?
    var options: [String: String]?
    /// nil = the built-in script.
    var scriptOverride: String?
    /// nil = keep; "" = none.
    var pfxPassword: String?

    @MainActor func apply(to d: inout Deployment, model: AppModel) throws {
        d.certPath = (certPath ?? "").trimmingCharacters(in: .whitespaces)
        d.keyPath = (keyPath ?? "").trimmingCharacters(in: .whitespaces)
        d.chainPath = (chainPath ?? "").trimmingCharacters(in: .whitespaces)
        d.verifyEndpoint = (verifyEndpoint ?? "").trimmingCharacters(in: .whitespaces)
        if let enabled { d.enabled = enabled }
        var options: [String: String] = [:]
        for (k, v) in self.options ?? [:] where k != DeploymentOption.pfxPassword.rawValue {
            let value = v.trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { options[k] = value }
        }
        d.options = options
        d.scriptOverride = scriptOverride.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
        if let pfxPassword { try model.setSecret(d.isPKCS12 ? pfxPassword : "", .pfxPassword, for: d.id) }
        if d.kind == .pihole && d.certPath.isEmpty { d.certPath = "/etc/pihole/tls.pem" }
    }
}

// MARK: - Outputs

struct SessionInfo: Encodable { var signedIn: Bool; var username: String?; var needsSetup: Bool }
struct VerifyResult: Encodable { var ok: Bool; var message: String; var zones: [String] }
struct FileDTO: Encodable { var name: String; var data: String; var secret: Bool }
struct ImportSummary: Encodable {
    var exportedAt: Date
    var hosts: Int, certificates: Int, deployments: Int, secretsInFile: Int, secretsImported: Int
    var message: String?
}
