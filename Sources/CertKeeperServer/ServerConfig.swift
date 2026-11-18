import Crypto
import _CryptoExtras
import Foundation

/// Settings from the environment (the TrueNAS install form sets these).
struct ServerConfig: Sendable {
    /// All state: inventory, encrypted secrets, users, TLS files, SSH keys (as HOME).
    var configDirectory: URL
    var host: String
    var port: Int
    /// A certificate and key the platform provides (TrueNAS writes the one picked in the install form).
    /// When both are set the server always uses them.
    var tlsCertificateFile: String?
    var tlsKeyFile: String?
    /// Key for the secrets file. When unset, a random key is kept in `secrets.key` next to it.
    var secretKey: String?
    /// Run rotation passes on the schedule. CERTKEEPER_SCHEDULE=off is for demos and tests, where
    /// the hosts in the inventory don't exist.
    var schedule = true

    static let defaultPort = 8443

    init(environment env: [String: String]) throws {
        configDirectory = URL(fileURLWithPath: env["CERTKEEPER_CONFIG_DIR"].flatMap { $0.isEmpty ? nil : $0 } ?? "/config",
                              isDirectory: true)
        host = env["CERTKEEPER_HOST"].flatMap { $0.isEmpty ? nil : $0 } ?? "0.0.0.0"
        if let raw = env["CERTKEEPER_PORT"], !raw.isEmpty {
            guard let p = Int(raw), (1...65535).contains(p) else { throw ConfigError("CERTKEEPER_PORT must be a port number, not \"\(raw)\"") }
            port = p
        } else {
            port = Self.defaultPort
        }
        tlsCertificateFile = env["CERTKEEPER_TLS_CERT"].flatMap { $0.isEmpty ? nil : $0 }
        tlsKeyFile = env["CERTKEEPER_TLS_KEY"].flatMap { $0.isEmpty ? nil : $0 }
        if (tlsCertificateFile == nil) != (tlsKeyFile == nil) {
            throw ConfigError("Set both CERTKEEPER_TLS_CERT and CERTKEEPER_TLS_KEY, or neither")
        }
        secretKey = env["CERTKEEPER_SECRET_KEY"].flatMap { $0.isEmpty ? nil : $0 }
        switch env["CERTKEEPER_SCHEDULE"]?.lowercased() {
        case nil, "", "on": schedule = true
        case "off": schedule = false
        case let other?: throw ConfigError("CERTKEEPER_SCHEDULE must be on or off, not \"\(other)\"")
        }
    }

    var inventoryFile: URL { configDirectory.appendingPathComponent("inventory.json") }
    var secretsFile: URL { configDirectory.appendingPathComponent("secrets.enc") }
    var secretsKeyFile: URL { configDirectory.appendingPathComponent("secrets.key") }
    var usersFile: URL { configDirectory.appendingPathComponent("users.json") }
    var serverSettingsFile: URL { configDirectory.appendingPathComponent("server.json") }
    var tlsDirectory: URL { configDirectory.appendingPathComponent("tls", isDirectory: true) }
}

struct ConfigError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// The key that encrypts `secrets.enc`.
enum SecretsKey {
    /// From CERTKEEPER_SECRET_KEY when set (32 bytes in base64, or any passphrase, stretched with
    /// PBKDF2), else from `secrets.key`, which is created on first start.
    static func load(_ config: ServerConfig) throws -> (key: SymmetricKey, source: String) {
        if let value = config.secretKey {
            if let raw = Data(base64Encoded: value), raw.count == 32 {
                return (SymmetricKey(data: raw), "CERTKEEPER_SECRET_KEY")
            }
            // A fixed salt is fine here: the passphrase protects one file, and PBKDF2 slows guessing.
            let key = try KDF.Insecure.PBKDF2.deriveKey(from: Array(value.utf8), salt: Array("certkeeper-secrets-v1".utf8),
                                                        using: .sha256, outputByteCount: 32, rounds: 600_000)
            return (key, "CERTKEEPER_SECRET_KEY (passphrase)")
        }
        let url = config.secretsKeyFile
        if FileManager.default.fileExists(atPath: url.path) {
            let text = try String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            guard let raw = Data(base64Encoded: text), raw.count == 32 else {
                throw ConfigError("\(url.path) isn't a valid secrets key")
            }
            return (SymmetricKey(data: raw), url.path)
        }
        let key = SymmetricKey(size: .bits256)
        let text = key.withUnsafeBytes { Data($0).base64EncodedString() } + "\n"
        try FileSecurity.writePrivate(Data(text.utf8), to: url)
        return (key, url.path + " (new)")
    }
}

enum FileSecurity {
    /// Writes `data` readable by the owner only, atomically (temporary file, then rename).
    static func writePrivate(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let temp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        // Created with mode 0600 from the start, so the contents are never readable by others.
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw ConfigError("Couldn't write \(url.path): \(String(cString: strerror(errno)))") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(temp.path, url.path) == 0 else { throw ConfigError("Couldn't write \(url.path): \(String(cString: strerror(errno)))") }
        } catch {
            try? FileManager.default.removeItem(at: temp)
            throw error
        }
    }
}
