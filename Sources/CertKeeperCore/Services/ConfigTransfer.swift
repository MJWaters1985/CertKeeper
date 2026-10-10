import CommonCrypto
import Crypto
import Foundation

/// Export and import of CertKeeper's configuration.
///
/// The file is JSON: the inventory (hosts, certificates, deployments, settings, ACME account links;
/// not the activity log) plus, optionally, the secrets from the Keychain, encrypted with a password
/// (PBKDF2-SHA256 → AES-256-GCM). Without the secrets the file contains no passwords or private keys.
public enum ConfigTransfer {
    public static let format = "certkeeper-configuration"
    public static let currentVersion = 1
    static let iterations: UInt32 = 600_000

    public struct File: Codable {
        public var format: String
        public var version: Int
        public var exportedAt: Date
        public var inventory: Inventory
        public var secrets: EncryptedSecrets?
    }

    public struct EncryptedSecrets: Codable {
        public var kdf: String
        public var iterations: UInt32
        public var salt: String     // base64
        public var sealed: String   // base64 AES-GCM combined (nonce + ciphertext + tag)
        public var count: Int
    }

    public enum TransferError: LocalizedError, Equatable {
        case notAConfiguration
        case unsupportedVersion(Int)
        case wrongPassword
        case passwordTooShort
        case keyDerivationFailed

        public var errorDescription: String? {
            switch self {
            case .notAConfiguration: "This isn't a CertKeeper configuration file."
            case .unsupportedVersion(let v): "This file is from a newer version of CertKeeper (format \(v))."
            case .wrongPassword: "The password is wrong, or the file has been altered."
            case .passwordTooShort: "Use a password of at least 8 characters."
            case .keyDerivationFailed: "Couldn't derive the encryption key."
            }
        }
    }

    // MARK: Secrets in an inventory

    /// Every Keychain item the inventory can refer to.
    public static func secretItems(for inventory: Inventory) -> [Keychain.Item] {
        var items: [Keychain.Item] = [.cloudflareToken, .acmeAccountKey]
        items += inventory.certificates.map { .certificateKey($0.id) }
        items += inventory.hosts.map { .hostPassword($0.id) }
        items += inventory.deployments.flatMap { d in DeploymentOption.secrets.map { .deploymentSecret(d.id, $0.rawValue) } }
        return items
    }

    // MARK: Export

    /// Builds the export. `password` nil = no secrets in the file.
    public static func export(_ inventory: Inventory, secrets store: SecretStore, password: String?, now: Date = Date()) throws -> Data {
        var inv = inventory
        inv.log = []
        var file = File(format: format, version: currentVersion, exportedAt: now, inventory: inv, secrets: nil)
        if let password {
            guard password.count >= 8 else { throw TransferError.passwordTooShort }
            var values: [String: String] = [:]
            for item in secretItems(for: inventory) {
                if let v = store.get(item) { values[item.account] = v }
            }
            let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
            let key = try deriveKey(password: password, salt: salt, iterations: iterations)
            let plaintext = try JSONEncoder().encode(values)
            let sealed = try AES.GCM.seal(plaintext, using: key).combined!
            file.secrets = EncryptedSecrets(kdf: "PBKDF2-SHA256", iterations: iterations, salt: salt.base64EncodedString(),
                                            sealed: sealed.base64EncodedString(), count: values.count)
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(file)
    }

    // MARK: Import

    public static func read(_ data: Data) throws -> File {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let file = try? decoder.decode(File.self, from: data), file.format == format else {
            throw TransferError.notAConfiguration
        }
        guard file.version <= currentVersion else { throw TransferError.unsupportedVersion(file.version) }
        return file
    }

    /// Decrypts the secrets in `file`, keyed by Keychain item.
    public static func decryptSecrets(_ file: File, password: String) throws -> [(Keychain.Item, String)] {
        guard let s = file.secrets, let salt = Data(base64Encoded: s.salt), let sealedData = Data(base64Encoded: s.sealed) else {
            return []
        }
        let key = try deriveKey(password: password, salt: salt, iterations: s.iterations)
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(try AES.GCM.SealedBox(combined: sealedData), using: key)
        } catch {
            throw TransferError.wrongPassword
        }
        let values = try JSONDecoder().decode([String: String].self, from: plaintext)
        let known = Dictionary(secretItems(for: file.inventory).map { ($0.account, $0) }, uniquingKeysWith: { a, _ in a })
        return values.compactMap { account, value in known[account].map { ($0, value) } }
    }

    static func deriveKey(password: String, salt: Data, iterations: UInt32) throws -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: 32)
        let pw = Array(password.utf8)
        let status = salt.withUnsafeBytes { saltBytes in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.map { Int8(bitPattern: $0) }, pw.count,
                                 saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &derived, derived.count)
        }
        guard status == kCCSuccess else { throw TransferError.keyDerivationFailed }
        return SymmetricKey(data: derived)
    }
}
