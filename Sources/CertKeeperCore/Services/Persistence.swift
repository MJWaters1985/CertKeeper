import Crypto
import Foundation

/// JSON file persistence for the inventory in ~/Library/Application Support/CertKeeper.
public enum InventoryFile {
    /// Where everything lives when set (the server's /config); otherwise the platform default.
    nonisolated(unsafe) public static var directoryOverride: URL?

    public static var directory: URL {
        if let directoryOverride { return directoryOverride }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("CertKeeper", isDirectory: true)
    }

    public static var url: URL { directory.appendingPathComponent("inventory.json") }

    public static func load(from url: URL = url) throws -> Inventory {
        guard FileManager.default.fileExists(atPath: url.path) else { return Inventory() }
        let data = try Data(contentsOf: url)
        return try decoder.decode(Inventory.self, from: data)
    }

    public static func save(_ inventory: Inventory, to url: URL = url) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try encoder.encode(inventory)
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

/// A secret CertKeeper keeps outside the inventory. `account` is its name in the secret store and
/// in configuration exports; changing one would orphan the stored secret.
public enum SecretItem: Sendable {
    case cloudflareToken
    case acmeAccountKey
    case certificateKey(UUID)
    case hostPassword(UUID)
    /// A secret deployment option (e.g. a .pfx password), keyed by deployment and option name.
    case deploymentSecret(UUID, String)

    public var account: String {
        switch self {
        case .deploymentSecret(let id, let name): "deployment-\(id.uuidString)-\(name)"
        case .hostPassword(let id): "host-password-\(id.uuidString)"
        case .cloudflareToken: "cloudflare-api-token"
        case .acmeAccountKey: "acme-account-key"
        case .certificateKey(let id): "certificate-key-\(id.uuidString)"
        }
    }
}

/// Where secrets live: an encrypted file in the app, memory in tests.
public protocol SecretStore: Sendable {
    func get(_ item: SecretItem) -> String?
    func set(_ value: String, for item: SecretItem) throws
    func delete(_ item: SecretItem)
}

/// Secrets in one AES-GCM encrypted JSON file.
/// The file holds `{account: value}`, sealed with `key`; it's rewritten atomically with mode 0600 on
/// every change. Anyone holding the key and the file can read every secret.
public final class EncryptedFileSecretStore: SecretStore, @unchecked Sendable {
    public let url: URL
    private let key: SymmetricKey
    private let lock = NSLock()
    private var values: [String: String]

    public struct DecryptionFailed: LocalizedError {
        public var errorDescription: String? {
            "The secrets file can't be decrypted with this key. Was the secrets key changed?"
        }
    }

    /// Loads the file if it exists. Throws when it exists but doesn't open with `key`, rather than
    /// starting empty and overwriting it on the next save.
    public init(url: URL, key: SymmetricKey) throws {
        self.url = url
        self.key = key
        if FileManager.default.fileExists(atPath: url.path) {
            let sealed = try Data(contentsOf: url)
            guard let box = try? AES.GCM.SealedBox(combined: sealed),
                  let plain = try? AES.GCM.open(box, using: key) else { throw DecryptionFailed() }
            values = try JSONDecoder().decode([String: String].self, from: plain)
        } else {
            values = [:]
        }
    }

    public func get(_ item: SecretItem) -> String? { lock.lock(); defer { lock.unlock() }; return values[item.account] }

    public func set(_ value: String, for item: SecretItem) throws {
        lock.lock(); defer { lock.unlock() }
        var next = values
        next[item.account] = value
        try write(next)
        values = next
    }

    public func delete(_ item: SecretItem) {
        lock.lock(); defer { lock.unlock() }
        var next = values
        guard next.removeValue(forKey: item.account) != nil else { return }
        if (try? write(next)) != nil { values = next }
    }

    private func write(_ values: [String: String]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let sealed = try AES.GCM.seal(try encoder.encode(values), using: key).combined else {
            throw CocoaError(.fileWriteUnknown)
        }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Create the temporary file with 0600 before any secret is written to it, then rename it into place.
        let temp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: temp.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteNoPermission)
        }
        do {
            let handle = try FileHandle(forWritingTo: temp)
            try handle.write(contentsOf: sealed)
            try handle.synchronize()
            try handle.close()
            guard rename(temp.path, url.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
        } catch {
            try? FileManager.default.removeItem(at: temp)
            throw error
        }
    }
}

public final class MemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]
    public init() {}
    public func get(_ item: SecretItem) -> String? { lock.lock(); defer { lock.unlock() }; return values[item.account] }
    public func set(_ value: String, for item: SecretItem) throws { lock.lock(); values[item.account] = value; lock.unlock() }
    public func delete(_ item: SecretItem) { lock.lock(); values[item.account] = nil; lock.unlock() }
    public var count: Int { lock.lock(); defer { lock.unlock() }; return values.count }
}
