import Foundation
import Security

/// JSON file persistence for the inventory in ~/Library/Application Support/CertKeeper.
public enum InventoryFile {
    public static var directory: URL {
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

/// Generic-password Keychain wrapper for secrets (Cloudflare token, ACME account key, certificate private keys).
public enum Keychain {
    static let service = "com.certkeeper.app"

    public enum Item {
        case cloudflareToken
        case acmeAccountKey
        case certificateKey(UUID)
        case hostPassword(UUID)
        /// A secret deployment option (e.g. a .pfx password), keyed by deployment and option name.
        case deploymentSecret(UUID, String)

        var account: String {
            switch self {
            case .deploymentSecret(let id, let name): "deployment-\(id.uuidString)-\(name)"
            case .hostPassword(let id): "host-password-\(id.uuidString)"
            case .cloudflareToken: "cloudflare-api-token"
            case .acmeAccountKey: "acme-account-key"
            case .certificateKey(let id): "certificate-key-\(id.uuidString)"
            }
        }
    }

    public static func set(_ value: String, for item: Item) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: item.account,
        ]
        let update: [String: Any] = [kSecValueData as String: data]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    public static func get(_ item: Item) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: item.account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    public static func delete(_ item: Item) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: item.account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public struct KeychainError: LocalizedError {
        public let status: OSStatus
        public var errorDescription: String? {
            "Keychain error \(status): \(SecCopyErrorMessageString(status, nil) as String? ?? "unknown")"
        }
    }
}

/// Where secrets live. The app uses the Keychain; tests use memory so they never touch the login keychain.
public protocol SecretStore: Sendable {
    func get(_ item: Keychain.Item) -> String?
    func set(_ value: String, for item: Keychain.Item) throws
    func delete(_ item: Keychain.Item)
}

public struct KeychainStore: SecretStore {
    public init() {}
    public func get(_ item: Keychain.Item) -> String? { Keychain.get(item) }
    public func set(_ value: String, for item: Keychain.Item) throws { try Keychain.set(value, for: item) }
    public func delete(_ item: Keychain.Item) { Keychain.delete(item) }
}

public final class MemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]
    public init() {}
    public func get(_ item: Keychain.Item) -> String? { lock.lock(); defer { lock.unlock() }; return values[item.account] }
    public func set(_ value: String, for item: Keychain.Item) throws { lock.lock(); values[item.account] = value; lock.unlock() }
    public func delete(_ item: Keychain.Item) { lock.lock(); values[item.account] = nil; lock.unlock() }
    public var count: Int { lock.lock(); defer { lock.unlock() }; return values.count }
}
