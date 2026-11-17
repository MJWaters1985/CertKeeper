import Crypto
import _CryptoExtras
import Foundation

/// The single administrator account, sessions and login throttling.
///
/// On first start there's no account: the server prints a one-time setup code in its log, and the
/// first visitor needs that code to create the account, so nobody else on the network can claim it.
/// To reset a forgotten password, delete users.json and restart: a new setup code is printed.
final class Auth: @unchecked Sendable {
    struct User: Codable {
        var username: String
        /// "pbkdf2-sha256$<rounds>$<salt b64>$<hash b64>"
        var passwordHash: String
    }

    struct AuthError: LocalizedError {
        let message: String
        let retryAfter: Int?
        init(_ message: String, retryAfter: Int? = nil) { self.message = message; self.retryAfter = retryAfter }
        var errorDescription: String? { message }
    }

    static let minimumPasswordLength = 10
    static let sessionLifetime: TimeInterval = 12 * 3600
    static let rounds = 600_000

    private let url: URL
    private let lock = NSLock()
    private var user: User?
    private(set) var setupCode: String?
    /// Keyed by the token's SHA-256, so a memory dump doesn't hand out usable tokens.
    private var sessions: [String: (username: String, expires: Date)] = [:]
    private var failures: [String: (count: Int, lockedUntil: Date)] = [:]

    init(usersFile: URL) throws {
        url = usersFile
        if FileManager.default.fileExists(atPath: usersFile.path) {
            user = try JSONDecoder().decode(User.self, from: Data(contentsOf: usersFile))
        } else {
            setupCode = Self.makeSetupCode()
        }
    }

    var needsSetup: Bool { lock.lock(); defer { lock.unlock() }; return user == nil }
    var username: String? { lock.lock(); defer { lock.unlock() }; return user?.username }

    /// Creates the account; returns a session token.
    func setUp(code: String, username: String, password: String) throws -> String {
        let name = username.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { throw AuthError("Choose a username") }
        try Self.checkStrength(password)
        lock.lock()
        defer { lock.unlock() }
        guard user == nil, let expected = setupCode else { throw AuthError("CertKeeper is already set up") }
        guard Self.normalizeCode(code) == Self.normalizeCode(expected) else {
            throw AuthError("That setup code isn't right. It's printed in CertKeeper's log.")
        }
        let created = User(username: name, passwordHash: try Self.hash(password))
        try FileSecurity.writePrivate(try JSONEncoder().encode(created), to: url)
        user = created
        setupCode = nil
        return newSession(for: name)
    }

    /// Checks the password; returns a session token. Repeated failures from one address lock it out
    /// for a while (30 s after five, doubling up to 15 minutes).
    func logIn(username: String, password: String, from address: String) throws -> String {
        lock.lock()
        if let f = failures[address], f.lockedUntil > Date() {
            lock.unlock()
            let wait = Int(f.lockedUntil.timeIntervalSinceNow.rounded(.up))
            throw AuthError("Too many failed logins. Try again in \(wait) seconds.", retryAfter: wait)
        }
        let current = user
        lock.unlock()
        // Verify outside the lock: PBKDF2 takes a moment.
        let ok = current.map { $0.username == username && Self.verify(password, against: $0.passwordHash) } ?? false
        lock.lock()
        defer { lock.unlock() }
        guard ok, let current else {
            let count = (failures[address]?.count ?? 0) + 1
            let lockout = count >= 5 ? min(30 * pow(2, Double(count - 5)), 900) : 0
            failures[address] = (count, Date().addingTimeInterval(lockout))
            throw AuthError("Wrong username or password")
        }
        failures[address] = nil
        return newSession(for: current.username)
    }

    /// The signed-in username for a session token, extending the session.
    func session(_ token: String) -> String? {
        let key = Self.tokenKey(token)
        lock.lock()
        defer { lock.unlock() }
        guard let s = sessions[key], s.expires > Date() else {
            sessions[key] = nil
            return nil
        }
        sessions[key] = (s.username, Date().addingTimeInterval(Self.sessionLifetime))
        return s.username
    }

    func logOut(_ token: String) {
        lock.lock()
        sessions[Self.tokenKey(token)] = nil
        lock.unlock()
    }

    /// Changes the password and ends every other session.
    func changePassword(current: String, new: String, keeping token: String) throws {
        try Self.checkStrength(new)
        lock.lock()
        let existing = user
        lock.unlock()
        guard let existing, Self.verify(current, against: existing.passwordHash) else {
            throw AuthError("The current password isn't right")
        }
        let updated = User(username: existing.username, passwordHash: try Self.hash(new))
        try FileSecurity.writePrivate(try JSONEncoder().encode(updated), to: url)
        lock.lock()
        user = updated
        let keep = Self.tokenKey(token)
        sessions = sessions.filter { $0.key == keep }
        lock.unlock()
    }

    // MARK: - Helpers

    /// Call with `lock` held.
    private func newSession(for username: String) -> String {
        let token = Self.randomBytes(32).base64URL
        sessions = sessions.filter { $0.value.expires > Date() }
        sessions[Self.tokenKey(token)] = (username, Date().addingTimeInterval(Self.sessionLifetime))
        return token
    }

    static func checkStrength(_ password: String) throws {
        guard password.count >= minimumPasswordLength else {
            throw AuthError("Use a password of at least \(minimumPasswordLength) characters")
        }
    }

    static func hash(_ password: String) throws -> String {
        let salt = randomBytes(16)
        let key = try KDF.Insecure.PBKDF2.deriveKey(from: Array(password.utf8), salt: salt, using: .sha256,
                                                    outputByteCount: 32, rounds: rounds)
        let hash = key.withUnsafeBytes { Data($0) }
        return "pbkdf2-sha256$\(rounds)$\(salt.base64EncodedString())$\(hash.base64EncodedString())"
    }

    static func verify(_ password: String, against stored: String) -> Bool {
        let parts = stored.split(separator: "$").map(String.init)
        guard parts.count == 4, parts[0] == "pbkdf2-sha256", let rounds = Int(parts[1]), rounds > 0,
              let salt = Data(base64Encoded: parts[2]), let expected = Data(base64Encoded: parts[3]),
              let key = try? KDF.Insecure.PBKDF2.deriveKey(from: Array(password.utf8), salt: salt, using: .sha256,
                                                           outputByteCount: expected.count, unsafeUncheckedRounds: rounds)
        else { return false }
        let actual = key.withUnsafeBytes { Data($0) }
        // Constant time: every byte is compared whatever the first difference.
        guard actual.count == expected.count else { return false }
        return zip(actual, expected).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    static func tokenKey(_ token: String) -> String {
        Data(SHA256.hash(data: Data(token.utf8))).base64EncodedString()
    }

    static func randomBytes(_ count: Int) -> Data {
        Data(SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Array($0) })
    }

    /// 12 characters from an alphabet without look-alikes (0/O, 1/I/L), shown as XXXX-XXXX-XXXX.
    static func makeSetupCode() -> String {
        let alphabet = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        let chars = randomBytes(12).map { alphabet[Int($0) % alphabet.count] }
        return stride(from: 0, to: 12, by: 4).map { String(chars[$0..<$0 + 4]) }.joined(separator: "-")
    }

    static func normalizeCode(_ s: String) -> String {
        s.uppercased().filter { $0.isLetter || $0.isNumber }
    }
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
