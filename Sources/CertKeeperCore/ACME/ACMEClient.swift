import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Minimal RFC 8555 ACME client supporting the dns-01 challenge.
public actor ACMEClient {
    public struct Directory: Decodable, Sendable {
        public let newNonce: URL
        public let newAccount: URL
        public let newOrder: URL
        public let revokeCert: URL?
        public let meta: Meta?
        public struct Meta: Decodable, Sendable { public let termsOfService: URL? }
    }

    public struct Order: Decodable, Sendable {
        public var status: String
        public var authorizations: [URL]
        public var finalize: URL
        public var certificate: URL?
        public var error: Problem?
    }

    public struct Authorization: Decodable, Sendable {
        public var status: String
        public var identifier: Identifier
        public var challenges: [Challenge]
        public var wildcard: Bool?
    }

    public struct Identifier: Codable, Sendable { public var type: String; public var value: String }

    public struct Challenge: Decodable, Sendable {
        public var type: String
        public var url: URL
        public var status: String
        public var token: String?
        public var error: Problem?
    }

    public struct Problem: Decodable, Error, LocalizedError, Sendable {
        public var type: String?
        public var detail: String?
        public var subproblems: [Problem]?
        public var errorDescription: String? {
            var s = "ACME: \(detail ?? type ?? "unknown error")"
            for sub in subproblems ?? [] { s += "\n  • \(sub.detail ?? sub.type ?? "")" }
            return s
        }
    }

    public enum ACMEError: LocalizedError {
        case http(Int, String)
        case missingHeader(String)
        case noDNSChallenge(String)
        case timeout(String)
        case invalidState(String)

        public var errorDescription: String? {
            switch self {
            case .http(let code, let body): "ACME HTTP \(code): \(body)"
            case .missingHeader(let h): "ACME response missing \(h) header"
            case .noDNSChallenge(let d): "No dns-01 challenge offered for \(d)"
            case .timeout(let what): "Timed out waiting for \(what)"
            case .invalidState(let s): s
            }
        }
    }

    private let directoryURL: URL
    private let accountKey: P256.Signing.PrivateKey
    private let session: URLSession
    private var directory: Directory?
    private var nonce: String?
    public private(set) var accountURL: URL?

    public init(directoryURL: URL, accountKeyPEM: String, accountURL: URL?, session: URLSession = .shared) throws {
        self.directoryURL = directoryURL
        self.accountKey = try P256.Signing.PrivateKey(pemRepresentation: accountKeyPEM)
        self.accountURL = accountURL
        self.session = session
    }

    public static func newAccountKeyPEM() -> String { P256.Signing.PrivateKey().pemRepresentation }

    // MARK: JWK / key authorization

    nonisolated static func jwk(for key: P256.Signing.PublicKey) -> [String: String] {
        let raw = key.x963Representation  // 0x04 || X || Y
        return [
            "crv": "P-256",
            "kty": "EC",
            "x": Data(raw[1..<33]).base64URL,
            "y": Data(raw[33..<65]).base64URL,
        ]
    }

    /// RFC 7638 thumbprint: SHA-256 over the JWK with required members in lexicographic order.
    nonisolated static func thumbprint(for key: P256.Signing.PublicKey) -> String {
        let j = jwk(for: key)
        let canonical = #"{"crv":"\#(j["crv"]!)","kty":"\#(j["kty"]!)","x":"\#(j["x"]!)","y":"\#(j["y"]!)"}"#
        return Data(SHA256.hash(data: Data(canonical.utf8))).base64URL
    }

    /// The value to publish in the `_acme-challenge` TXT record.
    public func dnsTXTValue(token: String) -> String {
        let keyAuth = token + "." + Self.thumbprint(for: accountKey.publicKey)
        return Data(SHA256.hash(data: Data(keyAuth.utf8))).base64URL
    }

    // MARK: Transport

    private func loadDirectory() async throws -> Directory {
        if let directory { return directory }
        let (data, response) = try await session.data(from: directoryURL)
        try Self.check(response, data)
        let d = try JSONDecoder().decode(Directory.self, from: data)
        directory = d
        return d
    }

    public func termsOfService() async throws -> URL? { try await loadDirectory().meta?.termsOfService }

    private func freshNonce() async throws -> String {
        if let n = nonce { nonce = nil; return n }
        var req = URLRequest(url: try await loadDirectory().newNonce)
        req.httpMethod = "HEAD"
        let (_, response) = try await session.data(for: req)
        guard let n = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Replay-Nonce") else {
            throw ACMEError.missingHeader("Replay-Nonce")
        }
        return n
    }

    /// Signed POST. `payload == nil` produces a POST-as-GET (empty payload).
    private func post(_ url: URL, payload: (any Encodable)?, useJWK: Bool = false, attempt: Int = 0) async throws -> (Data, HTTPURLResponse) {
        var protected: [String: Any] = ["alg": "ES256", "nonce": try await freshNonce(), "url": url.absoluteString]
        if useJWK || accountURL == nil {
            protected["jwk"] = Self.jwk(for: accountKey.publicKey)
        } else {
            protected["kid"] = accountURL!.absoluteString
        }
        let protectedB64 = try JSONSerialization.data(withJSONObject: protected, options: [.sortedKeys]).base64URL
        let payloadB64 = try payload.map { try JSONEncoder().encode($0).base64URL } ?? ""
        let signingInput = Data("\(protectedB64).\(payloadB64)".utf8)
        let signature = try accountKey.signature(for: signingInput).rawRepresentation.base64URL
        let body = ["protected": protectedB64, "payload": payloadB64, "signature": signature]

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/jose+json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        let http = response as! HTTPURLResponse
        if let n = http.value(forHTTPHeaderField: "Replay-Nonce") { nonce = n }

        if http.statusCode >= 400,
           let problem = try? JSONDecoder().decode(Problem.self, from: data) {
            if problem.type == "urn:ietf:params:acme:error:badNonce", attempt < 3 {
                return try await post(url, payload: payload, useJWK: useJWK, attempt: attempt + 1)
            }
            throw problem
        }
        try Self.check(http, data)
        return (data, http)
    }

    private static func check(_ response: URLResponse, _ data: Data) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw ACMEError.http(http.statusCode, String(decoding: data.prefix(2000), as: UTF8.self))
        }
    }

    // MARK: Account

    /// Registers (or looks up) the account for the current key. Returns the account URL.
    @discardableResult
    public func ensureAccount(email: String) async throws -> URL {
        if let accountURL { return accountURL }
        struct NewAccount: Encodable {
            let termsOfServiceAgreed = true
            let contact: [String]
        }
        let dir = try await loadDirectory()
        let contact = email.isEmpty ? [] : ["mailto:\(email)"]
        let (_, http) = try await post(dir.newAccount, payload: NewAccount(contact: contact), useJWK: true)
        guard let loc = http.value(forHTTPHeaderField: "Location"), let url = URL(string: loc) else {
            throw ACMEError.missingHeader("Location")
        }
        accountURL = url
        return url
    }

    // MARK: Orders

    public func newOrder(domains: [String]) async throws -> (Order, URL) {
        struct NewOrder: Encodable { let identifiers: [Identifier] }
        let dir = try await loadDirectory()
        let (data, http) = try await post(dir.newOrder, payload: NewOrder(identifiers: domains.map { .init(type: "dns", value: $0) }))
        guard let loc = http.value(forHTTPHeaderField: "Location"), let url = URL(string: loc) else {
            throw ACMEError.missingHeader("Location")
        }
        return (try JSONDecoder().decode(Order.self, from: data), url)
    }

    public func order(at url: URL) async throws -> Order {
        try JSONDecoder().decode(Order.self, from: try await post(url, payload: nil).0)
    }

    public func authorization(at url: URL) async throws -> Authorization {
        try JSONDecoder().decode(Authorization.self, from: try await post(url, payload: nil).0)
    }

    public func respond(to challenge: Challenge) async throws {
        struct Empty: Encodable {}
        _ = try await post(challenge.url, payload: Empty())
    }

    /// Polls an authorization until it leaves `pending`.
    public func waitForAuthorization(_ url: URL, timeout: TimeInterval = 180) async throws -> Authorization {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let authz = try await authorization(at: url)
            switch authz.status {
            case "valid": return authz
            case "pending", "processing": try await Task.sleep(for: .seconds(3))
            default:
                let err = authz.challenges.compactMap(\.error).first
                throw err ?? ACMEError.invalidState("Authorization for \(authz.identifier.value) is \(authz.status)")
            }
        }
        throw ACMEError.timeout("authorization")
    }

    public func finalize(order: Order, orderURL: URL, csrDER: Data) async throws -> Order {
        struct Finalize: Encodable { let csr: String }
        _ = try await post(order.finalize, payload: Finalize(csr: csrDER.base64URL))
        let deadline = Date().addingTimeInterval(180)
        while Date() < deadline {
            let o = try await self.order(at: orderURL)
            switch o.status {
            case "valid": return o
            case "processing", "ready", "pending": try await Task.sleep(for: .seconds(2))
            default: throw o.error ?? ACMEError.invalidState("Order became \(o.status)")
            }
        }
        throw ACMEError.timeout("order finalization")
    }

    /// Downloads the PEM chain (leaf first).
    public func downloadCertificate(_ url: URL) async throws -> String {
        String(decoding: try await post(url, payload: nil).0, as: UTF8.self)
    }
}
