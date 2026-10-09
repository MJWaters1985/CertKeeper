import Foundation

/// Cloudflare DNS API client, scoped to what DNS-01 needs.
/// The token needs `Zone:Read` and `DNS:Edit` for the relevant zones.
public struct CloudflareClient: Sendable {
    public struct Zone: Decodable, Sendable {
        public let id: String
        public let name: String
        public var account: Account?
        public struct Account: Decodable, Sendable { public let id: String; public let name: String? }

        public init(id: String, name: String, account: Account? = nil) {
            self.id = id
            self.name = name
            self.account = account
        }
    }
    struct Record: Decodable { let id: String; let name: String; let content: String; let type: String }
    struct Envelope<T: Decodable>: Decodable {
        let success: Bool
        let errors: [APIError]
        let result: T?
        let result_info: ResultInfo?
    }
    struct ResultInfo: Decodable { let page: Int; let total_pages: Int }
    struct APIError: Decodable { let code: Int; let message: String }

    public struct CloudflareError: LocalizedError {
        public let message: String
        public var codes: [Int] = []
        public var errorDescription: String? { "Cloudflare: \(message)" }
    }

    public struct CreatedRecord: Sendable, Hashable { public let zoneID: String; public let recordID: String; public let name: String }

    let token: String
    let session: URLSession
    let base = URL(string: "https://api.cloudflare.com/client/v4/")!

    public init(token: String, session: URLSession = .shared) {
        self.token = token
        self.session = session
    }

    private func request<T: Decodable>(_ method: String, _ path: String, query: [URLQueryItem] = [], body: [String: Any]? = nil) async throws -> Envelope<T> {
        var comps = URLComponents(url: base.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        if !query.isEmpty { comps.queryItems = query }
        var req = URLRequest(url: comps.url!)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body) }
        let (data, _) = try await session.data(for: req)
        let env: Envelope<T>
        do {
            env = try JSONDecoder().decode(Envelope<T>.self, from: data)
        } catch {
            throw CloudflareError(message: "Unexpected response: \(String(decoding: data.prefix(500), as: UTF8.self))")
        }
        guard env.success else {
            throw CloudflareError(message: env.errors.map { "\($0.message) (\($0.code))" }.joined(separator: "; "),
                                  codes: env.errors.map(\.code))
        }
        return env
    }

    public struct Verification: Sendable {
        public let status: String
        /// Set for an account-owned token (verified against that account), nil for a user token.
        public let accountName: String?
        public let zones: [Zone]
    }

    /// Confirms the token is active. User tokens verify at /user/tokens/verify; account-owned tokens
    /// are rejected there ("Invalid API Token", 1000) and verify at /accounts/{id}/tokens/verify,
    /// with the account found through the zones the token can read.
    public func verifyToken() async throws -> Verification {
        struct Status: Decodable { let status: String }
        do {
            let env: Envelope<Status> = try await request("GET", "user/tokens/verify")
            return Verification(status: env.result?.status ?? "unknown", accountName: nil, zones: try await listZones())
        } catch let userError as CloudflareError where userError.codes.contains(1000) {
            let zones: [Zone]
            do { zones = try await listZones() } catch { throw userError }
            let accounts = zones.compactMap(\.account).reduce(into: [Zone.Account]()) { list, a in
                if !list.contains(where: { $0.id == a.id }) { list.append(a) }
            }
            guard !accounts.isEmpty else { throw userError }
            var lastError: Error = userError
            for account in accounts {
                do {
                    let env: Envelope<Status> = try await request("GET", "accounts/\(account.id)/tokens/verify")
                    return Verification(status: env.result?.status ?? "unknown", accountName: account.name ?? account.id, zones: zones)
                } catch {
                    lastError = error
                }
            }
            throw lastError
        }
    }

    public func listZones() async throws -> [Zone] {
        var zones: [Zone] = []
        var page = 1
        while true {
            let env: Envelope<[Zone]> = try await request("GET", "zones", query: [
                .init(name: "per_page", value: "50"), .init(name: "page", value: String(page)),
            ])
            zones += env.result ?? []
            guard let info = env.result_info, info.page < info.total_pages else { break }
            page += 1
        }
        return zones
    }

    /// Picks the most specific zone that contains `domain`.
    public static func zone(for domain: String, in zones: [Zone]) -> Zone? {
        let name = domain.lowercased().replacingOccurrences(of: "*.", with: "")
        return zones
            .filter { name == $0.name.lowercased() || name.hasSuffix("." + $0.name.lowercased()) }
            .max { $0.name.count < $1.name.count }
    }

    public func createTXT(zone: Zone, name: String, content: String) async throws -> CreatedRecord {
        let env: Envelope<Record> = try await request("POST", "zones/\(zone.id)/dns_records", body: [
            "type": "TXT", "name": name, "content": content, "ttl": 60,
            "comment": "CertKeeper ACME challenge",
        ])
        guard let r = env.result else { throw CloudflareError(message: "No record returned") }
        return CreatedRecord(zoneID: zone.id, recordID: r.id, name: name)
    }

    public func deleteRecord(_ record: CreatedRecord) async throws {
        struct Deleted: Decodable { let id: String }
        let _: Envelope<Deleted> = try await request("DELETE", "zones/\(record.zoneID)/dns_records/\(record.recordID)")
    }
}

/// Checks public DNS (via DNS-over-HTTPS) for a TXT value.
public enum DNSPropagation {
    struct DoHResponse: Decodable {
        struct Answer: Decodable { let type: Int; let data: String }
        let Answer: [Answer]?
    }

    static let resolvers = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]

    public static func txtValues(name: String, resolver: String, session: URLSession = .shared) async throws -> [String] {
        var comps = URLComponents(string: resolver)!
        comps.queryItems = [.init(name: "name", value: name), .init(name: "type", value: "TXT")]
        var req = URLRequest(url: comps.url!)
        req.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        req.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, _) = try await session.data(for: req)
        let resp = try JSONDecoder().decode(DoHResponse.self, from: data)
        return (resp.Answer ?? []).filter { $0.type == 16 }.map {
            $0.data.replacingOccurrences(of: "\"", with: "")
        }
    }

    /// Waits until every resolver returns all `expected` values for `name`.
    public static func waitFor(name: String, expected: Set<String>, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var allGood = true
            for resolver in resolvers {
                let values = Set((try? await txtValues(name: name, resolver: resolver)) ?? [])
                if !expected.isSubset(of: values) { allGood = false; break }
            }
            if allGood { return }
            try await Task.sleep(for: .seconds(5))
        }
        throw ACMEClient.ACMEError.timeout("TXT record \(name) to propagate")
    }
}
