import Foundation

/// Connects to a TLS endpoint and returns the leaf certificate it presents (without validating trust,
/// so self-signed and staging certificates can be inspected too).
public enum TLSProbe {
    public static func fetchLeaf(endpoint: String, timeout: TimeInterval = 10) async throws -> CertificateSummary {
        guard let leaf = try await fetchChain(endpoint: endpoint, timeout: timeout).first else {
            throw DeployError("No certificate presented by \(endpoint)")
        }
        return leaf
    }

    /// True when a client can build a path from the leaf: it's self-issued, or the server also sent
    /// the certificate that issued it.
    public static func chainIsComplete(_ served: [CertificateSummary]) -> Bool {
        guard let leaf = served.first else { return false }
        if leaf.subject == leaf.issuer { return true }
        return served.dropFirst().contains { $0.subject == leaf.issuer }
    }

    public static func fetchChain(endpoint: String, timeout: TimeInterval = 10) async throws -> [CertificateSummary] {
        try await fetchServed(endpoint: endpoint, timeout: timeout).chain
    }

    public struct Served: Sendable {
        /// Leaf first.
        public var chain: [CertificateSummary]
        /// True when `chain` is exactly what the server sent. False when the connection didn't expose
        /// the peer's list and the certificates came from the trust object instead, which may include
        /// intermediates found locally — so chain completeness can't be judged.
        public var exact: Bool
    }

    /// The certificates the server actually sends (leaf first), not a chain rebuilt from local roots.
    public static func fetchServed(endpoint: String, timeout: TimeInterval = 10) async throws -> Served {
        let (hostPart, port) = split(endpoint)
        let (ders, exact) = try await peerChain(host: hostPart, port: port, endpoint: endpoint, timeout: timeout)
        guard !ders.isEmpty else { throw DeployError("No certificate presented by \(endpoint)") }
        return Served(chain: try ders.map { try CertCrypto.summarize(der: $0) }, exact: exact)
    }

    static func split(_ endpoint: String) -> (String, UInt16) {
        var s = endpoint
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        s = s.split(separator: "/").first.map(String.init) ?? s
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            return (host, rest.hasPrefix(":") ? UInt16(rest.dropFirst()) ?? 443 : 443)
        }
        let parts = s.split(separator: ":")
        if parts.count == 2, let p = UInt16(parts[1]) { return (String(parts[0]), p) }
        return (s, 443)
    }

}
