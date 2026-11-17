import Foundation
#if canImport(Network)
import Network
import Security
#endif

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

    #if canImport(Network)
    /// The peer's certificates as DER, and whether they're exactly what it sent (see `Served.exact`).
    static func peerChain(host hostPart: String, port: UInt16, endpoint: String, timeout: TimeInterval) async throws -> ([Data], Bool) {
        let tls = NWProtocolTLS.Options()
        let captured = CapturedCert()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { metadata, trust, complete in
            var ders: [Data] = []
            sec_protocol_metadata_access_peer_certificate_chain(metadata) { cert in
                ders.append(SecCertificateCopyData(sec_certificate_copy_ref(cert).takeRetainedValue()) as Data)
            }
            if !ders.isEmpty {
                captured.set(ders, exact: true)
            } else {
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                let certs = (SecTrustCopyCertificateChain(secTrust) as? [SecCertificate]) ?? []
                captured.set(certs.map { SecCertificateCopyData($0) as Data }, exact: false)
            }
            complete(true)
        }, .global())
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, hostPart)

        let params = NWParameters(tls: tls)
        let connection = NWConnection(host: NWEndpoint.Host(hostPart), port: NWEndpoint.Port(rawValue: port) ?? 443, using: params)

        let (ders, exact): ([Data], Bool) = try await withCheckedThrowingContinuation { continuation in
            let once = Once()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    once.run {
                        connection.cancel()
                        if let d = captured.get(), !d.0.isEmpty { continuation.resume(returning: d) }
                        else { continuation.resume(throwing: DeployError("No certificate presented by \(endpoint)")) }
                    }
                case .failed(let error), .waiting(let error):
                    once.run { connection.cancel(); continuation.resume(throwing: error) }
                default: break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                once.run { connection.cancel(); continuation.resume(throwing: DeployError("TLS connection to \(endpoint) timed out")) }
            }
        }
        return (ders, exact)
    }
    #endif

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

    #if canImport(Network)
    private final class CapturedCert: @unchecked Sendable {
        private let lock = NSLock()
        private var data: ([Data], Bool)?
        func set(_ d: [Data], exact: Bool) { lock.lock(); data = (d, exact); lock.unlock() }
        func get() -> ([Data], Bool)? { lock.lock(); defer { lock.unlock() }; return data }
    }

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func run(_ body: () -> Void) {
            lock.lock()
            guard !done else { lock.unlock(); return }
            done = true
            lock.unlock()
            body()
        }
    }
    #endif
}
