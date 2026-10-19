import CryptoKit
import Foundation
import Network
import Security

/// Client for devices that take certificates over HTTPS instead of SSH, such as the ESP32-S3 AMOLED
/// board: `GET /api/tls` describes the certificate being served and `PUT /api/tls/certificate`
/// installs a chain and key. Requests carry the host's API token (kept as its Keychain password).
///
/// Until a publicly trusted certificate is installed the device serves a self-signed one, so a
/// connection is accepted when the system trusts the certificate for the host's name, or when the
/// leaf matches the fingerprint pinned on the host. Anything else is refused before the token or a
/// private key is sent.
///
/// Requests go over Network.framework rather than URLSession: App Transport Security makes URLSession
/// refuse any certificate the system doesn't trust, even when the app has chosen to trust it, which
/// would make pinning a self-signed certificate impossible.
public struct DeviceAPI: Sendable {
    public struct TLSInfo: Decodable, Sendable, Equatable {
        /// "installed" or "self-signed".
        public var source: String
        public var subject: String
        public var issuer: String
        public var notAfter: String
        /// SHA-256 of the leaf's DER encoding, lowercase hex.
        public var sha256: String
        public var dnsNames: [String]
        public var chainLength: Int
        public var hostname: String?

        enum CodingKeys: String, CodingKey {
            case source, subject, issuer, sha256, hostname
            case notAfter = "not_after"
            case dnsNames = "dns_names"
            case chainLength = "chain_length"
        }

        public var isSelfSigned: Bool { source != "installed" }
    }

    struct InstallResponse: Decodable {
        var certificate: TLSInfo?
    }

    struct ErrorResponse: Decodable {
        var error: String?
    }

    public let baseURL: URL
    public let token: String
    public let pinnedSHA256: String

    public init(host: ManagedHost, token: String) throws {
        var c = URLComponents()
        c.scheme = "https"
        c.host = host.address
        if host.port != 443 { c.port = host.port }
        guard !host.address.isEmpty, let url = c.url else {
            throw DeployError("\(host.name) has no valid address")
        }
        guard !token.isEmpty else {
            throw DeployError("No API token saved for \(host.name). Create one in the device's web settings (Security › API token) and add it to the host.")
        }
        baseURL = url
        self.token = token
        pinnedSHA256 = Self.normalizeFingerprint(host.apiPinnedSHA256)
    }

    public func info() async throws -> TLSInfo {
        try JSONDecoder().decode(TLSInfo.self, from: try await send("GET", "/api/tls"))
    }

    /// Installs `chainPEM` (leaf first) with `keyPEM`. The device checks that they match and then
    /// restarts its HTTPS server, so the new certificate is served a moment after this returns.
    public func install(chainPEM: String, keyPEM: String) async throws -> TLSInfo? {
        let body = try JSONSerialization.data(withJSONObject: ["certificate": chainPEM, "private_key": keyPEM])
        return try JSONDecoder().decode(InstallResponse.self, from: try await send("PUT", "/api/tls/certificate", body: body)).certificate
    }

    private func send(_ method: String, _ path: String, body: Data? = nil) async throws -> Data {
        let host = baseURL.host ?? ""
        let port = UInt16(baseURL.port ?? 443)
        var head = "\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\nAuthorization: Bearer \(token)\r\n"
            + "Accept: application/json\r\nConnection: close\r\n"
        if let body { head += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n" }
        var request = Data((head + "\r\n").utf8)
        if let body { request.append(body) }

        let gate = TrustGate(pinned: pinnedSHA256)
        let raw: Data
        do {
            raw = try await HTTPOverTLS.exchange(host: host, port: port, request: request, gate: gate, timeout: 30)
        } catch {
            if let fingerprint = gate.rejectedFingerprint {
                throw DeployError(Self.untrustedMessage(host: host, fingerprint: fingerprint, pinned: pinnedSHA256))
            }
            throw error
        }
        let (status, data) = try HTTPOverTLS.parse(raw)
        guard (200..<300).contains(status) else {
            let message = (try? JSONDecoder().decode(ErrorResponse.self, from: data))?.error
            switch status {
            case 401: throw DeployError("The device rejected the API token. Create a new token in its web settings and update the host.")
            case 429: throw DeployError("The device is refusing logins for a minute after repeated failures.")
            default: throw DeployError("The device answered \(status)\(message.map { ": \($0)" } ?? "")")
            }
        }
        return data
    }

    static func untrustedMessage(host: String, fingerprint: String, pinned: String) -> String {
        let shown = formatFingerprint(fingerprint)
        if pinned.isEmpty {
            return "\(host) presented a certificate this Mac doesn't trust (SHA-256 \(shown)). If it matches the fingerprint in the device's web settings (Security › HTTPS certificate), pin it on the host."
        }
        return "\(host) presented a certificate that is neither trusted nor the pinned one (SHA-256 \(shown)). If the device made a new self-signed certificate, check its fingerprint in the web settings and pin the new one."
    }

    /// Accept a certificate the system trusts for the host's name, or the pinned one.
    public static func accepts(systemTrusted: Bool, leafSHA256: String, pinned: String) -> Bool {
        if systemTrusted { return true }
        let pin = normalizeFingerprint(pinned)
        return !pin.isEmpty && pin == leafSHA256.lowercased()
    }

    /// Lowercase hex without separators, so "AB:CD…" and "abcd…" compare equal.
    public static func normalizeFingerprint(_ s: String) -> String {
        String(s.lowercased().filter(\.isHexDigit))
    }

    public static func formatFingerprint(_ hex: String) -> String {
        let h = normalizeFingerprint(hex).uppercased()
        return stride(from: 0, to: h.count, by: 2).map { i -> String in
            let start = h.index(h.startIndex, offsetBy: i)
            return String(h[start..<h.index(start, offsetBy: min(2, h.count - i))])
        }.joined(separator: ":")
    }
}

/// Decides whether to trust the server, remembering a rejected leaf's fingerprint for the error message.
final class TrustGate: @unchecked Sendable {
    let pinned: String
    private let lock = NSLock()
    private var rejected: String?

    init(pinned: String) { self.pinned = pinned }

    var rejectedFingerprint: String? {
        lock.lock()
        defer { lock.unlock() }
        return rejected
    }

    func evaluate(_ trust: SecTrust) -> Bool {
        let trusted = SecTrustEvaluateWithError(trust, nil)
        let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        let sha = leaf.map { Data(SHA256.hash(data: SecCertificateCopyData($0) as Data)).hex } ?? ""
        if DeviceAPI.accepts(systemTrusted: trusted, leafSHA256: sha, pinned: pinned) { return true }
        lock.lock()
        rejected = sha
        lock.unlock()
        return false
    }
}

/// One HTTP/1.1 request over a TLS connection (`Connection: close`), returning the raw response.
enum HTTPOverTLS {
    static func exchange(host: String, port: UInt16, request: Data, gate: TrustGate, timeout: TimeInterval) async throws -> Data {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            complete(gate.evaluate(sec_trust_copy_ref(trust).takeRetainedValue()))
        }, .global())
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 443,
                                      using: NWParameters(tls: tls))
        let buffer = ResponseBuffer()

        return try await withCheckedThrowingContinuation { continuation in
            let once = Once()
            func finish(_ result: Result<Data, Error>) {
                once.run { connection.cancel(); continuation.resume(with: result) }
            }
            func receive() {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                    if let data { buffer.append(data) }
                    // Servers may keep the socket open despite "Connection: close" (the ESP32's does),
                    // so stop as soon as the response is whole.
                    if isComplete || isWhole(buffer.data) { finish(.success(buffer.data)) }
                    else if let error { buffer.data.isEmpty ? finish(.failure(error)) : finish(.success(buffer.data)) }
                    else { receive() }
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: request, completion: .contentProcessed { error in
                        if let error { finish(.failure(error)) } else { receive() }
                    })
                case .failed(let error):
                    finish(.failure(error))
                case .waiting(let error):
                    finish(.failure(error))
                default:
                    break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                finish(.failure(DeployError("\(host):\(port) didn't answer within \(Int(timeout)) seconds")))
            }
        }
    }

    /// Whether `raw` holds a complete response: headers plus Content-Length bytes, or a chunked body
    /// through its last chunk. A response with neither can only end when the server closes.
    static func isWhole(_ raw: Data) -> Bool {
        guard let split = raw.range(of: Data("\r\n\r\n".utf8)) else { return false }
        let head = String(decoding: raw[..<split.lowerBound], as: UTF8.self).lowercased()
        let bodyCount = raw.distance(from: split.upperBound, to: raw.endIndex)
        for line in head.components(separatedBy: "\r\n") {
            if line.hasPrefix("content-length:"), let n = Int(line.dropFirst(15).trimmingCharacters(in: .whitespaces)) {
                return bodyCount >= n
            }
            if line.hasPrefix("transfer-encoding:") && line.contains("chunked") {
                return raw[split.upperBound...].range(of: Data("\r\n0\r\n\r\n".utf8)) != nil
                    || raw[split.upperBound...].starts(with: Data("0\r\n\r\n".utf8))
            }
        }
        return false
    }

    /// Status code and body of a raw HTTP/1.1 response (Content-Length, chunked, or read-to-close).
    static func parse(_ raw: Data) throws -> (Int, Data) {
        guard let split = raw.range(of: Data("\r\n\r\n".utf8)) else {
            throw DeployError("The device sent an incomplete HTTP response")
        }
        let head = String(decoding: raw[..<split.lowerBound], as: UTF8.self)
        var body = Data(raw[split.upperBound...])
        let lines = head.components(separatedBy: "\r\n")
        let parts = lines.first?.split(separator: " ") ?? []
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), let status = Int(parts[1]) else {
            throw DeployError("The device sent a malformed HTTP response")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            body = try dechunk(body)
        } else if let length = headers["content-length"].flatMap(Int.init), length <= body.count {
            body = body.prefix(length)
        }
        return (status, body)
    }

    static func dechunk(_ data: Data) throws -> Data {
        var out = Data()
        var rest = data[...]
        while let lineEnd = rest.range(of: Data("\r\n".utf8)) {
            let sizeText = String(decoding: rest[..<lineEnd.lowerBound], as: UTF8.self).split(separator: ";").first ?? ""
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else {
                throw DeployError("The device sent a malformed chunked response")
            }
            if size == 0 { return out }
            let start = lineEnd.upperBound
            guard rest.distance(from: start, to: rest.endIndex) >= size else { break }
            let end = rest.index(start, offsetBy: size)
            out.append(rest[start..<end])
            rest = rest[(rest.index(end, offsetBy: 2, limitedBy: rest.endIndex) ?? rest.endIndex)...]  // skip CRLF
        }
        return out
    }

    private final class ResponseBuffer: @unchecked Sendable {
        private let lock = NSLock()
        private var storage = Data()
        func append(_ d: Data) { lock.lock(); storage.append(d); lock.unlock() }
        var data: Data { lock.lock(); defer { lock.unlock() }; return storage }
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
}
