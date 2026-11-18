import CertKeeperCore
import Crypto
import Foundation
import NIOCore
import NIOSSL
import X509

/// The certificate the web interface serves, picked in this order:
/// 1. CERTKEEPER_TLS_CERT / CERTKEEPER_TLS_KEY (the platform's certificate, e.g. one chosen in TrueNAS),
/// 2. tls/fullchain.pem + tls/privkey.pem, written when CertKeeper manages its own certificate,
/// 3. tls/self-signed/, generated on first start.
/// Each handshake gets the current certificate, so a renewal applies without a restart.
final class ServerTLS: @unchecked Sendable {
    enum Mode: String, Codable { case platform, managed, selfSigned = "self_signed" }

    struct Status: Codable {
        var mode: Mode
        var subject: String
        var dnsNames: [String]
        var notAfter: Date
        var sha256: String
        var issuer: String
    }

    private let config: ServerConfig
    private let lock = NSLock()
    private var chain: [NIOSSLCertificate] = []
    private var key: NIOSSLPrivateKey?
    private var current: Status?
    private var loadedStamp = ""
    /// Files that failed to load, so the periodic check reports them once rather than every minute.
    private var failedStamp = ""

    var managedCertificateFile: URL { config.tlsDirectory.appendingPathComponent("fullchain.pem") }
    var managedKeyFile: URL { config.tlsDirectory.appendingPathComponent("privkey.pem") }
    private var selfSignedDirectory: URL { config.tlsDirectory.appendingPathComponent("self-signed", isDirectory: true) }

    /// Why the configured certificate couldn't be used at startup, when the self-signed one stands in.
    private(set) var startupProblem: String?

    /// Starts on the configured certificate, or on the self-signed one if that can't be loaded, so a
    /// bad certificate file never locks people out of the web interface. The periodic reload switches
    /// over once the files are fixed.
    init(config: ServerConfig) throws {
        self.config = config
        do {
            try reload(force: true)
        } catch {
            startupProblem = error.localizedDescription
            let fallback = try selfSignedFiles()
            try load((fallback.cert, fallback.key, .selfSigned), stamp: "self-signed fallback")
        }
    }

    var status: Status? { lock.lock(); defer { lock.unlock() }; return current }

    var platformProvided: Bool { config.tlsCertificateFile != nil }

    /// The files in use now, creating the self-signed pair if nothing else exists.
    private func activeFiles() throws -> (cert: String, key: String, mode: Mode) {
        if let cert = config.tlsCertificateFile, let key = config.tlsKeyFile { return (cert, key, .platform) }
        if FileManager.default.fileExists(atPath: managedCertificateFile.path),
           FileManager.default.fileExists(atPath: managedKeyFile.path) {
            return (managedCertificateFile.path, managedKeyFile.path, .managed)
        }
        let selfSigned = try selfSignedFiles()
        return (selfSigned.cert, selfSigned.key, .selfSigned)
    }

    private func selfSignedFiles() throws -> (cert: String, key: String) {
        let cert = selfSignedDirectory.appendingPathComponent("cert.pem"), key = selfSignedDirectory.appendingPathComponent("key.pem")
        if !FileManager.default.fileExists(atPath: cert.path) || !FileManager.default.fileExists(atPath: key.path) {
            try Self.makeSelfSigned(certificate: cert, key: key)
        }
        return (cert.path, key.path)
    }

    /// Loads the active files if they changed (by path, size and modification time). Returns true
    /// when a new certificate took effect. A bad pair is reported and the previous one kept.
    @discardableResult
    func reload(force: Bool = false) throws -> Bool {
        let files = try activeFiles()
        let stamp = [files.cert, files.key].map { path -> String in
            let a = try? FileManager.default.attributesOfItem(atPath: path)
            return "\(path):\((a?[.size] as? Int) ?? -1):\((a?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)"
        }.joined(separator: "|")
        lock.lock()
        let unchanged = stamp == loadedStamp || stamp == failedStamp
        lock.unlock()
        if unchanged && !force { return false }
        do {
            try load(files, stamp: stamp)
        } catch let error as ConfigError {
            lock.lock(); failedStamp = stamp; lock.unlock()
            throw error
        } catch {
            lock.lock(); failedStamp = stamp; lock.unlock()
            // Parser errors can carry whole encoded structures; the start says what's wrong.
            let detail = String(describing: error)
            throw ConfigError("\(files.cert) can't be used: \(detail.count > 200 ? detail.prefix(200) + "…" : Substring(detail))")
        }
        return true
    }

    private func load(_ files: (cert: String, key: String, mode: Mode), stamp: String) throws {
        let pem = try String(contentsOfFile: files.cert, encoding: .utf8)
        let newChain = try NIOSSLCertificate.fromPEMBytes(Array(pem.utf8))
        guard let leafDER = try newChain.first?.toDERBytes() else { throw ConfigError("\(files.cert) holds no certificate") }
        let newKey = try NIOSSLPrivateKey(file: files.key, format: .pem)
        let summary = try CertCrypto.summarize(der: Data(leafDER))
        // The key must belong to the certificate, or every handshake would fail.
        let keyPEM = try String(contentsOfFile: files.key, encoding: .utf8)
        guard CertCrypto.keyMatches(certPEM: pem, keyPEM: keyPEM) else {
            throw ConfigError("\(files.key) isn't the private key for \(files.cert)")
        }
        lock.lock()
        chain = newChain
        key = newKey
        current = Status(mode: files.mode, subject: summary.subject, dnsNames: summary.dnsNames, notAfter: summary.notAfter,
                         sha256: summary.sha256, issuer: summary.issuer)
        loadedStamp = stamp
        lock.unlock()
    }

    /// TLS 1.2+ with the current certificate supplied per handshake.
    func configuration() throws -> TLSConfiguration {
        lock.lock()
        let initialChain = chain, initialKey = key
        lock.unlock()
        guard let initialKey else { throw ConfigError("No TLS key loaded") }
        var tls = TLSConfiguration.makeServerConfiguration(certificateChain: initialChain.map { .certificate($0) },
                                                           privateKey: .privateKey(initialKey))
        tls.minimumTLSVersion = .tlsv12
        tls.sslContextCallback = { [weak self] _, promise in
            var override = NIOSSLContextConfigurationOverride()
            if let self {
                self.lock.lock()
                override.certificateChain = self.chain.map { .certificate($0) }
                override.privateKey = self.key.map { .privateKey($0) }
                self.lock.unlock()
            }
            promise.succeed(override)
        }
        return tls
    }

    /// Installs a certificate CertKeeper manages for itself; takes effect on the next handshake.
    func installManaged(fullchainPEM: String, keyPEM: String) throws {
        guard CertCrypto.keyMatches(certPEM: fullchainPEM, keyPEM: keyPEM) else {
            throw ConfigError("The key doesn't match the certificate")
        }
        try FileSecurity.writePrivate(Data(keyPEM.utf8), to: managedKeyFile)
        try FileSecurity.writePrivate(Data(fullchainPEM.utf8), to: managedCertificateFile)
        try reload()
    }

    /// Goes back to the self-signed certificate (or the platform's).
    func removeManaged() throws {
        try? FileManager.default.removeItem(at: managedCertificateFile)
        try? FileManager.default.removeItem(at: managedKeyFile)
        try reload()
    }

    /// The SHA-256 of the managed certificate file's leaf, if there is one. The file holds the full
    /// chain, so the leaf is the first of several certificates.
    var managedLeafSHA256: String? {
        guard let pem = try? String(contentsOf: managedCertificateFile, encoding: .utf8),
              let leaf = try? NIOSSLCertificate.fromPEMBytes(Array(pem.utf8)).first,
              let der = try? leaf.toDERBytes() else { return nil }
        return try? CertCrypto.summarize(der: Data(der)).sha256
    }

    static func makeSelfSigned(certificate: URL, key: URL) throws {
        let privateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let host = ProcessInfo.processInfo.hostName
        var names: [GeneralName] = [.dnsName("localhost")]
        if !host.isEmpty, host != "localhost" { names.insert(.dnsName(host), at: 0) }
        let subject = try DistinguishedName {
            OrganizationName("CertKeeper")
            CommonName("CertKeeper (self-signed)")
        }
        let now = Date()
        let cert = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: privateKey.publicKey,
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(825 * 86_400),
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames(names)
            },
            issuerPrivateKey: privateKey)
        try FileSecurity.writePrivate(Data(try privateKey.serializeAsPEM().pemString.utf8), to: key)
        try FileSecurity.writePrivate(Data(try cert.serializeAsPEM().pemString.utf8), to: certificate)
    }
}
