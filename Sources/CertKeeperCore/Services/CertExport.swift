import _CryptoExtras
import Foundation
import SwiftASN1
import X509

/// Exports an issued certificate (with its full chain and private key) in common file formats.
/// PKCS#12 and PKCS#7 are produced by macOS's /usr/bin/openssl (LibreSSL); the rest are built here.
public enum CertExport {
    public enum Format: String, CaseIterable, Identifiable, Sendable {
        case pemSeparate, pemCombined, pkcs12, pkcs7, der

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .pemSeparate: "PEM — separate files"
            case .pemCombined: "PEM — single file"
            case .pkcs12: "PKCS#12 (.p12 / .pfx)"
            case .pkcs7: "PKCS#7 (.p7b) + key"
            case .der: "DER (.cer) + key"
            }
        }

        public var summary: String {
            switch self {
            case .pemSeparate: "cert.pem, chain.pem, fullchain.pem and privkey.pem: nginx, Apache, most Linux tools."
            case .pemCombined: "One file with the private key and full chain: HAProxy, Pi-hole, lighttpd."
            case .pkcs12: "One password-protected file with the full chain and key: Windows/IIS, macOS Keychain, Java, Jellyfin."
            case .pkcs7: "The full chain in a .p7b (PKCS#7 can't hold keys) plus the key as a separate PEM file: Windows, Java."
            case .der: "Each certificate as binary .cer (leaf, then intermediates) plus the key as binary PKCS#8: Windows, appliances, Android."
            }
        }

        public var needsPassword: Bool { self == .pkcs12 }
    }

    public struct OutputFile: Sendable, Equatable {
        public let name: String
        public let data: Data
        /// Holds private key material: write it readable only by the user.
        public let secret: Bool
    }

    public struct ExportError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// File-name-safe base for a certificate, e.g. "nas.example.com" or "_wildcard_.lab.example.com".
    public static func baseName(for cert: ManagedCertificate) -> String {
        (cert.domains.first ?? cert.name).replacingOccurrences(of: "*", with: "_wildcard_")
            .map { $0.isLetter || $0.isNumber || "-._".contains($0) ? $0 : "_" }
            .reduce(into: "") { $0.append($1) }
    }

    /// The files for `format`. `password` is required for PKCS#12; `legacy` selects 3DES/SHA-1
    /// encryption for systems that can't read AES-256 PKCS#12 (Windows Server 2016 and earlier, older Java).
    public static func files(for cert: ManagedCertificate, keyPEM: String, format: Format,
                             password: String? = nil, legacy: Bool = false,
                             openssl: String = "/usr/bin/openssl") throws -> [OutputFile] {
        guard let leaf = cert.leafPEM else { throw ExportError(message: "\(cert.name) hasn't been issued yet") }
        let base = baseName(for: cert)
        let chainPEMs = CertCrypto.certificatePEMs(in: cert.chainPEM ?? "")
        let leafPEM = CertCrypto.joinPEMs([leaf])
        let chain = CertCrypto.joinPEMs(chainPEMs)
        let fullchain = CertCrypto.joinPEMs([leaf] + chainPEMs)
        let key = CertCrypto.joinPEMs([keyPEM])
        func text(_ s: String) -> Data { Data(s.utf8) }

        switch format {
        case .pemSeparate:
            return [OutputFile(name: "\(base).cert.pem", data: text(leafPEM), secret: false),
                    OutputFile(name: "\(base).chain.pem", data: text(chain), secret: false),
                    OutputFile(name: "\(base).fullchain.pem", data: text(fullchain), secret: false),
                    OutputFile(name: "\(base).privkey.pem", data: text(key), secret: true)]

        case .pemCombined:
            return [OutputFile(name: "\(base).pem", data: text(key + fullchain), secret: true)]

        case .der:
            var out = [OutputFile(name: "\(base).cer", data: try der(of: leaf), secret: false)]
            for (i, pem) in chainPEMs.enumerated() {
                out.append(OutputFile(name: "\(base).chain-\(i + 1).cer", data: try der(of: pem), secret: false))
            }
            out.append(OutputFile(name: "\(base).key.der", data: try keyDER(keyPEM), secret: true))
            return out

        case .pkcs7:
            let p7b = try runOpenSSL(openssl, ["crl2pkcs7", "-nocrl", "-certfile", "fullchain.pem", "-outform", "DER", "-out", "out.p7b"],
                                     inputs: ["fullchain.pem": text(fullchain)], output: "out.p7b")
            return [OutputFile(name: "\(base).p7b", data: p7b, secret: false),
                    OutputFile(name: "\(base).key", data: text(key), secret: true)]

        case .pkcs12:
            guard let password, !password.isEmpty else { throw ExportError(message: "PKCS#12 needs a password") }
            var args = ["pkcs12", "-export", "-inkey", "key.pem", "-in", "fullchain.pem",
                        "-name", cert.domains.first ?? cert.name, "-passout", "env:CK_P12_PASSWORD", "-out", "out.p12"]
            if !legacy { args += ["-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "sha256"] }
            let p12 = try runOpenSSL(openssl, args, inputs: ["key.pem": text(key), "fullchain.pem": text(fullchain)],
                                     output: "out.p12", environment: ["CK_P12_PASSWORD": password])
            return [OutputFile(name: "\(base).p12", data: p12, secret: true)]
        }
    }

    static func der(of pem: String) throws -> Data {
        let cert = try Certificate(pemEncoded: pem)
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        return Data(serializer.serializedBytes)
    }

    /// The key as PKCS#8 DER. CertKeeper's ECDSA keys are already PKCS#8 ("BEGIN PRIVATE KEY"); RSA
    /// keys are stored as PKCS#1 ("BEGIN RSA PRIVATE KEY") and are re-encoded.
    static func keyDER(_ keyPEM: String) throws -> Data {
        let document = try PEMDocument(pemString: keyPEM)
        switch document.discriminator {
        case "PRIVATE KEY":
            return Data(document.derBytes)
        case "RSA PRIVATE KEY":
            return try _RSA.Signing.PrivateKey(pemRepresentation: keyPEM).pkcs8DERRepresentation
        default:
            throw ExportError(message: "Unsupported private key type: \(document.discriminator)")
        }
    }

    /// Runs openssl in a private temporary folder (key material never leaves it) and returns `output`.
    static func runOpenSSL(_ path: String, _ args: [String], inputs: [String: Data], output: String,
                           environment: [String: String] = [:]) throws -> Data {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("certkeeper-export-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        for (name, data) in inputs {
            let url = dir.appendingPathComponent(name)
            try data.write(to: url)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.currentDirectoryURL = dir
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { $1 }
        let err = Pipe()
        process.standardError = err
        process.standardOutput = Pipe()
        try process.run()
        process.waitUntilExit()
        let message = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0, let data = try? Data(contentsOf: dir.appendingPathComponent(output)) else {
            throw ExportError(message: "openssl \(args.first ?? "") failed: \(message.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return data
    }
}
