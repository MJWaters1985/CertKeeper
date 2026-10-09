import Crypto
import _CryptoExtras
import Foundation
import SwiftASN1
import X509

extension Data {
    public var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public var hex: String { map { String(format: "%02x", $0) }.joined() }
}

public enum CertCrypto {
    /// Generates a new private key for a certificate and returns it as PEM.
    public static func generateKeyPEM(_ algorithm: KeyAlgorithm) throws -> String {
        let key: Certificate.PrivateKey
        switch algorithm {
        case .ecdsaP256: key = .init(P256.Signing.PrivateKey())
        case .ecdsaP384: key = .init(P384.Signing.PrivateKey())
        case .rsa2048: key = .init(try _RSA.Signing.PrivateKey(keySize: .bits2048))
        case .rsa4096: key = .init(try _RSA.Signing.PrivateKey(keySize: .bits4096))
        }
        return try key.serializeAsPEM().pemString
    }

    /// Builds a DER-encoded PKCS#10 CSR covering all `domains`.
    public static func makeCSR(domains: [String], keyPEM: String) throws -> Data {
        precondition(!domains.isEmpty)
        let key = try Certificate.PrivateKey(pemEncoded: keyPEM)
        let sigAlg: Certificate.SignatureAlgorithm
        switch key.publicKey.description {
        case let d where d.contains("P384"): sigAlg = .ecdsaWithSHA384
        case let d where d.contains("RSA"): sigAlg = .sha256WithRSAEncryption
        default: sigAlg = .ecdsaWithSHA256
        }
        // CN is limited to 64 chars; Let's Encrypt only needs the SANs.
        let cn = domains[0]
        let subject = try DistinguishedName {
            if cn.count <= 64 { CommonName(cn) }
        }
        let extensions = try Certificate.Extensions {
            SubjectAlternativeNames(domains.map { GeneralName.dnsName($0) })
        }
        let attributes = CertificateSigningRequest.Attributes(
            [try .init(ExtensionRequest(extensions: extensions))]
        )
        let csr = try CertificateSigningRequest(
            version: .v1,
            subject: subject,
            privateKey: key,
            attributes: attributes,
            signatureAlgorithm: sigAlg
        )
        var serializer = DER.Serializer()
        try serializer.serialize(csr)
        return Data(serializer.serializedBytes)
    }

    /// Splits a downloaded ACME chain into the leaf and the intermediates, each block on its own lines.
    public static func splitIssuedBundle(_ bundle: String) -> (leaf: String, chain: String)? {
        let pems = certificatePEMs(in: normalizePEMBundle(bundle))
        guard let leaf = pems.first else { return nil }
        return (leaf, joinPEMs(Array(pems.dropFirst())))
    }

    /// Joins PEM blocks with newlines so every BEGIN/END marker starts its own line.
    public static func joinPEMs(_ pems: [String]) -> String {
        pems.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) + "\n" }.joined()
    }

    /// Re-flows a PEM bundle so each block is on its own lines — repairs bundles whose blocks were
    /// concatenated without newlines ("-----END CERTIFICATE----------BEGIN CERTIFICATE-----").
    public static func normalizePEMBundle(_ text: String) -> String {
        let pattern = #"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return text }
        let ns = text as NSString
        let blocks = regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { m -> String in
            let label = ns.substring(with: m.range(at: 1))
            let body = ns.substring(with: m.range(at: 2)).filter { !$0.isWhitespace }
            let lines = stride(from: 0, to: body.count, by: 64).map { i -> String in
                let start = body.index(body.startIndex, offsetBy: i)
                return String(body[start..<(body.index(start, offsetBy: 64, limitedBy: body.endIndex) ?? body.endIndex)])
            }
            return (["-----BEGIN \(label)-----"] + lines + ["-----END \(label)-----"]).joined(separator: "\n")
        }
        return blocks.isEmpty ? text : joinPEMs(blocks)
    }

    /// Splits a PEM bundle into its CERTIFICATE blocks (leaf first).
    public static func certificatePEMs(in bundle: String) -> [String] {
        guard let docs = try? PEMDocument.parseMultiple(pemString: bundle) else { return [] }
        return docs.filter { $0.discriminator == "CERTIFICATE" }.map(\.pemString)
    }

    public static func summarize(pem: String) throws -> CertificateSummary {
        let cert = try Certificate(pemEncoded: pem)
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        let der = Data(serializer.serializedBytes)
        var names: [String] = []
        if let sans = try cert.extensions.subjectAlternativeNames {
            for name in sans {
                if case .dnsName(let n) = name { names.append(n) }
                if case .ipAddress(let bytes) = name { names.append(ipString(bytes.bytes)) }
            }
        }
        return CertificateSummary(
            subject: cert.subject.description,
            issuer: cert.issuer.description,
            serial: cert.serialNumber.description,
            notBefore: cert.notValidBefore,
            notAfter: cert.notValidAfter,
            dnsNames: names,
            sha256: Data(SHA256.hash(data: der)).hex
        )
    }

    public static func summarize(der: Data) throws -> CertificateSummary {
        let cert = try Certificate(derEncoded: Array(der))
        return try summarize(pem: cert.serializeAsPEM().pemString)
    }

    /// True if the private key in `keyPEM` matches the public key in the leaf certificate.
    public static func keyMatches(certPEM: String, keyPEM: String) -> Bool {
        guard let leafPEM = certificatePEMs(in: certPEM).first,
              let cert = try? Certificate(pemEncoded: leafPEM),
              let key = try? Certificate.PrivateKey(pemEncoded: keyPEM) else { return false }
        return cert.publicKey == key.publicKey
    }

    private static func ipString(_ bytes: ArraySlice<UInt8>) -> String {
        if bytes.count == 4 { return bytes.map(String.init).joined(separator: ".") }
        return stride(from: bytes.startIndex, to: bytes.endIndex, by: 2)
            .map { String(format: "%x", (UInt16(bytes[$0]) << 8) | UInt16(bytes[$0 + 1])) }
            .joined(separator: ":")
    }
}
