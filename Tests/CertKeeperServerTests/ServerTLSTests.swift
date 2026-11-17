import CertKeeperCore
import Crypto
import Foundation
import Testing
import X509
@testable import CertKeeperServer

@Suite struct ServerTLSTests {
    /// A certificate signed by a throwaway CA, as PEM: (leaf + CA chain, leaf key).
    func chain(_ name: String) throws -> (String, String) {
        let caKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let caName = try DistinguishedName { CommonName("Test CA") }
        let now = Date()
        let ca = try Certificate(version: .v3, serialNumber: .init(), publicKey: caKey.publicKey,
                                 notValidBefore: now - 60, notValidAfter: now + 86_400, issuer: caName, subject: caName,
                                 signatureAlgorithm: .ecdsaWithSHA256,
                                 extensions: try Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)) },
                                 issuerPrivateKey: caKey)
        let leafKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leaf = try Certificate(version: .v3, serialNumber: .init(), publicKey: leafKey.publicKey,
                                   notValidBefore: now - 60, notValidAfter: now + 86_400, issuer: caName,
                                   subject: try DistinguishedName { CommonName(name) }, signatureAlgorithm: .ecdsaWithSHA256,
                                   extensions: try Certificate.Extensions { SubjectAlternativeNames([.dnsName(name)]) },
                                   issuerPrivateKey: caKey)
        return (CertCrypto.joinPEMs([try leaf.serializeAsPEM().pemString, try ca.serializeAsPEM().pemString]),
                try leafKey.serializeAsPEM().pemString)
    }

    func config() throws -> ServerConfig {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ck-server-\(UUID().uuidString)")
        return try ServerConfig(environment: ["CERTKEEPER_CONFIG_DIR": dir.path])
    }

    @Test func startsSelfSignedThenUsesAndReportsAManagedChain() throws {
        let config = try config()
        defer { try? FileManager.default.removeItem(at: config.configDirectory) }
        let tls = try ServerTLS(config: config)
        #expect(tls.status?.mode == .selfSigned)
        #expect(tls.managedLeafSHA256 == nil)

        let (full, key) = try chain("certkeeper.example.com")
        try tls.installManaged(fullchainPEM: full, keyPEM: key)
        let leafSHA = try CertCrypto.summarize(pem: try #require(CertCrypto.splitIssuedBundle(full)).leaf).sha256
        #expect(tls.status?.mode == .managed)
        #expect(tls.status?.sha256 == leafSHA)
        #expect(tls.managedLeafSHA256 == leafSHA, "the leaf of a full-chain file is read back, so it isn't reinstalled every minute")

        try tls.removeManaged()
        #expect(tls.status?.mode == .selfSigned)
    }

    @Test func refusesAKeyThatDoesntMatch() throws {
        let config = try config()
        defer { try? FileManager.default.removeItem(at: config.configDirectory) }
        let tls = try ServerTLS(config: config)
        let (full, _) = try chain("a.example.com")
        let (_, otherKey) = try chain("b.example.com")
        #expect(throws: (any Error).self) { try tls.installManaged(fullchainPEM: full, keyPEM: otherKey) }
        #expect(tls.status?.mode == .selfSigned)
    }
}
