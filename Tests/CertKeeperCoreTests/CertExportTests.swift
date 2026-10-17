import Foundation
import Testing
@testable import CertKeeperCore

@Suite struct CertExportTests {
    /// A certificate with a two-certificate chain, like Let's Encrypt's.
    func issued(_ alg: KeyAlgorithm = .ecdsaP256) throws -> (ManagedCertificate, String) {
        let (leaf, key) = try selfSigned(["nas.example.com"], algorithm: alg)
        let chain = try ["YE1 Test", "ISRG Root YE Test"].map { try selfSigned([$0]).0 }
        var c = ManagedCertificate(name: "nas.example.com", domains: ["nas.example.com"])
        c.leafPEM = leaf
        c.chainPEM = CertCrypto.joinPEMs(chain)
        return (c, key)
    }

    /// Runs openssl with `input` written to a temp file; returns stdout+stderr and the exit status.
    func openssl(_ args: [String], input: Data, env: [String: String] = [:]) throws -> (String, Int32) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ck-exp-\(UUID().uuidString)")
        try input.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = args + ["-in", url.path]
        p.environment = ProcessInfo.processInfo.environment.merging(env) { $1 }
        // Separate pipes: sharing one let stderr ("MAC verified OK") land inside a PEM block under load.
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        var errData = Data()
        let reader = Thread { errData = err.fileHandleForReading.readDataToEndOfFile() }
        reader.start()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        while reader.isExecuting { Thread.sleep(forTimeInterval: 0.01) }
        return (String(decoding: data, as: UTF8.self) + "\n" + String(decoding: errData, as: UTF8.self), p.terminationStatus)
    }

    func certCount(_ s: String) -> Int { s.components(separatedBy: "BEGIN CERTIFICATE").count - 1 }

    @Test func pemSeparate() throws {
        let (c, key) = try issued()
        let files = try CertExport.files(for: c, keyPEM: key, format: .pemSeparate)
        #expect(files.map(\.name) == ["nas.example.com.cert.pem", "nas.example.com.chain.pem", "nas.example.com.fullchain.pem", "nas.example.com.privkey.pem"])
        #expect(files.map(\.secret) == [false, false, false, true])
        let text = files.map { String(decoding: $0.data, as: UTF8.self) }
        let counts: [Int] = [certCount(text[0]), certCount(text[1]), certCount(text[2])]
        #expect(counts == [1, 2, 3], "leaf, chain, full chain")
        #expect(CertCrypto.keyMatches(certPEM: text[2], keyPEM: text[3]))
    }

    @Test func pemCombined() throws {
        let (c, key) = try issued()
        let files = try CertExport.files(for: c, keyPEM: key, format: .pemCombined)
        #expect(files.count == 1 && files[0].name == "nas.example.com.pem" && files[0].secret)
        let text = String(decoding: files[0].data, as: UTF8.self)
        #expect(text.hasPrefix("-----BEGIN PRIVATE KEY-----"), "key first, as HAProxy and Pi-hole expect")
        #expect(certCount(text) == 3)
        #expect(CertCrypto.keyMatches(certPEM: text, keyPEM: key))
    }

    @Test(arguments: [KeyAlgorithm.ecdsaP256, .rsa2048])
    func der(_ alg: KeyAlgorithm) throws {
        let (c, key) = try issued(alg)
        let files = try CertExport.files(for: c, keyPEM: key, format: .der)
        #expect(files.map(\.name) == ["nas.example.com.cer", "nas.example.com.chain-1.cer", "nas.example.com.chain-2.cer", "nas.example.com.key.der"])
        #expect(try CertCrypto.summarize(der: files[0].data).dnsNames == ["nas.example.com"])
        #expect(try CertCrypto.summarize(der: files[1].data).subject.contains("YE1 Test"))
        let (out, status) = try openssl(["pkcs8", "-inform", "DER", "-nocrypt"], input: files[3].data)
        #expect(status == 0, "key.der is PKCS#8: \(out)")
        #expect(CertCrypto.keyMatches(certPEM: c.leafPEM!, keyPEM: out))
    }

    @Test func pkcs7() throws {
        let (c, key) = try issued()
        let files = try CertExport.files(for: c, keyPEM: key, format: .pkcs7)
        #expect(files.map(\.name) == ["nas.example.com.p7b", "nas.example.com.key"])
        let (out, status) = try openssl(["pkcs7", "-inform", "DER", "-print_certs"], input: files[0].data)
        #expect(status == 0)
        #expect(certCount(out) == 3, "the full chain")
        #expect(!files[0].secret && files[1].secret)
    }

    @Test(arguments: [false, true])
    func pkcs12(legacy: Bool) throws {
        let (c, key) = try issued()
        let files = try CertExport.files(for: c, keyPEM: key, format: .pkcs12, password: "s3cret-p12", legacy: legacy)
        #expect(files.count == 1 && files[0].name == "nas.example.com.p12" && files[0].secret)
        let (out, status) = try openssl(["pkcs12", "-nodes", "-passin", "env:P"], input: files[0].data, env: ["P": "s3cret-p12"])
        #expect(status == 0)
        #expect(certCount(out) == 3, "the full chain")
        // openssl prints the certificates and key together, with "Bag Attributes" text; take the key block.
        let keyBlock = try #require(out.range(of: #"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#,
                                              options: .regularExpression).map { String(out[$0]) })
        #expect(CertCrypto.keyMatches(certPEM: c.leafPEM!, keyPEM: keyBlock))
        let (info, _) = try openssl(["pkcs12", "-info", "-noout", "-passin", "env:P"], input: files[0].data, env: ["P": "s3cret-p12"])
        #expect(info.contains("TripleDES") == legacy, "legacy uses 3DES; the default doesn't")
        let (_, wrong) = try openssl(["pkcs12", "-nodes", "-passin", "env:P"], input: files[0].data, env: ["P": "nope"])
        #expect(wrong != 0)
    }

    @Test func pkcs12NeedsAPasswordAndUnissuedCertsFail() throws {
        let (c, key) = try issued()
        #expect(throws: CertExport.ExportError.self) { try CertExport.files(for: c, keyPEM: key, format: .pkcs12) }
        let unissued = ManagedCertificate(name: "x", domains: ["x"])
        #expect(throws: CertExport.ExportError.self) { try CertExport.files(for: unissued, keyPEM: key, format: .pemSeparate) }
    }

    @Test func wildcardFileNames() {
        let c = ManagedCertificate(name: "lab", domains: ["*.lab.example.com"])
        #expect(CertExport.baseName(for: c) == "_wildcard_.lab.example.com")
    }
}
