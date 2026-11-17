import Foundation
import Testing
@testable import CertKeeperCore

@Suite @MainActor struct DeviceAPITests {
    func model() -> AppModel {
        AppModel(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ck-\(UUID().uuidString).json"), secrets: MemorySecretStore())
    }

    @Test func fingerprintFormats() {
        let colons = "C0:07:36:CC:8A:CF:BC:09:FB:1B:9F:57:9E:CF:BE:97:5E:6D:73:A5:2C:78:09:32:44:02:CC:23:2A:45:20:2B"
        let hex = "c00736cc8acfbc09fb1b9f579ecfbe975e6d73a52c7809324402cc232a45202b"
        #expect(DeviceAPI.normalizeFingerprint(colons) == hex)
        #expect(DeviceAPI.normalizeFingerprint("  \(colons.lowercased()) ") == hex)
        #expect(DeviceAPI.formatFingerprint(hex) == colons)
    }

    @Test func trustDecision() {
        let leaf = "c00736cc8acfbc09fb1b9f579ecfbe975e6d73a52c7809324402cc232a45202b"
        #expect(DeviceAPI.accepts(systemTrusted: true, leafSHA256: leaf, pinned: ""), "a publicly trusted certificate needs no pin")
        #expect(DeviceAPI.accepts(systemTrusted: false, leafSHA256: leaf, pinned: DeviceAPI.formatFingerprint(leaf)))
        #expect(!DeviceAPI.accepts(systemTrusted: false, leafSHA256: leaf, pinned: ""), "untrusted and unpinned is refused")
        #expect(!DeviceAPI.accepts(systemTrusted: false, leafSHA256: leaf, pinned: String(repeating: "ab", count: 32)))
        #expect(!DeviceAPI.accepts(systemTrusted: false, leafSHA256: "", pinned: ""), "an empty pin never matches an empty fingerprint")
    }

    @Test func untrustedErrorExplainsPinning() {
        let msg = DeviceAPI.untrustedMessage(host: "amoled.example.com", fingerprint: "ab".repeated(32), pinned: "")
        #expect(msg.contains("AB:AB"))
        #expect(msg.contains("pin it on the host"))
    }

    @Test func decodesDeviceTLSInfo() throws {
        let json = """
        {"source":"self-signed","subject":"CN=amoled.example.com, O=ESP32-S3 AMOLED","issuer":"CN=amoled.example.com, O=ESP32-S3 AMOLED",
         "not_after":"2049-12-31T23:59:59Z","sha256":"c00736cc","chain_length":1,
         "dns_names":["amoled.local","amoled","amoled.example.com"],"hostname":"amoled.example.com","api_token_set":true}
        """
        let info = try JSONDecoder().decode(DeviceAPI.TLSInfo.self, from: Data(json.utf8))
        #expect(info.isSelfSigned)
        #expect(info.dnsNames.contains("amoled.example.com"))
        #expect(info.chainLength == 1)
    }

    @Test func oldHostsDecodeAsSSH() throws {
        let host = ManagedHost(name: "pve", address: "pve.example.com")
        var dict = try JSONSerialization.jsonObject(with: JSONEncoder().encode(host)) as! [String: Any]
        dict.removeValue(forKey: "connection")
        dict.removeValue(forKey: "apiPinnedSHA256")
        let decoded = try JSONDecoder().decode(ManagedHost.self, from: JSONSerialization.data(withJSONObject: dict))
        #expect(decoded.connection == .ssh)
        #expect(decoded.apiPinnedSHA256.isEmpty)
    }

    @Test func deviceHostRoundTrips() throws {
        var host = ManagedHost(name: "amoled", address: "amoled.example.com", port: 443)
        host.connection = .deviceAPI
        host.apiPinnedSHA256 = "c00736cc"
        let decoded = try JSONDecoder().decode(ManagedHost.self, from: JSONEncoder().encode(host))
        #expect(decoded.isDeviceAPI)
        #expect(decoded.apiPinnedSHA256 == "c00736cc")
    }

    @Test func clientNeedsAToken() {
        var host = ManagedHost(name: "amoled", address: "amoled.example.com", port: 443)
        host.connection = .deviceAPI
        #expect(throws: DeployError.self) { try DeviceAPI(host: host, token: "") }
        let api = try? DeviceAPI(host: host, token: "ckd_x")
        #expect(api?.baseURL.absoluteString == "https://amoled.example.com")
        host.port = 8443
        #expect((try? DeviceAPI(host: host, token: "ckd_x"))?.baseURL.absoluteString == "https://amoled.example.com:8443")
    }

    /// Adopting the discovered web interface yields a Device API deployment verified on the device's port.
    @Test func adoptsDiscoveredWebInterface() throws {
        let m = model()
        var host = ManagedHost(name: "amoled", address: "amoled.example.com", port: 443)
        host.connection = .deviceAPI
        m.addHost(host)
        let (pem, _) = try selfSigned(["amoled.example.com"])
        let ep = DiscoveredEndpoint(kind: .deviceAPI, label: "Web interface", certPath: "", keyPath: "", chainPath: "",
                                    summary: try CertCrypto.summarize(pem: pem),
                                    options: [DeploymentOption.verifyPort.rawValue: "443"], note: nil)
        let d = m.adopt(ep, hostID: host.id, target: .new)
        #expect(d.kind == .deviceAPI)
        #expect(d.verifyEndpoint == "amoled.example.com:443")
        #expect(d.certPath.isEmpty)
        #expect(m.inventory.certificates.first?.domains == ["amoled.example.com"])
        #expect(m.isManaged(ep, hostID: host.id))
    }
}

@Suite struct HTTPOverTLSParseTests {
    @Test func contentLength() throws {
        let raw = Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}trailing".utf8)
        let (status, body) = try HTTPOverTLS.parse(raw)
        #expect(status == 200)
        #expect(String(decoding: body, as: UTF8.self) == "{\"ok\":true}")
    }

    @Test func chunked() throws {
        let raw = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n5\r\n:\"b\"}\r\n0\r\n\r\n".utf8)
        let (_, body) = try HTTPOverTLS.parse(raw)
        #expect(String(decoding: body, as: UTF8.self) == "{\"a\":\"b\"}")
    }

    @Test func errorStatusAndReadToClose() throws {
        let raw = Data("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Not logged in\"}".utf8)
        let (status, body) = try HTTPOverTLS.parse(raw)
        #expect(status == 401)
        #expect(String(decoding: body, as: UTF8.self).contains("Not logged in"))
    }

    @Test func knowsWhenAResponseIsWhole() {
        #expect(!HTTPOverTLS.isWhole(Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".utf8)))
        #expect(HTTPOverTLS.isWhole(Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde".utf8)))
        #expect(!HTTPOverTLS.isWhole(Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n".utf8)))
        #expect(HTTPOverTLS.isWhole(Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".utf8)))
        #expect(!HTTPOverTLS.isWhole(Data("HTTP/1.1 200 OK\r\n".utf8)), "headers not finished")
    }

    @Test func rejectsGarbage() {
        #expect(throws: DeployError.self) { try HTTPOverTLS.parse(Data("hello".utf8)) }
        #expect(throws: DeployError.self) { try HTTPOverTLS.parse(Data("SSH-2.0-x\r\n\r\n".utf8)) }
    }
}

private extension String {
    func repeated(_ n: Int) -> String { String(repeating: self, count: n) }
}
