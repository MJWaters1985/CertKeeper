import Foundation
import Testing
@testable import CertKeeperCore

/// Serves canned Cloudflare API responses keyed by request path.
final class CloudflareStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var routes: [String: (Int, String)] = [:]
    nonisolated(unsafe) static var seen: [String] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url!.path.replacingOccurrences(of: "/client/v4/", with: "")
        Self.seen.append(path)
        let (status, body) = Self.routes[path] ?? (404, #"{"success":false,"errors":[{"code":7003,"message":"No route"}],"result":null}"#)
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!,
                            cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CloudflareStub.self]
        return URLSession(configuration: config)
    }
}

@Suite(.serialized) struct CloudflareVerifyTests {
    let invalid = (401, #"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}"#)
    let active = (200, #"{"success":true,"errors":[],"messages":[],"result":{"id":"t1","status":"active"}}"#)
    let zones = (200, #"{"success":true,"errors":[],"result":[{"id":"z1","name":"example.com","account":{"id":"acc1","name":"Example Account"}}],"result_info":{"page":1,"total_pages":1}}"#)

    @Test func userToken() async throws {
        CloudflareStub.routes = ["user/tokens/verify": active, "zones": zones]
        CloudflareStub.seen = []
        let v = try await CloudflareClient(token: "t", session: CloudflareStub.session()).verifyToken()
        #expect(v.status == "active")
        #expect(v.accountName == nil)
        #expect(v.zones.map(\.name) == ["example.com"])
        #expect(!CloudflareStub.seen.contains { $0.hasPrefix("accounts/") })
    }

    @Test func accountOwnedTokenFallsBackToAccountEndpoint() async throws {
        CloudflareStub.routes = ["user/tokens/verify": invalid, "zones": zones, "accounts/acc1/tokens/verify": active]
        CloudflareStub.seen = []
        let v = try await CloudflareClient(token: "t", session: CloudflareStub.session()).verifyToken()
        #expect(v.status == "active")
        #expect(v.accountName == "Example Account")
        #expect(CloudflareStub.seen.contains("accounts/acc1/tokens/verify"))
    }

    @Test func reallyInvalidTokenStillReportsTheError() async throws {
        CloudflareStub.routes = ["user/tokens/verify": invalid, "zones": invalid]
        CloudflareStub.seen = []
        do {
            _ = try await CloudflareClient(token: "bad", session: CloudflareStub.session()).verifyToken()
            Issue.record("expected an error")
        } catch let e as CloudflareClient.CloudflareError {
            #expect(e.codes == [1000])
            #expect(e.localizedDescription.contains("Invalid API Token"))
        }
    }
}
