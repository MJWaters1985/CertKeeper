import Foundation
import Testing
@testable import CertKeeperCore

/// Talks to Let's Encrypt staging to validate JWS signing, account creation and order creation.
/// Opt-in: CK_ACME_STAGING=1 swift test --filter ACMEStaging
@Suite(.enabled(if: ProcessInfo.processInfo.environment["CK_ACME_STAGING"] == "1"))
struct ACMEStagingTests {
    @Test func accountAndOrder() async throws {
        let acme = try ACMEClient(
            directoryURL: AppSettings().directoryURL,  // staging by default
            accountKeyPEM: ACMEClient.newAccountKeyPEM(),
            accountURL: nil
        )
        let account = try await acme.ensureAccount(email: "")
        #expect(account.absoluteString.contains("acme-staging"))
        let base = "ck-\(UUID().uuidString.prefix(8).lowercased()).certkeeper-test.dev"
        let (order, orderURL) = try await acme.newOrder(domains: [base, "*." + base])
        #expect(order.status == "pending")
        #expect(order.authorizations.count == 2)
        let authz = try await acme.authorization(at: order.authorizations[0])
        let dns = try #require(authz.challenges.first { $0.type == "dns-01" })
        let value = await acme.dnsTXTValue(token: dns.token!)
        #expect(value.count == 43)
        _ = try await acme.order(at: orderURL)
    }
}
