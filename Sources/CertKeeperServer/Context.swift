import Foundation
import HTTPTypes
import Hummingbird
import NIOCore

/// Per-request context: the peer address (for login throttling) and the signed-in user.
struct AppContext: RequestContext {
    var coreContext: CoreRequestContextStorage
    let remoteAddress: String
    var username: String?
    var sessionToken: String?

    init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
        remoteAddress = source.channel.remoteAddress?.ipAddress ?? "unknown"
    }

    var requestDecoder: JSONDecoder { API.decoder }
    var responseEncoder: JSONEncoder { API.encoder }
}

/// Headers on every response: no framing, no sniffing, no referrers, scripts only from this server.
struct SecurityHeadersMiddleware: RouterMiddleware {
    typealias Context = AppContext

    func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        var response: Response
        do {
            response = try await next(request, context)
        } catch let error as HTTPResponseError {
            // Errors become responses here so they get these headers too.
            response = try error.response(from: request, context: context)
        }
        response.headers[.contentSecurityPolicy] =
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers[.xContentTypeOptions] = "nosniff"
        response.headers[.referrerPolicyHeader] = "no-referrer"
        response.headers[.xFrameOptions] = "DENY"
        if request.uri.path.hasPrefix("/api/") { response.headers[.cacheControl] = "no-store" }
        return response
    }
}

/// Requires a session for /api (except the sign-in endpoints) and, on changes, the X-CertKeeper
/// header. Browsers can't send a custom header cross-site without a CORS preflight, which this
/// server never answers, so a malicious page can't make a signed-in browser act on CertKeeper.
struct SessionMiddleware: RouterMiddleware {
    typealias Context = AppContext
    let auth: Auth
    static let cookieName = "certkeeper_session"
    static let open: Set<String> = ["/api/session", "/api/setup", "/api/login"]

    func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        var context = context
        if request.method != .get && request.method != .head && request.headers[.xCertKeeper] != "1" {
            throw HTTPError(.forbidden, message: "Missing the X-CertKeeper header")
        }
        if let token = request.cookies[Self.cookieName]?.value, let user = auth.session(token) {
            context.username = user
            context.sessionToken = token
        }
        if context.username == nil && !Self.open.contains(request.uri.path) {
            throw HTTPError(.unauthorized, message: "Sign in to CertKeeper")
        }
        return try await next(request, context)
    }

    static func cookie(_ token: String) -> Cookie {
        Cookie(name: cookieName, value: token, path: "/", secure: true, httpOnly: true, sameSite: .strict)
    }

    static func expiredCookie() -> Cookie {
        Cookie(name: cookieName, value: "", maxAge: 0, path: "/", secure: true, httpOnly: true, sameSite: .strict)
    }
}

extension HTTPField.Name {
    static let xCertKeeper = Self("X-CertKeeper")!
    static let xFrameOptions = Self("X-Frame-Options")!
    static let referrerPolicyHeader = Self("Referrer-Policy")!
}
