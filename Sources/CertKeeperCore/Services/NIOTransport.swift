#if !canImport(Network)
import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import X509

// TLS connections for systems without Network.framework (the Linux server), on SwiftNIO and
// BoringSSL. Each function matches its Network.framework counterpart in TLSProbe.swift and
// DeviceAPI.swift.

extension TLSProbe {
    /// The peer's certificates as DER, exactly as it sent them (see `Served.exact`).
    static func peerChain(host: String, port: UInt16, endpoint: String, timeout: TimeInterval) async throws -> ([Data], Bool) {
        let captured = NIOTransport.Captured<[Data]>()
        _ = try await NIOTransport.exchange(host: host, port: port, request: nil, timeout: timeout, minimumTLS: .tlsv1) { certs in
            captured.value = certs.compactMap { try? Data($0.toDERBytes()) }
            return true  // inspect anything: self-signed, expired, staging
        }
        return (captured.value ?? [], true)
    }
}

extension HTTPOverTLS {
    static func exchange(host: String, port: UInt16, request: Data, gate: TrustGate, timeout: TimeInterval) async throws -> Data {
        try await NIOTransport.exchange(host: host, port: port, request: request, timeout: timeout, minimumTLS: .tlsv12) { certs in
            let leaf = certs.first.flatMap { try? Data($0.toDERBytes()) }
            return gate.decide(systemTrusted: await NIOTransport.systemTrusts(certs, host: host), leafDER: leaf)
        }
    }
}

enum NIOTransport {
    /// Connects, completes a TLS handshake whose trust `verify` decides, then sends `request` (if
    /// any) and returns the raw response. Without a request it returns once the handshake is done.
    static func exchange(host: String, port: UInt16, request: Data?, timeout: TimeInterval, minimumTLS: TLSVersion,
                         verify: @escaping @Sendable ([NIOSSLCertificate]) async -> Bool) async throws -> Data {
        var config = TLSConfiguration.makeClientConfiguration()
        config.minimumTLSVersion = minimumTLS
        // `verify` decides trust, name included (systemTrusts checks it); NIOSSL's own hostname check
        // would otherwise run afterwards and refuse the probe's self-signed and IP-address peers.
        config.certificateVerification = .noHostnameVerification
        let context = try NIOSSLContext(configuration: config)
        // SNI carries names only; NIOSSL refuses an IP address there.
        let serverName: String? = isIPAddress(host) ? nil : host
        let group = MultiThreadedEventLoopGroup.singleton
        let result = Completion(group.next().makePromise(of: Data.self))
        let label = "\(host):\(port)"

        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.milliseconds(Int64(timeout * 1000)))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let tls = try NIOSSLClientHandler(context: context, serverHostname: serverName,
                                                      customVerificationCallback: { certs, verdict in
                        verdict.completeWithTask { await verify(certs) ? .certificateVerified : .failed }
                    })
                    try channel.pipeline.syncOperations.addHandler(tls)
                    try channel.pipeline.syncOperations.addHandler(ExchangeHandler(request: request, result: result, label: label))
                }
            }
        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: host, port: Int(port)).get()
        } catch {
            result.fail(error)
            throw DeployError("Couldn't connect to \(label): \(error)")
        }
        let deadline = channel.eventLoop.scheduleTask(in: .milliseconds(Int64(timeout * 1000))) {
            result.fail(DeployError("\(label) didn't answer within \(Int(timeout)) seconds"))
        }
        defer {
            deadline.cancel()
            channel.close(promise: nil)
        }
        return try await result.future.get()
    }

    /// Whether the chain leads to a root in the system's CA bundle and is valid for `host`.
    static func systemTrusts(_ certs: [NIOSSLCertificate], host: String) async -> Bool {
        let parsed = certs.compactMap { try? Certificate(derEncoded: $0.toDERBytes()) }
        guard let leaf = parsed.first else { return false }
        let ip = isIPAddress(host)
        var verifier = Verifier(rootCertificates: CertificateStore.systemTrustRoots) {
            RFC5280Policy(validationTime: Date())
            ServerIdentityPolicy(serverHostname: ip ? nil : host, serverIP: ip ? host : nil)
        }
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore(parsed.dropFirst()))
        if case .validCertificate = result { return true }
        return false
    }

    static func isIPAddress(_ host: String) -> Bool {
        (try? SocketAddress(ipAddress: host, port: 0)) != nil
    }

    /// After the handshake: sends the request and collects the response until it's whole or the
    /// server closes. Servers may keep the socket open despite "Connection: close" (the ESP32's
    /// does), so completeness is judged by `HTTPOverTLS.isWhole` as on macOS.
    final class ExchangeHandler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        typealias OutboundOut = ByteBuffer

        private let request: Data?
        private let result: Completion
        private let label: String
        private var response = Data()
        private var handshakeDone = false

        init(request: Data?, result: Completion, label: String) {
            self.request = request
            self.result = result
            self.label = label
        }

        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
                handshakeDone = true
                if let request {
                    context.writeAndFlush(wrapOutboundOut(context.channel.allocator.buffer(bytes: request)), promise: nil)
                } else {
                    result.succeed(Data())
                }
            }
            context.fireUserInboundEventTriggered(event)
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var buffer = unwrapInboundIn(data)
            if let bytes = buffer.readBytes(length: buffer.readableBytes) { response.append(contentsOf: bytes) }
            if HTTPOverTLS.isWhole(response) { result.succeed(response) }
        }

        func channelInactive(context: ChannelHandlerContext) {
            if !response.isEmpty { result.succeed(response) }
            else { result.fail(DeployError(handshakeDone ? "\(label) closed the connection without answering"
                                                          : "\(label) closed the connection during the TLS handshake")) }
            context.fireChannelInactive()
        }

        func errorCaught(context: ChannelHandlerContext, error: Error) {
            // A server that closes without a TLS close_notify still sent a usable response.
            if !response.isEmpty, let ssl = error as? NIOSSLError, case .uncleanShutdown = ssl {
                result.succeed(response)
            } else {
                result.fail(error)
            }
            context.close(promise: nil)
        }
    }

    /// Lets only the first outcome through: the handler, the deadline and a failed connect may each
    /// try to finish the exchange.
    final class Completion: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        private let promise: EventLoopPromise<Data>
        var future: EventLoopFuture<Data> { promise.futureResult }
        init(_ promise: EventLoopPromise<Data>) { self.promise = promise }
        func succeed(_ data: Data) { if claim() { promise.succeed(data) } }
        func fail(_ error: Error) { if claim() { promise.fail(error) } }
        private func claim() -> Bool {
            lock.lock(); defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }

    final class Captured<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value?
        var value: Value? {
            get { lock.lock(); defer { lock.unlock() }; return stored }
            set { lock.lock(); stored = newValue; lock.unlock() }
        }
    }
}
#endif
