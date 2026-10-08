import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

/// A loopback HTTP server that either redirects every request or answers it, and records every
/// request whole.
///
/// The redirect tests ask one question of the *second* of two servers: what arrived? A stub
/// that recorded only the fields a test thought to look for could not answer it — the header
/// that should not have travelled is, by construction, one nobody thought to record. This keeps
/// the method, the request target, every header and the body.
///
/// Test support only. It is a target rather than a file in a test target because two test
/// targets use it, and it is in no product, so no consumer builds it.
public final class RedirectWireServer: Sendable {

    /// One request, as it arrived.
    public struct Request: Sendable {
        /// The HTTP method.
        public let method: String
        /// The request target: path and query.
        public let target: String
        /// Every header, by lowercased name.
        public let headers: [String: String]
        /// The body, as text.
        public let body: String

        /// A header's value, whatever case it was sent in.
        public func header(_ name: String) -> String? {
            headers[name.lowercased()]
        }
    }

    /// What the server does with a request.
    public enum Behaviour: Sendable {
        /// Answer `200` with a JSON document that reads as a token response and as an
        /// introspection response both.
        case answer
        /// Answer with this redirect status and this `Location`.
        case redirect(status: Int, location: String)
        /// Record the request and never answer it.
        case silence
        /// Answer with this status, these headers and this body, whatever they are.
        ///
        /// `Content-Length` is added from the body unless `headers` names one — so a test can
        /// have the server declare a length it then does not send.
        case respond(status: Int, headers: [String: String], body: String)
        /// Answer `200` and then send `total` bytes in `chunk`-sized pieces with no
        /// `Content-Length`, stopping when the client goes away.
        ///
        /// What an endless body looks like to a client, with an end so that a client which
        /// reads all of it is a failed assertion rather than a machine out of memory.
        case stream(chunk: Int, total: Int)
    }

    /// What has arrived, and what was sent back.
    struct Log: Sendable {
        var requests: [Request] = []
        var bodyBytesWritten = 0
        var connectionsClosed = 0
    }

    /// What a test may need to wait for, as a stream.
    ///
    /// A stream rather than a stored continuation because iterating one ends when the waiting
    /// task is cancelled — so a test whose event never comes is stopped by its time limit
    /// instead of hanging the run.
    struct Signals: Sendable {
        let arrivals: AsyncStream<Void>
        let arrived: AsyncStream<Void>.Continuation
        let closures: AsyncStream<Void>
        let closed: AsyncStream<Void>.Continuation

        init() {
            (arrivals, arrived) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
            (closures, closed) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        }
    }

    private let channel: any Channel
    private let recorded: NIOLockedValueBox<Log>
    private let signals: Signals
    private let scheme: String

    private init(
        channel: any Channel, recorded: NIOLockedValueBox<Log>, signals: Signals, scheme: String
    ) {
        self.channel = channel
        self.recorded = recorded
        self.signals = signals
        self.scheme = scheme
    }

    /// Starts a server on a port the kernel assigns.
    ///
    /// - Parameter behaviour: What to do with each request. A redirect's `Location` is not
    ///   known until the *other* server has a port, so this is a closure asked per request.
    /// - Returns: The running server.
    public static func start(
        _ behaviour: @escaping @Sendable () -> Behaviour
    ) async throws -> RedirectWireServer {
        try await start(tls: nil, behaviour)
    }

    /// Starts a server on a port the kernel assigns, speaking TLS if given an identity.
    ///
    /// - Parameters:
    ///   - tls: The certificate to present, or `nil` for plaintext.
    ///   - behaviour: What to do with each request.
    /// - Returns: The running server.
    public static func start(
        tls: LoopbackCertificate?,
        _ behaviour: @escaping @Sendable () -> Behaviour
    ) async throws -> RedirectWireServer {
        let recorded = NIOLockedValueBox(Log())
        let signals = Signals()
        let context = try tls.map { try $0.serverContext() }
        let bootstrap = ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(.backlog, value: 16)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if let context {
                        try channel.pipeline.syncOperations.addHandler(
                            NIOSSLServerHandler(context: context))
                    }
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    try channel.pipeline.syncOperations.addHandler(
                        RecordingHandler(behaviour: behaviour, recorded: recorded, signals: signals))
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        return RedirectWireServer(
            channel: channel, recorded: recorded, signals: signals,
            scheme: tls == nil ? "http" : "https")
    }

    /// The port the kernel assigned, or `0` if the channel has no address.
    public var port: Int {
        channel.localAddress?.port ?? 0
    }

    /// This server's origin, as an error is expected to name it.
    public var origin: String {
        "\(scheme)://127.0.0.1:\(port)"
    }

    /// Returns once a connection to this server has closed. For one waiter at a time.
    ///
    /// What a test of a cut-off transfer waits for before asking how much was sent.
    public func waitForDisconnect() async {
        for await _ in signals.closures { return }
    }

    /// How many body bytes the server managed to write, across every response so far.
    public var bodyBytesWritten: Int {
        recorded.withLockedValue { $0.bodyBytesWritten }
    }

    /// Returns once a request has arrived. For one waiter at a time.
    ///
    /// An event, not a pause: a test that needs a request to be in flight before it acts waits
    /// here rather than sleeping for an interval that is long enough on an idle machine.
    public func waitForRequest() async {
        for await _ in signals.arrivals { return }
    }

    /// A URL on this server.
    ///
    /// Built from components with the loopback address written out, so the host a test
    /// connects to is a literal in this file and never something assembled from a string.
    ///
    /// - Parameter path: The path, with its leading slash.
    /// - Returns: `http://127.0.0.1:<port><path>` — `https` for a TLS server — or `nil` if
    ///   the path is not one.
    public func url(path: String) -> URL? {
        var components = URLComponents()
        components.scheme = scheme
        components.host = "127.0.0.1"
        components.port = port
        components.path = path
        return components.url
    }

    /// Every request received so far, in order.
    public var requests: [Request] {
        recorded.withLockedValue { $0.requests }
    }

    /// Stops listening.
    public func stop() async throws {
        try await channel.close().get()
    }
}

/// Records each request, then answers as the server was told to.
private final class RecordingHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let behaviour: @Sendable () -> RedirectWireServer.Behaviour
    private let recorded: NIOLockedValueBox<RedirectWireServer.Log>
    private let signals: RedirectWireServer.Signals
    private var head: HTTPRequestHead?
    private var body = ""

    init(
        behaviour: @escaping @Sendable () -> RedirectWireServer.Behaviour,
        recorded: NIOLockedValueBox<RedirectWireServer.Log>,
        signals: RedirectWireServer.Signals
    ) {
        self.behaviour = behaviour
        self.recorded = recorded
        self.signals = signals
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            self.head = head
            body = ""
        case .body(var buffer):
            body += buffer.readString(length: buffer.readableBytes) ?? ""
        case .end:
            guard let head else { return }
            var headers: [String: String] = [:]
            for (name, value) in head.headers {
                headers[name.lowercased()] = value
            }
            let request = RedirectWireServer.Request(
                method: head.method.rawValue, target: head.uri, headers: headers, body: body)
            recorded.withLockedValue { $0.requests.append(request) }
            signals.arrived.yield()
            respond(context: context)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        recorded.withLockedValue { $0.connectionsClosed += 1 }
        signals.closed.yield()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        // A client that hangs up mid-response is what several tests are about; the write that
        // was in flight fails, and there is nothing to do but let the channel go.
        context.close(promise: nil)
    }

    /// Sends `remaining` bytes in pieces, each written only once the one before it has left.
    ///
    /// Stops at the first failed write, which is what a client closing the connection
    /// produces — so a client that stops reading stops the server, and the count says where.
    private func stream(context: ChannelHandlerContext, chunk: Int, remaining: Int) {
        guard remaining > 0, chunk > 0 else {
            let channel = context.channel
            context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
                channel.close(promise: nil)
            }
            return
        }
        let size = min(chunk, remaining)
        var buffer = context.channel.allocator.buffer(capacity: size)
        buffer.writeRepeatingByte(UInt8(ascii: "a"), count: size)
        let recorded = self.recorded
        // The handler and its context belong to this event loop, and the write's future
        // completes on it; the box says so to the compiler and checks it at run time.
        let here = NIOLoopBound((handler: self, context: context), eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(.body(.byteBuffer(buffer)))).whenComplete { result in
            guard case .success = result else { return }
            recorded.withLockedValue { $0.bodyBytesWritten += size }
            here.value.handler.stream(
                context: here.value.context, chunk: chunk, remaining: remaining - size)
        }
    }

    private func respond(context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        let status: HTTPResponseStatus
        let payload: String
        switch behaviour() {
        case .silence:
            // Left open. The client is the one that ends this exchange.
            return
        case .stream(let chunk, let total):
            headers.add(name: "Content-Type", value: "application/json")
            headers.add(name: "Connection", value: "close")
            context.write(
                wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .ok, headers: headers))),
                promise: nil)
            stream(context: context, chunk: chunk, remaining: total)
            return
        case .respond(let code, let extra, let body):
            status = HTTPResponseStatus(statusCode: code)
            payload = body
            for (name, value) in extra {
                headers.add(name: name, value: value)
            }
        case .answer:
            status = .ok
            payload = #"{"access_token":"issued","token_type":"Bearer","expires_in":3600,"active":true}"#
            headers.add(name: "Content-Type", value: "application/json")
        case .redirect(let code, let location):
            status = HTTPResponseStatus(statusCode: code)
            payload = ""
            headers.add(name: "Location", value: location)
        }
        if !headers.contains(name: "Content-Length") {
            headers.add(name: "Content-Length", value: String(payload.utf8.count))
        }
        headers.add(name: "Connection", value: "close")

        context.write(
            wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: status, headers: headers))),
            promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: payload.utf8.count)
        buffer.writeString(payload)
        let recorded = self.recorded
        let count = payload.utf8.count
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer)))).whenSuccess {
            recorded.withLockedValue { $0.bodyBytesWritten += count }
        }
        // The channel, not the context: the context is confined to its event loop and may not
        // be captured by a closure that could run elsewhere.
        let channel = context.channel
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            channel.close(promise: nil)
        }
    }
}
