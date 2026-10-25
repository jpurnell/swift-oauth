import Foundation
import SwiftOAuthCore

/// Carries a device authorization request — RFC 8628 §3.1 — as well as the token requests
/// that redeem what it returns.
///
/// A refinement of ``TokenTransport`` rather than a sibling, because the grant cannot be run
/// with one and not the other: the device code this request returns is worth nothing until it
/// is redeemed at the token endpoint. ``URLSessionTokenTransport`` conforms.
///
/// A separate protocol rather than a new requirement on ``TokenTransport``, so a transport
/// written against an earlier version of this package still compiles: a requirement added to a
/// public protocol breaks every conformance outside it.
public protocol DeviceAuthorizationTransport: TokenTransport {

    /// Posts a device authorization request and returns the server's answer.
    ///
    /// - Parameters:
    ///   - endpoint: The device authorization endpoint.
    ///   - parameters: The form body, unencoded.
    ///   - credentials: Used for client authentication — RFC 8628 §3.1 applies the token
    ///     endpoint's rules (RFC 6749 §3.2.1) here.
    ///   - method: How the credentials should be presented.
    /// - Returns: The decoded response. Checking it is ``DeviceAuthorizationClient``'s job,
    ///   not the transport's, so a transport cannot skip it.
    /// - Throws: `OAuthError` for anything the server refused, or a transport error.
    func requestDeviceAuthorization(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> DeviceAuthorizationResponse
}

/// Why a ``DeviceAuthorizationClient`` could not be created.
public enum DeviceGrantConfigurationError: Error, Equatable, Sendable {

    /// The configuration names no device authorization endpoint, so the grant cannot begin.
    ///
    /// Refused when the client is created rather than at the first request: by then a user
    /// may have asked to sign in, and the honest answer — this provider does not offer it —
    /// was knowable at startup.
    case noDeviceAuthorizationEndpoint(provider: String)

    /// An endpoint the grant uses is not HTTPS.
    ///
    /// RFC 8628 §3.1: "All requests from the device MUST use the Transport Layer Security
    /// (TLS) protocol". Both endpoints are held to it: the device authorization request may
    /// carry a client secret, and every poll carries the device code, which is a bearer
    /// credential for the tokens the user is about to approve.
    case insecureEndpoint(URL)
}

/// The device grant from the client's side — RFC 8628, request through redemption.
///
/// For anything that cannot open a browser: a command-line tool, a terminal session over SSH,
/// a television. The client asks the device authorization endpoint for a pair of codes, shows
/// the user the short one and where to type it, and polls the token endpoint with the long one
/// until the user has approved, refused, or gone away.
///
/// ```swift
/// let configuration = ProviderConfiguration(
///     identifier: "example",
///     authorizationEndpoint: URL(string: "https://id.example.com/authorize")!,
///     tokenEndpoint: URL(string: "https://id.example.com/token")!,
///     deviceAuthorizationEndpoint: URL(string: "https://id.example.com/device_authorization")!,
///     scope: "openid")
/// let credentials = ClientCredentials(
///     environment: "production", clientID: "my-client", clientSecret: "")
/// let client = try DeviceAuthorizationClient(configuration: configuration, credentials: credentials)
/// let tokens = try await client.signIn { authorization in
///     print("Visit \(authorization.verificationURI) and enter \(authorization.userCode)")
/// }
/// ```
///
/// ## The server's answer is checked before it is shown
///
/// What the device authorization endpoint returns is shown to a person, who is about to act on
/// it with their password. So before the caller sees it: both verification URIs must be
/// absolute `https` URLs — a user sent to an `http` page signs in over cleartext — and the user
/// code must hold no control, format or separator characters, since it is printed to a screen
/// where an escape sequence rewrites what the user reads and a bidirectional override reorders
/// it. `expires_in` and `interval` must be positive, finite numbers of seconds, which the
/// polling loop would refuse anyway; refusing them here means the user is never shown a code
/// for a flow that is about to fail.
///
/// ## What it does not do
///
/// It does not store what it obtains. A device sign-in that should outlive the process hands
/// the `TokenResponse` to whatever keeps credentials; for the access token alone — a sign-in
/// gate that introspects it and lets it go — there is nothing to keep.
public struct DeviceAuthorizationClient: Sendable {

    private let deviceAuthorizationEndpoint: URL
    private let tokenEndpoint: URL
    private let configuration: ProviderConfiguration
    private let credentials: ClientCredentials
    private let transport: any DeviceAuthorizationTransport

    /// Creates a client for one provider's device grant.
    ///
    /// - Parameters:
    ///   - configuration: The provider. Its ``ProviderConfiguration/deviceAuthorizationEndpoint``
    ///     and ``ProviderConfiguration/tokenEndpoint`` are where the two requests go; its
    ///     ``ProviderConfiguration/scope`` is what is asked for, omitted when empty; its
    ///     ``ProviderConfiguration/resource`` travels on both requests; and its
    ///     ``ProviderConfiguration/authenticationMethod`` authenticates both.
    ///   - credentials: The client's identifier, and its secret if it is confidential. A
    ///     public client passes an empty secret and a configuration whose method is `.none`.
    ///   - transport: How the requests reach the network. Injectable so tests never touch it.
    /// - Throws: ``DeviceGrantConfigurationError`` if there is no device authorization endpoint
    ///   or either endpoint is not HTTPS.
    public init(
        configuration: ProviderConfiguration,
        credentials: ClientCredentials,
        transport: any DeviceAuthorizationTransport = URLSessionTokenTransport()
    ) throws {
        guard let deviceAuthorizationEndpoint = configuration.deviceAuthorizationEndpoint else {
            throw DeviceGrantConfigurationError.noDeviceAuthorizationEndpoint(
                provider: configuration.identifier)
        }
        for endpoint in [deviceAuthorizationEndpoint, configuration.tokenEndpoint] {
            // Compared lowercased: RFC 3986 §3.1 makes the scheme case-insensitive.
            guard endpoint.scheme?.lowercased() == "https" else {
                throw DeviceGrantConfigurationError.insecureEndpoint(endpoint)
            }
        }
        self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
        self.tokenEndpoint = configuration.tokenEndpoint
        self.configuration = configuration
        self.credentials = credentials
        self.transport = transport
    }

    // MARK: - The three steps

    /// Asks for a device code and a user code — RFC 8628 §3.1.
    ///
    /// §3.1 asks that this be done "only when prompted by the user and not automatically", so
    /// it is a call a caller makes when someone has asked to sign in, not one made at launch.
    ///
    /// - Returns: The codes and where to send the user, checked as the type's discussion
    ///   describes.
    /// - Throws: `OAuthError` for a refusal the server explained, or
    ///   `OAuthError.serverError(_:)` naming the field of a response that cannot be shown or
    ///   polled; ``OAuthRedirectRefused``, ``OAuthResponseTooLarge``, or a transport error.
    public func requestDeviceAuthorization() async throws -> DeviceAuthorizationResponse {
        var parameters: [String: String] = [:]
        // §3.1: "Parameters sent without a value MUST be treated as if they were omitted", so
        // an empty scope is omitted here rather than sent for the server to discard.
        if !configuration.scope.isEmpty {
            parameters["scope"] = configuration.scope
        }
        // RFC 8707 names the authorization request and the token request; this request is the
        // device grant's authorization request. §3.1 has a server "ignore unrecognized request
        // parameters", so a server that does not implement resource indicators is unaffected.
        if let resource = configuration.resourceParameter {
            parameters["resource"] = resource
        }

        let response = try await transport.requestDeviceAuthorization(
            endpoint: deviceAuthorizationEndpoint,
            parameters: parameters,
            credentials: credentials,
            method: configuration.authenticationMethod)
        return try Self.checked(response)
    }

    /// One attempt to redeem a device code at the token endpoint — RFC 8628 §3.4.
    ///
    /// The closure ``DeviceFlow/poll(interval:expiresIn:sleeper:elapsed:redeem:)`` takes as
    /// `redeem`. Called once it answers either with tokens or with the error the server
    /// returned, `authorization_pending` and `slow_down` included; deciding what those mean is
    /// the loop's job.
    ///
    /// - Parameter deviceCode: The `DeviceAuthorizationResponse.deviceCode` to redeem.
    /// - Returns: The tokens, once the user has approved.
    /// - Throws: `OAuthError` for whatever the token endpoint answered, or a transport error.
    public func redeem(deviceCode: String) async throws -> TokenResponse {
        var parameters = [
            "grant_type": GrantType.deviceCode.rawValue,
            "device_code": deviceCode
        ]
        if let resource = configuration.resourceParameter {
            parameters["resource"] = resource
        }
        return try await transport.exchange(
            endpoint: tokenEndpoint,
            parameters: parameters,
            credentials: credentials,
            method: configuration.authenticationMethod)
    }

    /// Polls until the user answers, the code dies, or its lifetime passes — RFC 8628 §3.5.
    ///
    /// ``DeviceFlow/poll(interval:expiresIn:sleeper:elapsed:redeem:)`` with this client's
    /// ``redeem(deviceCode:)``, at the interval and for the lifetime `authorization` states.
    ///
    /// - Parameters:
    ///   - authorization: What ``requestDeviceAuthorization()`` returned.
    ///   - sleeper: How to wait between polls.
    ///   - elapsed: How long it has been since `authorization` was received.
    /// - Returns: The tokens.
    /// - Throws: What ``DeviceFlow/poll(interval:expiresIn:sleeper:elapsed:redeem:)`` throws.
    public func poll(
        _ authorization: DeviceAuthorizationResponse,
        sleeper: any DeviceFlowSleeper = TaskSleeper(),
        elapsed: @escaping @Sendable () async -> TimeInterval
    ) async throws -> TokenResponse {
        let deviceCode = authorization.deviceCode
        return try await DeviceFlow.poll(
            interval: authorization.interval,
            expiresIn: authorization.expiresIn,
            sleeper: sleeper,
            elapsed: elapsed,
            redeem: { try await self.redeem(deviceCode: deviceCode) })
    }

    // MARK: - End to end

    /// Requests a device code, hands it to `present`, then polls for tokens.
    ///
    /// `present` is where the caller shows the user `DeviceAuthorizationResponse.userCode`
    /// and `DeviceAuthorizationResponse.verificationURI` — or
    /// `DeviceAuthorizationResponse.verificationURIComplete` as a QR code. It is called once,
    /// with the checked response, and polling begins when it returns. If it throws, nothing is
    /// polled and its error is what this throws: a user who dismissed the prompt has nobody
    /// to wait for.
    ///
    /// - Parameters:
    ///   - sleeper: How to wait between polls. Defaults to sleeping for real.
    ///   - elapsed: How long it has been since the device authorization response arrived. When
    ///     `nil`, measured on a monotonic clock from that moment — not from when `present`
    ///     returns, since the code's lifetime started when it was issued.
    ///   - present: Shows the user what to do.
    /// - Returns: The tokens.
    /// - Throws: Whatever ``requestDeviceAuthorization()``, `present` or
    ///   ``poll(_:sleeper:elapsed:)`` threw.
    public func signIn(
        sleeper: any DeviceFlowSleeper = TaskSleeper(),
        elapsed: (@Sendable () async -> TimeInterval)? = nil,
        present: @Sendable (DeviceAuthorizationResponse) async throws -> Void
    ) async throws -> TokenResponse {
        let authorization = try await requestDeviceAuthorization()
        let clock = ContinuousClock()
        let received = clock.now
        try await present(authorization)
        return try await poll(
            authorization,
            sleeper: sleeper,
            elapsed: elapsed ?? { Self.seconds(received.duration(to: clock.now)) })
    }

    // MARK: - What the server said

    /// The response, if it can be shown to a person and polled; otherwise the server's error.
    ///
    /// - Parameter response: What the device authorization endpoint returned.
    /// - Returns: The same response.
    /// - Throws: `OAuthError.serverError(_:)` naming the first unusable field.
    static func checked(_ response: DeviceAuthorizationResponse) throws -> DeviceAuthorizationResponse {
        guard !response.deviceCode.isEmpty else { throw unusable("device_code") }
        guard isDisplayable(response.userCode) else { throw unusable("user_code") }
        guard isSecureAbsolute(response.verificationURI) else { throw unusable("verification_uri") }
        if let complete = response.verificationURIComplete {
            guard isSecureAbsolute(complete) else { throw unusable("verification_uri_complete") }
        }
        try DeviceFlow.requireUsable(response.expiresIn, field: "expires_in")
        try DeviceFlow.requireUsable(response.interval, field: "interval")
        return response
    }

    /// Whether a user code can be printed for a person to read and type.
    ///
    /// Non-empty, with no control characters (an escape sequence on a terminal), no format
    /// characters (a bidirectional override, a zero-width joiner), and no line or paragraph
    /// separators. RFC 8628 §6.1 recommends a code drawn from a small, unambiguous character
    /// set; this does not impose one, only refuses what cannot be displayed as itself.
    private static func isDisplayable(_ code: String) -> Bool {
        guard !code.isEmpty else { return false }
        return code.unicodeScalars.allSatisfy { scalar in
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator: return false
            default: return true
            }
        }
    }

    /// Whether a verification URI is an absolute `https` URL with a host.
    private static func isSecureAbsolute(_ url: URL) -> Bool {
        guard let host = url.host, !host.isEmpty else { return false }
        return url.scheme?.lowercased() == "https"
    }

    /// The error for a device authorization response that cannot be shown or polled.
    ///
    /// `server_error`, for the reason ``DeviceFlow`` gives: the request was fine and the
    /// answer was not, and asking again is the one thing that might yield a usable one.
    private static func unusable(_ field: String) -> OAuthError {
        .serverError(
            "The authorization server's device authorization response has a \(field) that "
            + "cannot be shown to the user or used.")
    }

    /// A duration as seconds.
    private static func seconds(_ duration: Duration) -> TimeInterval {
        let (whole, fraction) = duration.components
        return TimeInterval(whole) + TimeInterval(fraction) / 1e18
    }
}
