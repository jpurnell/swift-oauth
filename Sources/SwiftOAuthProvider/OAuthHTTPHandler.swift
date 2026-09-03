import Foundation
import SwiftOAuthCore
#if canImport(os)
import os
#endif

/// HTTP request/response handler for OAuth 2.0 endpoints
///
/// Handles HTTP parsing and serialization for OAuth endpoints:
/// - `/.well-known/oauth-protected-resource` - Protected resource metadata (RFC 9728)
/// - `/.well-known/oauth-authorization-server` - Server metadata
/// - `/register` - Client registration
/// - `/authorize` - Authorization endpoint
/// - `/token` - Token endpoint
///
/// This is a stateless handler that delegates to OAuthServer for business logic.
public struct OAuthHTTPHandler: Sendable {

    private let server: OAuthServer

    // `os.Logger` is Apple-only, and this was an unguarded stored property of that type — so
    // the import was conditional and the use was not, and this file did not compile on Linux
    // at all. Matches the pattern in `EncryptedFileClientStorage`.
    #if canImport(os)
    private let logger: Logger
    #endif

    /// Creates a new OAuth HTTP handler
    ///
    /// - Parameter server: The OAuth server to delegate to
    public init(server: OAuthServer) {
        self.server = server
        #if canImport(os)
        self.logger = Logger(subsystem: "com.swiftoauth.provider", category: "OAuthHTTPHandler")
        #endif
    }

    // MARK: - Protected Resource Metadata

    /// Handles GET /.well-known/oauth-protected-resource
    ///
    /// Returns RFC 9728 Protected Resource Metadata so clients can discover
    /// which authorization server protects this resource and which scopes to request.
    ///
    /// - Returns: JSON-encoded protected resource metadata
    public func handleProtectedResourceMetadata() async -> OAuthHTTPResponse {
        let metadata = await server.getProtectedResourceMetadata()

        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(metadata)
            let body = String(data: data, encoding: .utf8) ?? "{}"

            return OAuthHTTPResponse(
                statusCode: 200,
                contentType: "application/json",
                body: body
            )
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError("Failed to encode protected resource metadata"))
        }
    }

    // MARK: - Server Metadata

    /// Handles GET /.well-known/oauth-authorization-server
    ///
    /// - Returns: JSON-encoded server metadata
    public func handleMetadataRequest() async -> OAuthHTTPResponse {
        let metadata = await server.getMetadata()

        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(metadata)
            let body = String(data: data, encoding: .utf8) ?? "{}"

            return OAuthHTTPResponse(
                statusCode: 200,
                contentType: "application/json",
                body: body
            )
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError("Failed to encode metadata"))
        }
    }

    // MARK: - Client Registration

    /// Handles POST /register
    ///
    /// - Parameter body: JSON-encoded ClientRegistrationRequest
    /// - Returns: JSON-encoded ClientRegistrationResponse or error
    public func handleRegistrationRequest(body: String) async -> OAuthHTTPResponse {
        guard let data = body.data(using: .utf8) else {
            return errorResponse(.invalidRequest(nil))
        }

        do {
            let request = try JSONDecoder().decode(ClientRegistrationRequest.self, from: data)
            let response = try await server.registerClient(request)

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted]
            let responseData = try encoder.encode(response)
            let responseBody = String(data: responseData, encoding: .utf8) ?? "{}"

            return OAuthHTTPResponse(
                statusCode: 201,
                contentType: "application/json",
                body: responseBody
            )
        } catch let error as OAuthError {
            #if canImport(os)
            logger.debug("OAuth error: \(error.code, privacy: .public)")
            #endif
            return errorResponse(error)
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.invalidRequest(nil))
        }
    }

    // MARK: - Authorization Endpoint

    /// Handles GET /authorize
    ///
    /// Shows a consent page for the user to approve or deny access.
    ///
    /// - Parameter queryParams: Query parameters from the URL
    /// - Returns: HTML consent page or error response
    public func handleAuthorizationRequest(queryParams: [String: String]) async -> OAuthHTTPResponse {
        guard let responseType = queryParams["response_type"],
              let clientId = queryParams["client_id"],
              let redirectUri = queryParams["redirect_uri"] else {
            return errorResponse(.invalidRequest(nil))
        }

        let request = AuthorizationRequest(
            responseType: responseType,
            clientId: clientId,
            redirectUri: redirectUri,
            scope: queryParams["scope"],
            state: queryParams["state"],
            codeChallenge: queryParams["code_challenge"],
            codeChallengeMethod: queryParams["code_challenge_method"]
        )

        do {
            // Validate the request and get client info
            let client = try await server.validateAuthorizationRequest(request)

            // Generate CSRF token for the consent form
            let csrfToken = try await server.generateCSRFToken(
                clientId: clientId,
                redirectUri: redirectUri
            )

            // Render consent page
            let consentPage = ConsentPage(
                clientName: client.clientName,
                clientId: clientId,
                scope: request.scope,
                redirectUri: redirectUri,
                state: request.state,
                csrfToken: csrfToken,
                codeChallenge: request.codeChallenge,
                codeChallengeMethod: request.codeChallengeMethod
            )

            return OAuthHTTPResponse(
                statusCode: 200,
                contentType: "text/html; charset=utf-8",
                body: consentPage.render()
            )
        } catch let error as OAuthError {
            #if canImport(os)
            logger.debug("OAuth error: \(error.code, privacy: .public)")
            #endif
            // For invalid redirect_uri, we must NOT redirect to it
            // Instead, show an error page directly
            // Matches any `invalid_request`, whatever detail it carries — narrowing this to
            // a nil detail would silently stop catching the redirect case the moment any
            // throw site started explaining itself.
            if case .invalidRequest = error {
                // Check if redirect_uri is invalid (not a registered URI)
                // We return a direct error response
                return OAuthHTTPResponse(
                    statusCode: 400,
                    contentType: "application/json",
                    body: "{\"error\": \"invalid_request\", \"error_description\": \"Invalid redirect_uri\"}"
                )
            }

            return errorResponse(error)
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError("Unexpected error"))
        }
    }

    // MARK: - Consent Submission

    /// Handles POST /authorize/consent
    ///
    /// Processes the user's approval or denial of the authorization request.
    ///
    /// - Parameter formParams: URL-encoded form parameters
    /// - Returns: Redirect with authorization code (approve) or error (deny)
    public func handleConsentSubmission(formParams: [String: String]) async -> OAuthHTTPResponse {
        guard let action = formParams["action"],
              let clientId = formParams["client_id"],
              let redirectUri = formParams["redirect_uri"],
              let csrfToken = formParams["csrf_token"] else {
            return jsonErrorResponse("invalid_request", "Missing required parameters")
        }

        if let validationError = await validateConsentRequest(clientId: clientId, redirectUri: redirectUri, csrfToken: csrfToken) {
            return validationError
        }

        let state = formParams["state"]

        switch action {
        case "deny":
            return buildRedirect(uri: redirectUri, queryItems: [
                URLQueryItem(name: "error", value: "access_denied"),
                URLQueryItem(name: "error_description", value: "User denied the authorization request"),
            ], state: state)

        case "approve":
            return await handleApproveAction(formParams: formParams, clientId: clientId, redirectUri: redirectUri, state: state)

        default:
            return jsonErrorResponse("invalid_request", "Invalid action")
        }
    }

    private func validateConsentRequest(clientId: String, redirectUri: String, csrfToken: String) async -> OAuthHTTPResponse? {
        do {
            let csrfResult = try await server.validateCSRFToken(token: csrfToken, clientId: clientId, redirectUri: redirectUri)
            guard csrfResult.isValid else {
                return jsonErrorResponse("invalid_request", "Invalid or expired csrf token")
            }
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return jsonErrorResponse("invalid_request", "CSRF validation failed")
        }
        do {
            guard let _ = try await server.getClient(clientId: clientId) else {
                return jsonErrorResponse("invalid_client", "Client not found")
            }
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return jsonErrorResponse("server_error", "Failed to verify client")
        }
        return nil
    }

    private func handleApproveAction(formParams: [String: String], clientId: String, redirectUri: String, state: String?) async -> OAuthHTTPResponse {
        let request = AuthorizationRequest(
            responseType: "code",
            clientId: clientId,
            redirectUri: redirectUri,
            scope: formParams["scope"],
            state: state,
            codeChallenge: formParams["code_challenge"],
            codeChallengeMethod: formParams["code_challenge_method"]
        )

        do {
            let response = try await server.handleAuthorizationRequest(request)
            return buildRedirect(uri: redirectUri, queryItems: [
                URLQueryItem(name: "code", value: response.code),
            ], state: response.state)
        } catch let error as OAuthError {
            #if canImport(os)
            logger.debug("OAuth error: \(error.code, privacy: .public)")
            #endif
            var items = [URLQueryItem(name: "error", value: error.code)]
            if let description = error.detail ?? error.standardDescription as String? {
                items.append(URLQueryItem(name: "error_description", value: description))
            }
            let redirect = buildRedirect(uri: redirectUri, queryItems: items, state: state)
            return redirect.statusCode == 302 ? redirect : errorResponse(error)
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError("Authorization failed"))
        }
    }

    private func buildRedirect(uri: String, queryItems: [URLQueryItem], state: String?) -> OAuthHTTPResponse {
        var components = URLComponents(string: uri)
        var items = components?.queryItems ?? []
        items.append(contentsOf: queryItems)
        if let state = state {
            items.append(URLQueryItem(name: "state", value: state))
        }
        components?.queryItems = items
        guard let redirectURL = components?.string else {
            return errorResponse(.serverError("Failed to build redirect URL"))
        }
        return OAuthHTTPResponse(statusCode: 302, contentType: "text/html", body: "", headers: ["Location": redirectURL])
    }

    private func jsonErrorResponse(_ error: String, _ description: String) -> OAuthHTTPResponse {
        OAuthHTTPResponse(
            statusCode: 400,
            contentType: "application/json",
            body: "{\"error\": \"\(error)\", \"error_description\": \"\(description)\"}"
        )
    }

    // MARK: - Token Endpoint

    /// Handles POST /token
    ///
    /// - Parameters:
    ///   - body: URL-encoded form body
    ///   - authHeader: Optional Authorization header for client auth
    /// - Returns: JSON-encoded TokenResponse or error
    public func handleTokenRequest(body: String, authHeader: String?) async -> OAuthHTTPResponse {
        // Parse URL-encoded form body
        let params = parseFormBody(body)

        guard let grantType = params["grant_type"],
              let clientId = params["client_id"] else {
            return errorResponse(.invalidRequest(nil))
        }

        // Authenticate client
        do {
            let authenticated = try await server.authenticateClient(
                clientId: clientId,
                authHeader: authHeader,
                bodyClientSecret: params["client_secret"]
            )

            guard authenticated else {
                return errorResponse(.invalidClient(nil))
            }

            let request = TokenRequest(
                grantType: grantType,
                code: params["code"],
                redirectUri: params["redirect_uri"],
                clientId: clientId,
                clientSecret: params["client_secret"],
                codeVerifier: params["code_verifier"],
                refreshToken: params["refresh_token"],
                // Read separately because it may repeat. A value that is not a URL is dropped
                // rather than rejected here — the policy refuses what it does not know, and it
                // is the one place that decision belongs.
                //
                // SECURITY: parses client-supplied identifiers; nothing is fetched from them.
                resource: Self.formValues(for: "resource", in: body).compactMap { URL(string: $0) }
            )

            let response = try await server.handleTokenRequest(request)

            let encoder = JSONEncoder()
            let responseData = try encoder.encode(response)
            let responseBody = String(data: responseData, encoding: .utf8) ?? "{}"

            return OAuthHTTPResponse(
                statusCode: 200,
                contentType: "application/json",
                body: responseBody,
                headers: [
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache"
                ]
            )
        } catch let error as OAuthError {
            #if canImport(os)
            logger.debug("OAuth error: \(error.code, privacy: .public)")
            #endif
            return errorResponse(error)
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError("Token request failed"))
        }
    }

    // MARK: - Token Validation

    /// Validates an access token from the Authorization header
    ///
    /// - Parameter authHeader: The Authorization header value
    /// - Returns: Validation result
    public func validateBearerToken(authHeader: String?) async -> TokenValidationResult {
        guard let header = authHeader,
              header.lowercased().hasPrefix("bearer ") else {
            return .invalid(reason: "Missing or invalid Authorization header")
        }

        let token = String(header.dropFirst(7))

        do {
            let result = try await server.validateAccessToken(token)

            // A bound token is not a bearer token — RFC 9449 §7.1 gives it its own scheme.
            //
            // Refused here rather than documented, because the alternative fails silently: a
            // server that accepts a bound token at this entry point accepts it *without
            // checking any proof*, the caller sees success, and the binding is gone. Nothing
            // logs, the code compiles, and a search for "DPoP" in that consumer's sources
            // finds nothing — so there is no thread to pull.
            //
            // Every consumer with a `Bearer` path would otherwise have to know that bound
            // tokens exist and write this check themselves, and the consumer who has not read
            // the DPoP notes is exactly the one it protects.
            if case .valid(let validated) = result, validated.keyThumbprint != nil {
                return .invalid(
                    reason: "This token is bound to a key and must be presented with the DPoP "
                        + "scheme, with a proof — not as a bearer token.")
            }
            return result
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return .invalid(reason: "Token validation failed")
        }
    }

    // MARK: - Helpers

    /// Handles a token introspection request — RFC 7662 §2.
    ///
    /// **The endpoint is authenticated, and that is not optional.** §2.1 requires it. Left
    /// open, this endpoint tells anyone whether any string is a live token: it turns a stolen
    /// token into a verified one, and turns guessing into something with a feedback signal.
    /// Authentication is checked before the token is looked at, so an unauthenticated caller
    /// learns nothing about it either way.
    ///
    /// A token that is expired, revoked or unknown answers `200` with `{"active":false}` — not
    /// an error status. RFC 7662 §2.2, and the distinction that matters to every caller: a
    /// dead token is an answer, and answering `401` for one makes callers treat it as a
    /// transport failure.
    ///
    /// - Parameters:
    ///   - body: The URL-encoded form body, carrying `token`.
    ///   - authHeader: The `Authorization` header presented by the caller.
    /// - Returns: The introspection response, or a refusal.
    public func handleIntrospectionRequest(
        body: String, authHeader: String?
    ) async -> OAuthHTTPResponse {
        let params = parseFormBody(body)

        guard let clientId = params["client_id"] ?? Self.clientId(fromBasic: authHeader) else {
            return errorResponse(.invalidClient(nil))
        }

        do {
            let authenticated = try await server.authenticateClient(
                clientId: clientId,
                authHeader: authHeader,
                bodyClientSecret: params["client_secret"]
            )
            guard authenticated else {
                return errorResponse(.invalidClient(nil))
            }

            guard let token = params["token"] else {
                return errorResponse(.invalidRequest(nil))
            }

            let result = try await server.introspect(token: token)
            let encoded = try JSONEncoder().encode(result)
            return OAuthHTTPResponse(
                statusCode: 200,
                contentType: "application/json",
                body: String(decoding: encoded, as: UTF8.self))
        } catch let error as OAuthError {
            return errorResponse(error)
        } catch {
            return errorResponse(.serverError(nil))
        }
    }

    /// The client id inside a Basic credential, when the caller authenticated that way.
    ///
    /// RFC 6749 §2.3.1 puts the id in the header rather than the body for `client_secret_basic`,
    /// so a request authenticating that way carries no `client_id` parameter to read.
    static func clientId(fromBasic authHeader: String?) -> String? {
        guard let authHeader,
              authHeader.lowercased().hasPrefix("basic "),
              let decoded = Data(base64Encoded: String(authHeader.dropFirst("basic ".count))),
              let pair = String(data: decoded, encoding: .utf8),
              let separator = pair.firstIndex(of: ":") else {
            return nil
        }
        return String(pair[pair.startIndex..<separator])
    }

    /// Every value a form body carries for one key, in the order they appear.
    ///
    /// ``parseFormBody(_:)`` keeps one value per key, which is right for the parameters OAuth
    /// defines as singular and wrong for `resource`: RFC 8707 §2 permits it to repeat, and
    /// collapsing a repeat would turn a request naming two resources into a request naming the
    /// last one. The refusal of several distinct resources would then be unreachable from a
    /// real request, and a client asking for two audiences would quietly get a token for one.
    ///
    /// Static so the parsing can be tested without standing up a server.
    static func formValues(for key: String, in body: String) -> [String] {
        body.split(separator: "&").compactMap { pair in
            let keyValue = pair.split(separator: "=", maxSplits: 1)
            guard keyValue.count == 2 else { return nil }
            let name = String(keyValue[0]).removingPercentEncoding ?? String(keyValue[0])
            guard name == key else { return nil }
            return String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])
        }
    }

    private func parseFormBody(_ body: String) -> [String: String] {
        var params: [String: String] = [:]

        for pair in body.split(separator: "&") {
            let keyValue = pair.split(separator: "=", maxSplits: 1)
            if keyValue.count == 2 {
                let key = String(keyValue[0]).removingPercentEncoding ?? String(keyValue[0])
                let value = String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])
                params[key] = value
            }
        }

        return params
    }

    private func errorResponse(_ error: OAuthError) -> OAuthHTTPResponse {
        let statusCode: Int
        switch error {
        case .invalidClient:
            statusCode = 401
        case .invalidRequest, .invalidScope:
            statusCode = 400
        case .authorizationPending, .slowDown, .expiredToken:
            // 400, which RFC 8628 §3.5 specifies even for `authorization_pending` — the
            // expected state of a flow that is working. It reads oddly and it is correct: the
            // specification reuses RFC 6749 §5.2's error response, and that response is a 400.
            // A server answering 200 here would be inventing a shape no client parses.
            statusCode = 400
        case .invalidTarget:
            // 400, alongside the other "your request was wrong" codes. RFC 8707 §2 names the
            // error but not a status, and the resource being unknown is a fact about the
            // request rather than about authentication — a 401 would invite a retry with new
            // credentials that cannot help.
            statusCode = 400
        case .invalidGrant, .unauthorizedClient, .unsupportedGrantType:
            statusCode = 400
        case .serverError:
            statusCode = 500
        case .temporarilyUnavailable:
            // 503, so a client's retry logic can tell "come back later" apart from "you are
            // wrong". RFC 6749 §4.1.2.1 defines this for the authorization endpoint; it maps
            // onto the standard meaning of the status.
            statusCode = 503
        case .accessDenied:
            // The resource owner refused. 403 rather than 401: the request authenticated
            // fine, and answering 401 would invite a client to retry with new credentials
            // that cannot help.
            statusCode = 403
        }

        let body: [String: String] = [
            "error": error.code,
            "error_description": error.detail ?? error.standardDescription
        ]

        do {
            let data = try JSONEncoder().encode(body)
            return OAuthHTTPResponse(
                statusCode: statusCode,
                contentType: "application/json",
                body: String(data: data, encoding: .utf8) ?? "{}"
            )
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return OAuthHTTPResponse(
                statusCode: statusCode,
                contentType: "application/json",
                body: "{\"error\": \"\(error)\"}"
            )
        }
    }
}

// MARK: - OAuth HTTP Response

/// HTTP response from OAuth endpoints
public struct OAuthHTTPResponse: Sendable {
    /// The HTTP status code
    public let statusCode: Int
    /// The Content-Type header value
    public let contentType: String
    /// The response body
    public let body: String
    /// Additional response headers
    public let headers: [String: String]

    /// Creates a new OAuth HTTP response
    public init(
        statusCode: Int,
        contentType: String,
        body: String,
        headers: [String: String] = [:]
    ) {
        self.statusCode = statusCode
        self.contentType = contentType
        self.body = body
        self.headers = headers
    }
}
