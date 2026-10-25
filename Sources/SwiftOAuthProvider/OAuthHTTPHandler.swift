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
/// - `/token` - Token endpoint, including the device grant (RFC 8628 §3.4)
/// - the device authorization endpoint (RFC 8628 §3.1), at whatever path
///   ``ServedCapabilities/deviceAuthorization`` names
/// - `/device` - Where a user enters a device's code (RFC 8628 §3.3)
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
            codeChallengeMethod: queryParams["code_challenge_method"],
            resource: queryParams["resource"]
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
                codeChallengeMethod: request.codeChallengeMethod,
                resource: request.resource
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
                return jsonErrorResponse("invalid_request", "Invalid redirect_uri")
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
    /// - Parameters:
    ///   - formParams: URL-encoded form parameters
    ///   - subject: Who is approving — the user the deployment authenticated for this request.
    ///     Carried onto the tokens as `sub`. Taken from the caller and never from the form,
    ///     which the browser controls. `nil` issues tokens naming nobody.
    /// - Returns: Redirect with authorization code (approve) or error (deny)
    public func handleConsentSubmission(
        formParams: [String: String], subject: String? = nil
    ) async -> OAuthHTTPResponse {
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
            return await handleApproveAction(
                formParams: formParams, clientId: clientId, redirectUri: redirectUri,
                state: state, subject: subject)

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

    private func handleApproveAction(
        formParams: [String: String], clientId: String, redirectUri: String, state: String?,
        subject: String?
    ) async -> OAuthHTTPResponse {
        let request = AuthorizationRequest(
            responseType: "code",
            clientId: clientId,
            redirectUri: redirectUri,
            scope: formParams["scope"],
            state: state,
            codeChallenge: formParams["code_challenge"],
            codeChallengeMethod: formParams["code_challenge_method"],
            resource: formParams["resource"]
        )

        do {
            let response = try await server.handleAuthorizationRequest(request, subject: subject)
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
            body: Self.errorBody(code: error, description: description)
        )
    }

    /// The body of an error response — RFC 6749 §5.2.
    ///
    /// Encoded, never assembled from a string literal. Interpolating a description between
    /// two quotes is correct for exactly as long as no description contains one, and the code
    /// that does it cannot say whether that holds. Sorted keys, so the same error is the same
    /// bytes on every run.
    ///
    /// - Parameters:
    ///   - code: The `error` field.
    ///   - description: The `error_description` field.
    /// - Returns: A JSON object carrying both.
    static func errorBody(code: String, description: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        do {
            let data = try encoder.encode(
                OAuthErrorResponse(error: code, errorDescription: description))
            return String(decoding: data, as: UTF8.self)
        } catch {
            // Two strings cannot fail to encode. If that stops being true the response still
            // has to be valid JSON, so it is a constant rather than anything built from the
            // values that could not be encoded.
            #if canImport(os)
            Logger(subsystem: "com.swiftoauth.provider", category: "OAuthHTTPHandler")
                .error("Error body not encodable: \(error.localizedDescription, privacy: .public)")
            #endif
            return unencodableErrorBody
        }
    }

    /// What is sent if an error body cannot be encoded: a literal, with nothing spliced in.
    private static let unencodableErrorBody = #"{"error":"server_error"}"#

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

        // RFC 6749 §2.3.1: `client_secret_basic` puts the id in the header, so a request
        // authenticating that way carries no `client_id` parameter to read. The helper below
        // existed and said exactly this; the introspection endpoint called it and this one did
        // not, so the spec-conformant request was the one that got `invalid_request`.
        guard let grantType = params["grant_type"],
              let clientId = params["client_id"] ?? Self.clientId(fromBasic: authHeader) else {
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
                resource: Self.formValues(for: "resource", in: body).compactMap { URL(string: $0) },
                scope: params["scope"],
                deviceCode: params["device_code"]
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
            return tokenEndpointErrorResponse(error)
        } catch {
            #if canImport(os)
            logger.debug("OAuth error: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError("Token request failed"))
        }
    }

    /// An error from the token endpoint, or from the device authorization endpoint.
    ///
    /// As ``errorResponse(_:)``, except that `access_denied` is a 400. RFC 8628 §3.5 returns it
    /// from the token endpoint in RFC 6749 §5.2's error response, which is a 400; the 403 the
    /// shared mapping uses is for a refusal with no specified status, and a device client
    /// reading a 403 here would be reading a shape the RFC never gives it.
    private func tokenEndpointErrorResponse(_ error: OAuthError) -> OAuthHTTPResponse {
        guard case .accessDenied = error else { return errorResponse(error) }
        return OAuthHTTPResponse(
            statusCode: 400,
            contentType: "application/json",
            body: Self.errorBody(
                code: error.code, description: error.detail ?? error.standardDescription),
            headers: Self.uncached)
    }

    /// RFC 6749 §5.1 and RFC 8628 §3.2: a response carrying a credential is not cached.
    private static let uncached = ["Cache-Control": "no-store", "Pragma": "no-cache"]

    // MARK: - Device Authorization Endpoint (RFC 8628 §3.1)

    /// Handles a POST to the device authorization endpoint — RFC 8628 §3.1 and §3.2.
    ///
    /// The client authenticates exactly as at the token endpoint (§3.1 applies RFC 6749
    /// §3.2.1): a public client names itself with `client_id`, a confidential one presents its
    /// secret. Then the deployment must serve the grant and the client must be registered for
    /// it. The answer is §3.2's JSON — `device_code`, `user_code`, `verification_uri`,
    /// `verification_uri_complete`, `expires_in` and `interval` — and is not cached, because
    /// the device code is a bearer credential until redeemed.
    ///
    /// - Parameters:
    ///   - body: The URL-encoded form body: `client_id` (unless authenticating with Basic) and
    ///     optionally `scope`.
    ///   - authHeader: The `Authorization` header, for a confidential client.
    /// - Returns: The §3.2 response, or an RFC 6749 §5.2 error: `invalid_client` (401),
    ///   `unauthorized_client`, `unsupported_grant_type` or `invalid_scope` (400).
    public func handleDeviceAuthorizationRequest(
        body: String, authHeader: String?
    ) async -> OAuthHTTPResponse {
        let params = parseFormBody(body)
        guard let clientId = params["client_id"] ?? Self.clientId(fromBasic: authHeader) else {
            return errorResponse(.invalidClient(nil))
        }

        do {
            let authenticated = try await server.authenticateClient(
                clientId: clientId, authHeader: authHeader,
                bodyClientSecret: params["client_secret"])
            guard authenticated else {
                return errorResponse(.invalidClient(nil))
            }

            let response = try await server.requestDeviceAuthorization(
                clientId: clientId, scope: params["scope"])
            let encoded = try JSONEncoder().encode(response)
            return OAuthHTTPResponse(
                statusCode: 200,
                contentType: "application/json",
                body: String(decoding: encoded, as: UTF8.self),
                headers: Self.uncached)
        } catch let error as OAuthError {
            #if canImport(os)
            logger.debug("Device authorization refused: \(error.code, privacy: .public)")
            #endif
            return tokenEndpointErrorResponse(error)
        } catch {
            #if canImport(os)
            logger.error("Unexpected error handling device authorization: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError(nil))
        }
    }

    // MARK: - Device Verification (RFC 8628 §3.3)

    /// What a verification CSRF token is issued for, in the place a consent token names a
    /// client. Its other half is the user's subject, so a token one user fetched cannot be
    /// spent as another.
    private static let verificationCSRFPurpose = "urn:swift-oauth:device-verification"

    /// Handles a GET of `/device` — the page where a user enters a device's code.
    ///
    /// **The deployment authenticates the user first** and passes who they are as `subject`:
    /// this package authenticates no user, and approving a device hands it a session in that
    /// user's name. The page carries a CSRF token bound to that subject, so a form posted from
    /// elsewhere — the forged-approval attack, which would hand the attacker's device the
    /// victim's session — fails unless it was loaded by the same user.
    ///
    /// - Parameters:
    ///   - queryParams: The query, which may carry `user_code` from
    ///     `verification_uri_complete` (§3.3.1). It is shown only if it is a well-formed code.
    ///   - subject: The user the deployment authenticated.
    /// - Returns: The entry form, uncached and not to be framed.
    public func handleDeviceVerificationPage(
        queryParams: [String: String], subject: String
    ) async -> OAuthHTTPResponse {
        let prefill = queryParams["user_code"].flatMap(TokenGenerator.normalizedUserCode)
        return await verificationPage(.entry(prefill: prefill, message: nil), subject: subject)
    }

    /// Handles a POST to `/device` — the user continuing, approving or denying.
    ///
    /// Three actions, each from the page the one before rendered:
    ///
    /// - `confirm` — look the code up and show which client is asking, and for what (§5.4),
    ///   with *Approve* and *Deny*. Nothing is approved.
    /// - `approve` — the device's next poll collects tokens whose `sub` is `subject`.
    /// - `deny` — the device's next poll is `access_denied`.
    ///
    /// Every action needs the CSRF token the previous page carried, issued to this same
    /// subject and unused. A code that matches nothing live is one answer whatever the reason,
    /// and counts towards the user's limit of wrong codes (§5.1).
    ///
    /// - Parameters:
    ///   - formParams: The posted form: `action`, `user_code` and `csrf_token`.
    ///   - subject: The user the deployment authenticated — never a form field, which the
    ///     browser controls.
    /// - Returns: The next page: 200 for a step that succeeded; 400 for a stale form, an
    ///   unknown action, or a code that matched nothing; 429 while the user is throttled.
    public func handleDeviceVerificationSubmission(
        formParams: [String: String], subject: String
    ) async -> OAuthHTTPResponse {
        guard let csrf = formParams["csrf_token"], let action = formParams["action"] else {
            return await verificationPage(
                .entry(prefill: nil, message: "That form was incomplete. Enter the code again."),
                subject: subject, status: 400)
        }
        do {
            let check = try await server.validateCSRFToken(
                token: csrf, clientId: Self.verificationCSRFPurpose, redirectUri: subject)
            guard check.isValid else {
                return await verificationPage(
                    .entry(prefill: nil, message: "That form has expired. Enter the code again."),
                    subject: subject, status: 400)
            }
        } catch {
            #if canImport(os)
            logger.error("Device verification CSRF check failed: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError(nil))
        }

        let userCode = formParams["user_code"] ?? ""
        do {
            switch action {
            case "confirm":
                let pending = try await server.pendingDeviceAuthorization(
                    userCode: userCode, subject: subject)
                return await verificationPage(.confirmation(pending), subject: subject)
            case "approve":
                try await server.approveDeviceCode(userCode: userCode, subject: subject)
                return await verificationPage(.finished(approved: true), subject: subject)
            case "deny":
                try await server.denyDeviceCode(userCode: userCode, subject: subject)
                return await verificationPage(.finished(approved: false), subject: subject)
            default:
                return await verificationPage(
                    .entry(prefill: nil, message: "Enter the code shown on your device."),
                    subject: subject, status: 400)
            }
        } catch let error as OAuthError {
            // The code the user typed is not logged: it is short, and a log of failed codes is
            // a list of guesses to try elsewhere.
            #if canImport(os)
            logger.debug("Device verification refused: \(error.code, privacy: .public)")
            #endif
            let throttled: Bool
            if case .slowDown = error { throttled = true } else { throttled = false }
            return await verificationPage(
                .entry(
                    prefill: nil,
                    message: error.detail ?? "That code is not valid, or has expired."),
                subject: subject, status: throttled ? 429 : 400)
        } catch {
            #if canImport(os)
            logger.error("Unexpected error handling device verification: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError(nil))
        }
    }

    /// Renders a verification stage with a fresh CSRF token bound to `subject`.
    private func verificationPage(
        _ stage: DeviceVerificationPage.Stage, subject: String, status: Int = 200
    ) async -> OAuthHTTPResponse {
        let csrf: String
        do {
            // The finished page has no form, so it is issued no token to leave unspent.
            if case .finished = stage {
                csrf = ""
            } else {
                csrf = try await server.generateCSRFToken(
                    clientId: Self.verificationCSRFPurpose, redirectUri: subject)
            }
        } catch {
            #if canImport(os)
            logger.error("Device verification CSRF token not stored: \(error.localizedDescription, privacy: .public)")
            #endif
            return errorResponse(.serverError(nil))
        }
        return OAuthHTTPResponse(
            statusCode: status,
            contentType: "text/html; charset=utf-8",
            body: DeviceVerificationPage(stage: stage, csrfToken: csrf).render(),
            // Uncached, because it carries a CSRF token; not framed, because a page that hands
            // a device a session behind one button is what clickjacking is for.
            headers: Self.uncached.merging([
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "frame-ancestors 'none'"
            ]) { current, _ in current })
    }

    // MARK: - Token Validation

    /// Which audiences a resource server will honour — RFC 8707's second half.
    ///
    /// Binding an audience onto a token accomplishes nothing on its own. The binding is a claim
    /// about where the token may be spent, and it does no work until somebody refuses a token
    /// spent elsewhere. That refusal belongs here rather than in every consumer, for the reason
    /// ``OAuthHTTPHandler/validateBearerToken(authHeader:acceptingAudiences:)`` already applies
    /// to bound tokens: the caller is asking whether to honour this token, and this package
    /// knows the answer better than the caller does. It holds the deployment's own identity.
    public enum AcceptedAudiences: Sendable, Hashable {

        /// Honour only tokens minted for this deployment, and tokens bound to no audience.
        ///
        /// The default, and the reason it is the default: the alternative is safe only when a
        /// consumer knows that a successful validation does not mean the token was meant for
        /// it. Every consumer would have to write this comparison, and the one who has not read
        /// the RFC 8707 notes is exactly the one it protects.
        ///
        /// An unbound token — `audience == nil` — is honoured. That is the permissive contract
        /// ``TokenValidationResult/ValidatedToken/audience`` documents rather than a mismatch:
        /// a deployment that has not adopted resource indicators issues tokens bound to
        /// nothing, and refusing them would break it on upgrade.
        case ownResource

        /// Honour any audience, leaving the comparison to the caller.
        ///
        /// For a gateway that legitimately holds tokens for other resources. Named rather than
        /// arrived at: honouring a foreign token is a decision, and it should look like one at
        /// the call site.
        case any
    }

    /// Validates an access token from the Authorization header.
    ///
    /// Refuses a token that is expired, revoked, unknown, bound to a key or certificate (those
    /// are not bearer tokens), or **minted for another resource**.
    ///
    /// - Parameters:
    ///   - authHeader: The Authorization header value.
    ///   - acceptingAudiences: Which audiences to honour. Defaults to ``AcceptedAudiences/ownResource``.
    /// - Returns: Validation result.
    public func validateBearerToken(
        authHeader: String?,
        acceptingAudiences: AcceptedAudiences = .ownResource
    ) async -> TokenValidationResult {
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
            if case .valid(let validated) = result {
                if validated.keyThumbprint != nil {
                    return .invalid(
                        reason: "This token is bound to a key and must be presented with the "
                            + "DPoP scheme, with a proof — not as a bearer token.")
                }
                // The audience is a claim about where this token may be spent, and until
                // something refuses a token spent elsewhere it is decoration. Compared against
                // what this deployment *advertises* rather than against the issuer: those are
                // the same string only for a colocated deployment, and assuming they are equal
                // is the defect `ResourceIdentity` exists to prevent — it would refuse a
                // correct token at any resource server whose authorization server is elsewhere.
                if case .ownResource = acceptingAudiences,
                   let audience = validated.audience {
                    let ours = await server.getProtectedResourceMetadata().resource
                    if audience.absoluteString != ours {
                        return .invalid(
                            reason: "This token was issued for \(audience.absoluteString) and "
                                + "this resource is \(ours). Obtain a token naming this "
                                + "resource in the `resource` parameter (RFC 8707).")
                    }
                }
                if validated.certificateThumbprint != nil {
                    // RFC 8705 §3: the same failure with a different key. Accepting it here
                    // accepts it without the certificate being checked, and the binding is
                    // gone with nothing to show for it.
                    return .invalid(
                        reason: "This token is bound to a client certificate and is only valid "
                            + "on a mutually-authenticated connection presenting it.")
                }
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
        // logging: an OAuth error *is* the response; nothing is discarded by converting it
        } catch let error as OAuthError {
            return errorResponse(error)
        } catch {
            // An error that is not an `OAuthError` is one this handler did not anticipate, and
            // the client is told only `server_error` — correctly, since the detail is not
            // theirs to see. Logged so the operator has the one copy that exists.
            #if canImport(os)
            logger.error("Unexpected error handling introspection: \(error.localizedDescription, privacy: .public)")
            #endif
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
        case .invalidClientMetadata:
            // RFC 7591 §3.2.2 specifies 400 for a refused registration.
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

        return OAuthHTTPResponse(
            statusCode: statusCode,
            contentType: "application/json",
            body: Self.errorBody(
                code: error.code, description: error.detail ?? error.standardDescription))
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
