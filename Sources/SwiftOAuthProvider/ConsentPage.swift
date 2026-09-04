import Foundation
import SwiftOAuthCore

/// OAuth consent page HTML generator
///
/// Renders an HTML page for user consent during OAuth authorization flow.
/// The page displays the requesting client's name, requested scopes,
/// and provides Approve/Deny buttons.
///
/// ## Security Features
/// - CSRF token protection against cross-site request forgery
/// - HTML escaping to prevent XSS attacks
/// - All form parameters are properly encoded
///
/// ## Example
///
/// ```swift
/// let page = ConsentPage(
///     clientName: "My MCP Client",
///     clientId: "client-123",
///     scope: "mcp:tools mcp:resources",
///     redirectUri: "http://localhost:8080/callback",
///     state: "random-state",
///     csrfToken: "csrf-token-xyz",
///     codeChallenge: nil,
///     codeChallengeMethod: nil
/// )
/// let html = page.render()
/// ```
public struct ConsentPage: Sendable {

    /// Name of the client application requesting access
    public let clientName: String

    /// Unique identifier for the client
    public let clientId: String

    /// Space-separated list of requested scopes
    public let scope: String?

    /// Redirect URI for the authorization response
    public let redirectUri: String

    /// OAuth state parameter (preserved across the flow)
    public let state: String?

    /// CSRF token for form submission
    public let csrfToken: String

    /// PKCE code challenge (optional)
    public let codeChallenge: String?

    /// PKCE code challenge method (optional, typically "S256")
    public let codeChallengeMethod: String?

    /// The resource the eventual token is for — RFC 8707.
    ///
    /// Rendered as a hidden field because the browser posts what this page contains, not what
    /// the original authorization request held. A resource that reaches the consent page and
    /// not the form is a resource the user's approval drops, and the flow then fails at the
    /// token endpoint — or worse, succeeds with no audience under a permissive policy.
    public let resource: String?

    /// Creates a new consent page
    ///
    /// - Parameters:
    ///   - clientName: Display name of the requesting application
    ///   - clientId: Client identifier
    ///   - scope: Requested scopes (space-separated)
    ///   - redirectUri: Where to redirect after consent
    ///   - state: OAuth state parameter
    ///   - csrfToken: Token for form protection
    ///   - codeChallenge: PKCE challenge
    ///   - codeChallengeMethod: PKCE method
    ///   - resource: The resource indicator to carry through the form — RFC 8707
    public init(
        clientName: String,
        clientId: String,
        scope: String?,
        redirectUri: String,
        state: String?,
        csrfToken: String,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        resource: String? = nil
    ) {
        self.clientName = clientName
        self.clientId = clientId
        self.scope = scope
        self.redirectUri = redirectUri
        self.state = state
        self.csrfToken = csrfToken
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.resource = resource
    }

    /// Renders the consent page as HTML
    ///
    /// - Returns: Complete HTML document as a string
    public func render() -> String {
        let escapedClientName = escapeHTML(clientName)
        let escapedClientId = escapeHTML(clientId)
        let escapedRedirectUri = escapeHTML(redirectUri)
        let escapedCsrfToken = escapeHTML(csrfToken)
        let escapedState = state.map { escapeHTML($0) }
        let escapedScope = scope.map { escapeHTML($0) }
        let escapedCodeChallenge = codeChallenge.map { escapeHTML($0) }
        let escapedCodeChallengeMethod = codeChallengeMethod.map { escapeHTML($0) }
        let escapedResource = resource.map { escapeHTML($0) }

        let scopeItems = (scope ?? "")
            .split(separator: " ")
            .map { "<li>\(escapeHTML(String($0)))</li>" }
            .joined(separator: "\n                    ")

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Authorization Request - MCP Server</title>
            <style>
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background-color: #f5f5f5;
                    color: #333;
                    line-height: 1.6;
                    padding: 20px;
                }
                .container {
                    max-width: 480px;
                    margin: 40px auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 32px;
                }
                h1 {
                    font-size: 24px;
                    margin-bottom: 8px;
                    color: #1a1a1a;
                }
                .subtitle {
                    color: #666;
                    margin-bottom: 24px;
                }
                .client-name {
                    font-weight: 600;
                    color: #2563eb;
                }
                .section {
                    margin-bottom: 24px;
                }
                .section-title {
                    font-size: 14px;
                    font-weight: 600;
                    color: #666;
                    text-transform: uppercase;
                    margin-bottom: 8px;
                }
                .scope-list {
                    list-style: none;
                    padding: 12px;
                    background: #f9fafb;
                    border-radius: 8px;
                }
                .scope-list li {
                    padding: 8px 0;
                    border-bottom: 1px solid #e5e7eb;
                    font-family: monospace;
                    font-size: 14px;
                }
                .scope-list li:last-child {
                    border-bottom: none;
                }
                .buttons {
                    display: flex;
                    gap: 12px;
                    margin-top: 24px;
                }
                button {
                    flex: 1;
                    padding: 12px 24px;
                    font-size: 16px;
                    font-weight: 500;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }
                .approve-btn {
                    background-color: #22c55e;
                    color: white;
                }
                .approve-btn:hover {
                    background-color: #16a34a;
                }
                .deny-btn {
                    background-color: #ef4444;
                    color: white;
                }
                .deny-btn:hover {
                    background-color: #dc2626;
                }
                .warning {
                    font-size: 12px;
                    color: #666;
                    margin-top: 16px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Authorization Request</h1>
                <p class="subtitle">
                    <span class="client-name">\(escapedClientName)</span>
                    is requesting access to your account.
                </p>

                \(scopeItems.isEmpty ? "" : """
                <div class="section">
                    <div class="section-title">Requested Permissions</div>
                    <ul class="scope-list">
                        \(scopeItems)
                    </ul>
                </div>
                """)

                <form method="POST" action="/authorize/consent">
                    <input type="hidden" name="client_id" value="\(escapedClientId)">
                    <input type="hidden" name="redirect_uri" value="\(escapedRedirectUri)">
                    <input type="hidden" name="csrf_token" value="\(escapedCsrfToken)">
                    \(escapedState.map { "<input type=\"hidden\" name=\"state\" value=\"\($0)\">" } ?? "")
                    \(escapedScope.map { "<input type=\"hidden\" name=\"scope\" value=\"\($0)\">" } ?? "")
                    \(escapedCodeChallenge.map { "<input type=\"hidden\" name=\"code_challenge\" value=\"\($0)\">" } ?? "")
                    \(escapedCodeChallengeMethod.map { "<input type=\"hidden\" name=\"code_challenge_method\" value=\"\($0)\">" } ?? "")
                    \(escapedResource.map { "<input type=\"hidden\" name=\"resource\" value=\"\($0)\">" } ?? "")

                    <div class="buttons">
                        <button type="submit" name="action" value="deny" class="deny-btn">
                            Deny
                        </button>
                        <button type="submit" name="action" value="approve" class="approve-btn">
                            Approve
                        </button>
                    </div>
                </form>

                <p class="warning">
                    Only authorize applications you trust.
                </p>
            </div>
        </body>
        </html>
        """
    }

    /// Escapes HTML special characters to prevent XSS
    ///
    /// - Parameter string: The string to escape
    /// - Returns: HTML-safe string
    private func escapeHTML(_ string: String) -> String {
        return string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
