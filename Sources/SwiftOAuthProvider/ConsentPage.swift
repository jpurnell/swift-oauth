import Foundation
import SwiftOAuthCore

/// A field on the consent page where the approver proves who they are.
///
/// A deployment that has to know *who* approved asks for it on the page itself, which is what a
/// person expects, rather than leaving it to a browser's own credential dialog, which says nothing
/// about what is being approved or why. The host decides what the secret is and checks it; this
/// type only describes the field.
///
/// Everything here is plain text and is escaped when rendered. A host passes words, never markup.
public struct ConsentSignIn: Sendable, Equatable {

    /// The form field's name: the host reads the secret from the submitted form under this name.
    /// Distinct from every field the consent form already carries.
    public static let fieldName = "owner_secret"

    /// The username field's name. The field is for a password manager's benefit: the form carries it, but nothing
    /// reads it, because who is approving is the host's own configuration and never a form field. Distinct from
    /// every field the consent form already carries.
    public static let usernameFieldName = "owner_username"

    /// The field's visible label, e.g. `Owner secret`.
    public let label: String

    /// One line telling the person where to find what to type.
    public let hint: String

    /// Why the last attempt failed, shown above the field; `nil` on a first visit.
    public let errorMessage: String?

    /// The account the secret belongs to, shown read-only ahead of the secret field, or `nil` for none.
    ///
    /// A password manager keys a saved credential on a username and a password in the same form; a lone password
    /// field gives it nothing to key on, so it neither offers to save the secret nor fills it next time. This is
    /// the account name the manager will record (for example `owner`). It is not typed, not required, and not
    /// trusted: the approver ignores it.
    public let username: String?

    /// A passkey button to show beside the secret field, or `nil` for none (the default).
    ///
    /// The secret field stays: it is the fallback when a device has no passkey, and the recovery for a lost one.
    public let passkey: PasskeyPrompt?

    /// Creates a sign-in field.
    ///
    /// - Parameters:
    ///   - label: The visible label.
    ///   - hint: Where to find the secret.
    ///   - errorMessage: Why the previous attempt failed, if it did.
    ///   - username: The account name to show read-only so a password manager can save and fill the secret.
    ///   - passkey: Where the passkey ceremony is, to show a passkey button, or `nil` for none.
    public init(label: String, hint: String, errorMessage: String? = nil, username: String? = nil, passkey: PasskeyPrompt? = nil) {
        self.label = label
        self.hint = hint
        self.errorMessage = errorMessage
        self.username = username
        self.passkey = passkey
    }
}

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

    /// A field for the approver to sign in on this page, or `nil` for none (the default).
    public let signIn: ConsentSignIn?

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
    ///   - signIn: A field asking the approver for a secret, or `nil` for none
    public init(
        clientName: String,
        clientId: String,
        scope: String?,
        redirectUri: String,
        state: String?,
        csrfToken: String,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        resource: String? = nil,
        signIn: ConsentSignIn? = nil
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
        self.signIn = signIn
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

        var signInHTML = ""
        if let signIn {
            let error = signIn.errorMessage.map {
                "<div class=\"error\" role=\"alert\">\(escapeHTML($0))</div>"
            } ?? ""
            let focus = signIn.errorMessage == nil ? "" : " autofocus"
            // Ahead of the password field and inside the same form, so a password manager sees the pair.
            let usernameName = ConsentSignIn.usernameFieldName
            let usernameHTML = signIn.username.map { account in
                let input = "<input type=\"text\" id=\"\(usernameName)\" name=\"\(usernameName)\" "
                    + "value=\"\(escapeHTML(account))\" autocomplete=\"username\" readonly>"
                return "<label for=\"\(usernameName)\">Account</label>\n                " + input
            } ?? ""
            let passkeyHTML = signIn.passkey.map { prompt in
                let binding = ConsentPasskeyBinding.make(clientID: clientId, redirectURI: redirectUri, csrfToken: csrfToken)
                return """
                <div class="passkey" id="passkey" hidden data-base="\(escapeHTML(prompt.base))" data-binding="\(escapeHTML(binding))">
                    <input type="hidden" id="\(PasskeyPrompt.fieldName)" name="\(PasskeyPrompt.fieldName)" value="">
                    <button type="button" id="passkey-approve" class="approve-btn">Approve with a passkey</button>
                    <div class="hint" id="passkey-status" role="status"></div>
                </div>
                """
            } ?? ""
            signInHTML = """
            <div class="signin">
                \(error)
                \(passkeyHTML)
                \(usernameHTML)
                <label for="\(ConsentSignIn.fieldName)">\(escapeHTML(signIn.label))</label>
                <input type="password" id="\(ConsentSignIn.fieldName)" name="\(ConsentSignIn.fieldName)" \
            autocomplete="current-password" required\(focus)>
                <div class="hint">\(escapeHTML(signIn.hint))</div>
            </div>
            """
        }

        // Only a page with a passkey button carries its rules, so a deployment without one renders exactly what it did.
        let passkeyStyle = signIn?.passkey == nil ? "" : ".passkey { margin-bottom: 16px; } .passkey button { width: 100%; }"
        let scriptTags = signIn?.passkey.map {
            "<script src=\"\(escapeHTML($0.libraryPath))\"></script>\n    <script src=\"\(escapeHTML($0.wiringPath))\"></script>"
        } ?? ""

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
                .signin {
                    margin-top: 24px;
                }
                .signin label {
                    display: block;
                    font-weight: 600;
                    margin-bottom: 6px;
                }
                .signin input[type=password] {
                    width: 100%;
                    padding: 10px 12px;
                    font-size: 16px;
                    border: 1px solid #d1d5db;
                    border-radius: 8px;
                }
                .signin .hint {
                    font-size: 13px;
                    color: #666;
                    margin-top: 6px;
                }
                .signin .error {
                    background: #fef2f2;
                    color: #b91c1c;
                    border-radius: 8px;
                    padding: 10px 12px;
                    margin-bottom: 12px;
                    font-size: 14px;
                }
                \(passkeyStyle)
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

                    \(signInHTML)

                    <div class="buttons">
                        <button type="submit" name="action" value="deny" class="deny-btn" formnovalidate>
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
            \(scriptTags)
        </body>
        </html>
        """
    }

    /// Escapes HTML special characters to prevent XSS
    ///
    /// - Parameter string: The string to escape
    /// - Returns: HTML-safe string
    private func escapeHTML(_ string: String) -> String {
        Self.htmlEscaped(string)
    }

    /// Escapes HTML special characters, for every page this package renders.
    ///
    /// - Parameter string: The string to escape
    /// - Returns: HTML-safe string
    static func htmlEscaped(_ string: String) -> String {
        return string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
