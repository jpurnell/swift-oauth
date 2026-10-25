import Foundation

/// The page where a user enters a device's code — RFC 8628 §3.3.
///
/// Three stages, each a form posted back to the same address:
///
/// 1. **Entry.** A field for the code — prefilled when the user arrived by
///    `verification_uri_complete` — and a button to continue.
/// 2. **Confirmation.** Which client is asking and for what, with *Approve* and *Deny*. §5.4's
///    remote-phishing attack is a user approving a code someone else's device is showing them;
///    naming the client is the defence the RFC offers, so the user is shown it before they
///    answer rather than after.
/// 3. **Finished.** What happened, and that they can return to the device.
///
/// Every value that reaches the page is HTML-escaped, and a prefilled code is shown only if it
/// is a well-formed user code, so the address cannot inject markup into the page.
struct DeviceVerificationPage: Sendable {

    /// Which stage to render.
    enum Stage: Sendable {
        /// The code field, optionally prefilled, optionally with a message above it.
        case entry(prefill: String?, message: String?)
        /// The client behind a code, awaiting the user's answer.
        case confirmation(PendingDeviceAuthorization)
        /// The user answered.
        case finished(approved: Bool)
    }

    /// What to render.
    let stage: Stage

    /// The CSRF token the form carries. Unused by ``Stage/finished(approved:)``, which has no
    /// form.
    let csrfToken: String

    /// Renders the page.
    ///
    /// - Returns: A complete HTML document.
    func render() -> String {
        let csrf = ConsentPage.htmlEscaped(csrfToken)
        let content: String
        switch stage {
        case .entry(let prefill, let message):
            let value = prefill.map { ConsentPage.htmlEscaped($0) } ?? ""
            let notice = message.map {
                "<p class=\"message\">\(ConsentPage.htmlEscaped($0))</p>"
            } ?? ""
            content = """
                <h1>Connect a device</h1>
                \(notice)
                <p>Enter the code shown on your device.</p>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="\(csrf)">
                    <input type="hidden" name="action" value="confirm">
                    <input type="text" name="user_code" value="\(value)" autocomplete="off"
                           autocapitalize="characters" spellcheck="false" required>
                    <button type="submit">Continue</button>
                </form>
                """
        case .confirmation(let pending):
            let name = ConsentPage.htmlEscaped(pending.clientName ?? pending.clientId)
            let code = ConsentPage.htmlEscaped(pending.userCode)
            let scopes = (pending.scope ?? "")
                .split(separator: " ")
                .map { "<li>\(ConsentPage.htmlEscaped(String($0)))</li>" }
                .joined(separator: "\n")
            content = """
                <h1>Allow this device?</h1>
                <p><strong>\(name)</strong> is asking to act on your behalf, with the code
                <strong>\(code)</strong>.</p>
                <p>Only continue if that code is on a device in front of you. If someone gave
                you this code, deny it.</p>
                \(scopes.isEmpty ? "" : "<ul>\n\(scopes)\n</ul>")
                <form method="post">
                    <input type="hidden" name="csrf_token" value="\(csrf)">
                    <input type="hidden" name="user_code" value="\(code)">
                    <button type="submit" name="action" value="deny">Deny</button>
                    <button type="submit" name="action" value="approve">Approve</button>
                </form>
                """
        case .finished(let approved):
            content = approved
                ? "<h1>Device connected</h1>\n<p>You can return to your device.</p>"
                : "<h1>Request denied</h1>\n<p>The device was not given access.</p>"
        }

        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Connect a device</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                           sans-serif; max-width: 420px; margin: 40px auto; padding: 0 20px;
                           color: #333; line-height: 1.6; }
                    input[type=text] { font-size: 1.5em; letter-spacing: 0.1em; width: 100%;
                                       text-transform: uppercase; margin: 12px 0; }
                    button { font-size: 1em; padding: 8px 16px; margin-right: 8px; }
                    .message { color: #b00020; }
                </style>
            </head>
            <body>
            \(content)
            </body>
            </html>
            """
    }
}
