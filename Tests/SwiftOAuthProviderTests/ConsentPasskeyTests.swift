import Crypto
import Foundation
import Testing
@testable import SwiftOAuthProvider

#if canImport(JavaScriptCore)
import JavaScriptCore
#endif

/// The consent page's optional passkey button: the page asks the browser for a passkey bound to *this* consent, and the host verifies it
/// beside the typed secret. What is checked here is the page and its wiring script; the ceremony itself is the host's (SwiftPasskeyServer).
@Suite("Consent page passkey prompt")
struct ConsentPasskeyTests {

    private static let prompt = PasskeyPrompt(base: "/v1/auth/passkey", libraryPath: "/passkey.js", wiringPath: "/authorize/consent-passkey.js")

    private static func page(
        passkey: PasskeyPrompt? = prompt, client: String = "client-1", redirect: String = "http://localhost:9000/callback", csrf: String = "csrf"
    ) -> String {
        ConsentPage(
            clientName: "Test Client", clientId: client, scope: "mcp:tools", redirectUri: redirect, state: "s", csrfToken: csrf,
            codeChallenge: nil, codeChallengeMethod: nil,
            signIn: ConsentSignIn(label: "Owner secret", hint: "h", passkey: passkey)
        ).render()
    }

    // MARK: The page

    @Test("Without a passkey prompt the page is exactly what it was: no button, no script, no assertion field")
    func absentByDefault() {
        let html = Self.page(passkey: nil)
        #expect(!html.contains("passkey"))
        #expect(!html.contains("<script"))
    }

    @Test("With a prompt the page carries a button, a hidden assertion field and two script files, all inside the form, and no inline script")
    func rendered() throws {
        let html = Self.page()
        let form = try #require(html.range(of: "<form"))
        let endForm = try #require(html.range(of: "</form>"))
        let inside = html[form.lowerBound..<endForm.upperBound]
        #expect(inside.contains("id=\"passkey-approve\""))
        #expect(inside.contains("<input type=\"hidden\" id=\"passkey_assertion\" name=\"passkey_assertion\" value=\"\">"))
        #expect(inside.contains("data-base=\"/v1/auth/passkey\""))
        #expect(html.contains("<script src=\"/passkey.js\"></script>"))
        #expect(html.contains("<script src=\"/authorize/consent-passkey.js\"></script>"))
        // Exactly two script tags, each a file: nothing a `script-src 'self'` policy would refuse.
        #expect(html.components(separatedBy: "<script").count == 3)
        #expect(!html.contains("onclick"))
        // The secret field is still there as the fallback, and Deny does not need a passkey.
        #expect(html.contains("name=\"owner_secret\""))
        #expect(html.contains("value=\"deny\""))
        // The passkey block is hidden until the script finds WebAuthn, so a browser without it shows only the secret field.
        #expect(inside.contains("id=\"passkey\" hidden"))
    }

    @Test("The button's binding is the one the approver recomputes from the form, so a changed field means a refused approval")
    func bindingMatches() throws {
        let html = Self.page(client: "c1", redirect: "https://x.example/cb", csrf: "tok")
        let expected = ConsentPasskeyBinding.make(clientID: "c1", redirectURI: "https://x.example/cb", csrfToken: "tok")
        #expect(html.contains("data-binding=\"\(expected)\""))
    }

    @Test("A binding is fixed-length, and differs when any part differs, including where parts only differ by where they split")
    func bindingProperties() {
        let base = ConsentPasskeyBinding.make(clientID: "a", redirectURI: "b", csrfToken: "c")
        #expect(base.utf8.count == ConsentPasskeyBinding.make(clientID: String(repeating: "x", count: 5_000), redirectURI: "b", csrfToken: "c").utf8.count)
        #expect(base.utf8.count <= 1_024)
        #expect(base == ConsentPasskeyBinding.make(clientID: "a", redirectURI: "b", csrfToken: "c"))
        let others = [
            ConsentPasskeyBinding.make(clientID: "A", redirectURI: "b", csrfToken: "c"),
            ConsentPasskeyBinding.make(clientID: "a", redirectURI: "B", csrfToken: "c"),
            ConsentPasskeyBinding.make(clientID: "a", redirectURI: "b", csrfToken: "C"),
            ConsentPasskeyBinding.make(clientID: "ab", redirectURI: "", csrfToken: "c"),
            ConsentPasskeyBinding.make(clientID: "", redirectURI: "ab", csrfToken: "c"),
            ConsentPasskeyBinding.make(clientID: "a", redirectURI: "bc", csrfToken: ""),
        ]
        for other in others { #expect(other != base) }
        #expect(Set(others).count == others.count)
    }

    @Test("Everything the host passes is escaped, and a path cannot break out of its attribute")
    func escaped() {
        let hostile = PasskeyPrompt(base: "/p\"><script>x</script>", libraryPath: "/a\"b.js", wiringPath: "/c'd.js")
        let html = Self.page(passkey: hostile)
        #expect(!html.contains("<script>x"))
        #expect(!html.contains("\"b.js"))
        #expect(html.contains("&quot;"))
    }

    // MARK: The wiring script

    @Test("The script's integrity is the SHA-256 of the exact bytes served")
    func integrity() {
        let digest = Data(SHA256.hash(data: Data(ConsentPasskeyScript.source.utf8))).base64EncodedString()
        #expect(ConsentPasskeyScript.integrity == "sha256-" + digest)
    }

    @Test("The script takes nothing from outside the page's own passkey block: no eval, storage, console, network or inline handlers")
    func hygiene() {
        for forbidden in ["eval(", "Function(", "innerHTML", "outerHTML", "localStorage", "sessionStorage", "console.", "XMLHttpRequest", "fetch(", "alert("] {
            #expect(!ConsentPasskeyScript.source.contains(forbidden), "\(forbidden)")
        }
    }

    #if canImport(JavaScriptCore)
    /// A page with a tiny fake DOM, `SwiftPasskey` scripted, and the wiring script loaded.
    private func page(webAuthn: Bool = true, result: String = "{ ok: true, json: '{\"id\":\"AQ\"}' }") throws -> JSContext {
        let context = try #require(JSContext())
        var failure: String?
        context.exceptionHandler = { _, exception in failure = exception?.toString() }
        context.evaluateScript("""
            globalThis.form = { appended: [], submitted: 0, appendChild(child) { this.appended.push(child); }, submit() { this.submitted++; } };
            const make = (id) => ({ id, hidden: true, disabled: false, textContent: '', value: '', dataset: {}, listeners: {},
                addEventListener(type, listener) { this.listeners[type] = listener; }, closest() { return form; } });
            globalThis.els = { passkey: make('passkey'), 'passkey-approve': make('passkey-approve'),
                               passkey_assertion: make('passkey_assertion'), 'passkey-status': make('passkey-status') };
            els.passkey.dataset = { base: '/v1/auth/passkey', binding: 'BOUND' };
            globalThis.document = { getElementById: (id) => els[id] || null, createElement: () => ({ type: '', name: '', value: '' }) };
            globalThis.approvals = [];
            \(webAuthn ? "globalThis.PublicKeyCredential = function () {};" : "")
            globalThis.SwiftPasskey = { approve: async (settings) => { approvals.push(settings); return \(result); } };
            """)
        context.evaluateScript(ConsentPasskeyScript.source)
        #expect(failure == nil, "the script loaded without an exception: \(failure ?? "")")
        return context
    }

    private func json(_ context: JSContext, _ expression: String) throws -> Any {
        let text = try #require(context.evaluateScript("JSON.stringify(\(expression))")?.toString())
        return try JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed])
    }

    @Test("A browser with WebAuthn shows the block; one without leaves it hidden")
    func showsOnlyWithWebAuthn() throws {
        #expect(try json(try page(), "els.passkey.hidden") as? Bool == false)
        #expect(try json(try page(webAuthn: false), "els.passkey.hidden") as? Bool == true)
    }

    @Test("Clicking asks for an approval bound to the page's binding, puts the assertion in the field, adds action=approve and submits once")
    func click() throws {
        let context = try page()
        context.evaluateScript("els['passkey-approve'].listeners.click();")
        #expect(try json(context, "approvals") as? [[String: String]] == [["base": "/v1/auth/passkey", "binding": "BOUND"]])
        #expect(try json(context, "els.passkey_assertion.value") as? String == #"{"id":"AQ"}"#)
        #expect(try json(context, "form.appended.map(a => [a.type, a.name, a.value])") as? [[String]] == [["hidden", "action", "approve"]])
        #expect(try json(context, "form.submitted") as? Int == 1)
    }

    @Test("A cancelled or refused ceremony says so on the page, submits nothing and lets the person try again")
    func failure() throws {
        let cancelled = try page(result: "{ ok: false, stage: 'browser', error: 'NotAllowedError' }")
        cancelled.evaluateScript("els['passkey-approve'].listeners.click();")
        #expect(try json(cancelled, "form.submitted") as? Int == 0)
        #expect(try json(cancelled, "els.passkey_assertion.value") as? String == "")
        #expect(try json(cancelled, "els['passkey-approve'].disabled") as? Bool == false)
        let message = try #require(try json(cancelled, "els['passkey-status'].textContent") as? String)
        #expect(!message.isEmpty)

        let server = try page(result: "{ ok: false, stage: 'options', status: 429 }")
        server.evaluateScript("els['passkey-approve'].listeners.click();")
        #expect(try json(server, "form.submitted") as? Int == 0)
        #expect(try json(server, "els['passkey-status'].textContent") as? String != message)
    }

    @Test("A second click while the first is waiting asks for nothing more")
    func noDoubleClick() throws {
        let context = try page(result: "await new Promise(() => {})")
        context.evaluateScript("els['passkey-approve'].listeners.click(); els['passkey-approve'].listeners.click();")
        #expect(try json(context, "approvals.length") as? Int == 1)
        #expect(try json(context, "form.submitted") as? Int == 0)
    }
    #endif
}
