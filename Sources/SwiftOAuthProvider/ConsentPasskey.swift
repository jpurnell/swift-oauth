import Crypto
import Foundation

/// Where the consent page finds the passkey ceremony: the routes it asks for options, and the two script files it loads.
///
/// The ceremony itself is the host's (`SwiftPasskeyServer`'s routes and ``PasskeyPrompt/libraryPath`` script); this type only says where they are,
/// so the page can render a button and load the scripts. Every value is a path on the host's own origin, and every one is escaped when rendered.
public struct PasskeyPrompt: Sendable, Equatable {

    /// The hidden form field the page puts the browser's assertion in. The host reads the assertion from the submitted form under this name.
    public static let fieldName = "passkey_assertion"

    /// The path the passkey routes sit under, for example `/v1/auth/passkey`: the script asks `<base>/approval/challenge` for options.
    public let base: String

    /// The path of the passkey library script (`SwiftPasskeyServer`'s `PasskeyBrowserScript`), for example `/passkey.js`.
    public let libraryPath: String

    /// The path the host serves ``ConsentPasskeyScript`` at, for example `/authorize/consent-passkey.js`.
    public let wiringPath: String

    /// Creates a prompt.
    ///
    /// - Parameters:
    ///   - base: The path the passkey routes sit under.
    ///   - libraryPath: Where the passkey library script is served.
    ///   - wiringPath: Where ``ConsentPasskeyScript`` is served.
    public init(base: String, libraryPath: String, wiringPath: String) {
        self.base = base
        self.libraryPath = libraryPath
        self.wiringPath = wiringPath
    }
}

/// What a passkey approval of one consent is bound to.
///
/// The page puts this on its button, and the script asks the passkey routes for a challenge bound to it; the host's approver computes it again
/// from the fields the browser submitted and the passkey ceremony accepts the assertion only if the two are equal. An assertion made for one
/// consent therefore cannot approve another: it differs in the client, the redirect or the anti-forgery token, and so in the binding.
///
/// Fixed-length (a SHA-256 over length-prefixed parts, so no choice of parts can run into another's), whatever the length of a client's URL.
public enum ConsentPasskeyBinding {

    /// The binding for a consent.
    ///
    /// - Parameters:
    ///   - clientID: The consent form's `client_id`.
    ///   - redirectURI: The consent form's `redirect_uri`.
    ///   - csrfToken: The consent form's `csrf_token`.
    /// - Returns: `oauth-consent:v1:` and 64 hexadecimal characters.
    public static func make(clientID: String, redirectURI: String, csrfToken: String) -> String {
        var input = Data()
        for part in [clientID, redirectURI, csrfToken] {
            let bytes = Data(part.utf8)
            input.append(Data("\(bytes.count):".utf8))
            input.append(bytes)
        }
        let digits = Array("0123456789abcdef")
        var digest = ""
        for byte in SHA256.hash(data: input) {
            digest.append(digits[Int(byte >> 4)])
            digest.append(digits[Int(byte & 0x0F)])
        }
        return "oauth-consent:v1:" + digest
    }
}

/// The page's own script: shows the passkey button where the browser can use one, and runs `SwiftPasskey.approve` when it is pressed.
///
/// Serve it as a file at ``PasskeyPrompt/wiringPath`` so the page keeps `script-src 'self'`. It reads the passkey routes' path and the binding
/// from the button's block, puts the assertion in the form's hidden field, adds `action=approve` and submits the form. It stores nothing, logs
/// nothing and makes no request of its own (the library script does that).
public enum ConsentPasskeyScript {

    /// The script, verbatim.
    public static let source = #"""
        (function (root) {
          var doc = root.document;
          var box = doc.getElementById('passkey');
          if (!box || !root.SwiftPasskey || !root.PublicKeyCredential) { return; }
          var button = doc.getElementById('passkey-approve');
          var field = doc.getElementById('passkey_assertion');
          var status = doc.getElementById('passkey-status');
          var form = box.closest('form');
          if (!button || !field || !status || !form) { return; }
          box.hidden = false;
          var busy = false;

          function message(result) {
            if (result.stage === 'browser') { return 'The passkey was not used. You can try again, or use the owner secret.'; }
            if (result.stage === 'arguments') { return 'This page cannot ask for a passkey.'; }
            return 'The server would not start a passkey approval. Try again in a moment, or use the owner secret.';
          }

          button.addEventListener('click', async function () {
            if (busy) { return; }
            busy = true;
            button.disabled = true;
            status.textContent = 'Waiting for your passkey.';
            var result = await root.SwiftPasskey.approve({ base: box.dataset.base, binding: box.dataset.binding });
            if (!result || !result.ok) {
              status.textContent = message(result || {});
              button.disabled = false;
              busy = false;
              return;
            }
            field.value = result.json;
            var action = doc.createElement('input');
            action.type = 'hidden';
            action.name = 'action';
            action.value = 'approve';
            form.appendChild(action);
            form.submit();
          });
        })(typeof globalThis !== 'undefined' ? globalThis : self);

        """#

    /// `sha256-<base64>` of the script's bytes, for a `<script integrity="...">` attribute or a CSP `'sha256-...'` source.
    public static var integrity: String {
        "sha256-" + Data(SHA256.hash(data: Data(source.utf8))).base64EncodedString()
    }
}
