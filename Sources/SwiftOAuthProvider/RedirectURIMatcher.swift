import Foundation

/// How a presented redirect URI is compared with a registered one, and what a native client may
/// register — RFC 8252.
///
/// RFC 6749 §3.1.2.3 and OAuth 2.1 require an exact match, and RFC 8252 §8.4 keeps that rule with
/// one exception: for a loopback redirect "an exact match is required except for the port URI
/// component", because a native app listening on a loopback interface cannot know its port
/// until it is running (§7.3: the server "MUST allow any port to be specified at the time of
/// the request for loopback IP redirect URIs").
///
/// The exception applies only to a registered `http` URI whose host is the IP literal
/// `127.0.0.1` or `[::1]`. `localhost` is **not** a loopback literal here: §8.3 recommends
/// against it (it can be remapped, and a name resolves to either family), so a client that
/// registers it gets an exact match. The two literals do not match each other.
public enum RedirectURIMatcher {

    /// Whether `presented` is acceptable for a client that registered `registered`.
    ///
    /// - Parameters:
    ///   - registered: A redirect URI from the client's registration.
    ///   - presented: The `redirect_uri` of a request.
    /// - Returns: `true` for an exact match, or, for a loopback IP literal over `http`, a match
    ///   in every component but the port.
    public static func matches(registered: String, presented: String) -> Bool {
        if registered == presented { return true }
        guard let reg = URLComponents(string: registered),
              let pre = URLComponents(string: presented),
              reg.scheme == "http", pre.scheme == "http",
              let regHost = loopbackLiteral(reg.host), let preHost = loopbackLiteral(pre.host),
              regHost == preHost else { return false }
        return reg.user == nil && pre.user == nil
            && reg.password == nil && pre.password == nil
            && reg.path == pre.path
            && reg.query == pre.query
            && reg.fragment == nil && pre.fragment == nil
    }

    /// Why a native application may not register `uri`, or `nil` if it may — RFC 8252 §7 and §8.4.
    ///
    /// A native redirect is one of: an `https` URI (§7.2, a claimed URL); an `http` URI whose host
    /// is a loopback IP literal (§7.3); or a private-use scheme whose name contains a period
    /// (§7.1, reverse domain name). §8.4 says a scheme with no period SHOULD be rejected, and
    /// this does.
    ///
    /// - Parameter uri: A redirect URI from a registration.
    /// - Returns: A reason fit for an error description, or `nil` when the URI is acceptable.
    public static func nativeRegistrationProblem(_ uri: String) -> String? {
        guard let components = URLComponents(string: uri), let scheme = components.scheme?.lowercased(),
              !scheme.isEmpty else {
            return "\(uri) is not an absolute URI."
        }
        switch scheme {
        case "https":
            return nil
        case "http":
            return loopbackLiteral(components.host) != nil ? nil
                : "\(uri): a native client may use http only with a loopback IP literal "
                    + "(127.0.0.1 or [::1]), not localhost or a named host (RFC 8252 §7.3, §8.3)."
        default:
            return scheme.contains(".") ? nil
                : "\(uri): a native client's private-use scheme must be a reverse domain name "
                    + "containing a period, such as com.example.app (RFC 8252 §7.1, §8.4)."
        }
    }

    /// The loopback IP literal a host names, normalised, or `nil` for any other host.
    private static func loopbackLiteral(_ host: String?) -> String? {
        guard let host else { return nil }
        switch host {
        case "127.0.0.1": return "127.0.0.1"
        case "::1", "[::1]": return "::1"
        default: return nil
        }
    }
}
