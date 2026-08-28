import Foundation
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// The half of the flow before a token exists.
///
/// Everything here protects against the same thing: an authorization that the user did not
/// start, or did not finish, being treated as one they did. That failure does not look like
/// an error — it looks like a working connection to the wrong account.
@Suite("Authorization — starting a flow")
struct AuthorizationStartTests {

    /// Every parameter RFC 6749 §4.1.1 requires, plus the PKCE pair.
    @Test("The authorization URL carries what the provider needs")
    func urlCarriesRequiredParameters() async throws {
        let connection = makeConnection()
        let begun = await connection.beginAuthorization(redirectURI: "https://app.example/cb")

        let components = try #require(
            URLComponents(url: begun.url, resolvingAgainstBaseURL: false))
        let items = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value) })

        #expect(items["response_type"] == "code")
        #expect(items["client_id"] == "test-client")
        #expect(items["redirect_uri"] == "https://app.example/cb")
        #expect(items["scope"] == "accounting")
        #expect(items["code_challenge_method"] == "S256")
        #expect(items["state"] == begun.pending.state)

        // The challenge travels; the verifier must not. Sending it would make PKCE
        // pointless — anyone who sees this request could then redeem the code.
        let challenge = try #require(items["code_challenge"] ?? nil)
        #expect(challenge != begun.pending.verifier)
        #expect(challenge == (try PKCE.generateCodeChallenge(
            verifier: begun.pending.verifier, method: .s256)))
    }

    /// Two flows must not share a state or a verifier. A reused state cannot distinguish a
    /// callback for one flow from a callback for another.
    @Test("Each flow gets its own state and verifier")
    func flowsAreDistinct() async throws {
        let connection = makeConnection()
        var states: Set<String> = []
        var verifiers: Set<String> = []

        for _ in 0..<64 {
            let begun = await connection.beginAuthorization(redirectURI: "https://app.example/cb")
            #expect(states.insert(begun.pending.state).inserted, "a state repeated")
            #expect(verifiers.insert(begun.pending.verifier).inserted, "a verifier repeated")
        }
    }

    /// A short state is guessable, and a guessable state is no protection at all.
    @Test("The state is long enough to be unguessable")
    func stateIsUnguessable() async throws {
        let connection = makeConnection()
        let begun = await connection.beginAuthorization(redirectURI: "https://app.example/cb")
        #expect(begun.pending.state.count >= 32)
        #expect(PKCE.isValidCodeVerifier(begun.pending.verifier))
    }
}

@Suite("Authorization — the callback")
struct AuthorizationCallbackTests {

    /// The ordinary case.
    @Test("A matching callback yields the code")
    func matchingCallbackYieldsCode() throws {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        let code = try AuthorizationCallback.code(
            from: url("https://app.example/cb?code=the-code&state=the-expected-state"),
            matching: pending)

        #expect(code == "the-code")
    }

    /// The single reason `state` exists. An attacker who can make the user's browser hit the
    /// redirect with *their* authorization code gets the user's account connected to the
    /// attacker's — the user sees a working connection and no error at all.
    @Test("A mismatched state is refused")
    func mismatchedStateRefused() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        #expect(throws: CallbackError.stateMismatch) {
            try AuthorizationCallback.code(
                from: url("https://app.example/cb?code=attacker-code&state=some-other-state"),
                matching: pending)
        }
    }

    /// An absent state must not be read as "nothing to check". Treating it as a pass is the
    /// same hole as not checking, reached by a different route.
    @Test("An absent state is refused, not skipped")
    func absentStateRefused() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        #expect(throws: CallbackError.stateMismatch) {
            try AuthorizationCallback.code(
                from: url("https://app.example/cb?code=the-code"),
                matching: pending)
        }
    }

    /// A provider that refuses says so in the callback. Reading that as a missing code would
    /// report the wrong failure, and `access_denied` in particular is a user decision rather
    /// than a fault.
    @Test("A provider error is surfaced as itself")
    func providerErrorSurfaced() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        do {
            _ = try AuthorizationCallback.code(
                from: url("https://app.example/cb?error=access_denied&error_description=User%20refused&state=the-expected-state"),
                matching: pending)
            Issue.record("the provider's refusal was not reported")
        } catch let error as CallbackError {
            guard case .provider(let oauthError) = error else {
                Issue.record("wrong error: \(error)")
                return
            }
            #expect(oauthError == .accessDenied("User refused"))
        } catch {
            Issue.record("wrong error type: \(error)")
        }
    }

    /// An error carrying a mismatched state is still a forged callback. The state check has
    /// to happen before anything else is believed.
    @Test("State is checked before a provider error is believed")
    func stateCheckedBeforeError() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        #expect(throws: CallbackError.stateMismatch) {
            try AuthorizationCallback.code(
                from: url("https://app.example/cb?error=access_denied&state=wrong"),
                matching: pending)
        }
    }

    /// A duplicated parameter is ambiguous, and the ambiguity is exploitable: if the last
    /// occurrence won, appending `&state=<the-real-state>` to a forged callback would defeat
    /// the check. First occurrence wins, so a smuggled second value is ignored rather than
    /// preferred.
    @Test("A smuggled second state cannot override the first")
    func duplicateStateCannotOverride() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        // Forged state first, real state appended — must still be refused.
        #expect(throws: CallbackError.stateMismatch) {
            try AuthorizationCallback.code(
                from: url("https://app.example/cb?code=c&state=forged&state=the-expected-state"),
                matching: pending)
        }

        // Real state first, forged appended — the real one is what is compared.
        let code = try? AuthorizationCallback.code(
            from: url("https://app.example/cb?code=c&state=the-expected-state&state=forged"),
            matching: pending)
        #expect(code == "c")
    }

    /// A state that is a prefix of the expected one must not pass. Length is part of the
    /// comparison, not something the constant-time helper can be assumed to cover.
    @Test("A truncated state is refused")
    func truncatedStateRefused() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        for candidate in ["the-expected-stat", "the-expected-statex", "", "THE-EXPECTED-STATE"] {
            #expect(throws: CallbackError.stateMismatch, "\"\(candidate)\" was accepted") {
                try AuthorizationCallback.code(
                    from: url("https://app.example/cb?code=c&state=\(candidate)"),
                    matching: pending)
            }
        }
    }

    /// Neither a code nor an error is a malformed callback, not an empty success.
    @Test("A callback with neither code nor error is refused")
    func emptyCallbackRefused() {
        let pending = PendingAuthorization(
            state: "the-expected-state",
            verifier: PKCE.generateCodeVerifier(),
            redirectURI: "https://app.example/cb")

        #expect(throws: CallbackError.missingCode) {
            try AuthorizationCallback.code(
                from: url("https://app.example/cb?state=the-expected-state"),
                matching: pending)
        }
    }
}

@Suite("Authorization — completing")
struct AuthorizationCompletionTests {

    /// End to end: begin, callback, tokens stored.
    @Test("Completing a flow stores a usable credential")
    func completionStoresCredential() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "first-access", refresh: "first-refresh", expiresIn: 3_600)
        ])
        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        let begun = await connection.beginAuthorization(redirectURI: "https://app.example/cb")
        let callback = url("https://app.example/cb?code=the-code&state=\(begun.pending.state)")

        let credential = try await connection.completeAuthorization(
            callback: callback, pending: begun.pending)

        #expect(credential.accessToken == "first-access")
        #expect(credential.refreshToken == "first-refresh")

        // Stored, not merely returned — otherwise the next call re-authorises.
        let stored = try #require(try await storage.credential(for: .testConnection))
        #expect(stored.accessToken == "first-access")

        // The verifier must reach the provider, or the exchange is not PKCE-protected.
        let requests = await transport.requests
        let sent = try #require(requests.first)
        #expect(sent["code_verifier"] == begun.pending.verifier)
        #expect(sent["code"] == "the-code")
        #expect(sent["redirect_uri"] == "https://app.example/cb")
    }

    /// A forged callback must not reach the token endpoint at all. Exchanging first and
    /// checking afterwards would burn the code and tell the attacker it was valid.
    @Test("A forged callback never reaches the provider")
    func forgedCallbackNeverExchanges() async throws {
        let transport = StubTransport([
            .tokens(access: "must-not-happen", refresh: "r", expiresIn: 3_600)
        ])
        let connection = makeConnection(transport: transport)
        let begun = await connection.beginAuthorization(redirectURI: "https://app.example/cb")

        await #expect(throws: CallbackError.stateMismatch) {
            try await connection.completeAuthorization(
                callback: url("https://app.example/cb?code=attacker-code&state=forged"),
                pending: begun.pending)
        }

        let exchanges = await transport.exchangeCount
        #expect(exchanges == 0, "a forged callback was sent to the token endpoint")
    }
}

// MARK: - Helpers

private func url(_ string: String) -> URL {
    // SECURITY: parses a callback literal written in this file; no request is ever issued from it.
    URL(string: string) ?? URL(fileURLWithPath: "/")
}

private func makeConnection(
    storage: any OAuthClientStorage = InMemoryClientStorage(),
    transport: any TokenTransport = StubTransport([]),
    clock: TestClock = TestClock()
) -> OAuthConnection {
    OAuthConnection(
        configuration: .testProvider,
        credentials: .testCredentials,
        storage: storage,
        connection: .testConnection,
        transport: transport,
        now: { clock.now })
}
