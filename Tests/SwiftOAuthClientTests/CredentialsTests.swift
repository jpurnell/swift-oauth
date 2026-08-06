import Foundation
import Testing
@testable import SwiftOAuthClient

/// Credentials are the one thing in this package that must never be committed, never be
/// logged, and never be paired with the wrong host. Each of those is a test.
@Suite("Credentials — variable naming")
struct CredentialVariableTests {

    /// Sandbox and production must read from *different* variables. Presenting one
    /// environment's credentials to the other's host fails with a bare `invalid_client`
    /// and no further explanation.
    @Test("Environments read from different variables")
    func environmentsAreNamespaced() {
        let sandbox = ClientCredentials.clientIDVariable(provider: "intuit", environment: "sandbox")
        let production = ClientCredentials.clientIDVariable(provider: "intuit", environment: "production")

        #expect(sandbox == "INTUIT_SANDBOX_CLIENT_ID")
        #expect(production == "INTUIT_PRODUCTION_CLIENT_ID")
        #expect(sandbox != production)
    }

    /// The identifier and the secret must not collide, or one would overwrite the other.
    @Test("Identifier and secret read from different variables")
    func identifierAndSecretDiffer() {
        let id = ClientCredentials.clientIDVariable(provider: "intuit", environment: "sandbox")
        let secret = ClientCredentials.clientSecretVariable(provider: "intuit", environment: "sandbox")
        #expect(id == "INTUIT_SANDBOX_CLIENT_ID")
        #expect(secret == "INTUIT_SANDBOX_CLIENT_SECRET")
        #expect(id != secret)
    }

    /// `INTUIT_SANDBOX_CLIENT_ID` is a name in a global namespace — the machine's
    /// environment. Two applications on one machine, each registered as its own Intuit app,
    /// would read each other's credentials. An application prefix makes them distinct.
    @Test("An application prefix namespaces the variable")
    func applicationPrefix() {
        let prefixed = ClientCredentials.clientIDVariable(
            provider: "intuit", environment: "sandbox", prefix: "ledgeos")
        #expect(prefixed == "LEDGEOS_INTUIT_SANDBOX_CLIENT_ID")

        let secret = ClientCredentials.clientSecretVariable(
            provider: "intuit", environment: "sandbox", prefix: "ledgeos")
        #expect(secret == "LEDGEOS_INTUIT_SANDBOX_CLIENT_SECRET")
    }

    /// A prefix is optional, and its absence must not leave a leading underscore — that
    /// would be a different variable name than the unprefixed one, and nothing would read it.
    @Test("No prefix leaves no separator")
    func absentPrefixLeavesNoSeparator() {
        for prefix in ["", "   "] {
            let name = ClientCredentials.clientIDVariable(
                provider: "intuit", environment: "sandbox", prefix: prefix)
            #expect(name == "INTUIT_SANDBOX_CLIENT_ID", "got \(name) for prefix \"\(prefix)\"")
        }
    }
}

@Suite("Credentials — loading")
struct CredentialLoadingTests {

    /// The ordinary case: both variables present.
    @Test("Both variables present loads credentials")
    func loadsFromVariables() throws {
        let credentials = try ClientCredentials.fromEnvironment(
            provider: "intuit",
            environment: "sandbox",
            reading: [
                "INTUIT_SANDBOX_CLIENT_ID": "an-identifier",
                "INTUIT_SANDBOX_CLIENT_SECRET": "a-secret"
            ])

        #expect(credentials.clientID == "an-identifier")
        #expect(credentials.clientSecret == "a-secret")
        #expect(credentials.environment == "sandbox")
    }

    /// The prefix must be honoured at load, not only when composing the name — a prefix that
    /// names a variable nobody reads is worse than none.
    @Test("A prefixed variable is read")
    func loadsPrefixedVariables() throws {
        let credentials = try ClientCredentials.fromEnvironment(
            provider: "intuit",
            environment: "sandbox",
            prefix: "ledgeos",
            reading: [
                "LEDGEOS_INTUIT_SANDBOX_CLIENT_ID": "an-identifier",
                "LEDGEOS_INTUIT_SANDBOX_CLIENT_SECRET": "a-secret",
                // The unprefixed pair is present and must be ignored: reading it would be
                // exactly the cross-application mix-up the prefix exists to prevent.
                "INTUIT_SANDBOX_CLIENT_ID": "another-app",
                "INTUIT_SANDBOX_CLIENT_SECRET": "another-secret"
            ])

        #expect(credentials.clientID == "an-identifier")
        #expect(credentials.clientSecret == "a-secret")
    }

    /// The error must name the variable. "Credentials missing" sends someone reading source;
    /// the variable name sends them to their shell.
    @Test("A missing variable is named in the error")
    func missingVariableIsNamed() {
        #expect(throws: ClientCredentialError.missing(variable: "INTUIT_SANDBOX_CLIENT_ID")) {
            try ClientCredentials.fromEnvironment(
                provider: "intuit", environment: "sandbox", reading: [:])
        }

        #expect(throws: ClientCredentialError.missing(variable: "INTUIT_SANDBOX_CLIENT_SECRET")) {
            try ClientCredentials.fromEnvironment(
                provider: "intuit",
                environment: "sandbox",
                reading: ["INTUIT_SANDBOX_CLIENT_ID": "an-identifier"])
        }
    }

    /// A blank value fails at the provider with the same opaque `invalid_client` as a wrong
    /// one. Catching it here is the difference between a legible error and an afternoon.
    @Test("A blank value counts as missing")
    func blankValueIsMissing() {
        #expect(throws: ClientCredentialError.missing(variable: "INTUIT_SANDBOX_CLIENT_SECRET")) {
            try ClientCredentials.fromEnvironment(
                provider: "intuit",
                environment: "sandbox",
                reading: [
                    "INTUIT_SANDBOX_CLIENT_ID": "an-identifier",
                    "INTUIT_SANDBOX_CLIENT_SECRET": "   "
                ])
        }
    }
}

@Suite("Credentials — redaction")
struct RedactionTests {

    /// String interpolation is how credentials reach logs. The default rendering must be
    /// safe, so exposing one has to be written on purpose.
    @Test("Interpolation never reveals the secret")
    func secretNeverInterpolated() {
        let credentials = ClientCredentials(
            environment: "sandbox",
            clientID: "ABCDefghijklmnopqrstuvwxyz0123456789",
            clientSecret: "a-secret-that-must-not-appear")

        let rendered = "\(credentials)"
        #expect(!rendered.contains("a-secret-that-must-not-appear"))
        #expect(rendered.contains("<redacted>"))

        // `String(reflecting:)` takes `debugDescription`, which debuggers and some logging
        // paths prefer. It must hide exactly what `description` hides.
        let reflected = String(reflecting: credentials)
        #expect(!reflected.contains("a-secret-that-must-not-appear"))
        #expect(reflected == rendered)
    }

    /// The identifier is shortened rather than hidden: enough to tell two apps apart in a
    /// log, never enough to use.
    @Test("The identifier is shortened, not hidden")
    func identifierShortened() {
        let credentials = ClientCredentials(
            environment: "sandbox",
            clientID: "ABCDefghijklmnop0123",
            clientSecret: "irrelevant")
        let rendered = "\(credentials)"

        #expect(rendered.contains("ABCD…0123"))
        #expect(!rendered.contains("ABCDefghijklmnop0123"))
    }

    /// A short value has no safe prefix to show — four characters of an eight-character
    /// secret is half of it. Redact entirely below the threshold.
    @Test("Short values are redacted entirely")
    func shortValuesFullyRedacted() {
        #expect(ClientCredentials.redact("abc") == "<redacted>")
        #expect(ClientCredentials.redact("12345678") == "<redacted>")
        #expect(ClientCredentials.redact("123456789") == "1234…6789")
    }
}
