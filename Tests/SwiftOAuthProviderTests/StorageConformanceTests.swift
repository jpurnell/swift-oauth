import Testing
import Foundation
import SwiftOAuthCore
import SwiftOAuthProvider
import SwiftOAuthProviderConformance

/// Every provider store, held to the one bar.
///
/// The suite lives in `SwiftOAuthProviderConformance`, a library, so a store written elsewhere
/// can run it. Here it is run against the two stores this package ships: the SQLite one that
/// production uses and the in-memory one for tests and single-process use. They must agree,
/// because `OAuthServer` is written against the protocol and cannot tell them apart.
@Suite("Provider storage conformance")
struct StorageConformanceTests {

    /// The stores under test, by name, each a factory for a fresh empty one.
    enum Store: String, CaseIterable, Sendable, CustomTestStringConvertible {
        case sqlite = "SQLite (OAuthStorage, :memory:)"
        case inMemory = "InMemoryOAuthStorage"

        var testDescription: String { rawValue }

        var suite: ProviderStorageConformanceSuite {
            switch self {
            case .sqlite:
                return ProviderStorageConformanceSuite { try OAuthStorage(path: ":memory:") }
            case .inMemory:
                return ProviderStorageConformanceSuite { InMemoryOAuthStorage() }
            }
        }
    }

    @Test("Each requirement holds", arguments: Store.allCases, ProviderStorageConformanceSuite.Requirement.allCases)
    func requirementHolds(store: Store, requirement: ProviderStorageConformanceSuite.Requirement) async {
        let result = await store.suite.run(requirement)
        #expect(result.verdict == .passed,
                "\(requirement.rawValue): \(result.verdict) \(result.detail)")
    }

    @Test("The suite is not vacuous: a store that refuses everything is not conformant")
    func aStoreThatRefusesEverythingFails() async {
        let report = await ProviderStorageConformanceSuite { RefusingStore() }.run()
        #expect(report.isConformant == false)
        // Positive controls are what turn a vacuous pass into `inconclusive`. A store that
        // returns nothing for everything must fail or be inconclusive on every requirement
        // that needs a stored thing to be found.
        #expect(report.failures.count + report.inconclusive.count >= 20, "\(report.summary)")
    }
}

/// A store that accepts every write and answers every read with "nothing" — correct for the
/// negative halves of the suite and wrong for the rest.
private actor RefusingStore: OAuthProviderStorage {
    func saveClient(_ client: RegisteredClient) throws {}
    func getClient(clientId: String) throws -> RegisteredClient? { nil }
    func clientSecretMatches(clientId: String, presented: String) throws -> Bool { false }
    func deleteClient(clientId: String) throws {}
    func saveAuthorizationCode(_ code: AuthorizationCode) throws {}
    func consumeAuthorizationCode(code: String) throws -> AuthorizationCode? { nil }
    func generateCSRFToken(clientId: String, redirectUri: String, expiresIn: TimeInterval) throws -> String { "" }
    func validateCSRFToken(token: String, clientId: String, redirectUri: String) throws -> CSRFValidationResult {
        CSRFValidationResult(isValid: false, error: "refused")
    }
    func saveAccessToken(
        token: String, clientId: String, scope: String?, expiresAt: Date, audience: URL?,
        keyThumbprint: String?, certificateThumbprint: String?, subject: String?
    ) throws {}
    func validateAccessToken(token: String) throws -> TokenValidationResult { .invalid(reason: "refused") }
    func introspectAccessToken(token: String) throws -> IntrospectionResult { .inactive }
    func revokeAccessToken(token: String) throws {}
    func revokeAllTokensForClient(clientId: String) throws {}
    func saveRefreshToken(token: String, clientId: String, scope: String?, expiresAt: Date, subject: String?) throws {}
    func getRefreshTokenInfo(token: String) throws -> RefreshTokenInfo? { nil }
    func saveDeviceCode(
        deviceCode: String, userCode: String, clientId: String, scope: String?, expiresAt: Date,
        interval: TimeInterval, now: Date
    ) throws {}
    func approveDeviceCode(userCode: String, subject: String, now: Date) throws -> Bool { false }
    func denyDeviceCode(userCode: String, subject: String, now: Date) throws -> Bool { false }
    func pendingDeviceCode(userCode: String, now: Date) throws -> (clientId: String, scope: String?)? { nil }
    func pacePendingPoll(deviceCode: String, now: Date) throws -> Bool { false }
    func deviceCodeState(deviceCode: String, clientId: String, now: Date) throws -> DeviceCodeState { .unknown }
    func markDeviceCodeRedeemed(deviceCode: String) throws -> Bool { false }
    func savePushedRequest(
        requestURI: String, clientId: String, redirectUri: String, scope: String?, state: String?,
        codeChallenge: String?, codeChallengeMethod: String?, expiresAt: Date
    ) throws {}
    func consumePushedRequest(requestURI: String, clientId: String) throws -> PushedAuthorizationRequest? { nil }
    func claimProofIdentifier(_ identifier: String, expiresAt: Date) throws -> Bool { false }
    func sweepExpiredProofIdentifiers(now: Date) throws -> Int { 0 }
}
