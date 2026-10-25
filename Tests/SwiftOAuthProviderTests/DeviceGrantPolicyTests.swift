import Foundation
import Testing
import CSQLite
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// A clock a test moves by hand.
// Justification: mutable `current` is read and written only under `lock`.
final class ManualClock: @unchecked Sendable {
    private var current: Date
    private let lock = NSLock()

    init(_ start: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        current = start
    }

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        current = current.addingTimeInterval(seconds)
    }
}

/// What RFC 8628 asks of the provider beyond issuing and redeeming: the user code's shape and
/// how it is compared (§6.1), refusal by the user (§3.5 `access_denied`), pacing (§3.5
/// `slow_down`, §5.2), expiry (§3.5 `expired_token`), single use (§3.5, §5.6), and throttling the
/// step where a person types a code (§5.1).
@Suite("RFC 8628 — the provider's device-grant policy")
struct DeviceGrantPolicyTests {

    static let issuer = "https://auth.example.com"

    private static func makeServer(
        clock: ManualClock = ManualClock()
    ) throws -> (OAuthServer, OAuthStorage, ManualClock) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read"], served: .core,
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            now: { clock.now })
        return (server, storage, clock)
    }

    private static func pollError(
        _ server: OAuthServer, _ deviceCode: String, clientId: String = "tv-app"
    ) async -> String? {
        do {
            _ = try await server.redeemDeviceCode(deviceCode, clientId: clientId)
            return nil
        } catch let error as OAuthError {
            return error.code
        } catch {
            return "unexpected: \(error)"
        }
    }

    // MARK: - §3.2 / §3.3.1 — the response

    @Test("The response carries verification_uri_complete, the code already in it")
    func verificationURIComplete() async throws {
        let (server, _, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        let complete = try #require(issued.verificationURIComplete)
        let components = try #require(URLComponents(url: complete, resolvingAgainstBaseURL: false))
        #expect(complete.absoluteString.hasPrefix(issued.verificationURI.absoluteString + "?"))
        #expect(components.queryItems == [URLQueryItem(name: "user_code", value: issued.userCode)])
        #expect(issued.verificationURI.absoluteString == "\(Self.issuer)/device")
    }

    // MARK: - §6.1 — the user code

    /// §6.1: eight characters from the twenty-consonant alphabet, about 34.5 bits — the
    /// example the RFC itself gives.
    @Test("A user code is eight characters from BCDFGHJKLMNPQRSTVWXZ")
    func userCodeAlphabet() async throws {
        let (server, _, _) = try Self.makeServer()
        let alphabet = Set("BCDFGHJKLMNPQRSTVWXZ")
        for _ in 0..<20 {
            let code = try await server.authorizeDevice(clientId: "tv-app", scope: nil).userCode
            let bare = code.replacingOccurrences(of: "-", with: "")
            #expect(bare.count == 8)
            #expect(bare.allSatisfy { alphabet.contains($0) }, "\(code)")
        }
    }

    /// §6.1: "the authorization server should be case-insensitive when comparing the entered
    /// user code ... and ignore dashes or other punctuation".
    @Test("Approval accepts the code in any case, with or without its dash", arguments: [
        "lowercased", "undashed", "spaced"
    ])
    func userCodeIsNormalised(_ typing: String) async throws {
        let (server, _, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        let typed: String
        switch typing {
        case "lowercased": typed = issued.userCode.lowercased()
        case "undashed": typed = issued.userCode.replacingOccurrences(of: "-", with: "")
        default:
            typed = " " + issued.userCode.lowercased().replacingOccurrences(of: "-", with: " ") + " "
        }

        try await server.approveDeviceCode(userCode: typed, subject: "ada")

        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        #expect(!tokens.accessToken.isEmpty)
    }

    @Test("Normalisation refuses what cannot be a user code", arguments: [
        "", "BCDF-GHJ", "BCDF-GHJKL", "BCDF-GHJ0", "AEIO-UBCD", "BCDF-GHJ\u{202E}K"
    ])
    func normalisationRefuses(_ typed: String) {
        #expect(TokenGenerator.normalizedUserCode(typed) == nil)
    }

    /// The comparison happens on a hash: the stored value is a SHA-256 of the canonical code,
    /// so a database read does not yield a code to type, and the lookup's timing depends on a
    /// digest of the input rather than on how much of a live code it matched.
    @Test("The user code is stored as a hash, not as the code")
    func userCodeIsHashedAtRest() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("device-\(UUID().uuidString).db").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path)
        let server = OAuthServer(
            storage: storage, issuer: Self.issuer, scopesSupported: ["read"], served: .core,
            resourceIdentity: .colocated)
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            Issue.record("could not open the database")
            return
        }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        #expect(sqlite3_prepare_v2(db, "SELECT user_code FROM device_codes", -1, &stmt, nil) == SQLITE_OK)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        let stored = try #require(sqlite3_column_text(stmt, 0).map { String(cString: $0) })
        #expect(stored != issued.userCode)
        #expect(stored == TokenGenerator.sha256Hash(issued.userCode))
    }

    /// A code issued before schema 10 was stored in the clear. The upgrade hashes it in place,
    /// so a user mid-flow during the upgrade can still type it.
    @Test("Upgrading hashes an earlier release's user codes, which still approve")
    func upgradeHashesUserCodes() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("device-upgrade-\(UUID().uuidString).db").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try OAuthStorage(path: path, schemaVersion: 9)
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            Issue.record("could not open the database to plant a row")
            return
        }
        let expiry = Date().addingTimeInterval(600).timeIntervalSince1970
        let insert = """
            INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, subject,
                                      approved, redeemed, expires_at, created_at)
            VALUES ('\(TokenGenerator.sha256Hash("old-device-code"))', 'WDJB-MJHT', 'tv-app',
                    'read', NULL, 0, 0, \(expiry), 0)
            """
        let planted = sqlite3_exec(db, insert, nil, nil, nil)
        sqlite3_close(db)
        #expect(planted == SQLITE_OK)

        let upgraded = try OAuthStorage(path: path)
        #expect(try await upgraded.approveDeviceCode(userCode: "wdjb mjht", subject: "ada"))
        #expect(try await upgraded.deviceCodeState(deviceCode: "old-device-code", clientId: "tv-app")
                == .approved(scope: "read", subject: "ada"))
    }

    // MARK: - §3.5 access_denied

    @Test("A denied code polls as access_denied, and cannot then be approved")
    func deniedCodeIsAccessDenied() async throws {
        let (server, _, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        try await server.denyDeviceCode(userCode: issued.userCode, subject: "ada")

        #expect(await Self.pollError(server, issued.deviceCode) == "access_denied")
        await #expect(throws: OAuthError.self) {
            try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")
        }
        #expect(await Self.pollError(server, issued.deviceCode) == "access_denied")
    }

    /// One approval per code. A second approval — by anyone — would rewrite whose session the
    /// device is about to collect.
    @Test("An approved code cannot be approved again, by another user")
    func approvalIsOnce() async throws {
        let (server, _, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")

        await #expect(throws: OAuthError.self) {
            try await server.approveDeviceCode(userCode: issued.userCode, subject: "mallory")
        }
        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        #expect(try await server.introspect(token: tokens.accessToken).subject == "ada")
    }

    // MARK: - §3.5 slow_down

    /// §3.5: polling faster than the interval earns `slow_down`, and "the interval MUST be
    /// increased by 5 seconds for this and all subsequent requests".
    @Test("Polling inside the interval is slow_down, and each one widens it by five seconds")
    func slowDownWidensTheInterval() async throws {
        let (server, _, clock) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        #expect(issued.interval == 5)

        #expect(await Self.pollError(server, issued.deviceCode) == "authorization_pending")
        clock.advance(1)
        #expect(await Self.pollError(server, issued.deviceCode) == "slow_down")   // now 10
        clock.advance(6)
        #expect(await Self.pollError(server, issued.deviceCode) == "slow_down")   // now 15
        clock.advance(15)
        #expect(await Self.pollError(server, issued.deviceCode) == "authorization_pending")
        clock.advance(14)
        #expect(await Self.pollError(server, issued.deviceCode) == "slow_down")   // now 20
        clock.advance(20)
        #expect(await Self.pollError(server, issued.deviceCode) == "authorization_pending")
    }

    @Test("Polling at the stated interval is never slow_down")
    func pollingOnTimeIsPending() async throws {
        let (server, _, clock) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        for _ in 0..<4 {
            #expect(await Self.pollError(server, issued.deviceCode) == "authorization_pending")
            clock.advance(5)
        }
    }

    /// The pace belongs to one device code: one device polling too fast says nothing about
    /// another.
    @Test("slow_down is per device code")
    func slowDownIsPerCode() async throws {
        let (server, _, clock) = try Self.makeServer()
        let first = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        let second = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        #expect(await Self.pollError(server, first.deviceCode) == "authorization_pending")
        clock.advance(1)
        #expect(await Self.pollError(server, first.deviceCode) == "slow_down")
        #expect(await Self.pollError(server, second.deviceCode) == "authorization_pending")
    }

    // MARK: - §3.5 expired_token

    @Test("A code past its lifetime polls as expired_token, and cannot be approved")
    func expiryIsEnforced() async throws {
        let (server, _, clock) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        clock.advance(issued.expiresIn + 1)

        await #expect(throws: OAuthError.self) {
            try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")
        }
        #expect(await Self.pollError(server, issued.deviceCode) == "expired_token")
    }

    @Test("An approved code not collected in time is expired_token too")
    func approvedButExpired() async throws {
        let (server, _, clock) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")

        clock.advance(issued.expiresIn + 1)

        #expect(await Self.pollError(server, issued.deviceCode) == "expired_token")
    }

    // MARK: - Single use

    @Test("Marking a device code redeemed succeeds once")
    func markRedeemedIsOnce() async throws {
        let (server, storage, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        #expect(try await storage.markDeviceCodeRedeemed(deviceCode: issued.deviceCode))
        #expect(try await !storage.markDeviceCodeRedeemed(deviceCode: issued.deviceCode))
    }

    /// Two polls racing on one approved code: exactly one collects tokens.
    @Test("Concurrent redemptions of one approved code yield one set of tokens")
    func concurrentRedemption() async throws {
        let (server, _, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")

        let successes = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    (try? await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")) != nil
                }
            }
            var count = 0
            for await succeeded in group where succeeded {
                count += 1
            }
            return count
        }
        #expect(successes == 1)
    }

    // MARK: - §5.1 — throttling the person typing

    /// §5.1: a user code has about 34 bits, so the verification step must be rate-limited.
    /// Five wrong codes from one user stop that user — even a right code is refused until the
    /// window passes — and nobody else.
    @Test("Five wrong codes from one user throttle that user, and only that user")
    func verificationIsThrottled() async throws {
        let (server, _, clock) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        for _ in 0..<5 {
            await #expect(throws: OAuthError.invalidGrant("That code is not valid, or has expired.")) {
                try await server.approveDeviceCode(userCode: "BBBB-BBBB", subject: "mallory")
            }
        }
        await #expect(throws: OAuthError.self) {
            try await server.approveDeviceCode(userCode: issued.userCode, subject: "mallory")
        }
        let throttled = await #expect(throws: OAuthError.self) {
            _ = try await server.pendingDeviceAuthorization(
                userCode: issued.userCode, subject: "mallory")
        }
        #expect(throttled?.code == "slow_down")

        // Another user is not affected.
        let pending = try await server.pendingDeviceAuthorization(
            userCode: issued.userCode, subject: "ada")
        #expect(pending.clientId == "tv-app")
        #expect(pending.scope == "read")

        // And the window passes.
        clock.advance(301)
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "mallory")
    }

    @Test("Looking up a code for confirmation names the client and scope, and approves nothing")
    func pendingLookupApprovesNothing() async throws {
        let (server, _, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        let pending = try await server.pendingDeviceAuthorization(
            userCode: issued.userCode.lowercased(), subject: "ada")

        #expect(pending.clientId == "tv-app")
        #expect(pending.userCode == issued.userCode)
        #expect(await Self.pollError(server, issued.deviceCode) == "authorization_pending")
    }
}
