import Foundation
import Testing
@testable import SwiftOAuthCore

/// RFC 8628 device authorization grant — the wire shapes and the polling rules.
///
/// This is how anything without a browser signs in: a TV, a CLI, a headless box. The device
/// shows a short code, the user types it somewhere else, and the device polls until that
/// happens. Everything hard about it is in the polling.
@Suite("RFC 8628 — device authorization")
struct DeviceAuthorizationTests {

    /// The authorization response, as §3.2 defines it.
    @Test("A device authorization response decodes")
    func responseDecodes() throws {
        let json = """
        {"device_code":"dev-123","user_code":"WDJB-MJHT",
         "verification_uri":"https://example.com/device",
         "verification_uri_complete":"https://example.com/device?user_code=WDJB-MJHT",
         "expires_in":1800,"interval":5}
        """
        let response = try JSONDecoder().decode(
            DeviceAuthorizationResponse.self, from: Data(json.utf8))

        #expect(response.deviceCode == "dev-123")
        #expect(response.userCode == "WDJB-MJHT")
        #expect(response.verificationURI.absoluteString == "https://example.com/device")
        #expect(response.verificationURIComplete?.absoluteString
            == "https://example.com/device?user_code=WDJB-MJHT")
        #expect(response.expiresIn == 1800)
        #expect(response.interval == 5)
    }

    /// `interval` is optional and defaults to 5 seconds — §3.2. A client that treats an absent
    /// interval as "no delay" polls as fast as it can and is told to slow down, which it will
    /// then have to handle anyway.
    @Test("An absent interval defaults to five seconds")
    func absentIntervalDefaults() throws {
        let json = """
        {"device_code":"d","user_code":"U","verification_uri":"https://e.com/d","expires_in":600}
        """
        let response = try JSONDecoder().decode(
            DeviceAuthorizationResponse.self, from: Data(json.utf8))

        #expect(response.interval == 5)
    }

    /// `verification_uri_complete` is optional — §3.3.1. Most servers omit it.
    @Test("An absent complete URI is not an error")
    func absentCompleteURIDecodes() throws {
        let json = """
        {"device_code":"d","user_code":"U","verification_uri":"https://e.com/d","expires_in":600}
        """
        let response = try JSONDecoder().decode(
            DeviceAuthorizationResponse.self, from: Data(json.utf8))

        #expect(response.verificationURIComplete == nil)
    }
}

/// The polling rules — RFC 8628 §3.5.
///
/// These are the part implementations get wrong, and getting them wrong is what gets a client
/// rate-limited by a server that was trying to be helpful.
@Suite("RFC 8628 — the polling contract")
struct DevicePollingTests {

    /// `authorization_pending` means keep waiting at the current interval. It is not an error
    /// to surface — it is the expected answer for most of the flow.
    @Test("authorization_pending keeps the interval unchanged")
    func pendingKeepsInterval() {
        var schedule = DevicePollSchedule(interval: 5)
        schedule.apply(.authorizationPending)

        #expect(schedule.interval == 5)
        #expect(schedule.shouldContinue)
    }

    /// `slow_down` widens the interval by five seconds, permanently — §3.5. The specification
    /// says the client must increase its interval, and the increase persists for the rest of
    /// the flow rather than applying to one request.
    @Test("slow_down widens the interval by five seconds")
    func slowDownWidensInterval() {
        var schedule = DevicePollSchedule(interval: 5)
        schedule.apply(.slowDown)

        #expect(schedule.interval == 10)
        #expect(schedule.shouldContinue)
    }

    /// And it accumulates. A server saying `slow_down` twice is asking for twice the room; a
    /// client that resets between requests keeps making the same mistake.
    @Test("Repeated slow_down accumulates")
    func slowDownAccumulates() {
        var schedule = DevicePollSchedule(interval: 5)
        schedule.apply(.slowDown)
        schedule.apply(.slowDown)

        #expect(schedule.interval == 15)
    }

    /// An expired device code ends the flow. Continuing to poll a dead code is how a client
    /// keeps a server busy on behalf of a user who walked away.
    @Test("expired_token stops the polling")
    func expiryStopsPolling() {
        var schedule = DevicePollSchedule(interval: 5)
        schedule.apply(.expiredToken)

        #expect(!schedule.shouldContinue)
    }

    /// A refusal ends it too, and is a different outcome from expiry: the user said no.
    @Test("access_denied stops the polling")
    func denialStopsPolling() {
        var schedule = DevicePollSchedule(interval: 5)
        schedule.apply(.accessDenied)

        #expect(!schedule.shouldContinue)
    }
}

/// The grant type and error codes RFC 8628 adds.
@Suite("RFC 8628 — grant type and errors")
struct DeviceGrantTypeTests {

    /// The wire value is the URN, not a short name — §3.4. A server matching on
    /// `"device_code"` refuses every conformant client.
    @Test("The device grant's wire value is the URN")
    func grantTypeWireValue() {
        #expect(GrantType.deviceCode.rawValue
            == "urn:ietf:params:oauth:grant-type:device_code")
    }

    /// Round-trips, so a provider dispatching on the raw string and a client encoding one agree.
    @Test("The device grant round-trips through its wire value")
    func grantTypeRoundTrips() {
        #expect(GrantType(rawValue: "urn:ietf:params:oauth:grant-type:device_code")
            == .deviceCode)
    }

    /// The three codes §3.5 defines, parsed from the wire.
    ///
    /// Without these a client sees `server_error` for `authorization_pending` — the expected
    /// answer during most of the flow — and has no way to tell "still waiting" from "something
    /// broke".
    @Test("The device grant's error codes parse")
    func errorCodesParse() {
        #expect(OAuthError(code: "authorization_pending") == .authorizationPending(nil))
        #expect(OAuthError(code: "slow_down") == .slowDown(nil))
        #expect(OAuthError(code: "expired_token") == .expiredToken(nil))
    }

    /// And encode back, so a provider can emit them.
    @Test("The device grant's error codes encode")
    func errorCodesEncode() {
        #expect(OAuthError.authorizationPending(nil).code == "authorization_pending")
        #expect(OAuthError.slowDown(nil).code == "slow_down")
        #expect(OAuthError.expiredToken(nil).code == "expired_token")
    }

    /// A poll outcome is derived from the error, in one place.
    ///
    /// Two sites deciding what `slow_down` means would eventually disagree, and the
    /// disagreement would show up as a client that polls correctly in one code path.
    @Test("A poll outcome is read from the error code")
    func outcomeFromError() {
        #expect(DevicePollOutcome(error: .authorizationPending(nil)) == .authorizationPending)
        #expect(DevicePollOutcome(error: .slowDown(nil)) == .slowDown)
        #expect(DevicePollOutcome(error: .expiredToken(nil)) == .expiredToken)
        #expect(DevicePollOutcome(error: .accessDenied(nil)) == .accessDenied)
        // Anything else is a real failure, not a polling state.
        #expect(DevicePollOutcome(error: .invalidClient(nil)) == nil)
    }
}
