import Foundation

/// What an authorization server returns when a device asks to sign in — RFC 8628 §3.2.
///
/// The device grant exists for anything that cannot open a browser: a television, a
/// command-line tool, a headless machine. The device asks here, shows the user a short code,
/// and polls the token endpoint until the user has typed that code somewhere with a keyboard
/// and a screen.
public struct DeviceAuthorizationResponse: Codable, Sendable, Equatable {

    /// The device's own credential, polled with and never shown to anyone.
    ///
    /// Long and opaque, unlike ``userCode``. It is a bearer credential until redeemed: whoever
    /// holds it collects the token the user is about to authorise.
    public let deviceCode: String

    /// The short code the user types. Shown on the device's screen and nowhere else.
    public let userCode: String

    /// Where the user goes to enter it.
    public let verificationURI: URL

    /// The same place with the code already in it — §3.3.1, optional and often absent.
    ///
    /// For devices that can show a QR code, so the user types nothing.
    public let verificationURIComplete: URL?

    /// How long the device code is good for, in seconds.
    public let expiresIn: TimeInterval

    /// How long to wait between polls, in seconds.
    ///
    /// Defaults to 5 when the server omits it, per §3.2. Treating an absent interval as "no
    /// delay" means polling flat out, being told to slow down, and having to handle that anyway
    /// — with a rate limit in between.
    public let interval: TimeInterval

    private enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationURI = "verification_uri"
        case verificationURIComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
    }

    /// Creates a device authorization response.
    public init(
        deviceCode: String,
        userCode: String,
        verificationURI: URL,
        verificationURIComplete: URL? = nil,
        expiresIn: TimeInterval,
        interval: TimeInterval = 5
    ) {
        self.deviceCode = deviceCode
        self.userCode = userCode
        self.verificationURI = verificationURI
        self.verificationURIComplete = verificationURIComplete
        self.expiresIn = expiresIn
        self.interval = interval
    }

    /// Decodes a response, defaulting the interval the specification allows a server to omit.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        deviceCode = try container.decode(String.self, forKey: .deviceCode)
        userCode = try container.decode(String.self, forKey: .userCode)
        verificationURI = try container.decode(URL.self, forKey: .verificationURI)
        verificationURIComplete = try container.decodeIfPresent(
            URL.self, forKey: .verificationURIComplete)
        expiresIn = try container.decode(TimeInterval.self, forKey: .expiresIn)
        interval = try container.decodeIfPresent(TimeInterval.self, forKey: .interval) ?? 5
    }
}

/// What a poll of the token endpoint said, in the device grant — RFC 8628 §3.5.
public enum DevicePollOutcome: Sendable, Equatable {
    /// The user has not finished yet. Keep waiting, at the same interval.
    case authorizationPending
    /// Polling too fast. Widen the interval and keep waiting.
    case slowDown
    /// The user refused.
    case accessDenied
    /// The device code expired before the user finished.
    case expiredToken
    /// The user approved, and the token endpoint answered.
    case issued

    /// Reads a poll outcome from what the token endpoint returned.
    ///
    /// One place decides what `slow_down` means. Two sites deciding it would eventually
    /// disagree, and the disagreement would surface as a client that polls correctly along one
    /// code path and gets rate-limited along another.
    ///
    /// - Parameter error: The error the token endpoint returned.
    /// - Returns: The polling state, or `nil` if this is a real failure rather than one of the
    ///   states the flow passes through. `invalid_client` is not a reason to keep waiting.
    public init?(error: OAuthError) {
        switch error {
        case .authorizationPending: self = .authorizationPending
        case .slowDown: self = .slowDown
        case .expiredToken: self = .expiredToken
        case .accessDenied: self = .accessDenied
        default: return nil
        }
    }
}

/// How long to wait before the next poll, and whether to poll at all — RFC 8628 §3.5.
///
/// Small enough to look unnecessary, and it is the part implementations get wrong. Both rules
/// here are ones a plausible implementation breaks:
///
/// - `slow_down` widens the interval **permanently**, not for one request. A client that
///   applies it once and reverts keeps making the same mistake at the same rate.
/// - The widening **accumulates**. A server saying it twice is asking for twice the room.
///
/// The consequence of getting either wrong is a rate limit, arriving from a server that was
/// trying to tell the client how to avoid one.
public struct DevicePollSchedule: Sendable, Equatable {

    /// Seconds to wait before the next poll.
    public private(set) var interval: TimeInterval

    /// Whether the flow is still running.
    public private(set) var shouldContinue: Bool

    /// How much a `slow_down` adds — §3.5 names five seconds.
    private static let slowDownIncrement: TimeInterval = 5

    /// Creates a schedule from a server's stated interval.
    public init(interval: TimeInterval) {
        self.interval = interval
        self.shouldContinue = true
    }

    /// Applies what a poll returned.
    ///
    /// - Parameter outcome: What the token endpoint said.
    public mutating func apply(_ outcome: DevicePollOutcome) {
        switch outcome {
        case .authorizationPending:
            break
        case .slowDown:
            interval += Self.slowDownIncrement
        case .accessDenied, .expiredToken, .issued:
            shouldContinue = false
        }
    }
}
