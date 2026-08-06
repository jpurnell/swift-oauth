import Testing
@testable import SwiftOAuthClient

@Suite("SwiftOAuthClient — scaffold")
struct SwiftOAuthClientScaffoldTests {

    /// The module is present and links. Replaced as real behaviour lands.
    @Test("The module reports a version")
    func versionIsSet() {
        #expect(SwiftOAuthClient.version == "0.0.1")
    }
}
