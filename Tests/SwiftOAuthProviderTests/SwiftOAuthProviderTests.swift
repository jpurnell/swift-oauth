import Testing
@testable import SwiftOAuthProvider

@Suite("SwiftOAuthProvider — scaffold")
struct SwiftOAuthProviderScaffoldTests {

    /// The module is present and links. Replaced as real behaviour lands.
    @Test("The module reports a version")
    func versionIsSet() {
        #expect(SwiftOAuthProvider.version == "0.0.1")
    }
}
