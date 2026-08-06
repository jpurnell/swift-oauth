import Testing
@testable import SwiftOAuthCore

@Suite("SwiftOAuthCore — scaffold")
struct SwiftOAuthCoreScaffoldTests {

    /// The module is present and links. Replaced as real behaviour lands.
    @Test("The module reports a version")
    func versionIsSet() {
        #expect(SwiftOAuthCore.version == "0.0.1")
    }
}
