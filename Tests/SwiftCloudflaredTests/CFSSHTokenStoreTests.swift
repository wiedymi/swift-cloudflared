import XCTest
@testable import SwiftCloudflared
#if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))
import Security
#endif

final class CFSSHTokenStoreTests: XCTestCase {
    func testInMemoryStoreRoundTrip() async throws {
        let store = CFSSHInMemoryTokenStore()
        let initial = try await store.readToken(for: "k")
        XCTAssertNil(initial)

        try await store.writeToken("value", for: "k")
        let saved = try await store.readToken(for: "k")
        XCTAssertEqual(saved, "value")

        try await store.removeToken(for: "k")
        let removed = try await store.readToken(for: "k")
        XCTAssertNil(removed)
    }

#if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))
    func testKeychainStoreRoundTrip() async throws {
        guard ProcessInfo.processInfo.environment["SWIFT_CLOUDFLARED_KEYCHAIN_TESTS"] == "1" else {
            throw XCTSkip(
                "Keychain round-trip test is opt-in. Set SWIFT_CLOUDFLARED_KEYCHAIN_TESTS=1 to run it."
            )
        }

        let service = "com.swift-cloudflared.tests.\(UUID().uuidString)"
        let key = "token-\(UUID().uuidString)"
        let store = CFSSHKeychainTokenStore(service: service)

        try await store.removeToken(for: key)
        let initial = try await store.readToken(for: key)
        XCTAssertNil(initial)

        try await store.writeToken("value", for: key)
        let saved = try await store.readToken(for: key)
        XCTAssertEqual(saved, "value")

        try await store.removeToken(for: key)
        let removed = try await store.readToken(for: key)
        XCTAssertNil(removed)
    }
#endif
}
