import XCTest
@testable import Cloudflared

final class TypesTests: XCTestCase {
    func testRetryableFlag() {
        XCTAssertTrue(Failure.transport("x", retryable: true).isRetryable)
        XCTAssertFalse(Failure.auth("x").isRetryable)
    }
}
