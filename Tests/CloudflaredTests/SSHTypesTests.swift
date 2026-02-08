import XCTest
@testable import Cloudflared

final class SSHTypesTests: XCTestCase {
    func testRetryableFlag() {
        XCTAssertTrue(SSHFailure.transport("x", retryable: true).isRetryable)
        XCTAssertFalse(SSHFailure.auth("x").isRetryable)
    }
}
