import XCTest
@testable import SwiftCloudflared

final class CFSSHTypesTests: XCTestCase {
    func testRetryableFlag() {
        XCTAssertTrue(CFSSHFailure.transport("x", retryable: true).isRetryable)
        XCTAssertFalse(CFSSHFailure.auth("x").isRetryable)
    }
}
