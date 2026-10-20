import XCTest
@testable import Cloudflared

final class RetryPolicyTests: XCTestCase {
    func testDelayClampsAttemptsAndPreservesExactProducts() {
        let policy = RetryPolicy(baseDelayNanoseconds: 7)
        XCTAssertEqual(policy.delayNanoseconds(for: Int.min), 7)
        XCTAssertEqual(policy.delayNanoseconds(for: 0), 7)
        XCTAssertEqual(policy.delayNanoseconds(for: 3), 21)
        XCTAssertEqual(RetryPolicy(baseDelayNanoseconds: 0).delayNanoseconds(for: Int.max), 0)
        XCTAssertEqual(RetryPolicy(baseDelayNanoseconds: UInt64.max).delayNanoseconds(for: 1), UInt64.max)
    }

    func testOverflowSaturatesWithoutWrappingOrTrapping() {
        XCTAssertEqual(RetryPolicy(baseDelayNanoseconds: UInt64.max).delayNanoseconds(for: 2), UInt64.max)
        XCTAssertEqual(RetryPolicy(baseDelayNanoseconds: UInt64.max / 2 + 1).delayNanoseconds(for: 2), UInt64.max)
        XCTAssertEqual(RetryPolicy(baseDelayNanoseconds: 3).delayNanoseconds(for: Int.max), UInt64.max)
    }
}
