import XCTest
@testable import Cloudflared

final class SSHJWTValidatorTests: XCTestCase {
    func testValidTokenNotExpired() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let token = makeJWT(expiration: 2_000)
        let validator = SSHJWTValidator(clock: FixedClock(now: now))

        XCTAssertFalse(try validator.isExpired(token))
    }

    func testExpiredToken() throws {
        let now = Date(timeIntervalSince1970: 3_000)
        let token = makeJWT(expiration: 2_000)
        let validator = SSHJWTValidator(clock: FixedClock(now: now))

        XCTAssertTrue(try validator.isExpired(token))
    }

    func testRejectsMalformedToken() {
        let validator = SSHJWTValidator(clock: FixedClock(now: Date(timeIntervalSince1970: 0)))
        XCTAssertThrowsError(try validator.isExpired("not-a-jwt"))
    }

    func testRejectsMissingExp() {
        let validator = SSHJWTValidator(clock: FixedClock(now: Date(timeIntervalSince1970: 0)))
        XCTAssertThrowsError(try validator.isExpired(makeInvalidJWTWithoutExp()))
    }

    func testRejectsInvalidBase64Payload() {
        let validator = SSHJWTValidator(clock: FixedClock(now: Date(timeIntervalSince1970: 0)))
        XCTAssertThrowsError(try validator.isExpired("a.*.sig"))
    }

    func testDefaultClockInitializerPath() throws {
        let validator = SSHJWTValidator()
        let token = makeJWT(expiration: 4_102_444_800) // year 2100
        _ = try validator.isExpired(token)
    }
}
