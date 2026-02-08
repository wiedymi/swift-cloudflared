import XCTest
@testable import SwiftCloudflared

final class CFSSHOAuthProviderTests: XCTestCase {
    func testUsesCachedTokenWhenValid() async throws {
        let now = Date(timeIntervalSince1970: 100)
        let token = makeJWT(expiration: 200)
        let store = CFSSHInMemoryTokenStore(initialStorage: [
            "oauth|team|app|host": token
        ])
        let flow = MockOAuthFlow(token: makeJWT(expiration: 500))
        let provider = CFSSHOAuthProvider(
            flow: flow,
            tokenStore: store,
            validator: CFSSHJWTValidator(clock: FixedClock(now: now))
        )

        let context = try await provider.authenticate(
            hostname: "host",
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        XCTAssertEqual(context, .appToken(token))
        let calls = await flow.callCount
        XCTAssertEqual(calls, 0)
    }

    func testFetchesAndStoresTokenWhenMissing() async throws {
        let now = Date(timeIntervalSince1970: 100)
        let fresh = makeJWT(expiration: 500)
        let store = CFSSHInMemoryTokenStore()
        let flow = MockOAuthFlow(token: fresh)
        let provider = CFSSHOAuthProvider(
            flow: flow,
            tokenStore: store,
            validator: CFSSHJWTValidator(clock: FixedClock(now: now))
        )

        let context = try await provider.authenticate(
            hostname: "host",
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        XCTAssertEqual(context, .appToken(fresh))
        let calls = await flow.callCount
        let saved = try await store.readToken(for: "oauth|team|app|host")
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(saved, fresh)
    }

    func testExpiredCachedTokenGetsReplaced() async throws {
        let now = Date(timeIntervalSince1970: 500)
        let expired = makeJWT(expiration: 100)
        let fresh = makeJWT(expiration: 1000)
        let store = CFSSHInMemoryTokenStore(initialStorage: [
            "oauth|team|app|host": expired
        ])
        let flow = MockOAuthFlow(token: fresh)
        let provider = CFSSHOAuthProvider(
            flow: flow,
            tokenStore: store,
            validator: CFSSHJWTValidator(clock: FixedClock(now: now))
        )

        let context = try await provider.authenticate(
            hostname: "host",
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        XCTAssertEqual(context, .appToken(fresh))
        let calls = await flow.callCount
        XCTAssertEqual(calls, 1)
    }

    func testMalformedCachedTokenGetsReplaced() async throws {
        let now = Date(timeIntervalSince1970: 100)
        let store = CFSSHInMemoryTokenStore(initialStorage: [
            "oauth|team|app|host": "not-a-jwt"
        ])
        let fresh = makeJWT(expiration: 500)
        let flow = MockOAuthFlow(token: fresh)
        let provider = CFSSHOAuthProvider(
            flow: flow,
            tokenStore: store,
            validator: CFSSHJWTValidator(clock: FixedClock(now: now))
        )

        let context = try await provider.authenticate(
            hostname: "host",
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        XCTAssertEqual(context, .appToken(fresh))
        let calls = await flow.callCount
        XCTAssertEqual(calls, 1)
    }

    func testRejectsNonOAuthMethod() async {
        let provider = CFSSHOAuthProvider(
            flow: MockOAuthFlow(token: makeJWT(expiration: 200)),
            tokenStore: CFSSHInMemoryTokenStore(),
            validator: CFSSHJWTValidator(clock: FixedClock(now: Date(timeIntervalSince1970: 0)))
        )

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .configuration("oauth provider requires oauth auth method"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsEmptyTokenFromFlow() async {
        let provider = CFSSHOAuthProvider(
            flow: MockOAuthFlow(token: "  "),
            tokenStore: CFSSHInMemoryTokenStore(),
            validator: CFSSHJWTValidator(clock: FixedClock(now: Date(timeIntervalSince1970: 0)))
        )

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("oauth flow returned empty token"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsExpiredTokenFromFlow() async {
        let now = Date(timeIntervalSince1970: 500)
        let provider = CFSSHOAuthProvider(
            flow: MockOAuthFlow(token: makeJWT(expiration: 100)),
            tokenStore: CFSSHInMemoryTokenStore(),
            validator: CFSSHJWTValidator(clock: FixedClock(now: now))
        )

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("oauth flow returned expired token"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsInvalidTokenFromFlow() async {
        let header = Data("{\"alg\":\"none\"}".utf8).base64EncodedString()
        let payload = Data("not-json".utf8).base64EncodedString()
        let invalid = "\(header).\(payload).sig"

        let provider = CFSSHOAuthProvider(
            flow: MockOAuthFlow(token: invalid),
            tokenStore: CFSSHInMemoryTokenStore(),
            validator: CFSSHJWTValidator(clock: FixedClock(now: Date(timeIntervalSince1970: 0)))
        )

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("oauth flow returned invalid token"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
