import XCTest
@testable import SwiftCloudflared

final class CFSSHAuthMultiplexerTests: XCTestCase {
    func testRoutesOAuthRequestsToOAuthProvider() async throws {
        let multiplexer = CFSSHAuthMultiplexer(
            oauthProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            serviceProvider: ClosureAuthProvider { _, _ in .serviceToken(id: "id", secret: "secret") }
        )

        let context = try await multiplexer.authenticate(
            hostname: "host",
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        XCTAssertEqual(context, .appToken("jwt"))
    }

    func testRoutesServiceRequestsToServiceProvider() async throws {
        let multiplexer = CFSSHAuthMultiplexer(
            oauthProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            serviceProvider: ClosureAuthProvider { _, _ in .serviceToken(id: "id", secret: "secret") }
        )

        let context = try await multiplexer.authenticate(
            hostname: "host",
            method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
        )

        XCTAssertEqual(context.headers[CFSSHAccessHeader.clientID], "id")
    }

    func testFallsBackToOAuthWhenConfigured() async throws {
        let multiplexer = CFSSHAuthMultiplexer(
            oauthProvider: ClosureAuthProvider { _, _ in .appToken("oauth-token") },
            serviceProvider: ClosureAuthProvider { _, _ in throw CFSSHFailure.auth("service denied") },
            oauthFallback: { _ in
                .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            }
        )

        let context = try await multiplexer.authenticate(
            hostname: "host",
            method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
        )

        XCTAssertEqual(context, .appToken("oauth-token"))
    }

    func testServiceErrorWithoutFallbackIsPropagated() async {
        let multiplexer = CFSSHAuthMultiplexer(
            oauthProvider: ClosureAuthProvider { _, _ in .appToken("oauth-token") },
            serviceProvider: ClosureAuthProvider { _, _ in throw CFSSHFailure.auth("service denied") },
            oauthFallback: nil
        )

        do {
            _ = try await multiplexer.authenticate(
                hostname: "host",
                method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("service denied"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
