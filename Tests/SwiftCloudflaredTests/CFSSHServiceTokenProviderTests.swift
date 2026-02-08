import XCTest
@testable import SwiftCloudflared

final class CFSSHServiceTokenProviderTests: XCTestCase {
    func testBuildsServiceTokenContext() async throws {
        let provider = CFSSHServiceTokenProvider()
        let context = try await provider.authenticate(
            hostname: "host",
            method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
        )

        XCTAssertNil(context.accessToken)
        XCTAssertEqual(context.headers[CFSSHAccessHeader.clientID], "id")
        XCTAssertEqual(context.headers[CFSSHAccessHeader.clientSecret], "secret")
    }

    func testRejectsInvalidMethod() async {
        let provider = CFSSHServiceTokenProvider()

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .configuration("service token provider requires serviceToken auth method"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsEmptyClientID() async {
        let provider = CFSSHServiceTokenProvider()

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .serviceToken(teamDomain: "team", clientID: " ", clientSecret: "secret")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("service token client id must not be empty"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsEmptyClientSecret() async {
        let provider = CFSSHServiceTokenProvider()

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: " ")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("service token client secret must not be empty"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
