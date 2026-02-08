import XCTest
@testable import Cloudflared

final class SSHServiceTokenProviderTests: XCTestCase {
    func testBuildsServiceTokenContext() async throws {
        let provider = SSHServiceTokenProvider()
        let context = try await provider.authenticate(
            hostname: "host",
            method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
        )

        XCTAssertNil(context.accessToken)
        XCTAssertEqual(context.headers[SSHAccessHeader.clientID], "id")
        XCTAssertEqual(context.headers[SSHAccessHeader.clientSecret], "secret")
    }

    func testRejectsInvalidMethod() async {
        let provider = SSHServiceTokenProvider()

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as SSHFailure {
            XCTAssertEqual(failure, .configuration("service token provider requires serviceToken auth method"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsEmptyClientID() async {
        let provider = SSHServiceTokenProvider()

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .serviceToken(teamDomain: "team", clientID: " ", clientSecret: "secret")
            )
            XCTFail("expected failure")
        } catch let failure as SSHFailure {
            XCTAssertEqual(failure, .auth("service token client id must not be empty"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testRejectsEmptyClientSecret() async {
        let provider = SSHServiceTokenProvider()

        do {
            _ = try await provider.authenticate(
                hostname: "host",
                method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: " ")
            )
            XCTFail("expected failure")
        } catch let failure as SSHFailure {
            XCTAssertEqual(failure, .auth("service token client secret must not be empty"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
