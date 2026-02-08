import XCTest
@testable import Cloudflared

final class AccessRequestBuilderTests: XCTestCase {
    func testBuildIncludesAccessTokenAndUserAgent() throws {
        let builder = AccessRequestBuilder(userAgent: "ua")
        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: .appToken("jwt")
        )

        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "ua")
        XCTAssertEqual(request.value(forHTTPHeaderField: AccessHeader.accessToken), "jwt")
    }

    func testBuildIncludesServiceTokenAndDestinationAndExtraHeaders() throws {
        let builder = AccessRequestBuilder()
        let context = AuthContext.serviceToken(id: "id", secret: "secret")

        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: context,
            destination: "10.0.0.10:22",
            additionalHeaders: ["X-Test": "1"]
        )

        XCTAssertEqual(request.value(forHTTPHeaderField: AccessHeader.clientID), "id")
        XCTAssertEqual(request.value(forHTTPHeaderField: AccessHeader.clientSecret), "secret")
        XCTAssertEqual(request.value(forHTTPHeaderField: AccessHeader.jumpDestination), "10.0.0.10:22")
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-Test"), "1")
    }

    func testBuildSkipsEmptyTokenAndDestination() throws {
        let builder = AccessRequestBuilder()
        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: AuthContext(accessToken: "", headers: [:]),
            destination: ""
        )

        XCTAssertNil(request.value(forHTTPHeaderField: AccessHeader.accessToken))
        XCTAssertNil(request.value(forHTTPHeaderField: AccessHeader.jumpDestination))
    }
}
