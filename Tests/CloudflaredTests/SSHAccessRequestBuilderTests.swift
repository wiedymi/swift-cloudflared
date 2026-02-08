import XCTest
@testable import Cloudflared

final class SSHAccessRequestBuilderTests: XCTestCase {
    func testBuildIncludesAccessTokenAndUserAgent() throws {
        let builder = SSHAccessRequestBuilder(userAgent: "ua")
        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: .appToken("jwt")
        )

        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "ua")
        XCTAssertEqual(request.value(forHTTPHeaderField: SSHAccessHeader.accessToken), "jwt")
    }

    func testBuildIncludesServiceTokenAndDestinationAndExtraHeaders() throws {
        let builder = SSHAccessRequestBuilder()
        let context = SSHAuthContext.serviceToken(id: "id", secret: "secret")

        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: context,
            destination: "10.0.0.10:22",
            additionalHeaders: ["X-Test": "1"]
        )

        XCTAssertEqual(request.value(forHTTPHeaderField: SSHAccessHeader.clientID), "id")
        XCTAssertEqual(request.value(forHTTPHeaderField: SSHAccessHeader.clientSecret), "secret")
        XCTAssertEqual(request.value(forHTTPHeaderField: SSHAccessHeader.jumpDestination), "10.0.0.10:22")
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-Test"), "1")
    }

    func testBuildSkipsEmptyTokenAndDestination() throws {
        let builder = SSHAccessRequestBuilder()
        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: SSHAuthContext(accessToken: "", headers: [:]),
            destination: ""
        )

        XCTAssertNil(request.value(forHTTPHeaderField: SSHAccessHeader.accessToken))
        XCTAssertNil(request.value(forHTTPHeaderField: SSHAccessHeader.jumpDestination))
    }
}
