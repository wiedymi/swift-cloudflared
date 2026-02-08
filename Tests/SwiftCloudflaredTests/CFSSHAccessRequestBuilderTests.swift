import XCTest
@testable import SwiftCloudflared

final class CFSSHAccessRequestBuilderTests: XCTestCase {
    func testBuildIncludesAccessTokenAndUserAgent() throws {
        let builder = CFSSHAccessRequestBuilder(userAgent: "ua")
        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: .appToken("jwt")
        )

        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "ua")
        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.accessToken), "jwt")
    }

    func testBuildIncludesServiceTokenAndDestinationAndExtraHeaders() throws {
        let builder = CFSSHAccessRequestBuilder()
        let context = CFSSHAuthContext.serviceToken(id: "id", secret: "secret")

        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: context,
            destination: "10.0.0.10:22",
            additionalHeaders: ["X-Test": "1"]
        )

        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.clientID), "id")
        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.clientSecret), "secret")
        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.jumpDestination), "10.0.0.10:22")
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-Test"), "1")
    }

    func testBuildSkipsEmptyTokenAndDestination() throws {
        let builder = CFSSHAccessRequestBuilder()
        let request = builder.build(
            originURL: try XCTUnwrap(URL(string: "https://ssh.example.com")),
            authContext: CFSSHAuthContext(accessToken: "", headers: [:]),
            destination: ""
        )

        XCTAssertNil(request.value(forHTTPHeaderField: CFSSHAccessHeader.accessToken))
        XCTAssertNil(request.value(forHTTPHeaderField: CFSSHAccessHeader.jumpDestination))
    }
}
