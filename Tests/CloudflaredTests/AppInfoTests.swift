import XCTest
import Foundation
@testable import Cloudflared

final class AppInfoTests: XCTestCase {
    func testParseFromLoginRedirect() throws {
        let requestURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let finalURL = try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/cdn-cgi/access/login?kid=aud123"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: finalURL,
                statusCode: 302,
                httpVersion: nil,
                headerFields: [
                    AccessHeader.appDomain: "ssh.example.com"
                ]
            )
        )

        let info = try AppInfoParser.parse(requestURL: requestURL, response: response)
        XCTAssertEqual(info, AppInfo(authDomain: "team.cloudflareaccess.com", appAUD: "aud123", appDomain: "ssh.example.com"))
    }

    func testParseFromAUDHeader() throws {
        let requestURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let finalURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: finalURL,
                statusCode: 403,
                httpVersion: nil,
                headerFields: [
                    AccessHeader.appDomain: "ssh.example.com",
                    AccessHeader.appAUD: "aud456",
                ]
            )
        )

        let info = try AppInfoParser.parse(requestURL: requestURL, response: response)
        XCTAssertEqual(info, AppInfo(authDomain: "ssh.example.com", appAUD: "aud456", appDomain: "ssh.example.com"))
    }

    func testParseRejectsMissingDomainHeader() throws {
        let requestURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: try XCTUnwrap(URL(string: "https://ssh.example.com")),
                statusCode: 403,
                httpVersion: nil,
                headerFields: [:]
            )
        )

        XCTAssertThrowsError(try AppInfoParser.parse(requestURL: requestURL, response: response))
    }

    func testParseRejectsMissingKidOnLoginRedirect() throws {
        let requestURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/cdn-cgi/access/login")),
                statusCode: 302,
                httpVersion: nil,
                headerFields: [
                    AccessHeader.appDomain: "ssh.example.com"
                ]
            )
        )

        XCTAssertThrowsError(try AppInfoParser.parse(requestURL: requestURL, response: response))
    }

    func testParseRejectsMissingAuthDomain() throws {
        let requestURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: try XCTUnwrap(URL(string: "file:///tmp/no-host")),
                statusCode: 200,
                httpVersion: nil,
                headerFields: [AccessHeader.appDomain: "ssh.example.com", AccessHeader.appAUD: "aud"]
            )
        )

        XCTAssertThrowsError(try AppInfoParser.parse(requestURL: requestURL, response: response))
    }

    func testParseRejectsMissingAUDOutsideLogin() throws {
        let requestURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: try XCTUnwrap(URL(string: "https://ssh.example.com/allowed")),
                statusCode: 403,
                httpVersion: nil,
                headerFields: [AccessHeader.appDomain: "ssh.example.com"]
            )
        )

        XCTAssertThrowsError(try AppInfoParser.parse(requestURL: requestURL, response: response))
    }

    func testResolverBuildsHEADRequestAndParsesResponse() async throws {
        let appURL = try XCTUnwrap(URL(string: "https://ssh.example.com"))
        let client = MockHTTPClient(
            responseURL: try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/cdn-cgi/access/login?kid=aud789")),
            statusCode: 302,
            headers: [AccessHeader.appDomain: "ssh.example.com"]
        )

        let resolver = AppInfoResolver(client: client, userAgent: "test-agent")
        let info = try await resolver.resolve(appURL: appURL)

        XCTAssertEqual(info.appAUD, "aud789")
        let request = await client.lastRequest
        XCTAssertEqual(request?.httpMethod, "HEAD")
        XCTAssertEqual(request?.value(forHTTPHeaderField: "User-Agent"), "test-agent")
    }
}

actor MockHTTPClient: HTTPClient {
    private(set) var lastRequest: URLRequest?

    private let responseURL: URL
    private let statusCode: Int
    private let headers: [String: String]

    init(responseURL: URL, statusCode: Int, headers: [String: String]) {
        self.responseURL = responseURL
        self.statusCode = statusCode
        self.headers = headers
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        lastRequest = request
        let response = HTTPURLResponse(
            url: responseURL,
            statusCode: statusCode,
            httpVersion: nil,
            headerFields: headers
        )!
        return (Data(), response)
    }
}
