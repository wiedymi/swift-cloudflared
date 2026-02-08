import XCTest
@testable import Cloudflared

final class SSHURLToolsTests: XCTestCase {
    func testNormalizeAddsHTTPS() throws {
        let url = try SSHURLTools.normalizeOriginURL(from: "ssh.example.com")
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "ssh.example.com")
    }

    func testNormalizeConvertsHTTPToHTTPS() throws {
        let url = try SSHURLTools.normalizeOriginURL(from: "http://ssh.example.com:8443/path")
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "ssh.example.com")
        XCTAssertEqual(url.port, 8443)
        XCTAssertEqual(url.path, "/path")
    }

    func testNormalizeRejectsEmptyHostname() {
        XCTAssertThrowsError(try SSHURLTools.normalizeOriginURL(from: "  ")) { error in
            XCTAssertEqual(error as? SSHFailure, .configuration("hostname must not be empty"))
        }
    }

    func testNormalizeRejectsMissingHost() {
        XCTAssertThrowsError(try SSHURLTools.normalizeOriginURL(from: "https:///path"))
    }

    func testNormalizeRejectsInvalidURLComponents() {
        XCTAssertThrowsError(try SSHURLTools.normalizeOriginURL(from: "https://[::1"))
    }

    func testWebsocketURLConversion() throws {
        let https = try XCTUnwrap(URL(string: "https://ssh.example.com/path"))
        let http = try XCTUnwrap(URL(string: "http://ssh.example.com/path"))
        let wss = try XCTUnwrap(URL(string: "wss://ssh.example.com/path"))
        let ws = try XCTUnwrap(URL(string: "ws://ssh.example.com/path"))
        let noScheme = try XCTUnwrap(URL(string: "ssh.example.com/path"))

        XCTAssertEqual(try SSHURLTools.websocketURL(from: https).scheme, "wss")
        XCTAssertEqual(try SSHURLTools.websocketURL(from: http).scheme, "ws")
        XCTAssertEqual(try SSHURLTools.websocketURL(from: wss).scheme, "wss")
        XCTAssertEqual(try SSHURLTools.websocketURL(from: ws).scheme, "ws")
        XCTAssertEqual(try SSHURLTools.websocketURL(from: noScheme).scheme, "ws")
    }

    func testWebsocketURLRejectsUnsupportedScheme() throws {
        let ftp = try XCTUnwrap(URL(string: "ftp://ssh.example.com"))
        XCTAssertThrowsError(try SSHURLTools.websocketURL(from: ftp))
    }

    func testAccessRedirectDetection() throws {
        let loginURL = try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/cdn-cgi/access/login?kid=abc"))
        let otherURL = try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/hello"))

        XCTAssertTrue(SSHURLTools.isAccessLoginRedirect(statusCode: 302, location: loginURL))
        XCTAssertFalse(SSHURLTools.isAccessLoginRedirect(statusCode: 200, location: loginURL))
        XCTAssertFalse(SSHURLTools.isAccessLoginRedirect(statusCode: 302, location: otherURL))
        XCTAssertFalse(SSHURLTools.isAccessLoginRedirect(statusCode: 302, location: nil))
    }
}
