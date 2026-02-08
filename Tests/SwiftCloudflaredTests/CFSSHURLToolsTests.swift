import XCTest
@testable import SwiftCloudflared

final class CFSSHURLToolsTests: XCTestCase {
    func testNormalizeAddsHTTPS() throws {
        let url = try CFSSHURLTools.normalizeOriginURL(from: "ssh.example.com")
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "ssh.example.com")
    }

    func testNormalizeConvertsHTTPToHTTPS() throws {
        let url = try CFSSHURLTools.normalizeOriginURL(from: "http://ssh.example.com:8443/path")
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "ssh.example.com")
        XCTAssertEqual(url.port, 8443)
        XCTAssertEqual(url.path, "/path")
    }

    func testNormalizeRejectsEmptyHostname() {
        XCTAssertThrowsError(try CFSSHURLTools.normalizeOriginURL(from: "  ")) { error in
            XCTAssertEqual(error as? CFSSHFailure, .configuration("hostname must not be empty"))
        }
    }

    func testNormalizeRejectsMissingHost() {
        XCTAssertThrowsError(try CFSSHURLTools.normalizeOriginURL(from: "https:///path"))
    }

    func testNormalizeRejectsInvalidURLComponents() {
        XCTAssertThrowsError(try CFSSHURLTools.normalizeOriginURL(from: "https://[::1"))
    }

    func testWebsocketURLConversion() throws {
        let https = try XCTUnwrap(URL(string: "https://ssh.example.com/path"))
        let http = try XCTUnwrap(URL(string: "http://ssh.example.com/path"))
        let wss = try XCTUnwrap(URL(string: "wss://ssh.example.com/path"))
        let ws = try XCTUnwrap(URL(string: "ws://ssh.example.com/path"))
        let noScheme = try XCTUnwrap(URL(string: "ssh.example.com/path"))

        XCTAssertEqual(try CFSSHURLTools.websocketURL(from: https).scheme, "wss")
        XCTAssertEqual(try CFSSHURLTools.websocketURL(from: http).scheme, "ws")
        XCTAssertEqual(try CFSSHURLTools.websocketURL(from: wss).scheme, "wss")
        XCTAssertEqual(try CFSSHURLTools.websocketURL(from: ws).scheme, "ws")
        XCTAssertEqual(try CFSSHURLTools.websocketURL(from: noScheme).scheme, "ws")
    }

    func testWebsocketURLRejectsUnsupportedScheme() throws {
        let ftp = try XCTUnwrap(URL(string: "ftp://ssh.example.com"))
        XCTAssertThrowsError(try CFSSHURLTools.websocketURL(from: ftp))
    }

    func testAccessRedirectDetection() throws {
        let loginURL = try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/cdn-cgi/access/login?kid=abc"))
        let otherURL = try XCTUnwrap(URL(string: "https://team.cloudflareaccess.com/hello"))

        XCTAssertTrue(CFSSHURLTools.isAccessLoginRedirect(statusCode: 302, location: loginURL))
        XCTAssertFalse(CFSSHURLTools.isAccessLoginRedirect(statusCode: 200, location: loginURL))
        XCTAssertFalse(CFSSHURLTools.isAccessLoginRedirect(statusCode: 302, location: otherURL))
        XCTAssertFalse(CFSSHURLTools.isAccessLoginRedirect(statusCode: 302, location: nil))
    }
}
