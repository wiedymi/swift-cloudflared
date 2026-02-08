import Foundation
import XCTest
import TweetNacl
@testable import Cloudflared

private actor MockOAuthWebSession: OAuthWebSession {
    private(set) var startedURLs: [URL] = []
    private(set) var stopCalls = 0
    private var cancelled = false
    private let cancelAfterStart: Bool

    init(cancelAfterStart: Bool = false) {
        self.cancelAfterStart = cancelAfterStart
    }

    func start(url: URL) async throws {
        startedURLs.append(url)
        if cancelAfterStart {
            cancelled = true
        }
    }

    func stop() async {
        stopCalls += 1
    }

    func didCancelLogin() async -> Bool {
        cancelled
    }
}

private struct ClosureHTTPClient: HTTPClient {
    let handler: @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await handler(request)
    }
}

private func base64URLEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
}

private func decodeBase64URL(_ value: String) -> Data? {
    let variants = [
        value,
        value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
    ]

    for variant in variants {
        var candidate = variant
        let paddingNeeded = (4 - (candidate.count % 4)) % 4
        if paddingNeeded > 0 {
            candidate.append(String(repeating: "=", count: paddingNeeded))
        }
        if let decoded = Data(base64Encoded: candidate) {
            return decoded
        }
    }

    return nil
}

final class TransferOAuthFlowTests: XCTestCase {
    func testFetchTokenDecryptsTransferPayload() async throws {
        let appHost = "maomao.aestia.dev"
        let appURL = URL(string: "https://\(appHost)")!
        let token = makeJWT(expiration: 10_000)
        let serviceKeys = try NaclBox.keyPair()
        let servicePublicKey = base64URLEncode(serviceKeys.publicKey)
        let session = MockOAuthWebSession()

        let client = ClosureHTTPClient { request in
            guard let requestURL = request.url else {
                throw Failure.protocolViolation("missing request url")
            }

            if requestURL.host == appHost, request.httpMethod == "HEAD" {
                let loginURL = URL(string: "https://login.cloudflareaccess.org/cdn-cgi/access/login?kid=test-aud")!
                let response = HTTPURLResponse(
                    url: loginURL,
                    statusCode: 302,
                    httpVersion: nil,
                    headerFields: [AccessHeader.appDomain: appHost]
                )!
                return (Data(), response)
            }

            if requestURL.host == "login.cloudflareaccess.org", requestURL.path.hasPrefix("/transfer/") {
                let encodedClientPublicKey = (requestURL.lastPathComponent.removingPercentEncoding ?? requestURL.lastPathComponent)
                guard let clientPublicKey = decodeBase64URL(encodedClientPublicKey) else {
                    throw Failure.protocolViolation("unable to decode client transfer key")
                }

                let payloadData = try JSONSerialization.data(
                    withJSONObject: ["app_token": token],
                    options: []
                )
                let nonce = Data((0..<24).map { UInt8($0) })
                let boxed = try NaclBox.box(
                    message: payloadData,
                    nonce: nonce,
                    publicKey: clientPublicKey,
                    secretKey: serviceKeys.secretKey
                )
                var encryptedPayload = Data()
                encryptedPayload.append(nonce)
                encryptedPayload.append(boxed)

                let response = HTTPURLResponse(
                    url: requestURL,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["service-public-key": servicePublicKey]
                )!
                return (Data(encryptedPayload.base64EncodedString().utf8), response)
            }

            throw Failure.protocolViolation("unexpected request \(requestURL.absoluteString)")
        }

        let flow = TransferOAuthFlow(
            webSession: session,
            httpClient: client,
            userAgent: "CloudflaredTests",
            pollAttempts: 1,
            pollDelayNanoseconds: 0
        )

        let receivedToken = try await flow.fetchToken(
            teamDomain: "",
            appDomain: "",
            callbackScheme: "ignored",
            hostname: appURL.absoluteString
        )

        XCTAssertEqual(receivedToken, token)
        let startedURLs = await session.startedURLs
        let stopCalls = await session.stopCalls
        XCTAssertEqual(startedURLs.count, 1)
        XCTAssertEqual(startedURLs.first?.host, appHost)
        XCTAssertEqual(startedURLs.first?.path, "/cdn-cgi/access/cli")
        XCTAssertEqual(stopCalls, 1)
    }

    func testFetchTokenStopsSessionWhenUserCancels() async {
        let appHost = "maomao.aestia.dev"
        let session = MockOAuthWebSession(cancelAfterStart: true)
        let client = ClosureHTTPClient { request in
            guard let requestURL = request.url else {
                throw Failure.protocolViolation("missing request url")
            }

            if requestURL.host == appHost, request.httpMethod == "HEAD" {
                let loginURL = URL(string: "https://login.cloudflareaccess.org/cdn-cgi/access/login?kid=test-aud")!
                let response = HTTPURLResponse(
                    url: loginURL,
                    statusCode: 302,
                    httpVersion: nil,
                    headerFields: [AccessHeader.appDomain: appHost]
                )!
                return (Data(), response)
            }

            throw Failure.protocolViolation("poll should not run when session is already cancelled")
        }

        let flow = TransferOAuthFlow(
            webSession: session,
            httpClient: client,
            userAgent: "CloudflaredTests",
            pollAttempts: 1,
            pollDelayNanoseconds: 0
        )

        do {
            _ = try await flow.fetchToken(
                teamDomain: "",
                appDomain: "",
                callbackScheme: "ignored",
                hostname: appHost
            )
            XCTFail("expected cancellation failure")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .auth("Cloudflare login was cancelled"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        let stopCalls = await session.stopCalls
        XCTAssertEqual(stopCalls, 1)
    }

}
