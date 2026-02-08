import Foundation

public struct SSHAppInfo: Sendable, Equatable {
    public let authDomain: String
    public let appAUD: String
    public let appDomain: String

    public init(authDomain: String, appAUD: String, appDomain: String) {
        self.authDomain = authDomain
        self.appAUD = appAUD
        self.appDomain = appDomain
    }
}

public enum SSHAppInfoParser {
    public static func parse(requestURL: URL, response: HTTPURLResponse) throws -> SSHAppInfo {
        guard let finalURL = response.url, let authDomain = finalURL.host, !authDomain.isEmpty else {
            throw SSHFailure.protocolViolation("response is missing final URL host")
        }

        let appDomain = response.value(forHTTPHeaderField: SSHAccessHeader.appDomain) ?? ""
        guard !appDomain.isEmpty else {
            throw SSHFailure.protocolViolation("missing \(SSHAccessHeader.appDomain) header")
        }

        let appAUD: String
        if finalURL.path.contains(SSHAccessPath.login) {
            appAUD = URLComponents(url: finalURL, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "kid" })?
                .value ?? ""
            guard !appAUD.isEmpty else {
                throw SSHFailure.protocolViolation("missing kid query parameter in login redirect")
            }
        } else if let headerAUD = response.value(forHTTPHeaderField: SSHAccessHeader.appAUD), !headerAUD.isEmpty {
            appAUD = headerAUD
        } else {
            throw SSHFailure.protocolViolation("unable to resolve app AUD for \(requestURL.absoluteString)")
        }

        return SSHAppInfo(authDomain: authDomain, appAUD: appAUD, appDomain: appDomain)
    }
}

public protocol SSHHTTPClient: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct SSHAppInfoResolver: Sendable {
    private let client: any SSHHTTPClient
    private let userAgent: String

    public init(client: any SSHHTTPClient, userAgent: String = "swift-cloudflared") {
        self.client = client
        self.userAgent = userAgent
    }

    public func resolve(appURL: URL) async throws -> SSHAppInfo {
        var request = URLRequest(url: appURL)
        request.httpMethod = "HEAD"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        let (_, response) = try await client.send(request)
        return try SSHAppInfoParser.parse(requestURL: appURL, response: response)
    }
}
