import Foundation

public struct CFSSHAppInfo: Sendable, Equatable {
    public let authDomain: String
    public let appAUD: String
    public let appDomain: String

    public init(authDomain: String, appAUD: String, appDomain: String) {
        self.authDomain = authDomain
        self.appAUD = appAUD
        self.appDomain = appDomain
    }
}

public enum CFSSHAppInfoParser {
    public static func parse(requestURL: URL, response: HTTPURLResponse) throws -> CFSSHAppInfo {
        guard let finalURL = response.url, let authDomain = finalURL.host, !authDomain.isEmpty else {
            throw CFSSHFailure.protocolViolation("response is missing final URL host")
        }

        let appDomain = response.value(forHTTPHeaderField: CFSSHAccessHeader.appDomain) ?? ""
        guard !appDomain.isEmpty else {
            throw CFSSHFailure.protocolViolation("missing \(CFSSHAccessHeader.appDomain) header")
        }

        let appAUD: String
        if finalURL.path.contains(CFSSHAccessPath.login) {
            appAUD = URLComponents(url: finalURL, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "kid" })?
                .value ?? ""
            guard !appAUD.isEmpty else {
                throw CFSSHFailure.protocolViolation("missing kid query parameter in login redirect")
            }
        } else if let headerAUD = response.value(forHTTPHeaderField: CFSSHAccessHeader.appAUD), !headerAUD.isEmpty {
            appAUD = headerAUD
        } else {
            throw CFSSHFailure.protocolViolation("unable to resolve app AUD for \(requestURL.absoluteString)")
        }

        return CFSSHAppInfo(authDomain: authDomain, appAUD: appAUD, appDomain: appDomain)
    }
}

public protocol CFSSHHTTPClient: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct CFSSHAppInfoResolver: Sendable {
    private let client: any CFSSHHTTPClient
    private let userAgent: String

    public init(client: any CFSSHHTTPClient, userAgent: String = "swift-cloudflared") {
        self.client = client
        self.userAgent = userAgent
    }

    public func resolve(appURL: URL) async throws -> CFSSHAppInfo {
        var request = URLRequest(url: appURL)
        request.httpMethod = "HEAD"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        let (_, response) = try await client.send(request)
        return try CFSSHAppInfoParser.parse(requestURL: appURL, response: response)
    }
}
