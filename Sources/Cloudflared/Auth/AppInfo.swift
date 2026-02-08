import Foundation

public struct AppInfo: Sendable, Equatable {
    public let authDomain: String
    public let appAUD: String
    public let appDomain: String

    public init(authDomain: String, appAUD: String, appDomain: String) {
        self.authDomain = authDomain
        self.appAUD = appAUD
        self.appDomain = appDomain
    }
}

public enum AppInfoParser {
    public static func parse(requestURL: URL, response: HTTPURLResponse) throws -> AppInfo {
        guard let finalURL = response.url, let authDomain = finalURL.host, !authDomain.isEmpty else {
            throw Failure.protocolViolation("response is missing final URL host")
        }

        let appDomain = response.value(forHTTPHeaderField: AccessHeader.appDomain) ?? ""
        guard !appDomain.isEmpty else {
            throw Failure.protocolViolation("missing \(AccessHeader.appDomain) header")
        }

        let appAUD: String
        if finalURL.path.contains(AccessPath.login) {
            appAUD = URLComponents(url: finalURL, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "kid" })?
                .value ?? ""
            guard !appAUD.isEmpty else {
                throw Failure.protocolViolation("missing kid query parameter in login redirect")
            }
        } else if let headerAUD = response.value(forHTTPHeaderField: AccessHeader.appAUD), !headerAUD.isEmpty {
            appAUD = headerAUD
        } else {
            throw Failure.protocolViolation("unable to resolve app AUD for \(requestURL.absoluteString)")
        }

        return AppInfo(authDomain: authDomain, appAUD: appAUD, appDomain: appDomain)
    }
}

public protocol HTTPClient: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct AppInfoResolver: Sendable {
    private let client: any HTTPClient
    private let userAgent: String

    public init(client: any HTTPClient, userAgent: String = "swift-cloudflared") {
        self.client = client
        self.userAgent = userAgent
    }

    public func resolve(appURL: URL) async throws -> AppInfo {
        var request = URLRequest(url: appURL)
        request.httpMethod = "HEAD"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        let (_, response) = try await client.send(request)
        return try AppInfoParser.parse(requestURL: appURL, response: response)
    }
}
