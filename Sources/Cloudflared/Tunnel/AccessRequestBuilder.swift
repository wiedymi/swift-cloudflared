import Foundation

public struct AccessRequestBuilder: Sendable {
    private let userAgent: String

    public init(userAgent: String = "swift-cloudflared") {
        self.userAgent = userAgent
    }

    public func build(
        originURL: URL,
        authContext: AuthContext,
        destination: String? = nil,
        additionalHeaders: [String: String] = [:]
    ) -> URLRequest {
        var request = URLRequest(url: originURL)
        request.httpMethod = "GET"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        if let token = authContext.accessToken, !token.isEmpty {
            request.setValue(token, forHTTPHeaderField: AccessHeader.accessToken)
        }

        for (header, value) in authContext.headers {
            request.setValue(value, forHTTPHeaderField: header)
        }

        if let destination, !destination.isEmpty {
            request.setValue(destination, forHTTPHeaderField: AccessHeader.jumpDestination)
        }

        for (header, value) in additionalHeaders {
            request.setValue(value, forHTTPHeaderField: header)
        }

        return request
    }
}
