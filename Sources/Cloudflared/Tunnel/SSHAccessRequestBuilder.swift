import Foundation

public struct SSHAccessRequestBuilder: Sendable {
    private let userAgent: String

    public init(userAgent: String = "swift-cloudflared") {
        self.userAgent = userAgent
    }

    public func build(
        originURL: URL,
        authContext: SSHAuthContext,
        destination: String? = nil,
        additionalHeaders: [String: String] = [:]
    ) -> URLRequest {
        var request = URLRequest(url: originURL)
        request.httpMethod = "GET"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        if let token = authContext.accessToken, !token.isEmpty {
            request.setValue(token, forHTTPHeaderField: SSHAccessHeader.accessToken)
        }

        for (header, value) in authContext.headers {
            request.setValue(value, forHTTPHeaderField: header)
        }

        if let destination, !destination.isEmpty {
            request.setValue(destination, forHTTPHeaderField: SSHAccessHeader.jumpDestination)
        }

        for (header, value) in additionalHeaders {
            request.setValue(value, forHTTPHeaderField: header)
        }

        return request
    }
}
