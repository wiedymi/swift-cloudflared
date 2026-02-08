public enum AuthMethod: Sendable, Equatable {
    case oauth(teamDomain: String, appDomain: String, callbackScheme: String)
    case serviceToken(teamDomain: String, clientID: String, clientSecret: String)
}

public struct AuthContext: Sendable, Equatable {
    public var accessToken: String?
    public var headers: [String: String]

    public init(accessToken: String? = nil, headers: [String: String] = [:]) {
        self.accessToken = accessToken
        self.headers = headers
    }

    public static func appToken(_ token: String) -> Self {
        Self(accessToken: token)
    }

    public static func serviceToken(id: String, secret: String) -> Self {
        Self(
            accessToken: nil,
            headers: [
                AccessHeader.clientID: id,
                AccessHeader.clientSecret: secret,
            ]
        )
    }
}

public enum Failure: Error, Sendable, Equatable {
    case invalidState(String)
    case auth(String)
    case transport(String, retryable: Bool)
    case configuration(String)
    case protocolViolation(String)
    case internalError(String)

    public var isRetryable: Bool {
        switch self {
        case .transport(_, let retryable):
            return retryable
        default:
            return false
        }
    }
}

public enum ConnectionState: Sendable, Equatable {
    case idle
    case authenticating
    case connecting
    case connected(localPort: UInt16)
    case reconnecting(attempt: Int)
    case disconnected
    case failed(Failure)
}

public protocol Client: Sendable {
    var state: AsyncStream<ConnectionState> { get }
    func connect(hostname: String, method: AuthMethod) async throws -> UInt16
    func disconnect() async
}
