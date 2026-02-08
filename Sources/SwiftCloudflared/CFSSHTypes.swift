public enum CFSSHAuthMethod: Sendable, Equatable {
    case oauth(teamDomain: String, appDomain: String, callbackScheme: String)
    case serviceToken(teamDomain: String, clientID: String, clientSecret: String)
}

public struct CFSSHAuthContext: Sendable, Equatable {
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
                CFSSHAccessHeader.clientID: id,
                CFSSHAccessHeader.clientSecret: secret,
            ]
        )
    }
}

public enum CFSSHFailure: Error, Sendable, Equatable {
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

public enum CFSSHConnectionState: Sendable, Equatable {
    case idle
    case authenticating
    case connecting
    case connected(localPort: UInt16)
    case reconnecting(attempt: Int)
    case disconnected
    case failed(CFSSHFailure)
}

public protocol CFSSHClient: Sendable {
    var state: AsyncStream<CFSSHConnectionState> { get }
    func connect(hostname: String, method: CFSSHAuthMethod) async throws -> UInt16
    func disconnect() async
}
