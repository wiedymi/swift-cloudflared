# Public API

## 1. Core Types

```swift
public enum CFSSHAuthMethod: Sendable, Equatable {
    case oauth(teamDomain: String, appDomain: String, callbackScheme: String)
    case serviceToken(teamDomain: String, clientID: String, clientSecret: String)
}

public struct CFSSHAuthContext: Sendable, Equatable {
    public var accessToken: String?
    public var headers: [String: String]
}

public enum CFSSHFailure: Error, Sendable, Equatable {
    case invalidState(String)
    case auth(String)
    case transport(String, retryable: Bool)
    case configuration(String)
    case protocolViolation(String)
    case internalError(String)

    public var isRetryable: Bool { get }
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
```

## 2. Client API

```swift
public protocol CFSSHClient: Sendable {
    var state: AsyncStream<CFSSHConnectionState> { get }
    func connect(hostname: String, method: CFSSHAuthMethod) async throws -> UInt16
    func disconnect() async
}
```

Default implementation entry point:
- `CFSSHSessionActor`

Retry policy:
```swift
public struct CFSSHRetryPolicy: Sendable, Equatable {
    public let maxReconnectAttempts: Int
    public let baseDelayNanoseconds: UInt64
}
```

## 3. Dependency Protocols (Injection Points)

```swift
public protocol CFSSHAuthProviding: Sendable {
    func authenticate(hostname: String, method: CFSSHAuthMethod) async throws -> CFSSHAuthContext
}

public protocol CFSSHTunnelProviding: Sendable {
    func open(hostname: String, authContext: CFSSHAuthContext, method: CFSSHAuthMethod) async throws -> UInt16
    func close() async
}
```

## 4. Auth Module API

```swift
public protocol CFSSHOAuthFlow: Sendable {
    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String
}

public protocol CFSSHTokenStore: Sendable {
    func readToken(for key: String) async throws -> String?
    func writeToken(_ token: String, for key: String) async throws
    func removeToken(for key: String) async throws
}
```

Concrete providers:
- `CFSSHOAuthProvider`
- `CFSSHServiceTokenProvider`
- `CFSSHAuthMultiplexer`

## 5. HTTP/Request Utilities

- `CFSSHAccessRequestBuilder` builds Access-authenticated `URLRequest` instances.
- `CFSSHAppInfoResolver` + `CFSSHAppInfoParser` implement Access app metadata discovery semantics.
- `CFSSHURLTools` normalizes origin URL and applies websocket scheme translation.

## 6. Compatibility Notes

- `CFSSHKeychainTokenStore` is compiled on Apple platforms that expose `Security` (`macOS`, `iOS`, `tvOS`, `watchOS`).
- On `macOS`, the store defaults to data-protection keychain mode (`kSecUseDataProtectionKeychain`).
- Session actor API is fully async and does not require `@MainActor`.
