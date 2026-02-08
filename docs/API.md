# Public API

## 1. Core Types

```swift
public enum SSHAuthMethod: Sendable, Equatable {
    case oauth(teamDomain: String, appDomain: String, callbackScheme: String)
    case serviceToken(teamDomain: String, clientID: String, clientSecret: String)
}

public struct SSHAuthContext: Sendable, Equatable {
    public var accessToken: String?
    public var headers: [String: String]
}

public enum SSHFailure: Error, Sendable, Equatable {
    case invalidState(String)
    case auth(String)
    case transport(String, retryable: Bool)
    case configuration(String)
    case protocolViolation(String)
    case internalError(String)

    public var isRetryable: Bool { get }
}

public enum SSHConnectionState: Sendable, Equatable {
    case idle
    case authenticating
    case connecting
    case connected(localPort: UInt16)
    case reconnecting(attempt: Int)
    case disconnected
    case failed(SSHFailure)
}
```

## 2. Client API

```swift
public protocol SSHClient: Sendable {
    var state: AsyncStream<SSHConnectionState> { get }
    func connect(hostname: String, method: SSHAuthMethod) async throws -> UInt16
    func disconnect() async
}
```

Default implementation entry point:
- `SSHSessionActor`

Retry policy:
```swift
public struct SSHRetryPolicy: Sendable, Equatable {
    public let maxReconnectAttempts: Int
    public let baseDelayNanoseconds: UInt64
}
```

## 3. Dependency Protocols (Injection Points)

```swift
public protocol SSHAuthProviding: Sendable {
    func authenticate(hostname: String, method: SSHAuthMethod) async throws -> SSHAuthContext
}

public protocol SSHTunnelProviding: Sendable {
    func open(hostname: String, authContext: SSHAuthContext, method: SSHAuthMethod) async throws -> UInt16
    func close() async
}
```

## 4. Auth Module API

```swift
public protocol SSHOAuthFlow: Sendable {
    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String
}

public protocol SSHTokenStore: Sendable {
    func readToken(for key: String) async throws -> String?
    func writeToken(_ token: String, for key: String) async throws
    func removeToken(for key: String) async throws
}
```

Concrete providers:
- `SSHOAuthProvider`
- `SSHServiceTokenProvider`
- `SSHAuthMultiplexer`

## 5. HTTP/Request Utilities

- `SSHAccessRequestBuilder` builds Access-authenticated `URLRequest` instances.
- `SSHAppInfoResolver` + `SSHAppInfoParser` implement Access app metadata discovery semantics.
- `SSHURLTools` normalizes origin URL and applies websocket scheme translation.

## 6. Compatibility Notes

- `SSHKeychainTokenStore` is compiled on Apple platforms that expose `Security` (`macOS`, `iOS`, `tvOS`, `watchOS`).
- On `macOS`, the store defaults to data-protection keychain mode (`kSecUseDataProtectionKeychain`).
- Session actor API is fully async and does not require `@MainActor`.
