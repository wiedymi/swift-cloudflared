# Public API

## 1. Core Types

```swift
public enum AuthMethod: Sendable, Equatable {
    case oauth(teamDomain: String, appDomain: String, callbackScheme: String)
    case serviceToken(teamDomain: String, clientID: String, clientSecret: String)
}

public struct AuthContext: Sendable, Equatable {
    public var accessToken: String?
    public var headers: [String: String]
}

public enum Failure: Error, Sendable, Equatable {
    case invalidState(String)
    case auth(String)
    case transport(String, retryable: Bool)
    case configuration(String)
    case protocolViolation(String)
    case internalError(String)

    public var isRetryable: Bool { get }
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
```

## 2. Client API

```swift
public protocol Client: Sendable {
    var state: AsyncStream<ConnectionState> { get }
    func connect(hostname: String, method: AuthMethod) async throws -> UInt16
    func disconnect() async
}
```

Default implementation entry point:
- `SessionActor`

Retry policy:
```swift
public struct RetryPolicy: Sendable, Equatable {
    public let maxReconnectAttempts: Int
    public let baseDelayNanoseconds: UInt64
}
```

## 3. Dependency Protocols (Injection Points)

```swift
public protocol AuthProviding: Sendable {
    func authenticate(hostname: String, method: AuthMethod) async throws -> AuthContext
}

public protocol TunnelProviding: Sendable {
    func open(hostname: String, authContext: AuthContext, method: AuthMethod) async throws -> UInt16
    func close() async
}
```

## 4. Auth Module API

```swift
public protocol OAuthFlow: Sendable {
    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String
}

public protocol TokenStore: Sendable {
    func readToken(for key: String) async throws -> String?
    func writeToken(_ token: String, for key: String) async throws
    func removeToken(for key: String) async throws
}
```

Concrete providers:
- `OAuthProvider`
- `ServiceTokenProvider`
- `AuthMultiplexer`

Token store implementations:
- `InMemoryTokenStore`
- `KeychainTokenStore`
- `ICloudKeychainTokenStore`

## 5. HTTP/Request Utilities

- `AccessRequestBuilder` builds Access-authenticated `URLRequest` instances.
- `AppInfoResolver` + `AppInfoParser` implement Access app metadata discovery semantics.
- `URLTools` normalizes origin URL and applies websocket scheme translation.

## 6. Compatibility Notes

- `KeychainTokenStore` is compiled on Apple platforms that expose `Security` (`macOS`, `iOS`, `tvOS`, `watchOS`).
- On `macOS`, the store defaults to data-protection keychain mode (`kSecUseDataProtectionKeychain`).
- `KeychainTokenStore` supports `syncMode: .localOnly` (default) and `syncMode: .iCloud`.
- `ICloudKeychainTokenStore` is a convenience wrapper over `KeychainTokenStore(syncMode: .iCloud)`.
- Session actor API is fully async and does not require `@MainActor`.
