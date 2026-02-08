# Architecture

## 1. Design Goals

- Follow critical `cloudflared access tcp/ssh` behavior.
- Keep core SDK transport/auth logic UI-framework agnostic.
- Use actor isolation for lifecycle-critical mutable state.
- Keep secrets and token handling explicit and testable.

## 2. Implemented Modules

- `Sources/SwiftCloudflared/CFSSHTypes.swift`
  - Public auth method, error taxonomy, state model, client protocol.
- `Sources/SwiftCloudflared/Auth/CFSSHAuthProviding.swift`
  - `CFSSHOAuthProvider`
  - `CFSSHServiceTokenProvider`
  - `CFSSHAuthMultiplexer`
- `Sources/SwiftCloudflared/Auth/CFSSHJWTValidator.swift`
  - JWT `exp` validation for cached/fresh tokens.
- `Sources/SwiftCloudflared/Auth/CFSSHTokenStore.swift`
  - In-memory token store (testable baseline).
- `Sources/SwiftCloudflared/Auth/CFSSHKeychainTokenStore.swift`
  - iOS/tvOS/watchOS keychain-backed store.
- `Sources/SwiftCloudflared/Auth/CFSSHAppInfo.swift`
  - Access app metadata parser/resolver from `HEAD` response.
- `Sources/SwiftCloudflared/Tunnel/CFSSHAccessRequestBuilder.swift`
  - Header construction for Access token/service token/jump destination.
- `Sources/SwiftCloudflared/Tunnel/CFSSHLoopbackTunnelProvider.swift`
  - Loopback listener lifecycle, fault injection points for tests.
- `Sources/SwiftCloudflared/Session/CFSSHSessionActor.swift`
  - Connection orchestrator + retry/fallback state machine.

## 3. Concurrency and Isolation

- `CFSSHSessionActor` is the single writer for:
  - connection lifecycle state
  - transition publication over `AsyncStream`
  - retry/fallback decisions
- Auth providers and tunnel providers are protocol-based dependencies injected into the actor.
- Core package has no blanket `@MainActor`; UI adapters belong in host app code.

## 4. Connection Lifecycle

1. Validate and normalize hostname.
2. Publish `.authenticating`.
3. Resolve `CFSSHAuthContext` via selected auth provider.
4. Attempt tunnel open:
  - publish `.connecting`
  - on retryable transport failure, publish `.reconnecting(attempt:)` and backoff
5. On success publish `.connected(localPort:)`.
6. On failure publish `.failed(CFSSHFailure)`.
7. On explicit disconnect call provider `close()` and publish `.disconnected`.

## 5. Auth Architecture

- OAuth path:
  - consult token store cache
  - validate JWT expiry
  - fetch new token via `CFSSHOAuthFlow` when cache is missing/invalid
- Service token path:
  - validate non-empty ID/secret
  - produce `CFSSHAuthContext` headers only
- Multiplexer:
  - routes by `CFSSHAuthMethod`
  - optional fallback from service token failure to OAuth method

## 6. Tunnel Abstraction

- `CFSSHTunnelProviding` is the boundary between policy/orchestration and network transport.
- Current implementation is loopback-focused test transport.
- Production connector can be added behind the same protocol without changing session API.

## 7. Failure Model

- `CFSSHFailure.transport(_, retryable: Bool)` drives reconnect decisions.
- All unknown errors are wrapped as `.internalError`.
- Invalid state transitions are explicit `.invalidState`.

## 8. Testability Strategy

- All external effects are injected:
  - OAuth flow callback
  - token store
  - HTTP client
  - tunnel provider
  - sleep/backoff clock
- Fault-injection tunnel provider enables deterministic transport error path coverage.
