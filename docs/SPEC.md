# swift-cloudflared Specification

## 1. Objective

Build an iOS-first Swift package that reproduces the core `cloudflared access tcp/ssh` client behavior needed for SSH libraries to reach Cloudflare Access protected origins through a localhost endpoint.

Integration contract:
- Host app asks SDK to connect to Access-protected hostname.
- SDK returns local loopback port.
- SSH client (for example `libssh2`) connects to `127.0.0.1:<port>`.

## 2. Scope

### In Scope

- Dual auth mode modeling:
  - OAuth (interactive user flow via host-provided callback implementation).
  - Service token (`Cf-Access-Client-Id`, `Cf-Access-Client-Secret`).
- Token lifecycle primitives:
  - cache abstraction
  - JWT expiry validation
  - stale/invalid token recovery orchestration
- Access request construction:
  - `Cf-Access-Token`
  - service token headers
  - `Cf-Access-Jump-Destination`
  - user-agent injection
- Session lifecycle state machine and retry policy.
- Loopback tunnel provider abstraction and deterministic test transport.

### Out of Scope (Current Package)

- Running `cloudflared` binary/subprocess in app.
- Full parity with all `cloudflared access` CLI commands.
- Full short-lived SSH certificate issuance flow.
- End-to-end websocket carrier parity in this package revision.

## 3. Constraints

- App Store safe runtime model.
- No secret persistence in plaintext stores.
- Loopback bind only for local listener (`127.0.0.1`).
- Core SDK must remain UI-framework agnostic.

## 4. Functional Requirements

### FR-1 Auth Modes

- SDK must accept OAuth and service-token methods per connection.
- SDK must optionally support service-token-to-OAuth fallback.
- SDK must produce a normalized `CFSSHAuthContext` for transport layer.

### FR-2 Token Lifecycle

- SDK must validate JWT expiry before reusing cached OAuth token.
- SDK must delete malformed/expired cache entries.
- SDK must return typed auth failures for invalid fresh tokens.

### FR-3 Access Protocol Semantics

- SDK must emit Cloudflare Access headers using canonical names.
- SDK must implement Access login redirect detection (`302 + /cdn-cgi/access/login*`).
- SDK must normalize origin URL to HTTPS and host-safe form before use.
- SDK must convert origin scheme to websocket-compatible scheme when required.

### FR-4 Session and Retry

- SDK must expose deterministic async state transitions.
- SDK must reject invalid connect calls from non-terminal states.
- SDK must reconnect only when transport failures are marked retryable.
- SDK must apply bounded retry attempts with deterministic delay function.

### FR-5 Public API

- SDK must provide:
  - `connect(hostname:method:) async throws -> UInt16`
  - `disconnect() async`
  - `state: AsyncStream<CFSSHConnectionState>`
- SDK must provide typed failure taxonomy:
  - invalidState
  - auth
  - transport(retryable)
  - configuration
  - protocolViolation
  - internalError

## 5. Non-Functional Requirements

- Security:
  - keychain store available for Apple mobile targets.
  - no token logging in SDK internals.
- Reliability:
  - deterministic teardown on disconnect.
  - deterministic failure-state publication.
- Testability:
  - all external effects injected via protocols.
  - retry clock/sleep injection for deterministic tests.

## 6. Acceptance Criteria

- AC-1 Auth providers produce correct `CFSSHAuthContext` for both modes.
- AC-2 Access request builder emits expected headers and preserves custom headers.
- AC-3 Session actor publishes expected state sequences for:
  - success path
  - invalid state
  - fallback success
  - fallback failure
  - retry success
  - retry exhaustion
- AC-4 Loopback tunnel provider enforces bind/open/close invariants.
- AC-5 Coverage gate: package source coverage is 100% with `swift test --enable-code-coverage`.

## 7. Verification Commands

```bash
swift test
swift test --enable-code-coverage
xcrun llvm-cov report \
  .build/arm64-apple-macosx/debug/swift-cloudflaredPackageTests.xctest/Contents/MacOS/swift-cloudflaredPackageTests \
  -instr-profile .build/arm64-apple-macosx/debug/codecov/default.profdata \
  -ignore-filename-regex='(.build|Tests|/usr/)'
```

Expected gate for this revision:
- `TOTAL ... 100.00%` for regions/functions/lines in package sources.

## 8. Dependencies

- `Foundation`
- `Network.framework` (transport implementation extensions)
- `AuthenticationServices` (host OAuth implementation)
- `Security` (keychain-backed token store for mobile Apple targets)
- `reference/cloudflared` git submodule for protocol/reference validation

## 9. Open Items

- Implement production Access websocket transport provider behind `CFSSHTunnelProviding`.
- Add integration harness for real Cloudflare Access-protected test origin.
- Add optional short-lived SSH cert flow (`/cdn-cgi/access/cert_sign`) as v2 extension.
