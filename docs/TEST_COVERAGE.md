# Test Coverage and Traceability

## 1. Coverage Gate

Verification commands:

```bash
swift test
swift test --enable-code-coverage
xcrun llvm-cov report \
  .build/arm64-apple-macosx/debug/swift-cloudflaredPackageTests.xctest/Contents/MacOS/swift-cloudflaredPackageTests \
  -instr-profile .build/arm64-apple-macosx/debug/codecov/default.profdata \
  -ignore-filename-regex='(.build|Tests|/usr/)'
```

Current result:
- Source regions: `100.00%`
- Source functions: `100.00%`
- Source lines: `100.00%`

## 2. Requirement-to-Test Matrix

- FR-1 Auth modes:
  - `Tests/CloudflaredTests/SSHOAuthProviderTests.swift`
  - `Tests/CloudflaredTests/SSHServiceTokenProviderTests.swift`
  - `Tests/CloudflaredTests/SSHAuthMultiplexerTests.swift`
  - `Tests/CloudflaredTests/SSHSessionActorTests.swift`

- FR-2 Token lifecycle:
  - `Tests/CloudflaredTests/SSHJWTValidatorTests.swift`
  - `Tests/CloudflaredTests/SSHOAuthProviderTests.swift`
  - `Tests/CloudflaredTests/SSHTokenStoreTests.swift`

- FR-3 Access protocol semantics:
  - `Tests/CloudflaredTests/SSHAccessRequestBuilderTests.swift`
  - `Tests/CloudflaredTests/SSHURLToolsTests.swift`
  - `Tests/CloudflaredTests/SSHAppInfoTests.swift`

- FR-4 Session and retry:
  - `Tests/CloudflaredTests/SSHSessionActorTests.swift`
  - `Tests/CloudflaredTests/SSHLoopbackTunnelProviderTests.swift`

- FR-5 Public API and failure model:
  - `Tests/CloudflaredTests/SSHTypesTests.swift`
  - `Tests/CloudflaredTests/SSHSessionActorTests.swift`

## 3. Fault Injection Coverage

Transport and lifecycle failure paths are explicitly covered by:
- `Tests/CloudflaredTests/SSHLoopbackTunnelProviderTests.swift`
- `Tests/CloudflaredTests/SSHSessionActorTests.swift`

This includes:
- bind/listen/socket/getsockname failures
- retryable vs non-retryable transport failures
- fallback success/failure behavior
- invalid state transition handling
