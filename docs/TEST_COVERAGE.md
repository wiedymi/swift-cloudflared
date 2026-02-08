# Test Coverage and Traceability

## 1. Coverage Gate

Verification commands:

```bash
swift test
swift test --enable-code-coverage
xcrun llvm-cov report \
  .build/arm64-apple-macosx/debug/CloudflaredPackageTests.xctest/Contents/MacOS/CloudflaredPackageTests \
  -instr-profile .build/arm64-apple-macosx/debug/codecov/default.profdata \
  -ignore-filename-regex='(.build|Tests|/usr/)'
```

Current result:
- Source regions: `100.00%`
- Source functions: `100.00%`
- Source lines: `100.00%`

## 2. Requirement-to-Test Matrix

- FR-1 Auth modes:
  - `Tests/CloudflaredTests/OAuthProviderTests.swift`
  - `Tests/CloudflaredTests/ServiceTokenProviderTests.swift`
  - `Tests/CloudflaredTests/AuthMultiplexerTests.swift`
  - `Tests/CloudflaredTests/SessionActorTests.swift`

- FR-2 Token lifecycle:
  - `Tests/CloudflaredTests/JWTValidatorTests.swift`
  - `Tests/CloudflaredTests/OAuthProviderTests.swift`
  - `Tests/CloudflaredTests/TokenStoreTests.swift`

- FR-3 Access protocol semantics:
  - `Tests/CloudflaredTests/AccessRequestBuilderTests.swift`
  - `Tests/CloudflaredTests/URLToolsTests.swift`
  - `Tests/CloudflaredTests/AppInfoTests.swift`

- FR-4 Session and retry:
  - `Tests/CloudflaredTests/SessionActorTests.swift`
  - `Tests/CloudflaredTests/LoopbackTunnelProviderTests.swift`

- FR-5 Public API and failure model:
  - `Tests/CloudflaredTests/TypesTests.swift`
  - `Tests/CloudflaredTests/SessionActorTests.swift`

## 3. Fault Injection Coverage

Transport and lifecycle failure paths are explicitly covered by:
- `Tests/CloudflaredTests/LoopbackTunnelProviderTests.swift`
- `Tests/CloudflaredTests/SessionActorTests.swift`

This includes:
- bind/listen/socket/getsockname failures
- retryable vs non-retryable transport failures
- fallback success/failure behavior
- invalid state transition handling
