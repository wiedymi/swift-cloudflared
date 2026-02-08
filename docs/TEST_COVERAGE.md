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
  - `Tests/SwiftCloudflaredTests/CFSSHOAuthProviderTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHServiceTokenProviderTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHAuthMultiplexerTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHSessionActorTests.swift`

- FR-2 Token lifecycle:
  - `Tests/SwiftCloudflaredTests/CFSSHJWTValidatorTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHOAuthProviderTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHTokenStoreTests.swift`

- FR-3 Access protocol semantics:
  - `Tests/SwiftCloudflaredTests/CFSSHAccessRequestBuilderTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHURLToolsTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHAppInfoTests.swift`

- FR-4 Session and retry:
  - `Tests/SwiftCloudflaredTests/CFSSHSessionActorTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHLoopbackTunnelProviderTests.swift`

- FR-5 Public API and failure model:
  - `Tests/SwiftCloudflaredTests/CFSSHTypesTests.swift`
  - `Tests/SwiftCloudflaredTests/CFSSHSessionActorTests.swift`

## 3. Fault Injection Coverage

Transport and lifecycle failure paths are explicitly covered by:
- `Tests/SwiftCloudflaredTests/CFSSHLoopbackTunnelProviderTests.swift`
- `Tests/SwiftCloudflaredTests/CFSSHSessionActorTests.swift`

This includes:
- bind/listen/socket/getsockname failures
- retryable vs non-retryable transport failures
- fallback success/failure behavior
- invalid state transition handling
