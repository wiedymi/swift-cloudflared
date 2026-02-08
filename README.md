# swift-cloudflared

[![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/wiedymi)
[![Twitter](https://img.shields.io/badge/-Twitter-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://x.com/wiedymi)
[![Email](https://img.shields.io/badge/-Email-EA4335?style=flat-square&logo=gmail&logoColor=white)](mailto:contact@wiedymi.com)
[![Discord](https://img.shields.io/badge/-Discord-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/zemMZtrkSb)
[![Support me](https://img.shields.io/badge/-Support%20me-ff69b4?style=flat-square&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/vivy-company)

Pure Swift Cloudflare Access TCP tunnel SDK for SSH clients on Apple platforms.

Use it to open an Access-authenticated local endpoint (`127.0.0.1:<port>`) and connect your SSH stack (for example `libssh2`) through it.

## Features

- OAuth and Service Token auth method support
- Async session API with connection state stream
- Local loopback tunnel endpoint for SSH client libraries
- Secure default local listener policy:
  - one active local client by default
  - listener closes after first accepted client by default
- Pluggable auth, token storage, and tunnel layers
- Built-in keychain token store on `macOS`, `iOS`, `tvOS`, `watchOS`

## Platforms

- iOS 16+
- macOS 13+
- Swift tools 6.0+

## Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/wiedymi/swift-cloudflared.git", from: "0.1.0")
]
```

Then add the library target:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "Cloudflared", package: "swift-cloudflared")
    ]
)
```

## Quick Start (Service Token)

```swift
import Cloudflared

let session = SSHSessionActor(
    authProvider: SSHServiceTokenProvider(),
    tunnelProvider: SSHCloudflareTunnelProvider(),
    retryPolicy: SSHRetryPolicy(maxReconnectAttempts: 2, baseDelayNanoseconds: 500_000_000),
    oauthFallback: nil,
    sleep: { delay in try? await Task.sleep(nanoseconds: delay) }
)

let localPort = try await session.connect(
    hostname: "ssh.example.com",
    method: .serviceToken(
        teamDomain: "your-team.cloudflareaccess.com",
        clientID: "<CF_ACCESS_CLIENT_ID>",
        clientSecret: "<CF_ACCESS_CLIENT_SECRET>"
    )
)

// Use 127.0.0.1:localPort from libssh2
print("Tunnel endpoint: 127.0.0.1:\(localPort)")
```

## OAuth Flow Integration

OAuth UI/token acquisition is app-owned via `SSHOAuthFlow`:

```swift
import Cloudflared

struct MyOAuthFlow: SSHOAuthFlow {
    func fetchToken(
        teamDomain: String,
        appDomain: String,
        callbackScheme: String,
        hostname: String
    ) async throws -> String {
        // Implement your Access login UX (for example ASWebAuthenticationSession)
        // and return CF_Authorization JWT.
        throw SSHFailure.auth("not implemented")
    }
}

let oauthProvider = SSHOAuthProvider(
    flow: MyOAuthFlow(),
    tokenStore: SSHKeychainTokenStore()
)
```

For app metadata discovery (`authDomain`, `appDomain`, `appAUD`) you can use `SSHAppInfoResolver`.

## State Stream

Observe state changes from the session:

```swift
Task {
    for await state in session.state {
        print("state:", state)
    }
}
```

States: `idle`, `authenticating`, `connecting`, `connected(localPort)`, `reconnecting(attempt)`, `disconnected`, `failed`.

## libssh2 Integration

Once connected, point your SSH stack to loopback:

```c
// Connect libssh2 socket to 127.0.0.1:<localPort>
// then run regular libssh2 handshake/auth/channel flow.
```

Example runtime mapping:
- Host: `127.0.0.1`
- Port: `<localPort from session.connect(...)>`

## Token Storage Customization

If you need your own keychain layout or storage backend, implement `SSHTokenStore`:

```swift
import Cloudflared

actor CustomTokenStore: SSHTokenStore {
    func readToken(for key: String) async throws -> String? { nil }
    func writeToken(_ token: String, for key: String) async throws {}
    func removeToken(for key: String) async throws {}
}
```

Then inject it into `SSHOAuthProvider`.

`SSHKeychainTokenStore` defaults:
- iOS/tvOS/watchOS: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- macOS: `kSecAttrAccessibleAfterFirstUnlock` + data-protection keychain mode

## Local Security Defaults

`SSHCloudflareTunnelProvider` defaults to:
- `maxConcurrentConnections = 1`
- `stopAcceptingAfterFirstConnection = true`

You can override via:

```swift
let tunnel = SSHCloudflareTunnelProvider(
    connectionLimits: .init(
        maxConcurrentConnections: 2,
        stopAcceptingAfterFirstConnection: false
    )
)
```

## Sandbox and Entitlements

- iOS app sandbox: supported (foreground usage; OAuth flow is app-defined).
- macOS App Sandbox: enable network client/server entitlements if sandboxed, because the SDK opens:
  - outbound websocket connection to Cloudflare Access
  - local loopback listener for SSH client connection

## E2E Harness

Run the local interactive harness:

```bash
swift run cloudflared-e2e
```

It prints a local endpoint (`127.0.0.1:<port>`) you can test with SSH/libssh2.

## Development

```bash
swift test
swift build
```

Optional keychain integration test:

```bash
CLOUDFLARED_KEYCHAIN_TESTS=1 swift test --filter SSHTokenStoreTests/testKeychainStoreRoundTrip
```

## Docs

- `docs/SPEC.md` - requirements and acceptance criteria
- `docs/ARCHITECTURE.md` - design and concurrency model
- `docs/API.md` - API surface and compatibility notes
- `docs/PROTOCOL_MAPPING.md` - upstream behavior mapping
- `docs/TEST_COVERAGE.md` - test traceability/coverage gates

## Repository Notes

- `reference/cloudflared` is included as a git submodule for upstream reference.

## License

- Root project: MIT (`LICENSE`)
- Third-party notices: `THIRD_PARTY_NOTICES.md`
