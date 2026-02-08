# Protocol Mapping (cloudflared -> swift-cloudflared)

This file records behavior validated against `reference/cloudflared` and maps it to current Swift implementation points.

## 1. access tcp/ssh Execution Path

Upstream:
- `access tcp` command aliases include `ssh`, `rdp`, `smb`.
- `reference/cloudflared/cmd/cloudflared/access/cmd.go:143-146`
- handler entry: `reference/cloudflared/cmd/cloudflared/access/carrier.go:64`

Swift mapping:
- Single session/tunnel abstraction for TCP/SSH workloads:
  - `Sources/Cloudflared/Session/SessionActor.swift`
  - `Sources/Cloudflared/Tunnel/TunnelProviding.swift`

## 2. URL Normalization

Upstream:
- Parse input, default to `https://`, enforce host validity.
- `reference/cloudflared/cmd/cloudflared/access/validation.go:29-54`

Swift mapping:
- `URLTools.normalizeOriginURL(from:)`:
  - adds https scheme when missing
  - forces https scheme
  - rejects empty/invalid host
  - file: `Sources/Cloudflared/URLTools.swift`

## 3. Access Header Contracts

Upstream:
- Service headers in access carrier:
  - `Cf-Access-Client-Id`
  - `Cf-Access-Client-Secret`
  - `reference/cloudflared/cmd/cloudflared/access/carrier.go:23-24,82-87`
- App token header:
  - `Cf-Access-Token`
  - `reference/cloudflared/carrier/carrier.go:24,154`
- Bastion destination:
  - `Cf-Access-Jump-Destination`
  - `reference/cloudflared/carrier/carrier.go:25,165-173`

Swift mapping:
- Header constants:
  - `Sources/Cloudflared/AccessHeaders.swift`
- Request builder:
  - `Sources/Cloudflared/Tunnel/AccessRequestBuilder.swift`

## 4. Access Redirect Detection and Token Invalidity Heuristic

Upstream:
- Access redirect detection:
  - `302` + `/cdn-cgi/access/login`
  - `reference/cloudflared/carrier/carrier.go:118-133`
- Token validation probe:
  - adds `cloudflared_token_check=true`
  - treats login redirect as invalid token
  - `reference/cloudflared/cmd/cloudflared/access/cmd.go:575-601`

Swift mapping:
- Redirect detection helper:
  - `URLTools.isAccessLoginRedirect(statusCode:location:)`
- Session retry/failure orchestration:
  - `Sources/Cloudflared/Session/SessionActor.swift`

## 5. WebSocket Dial Semantics

Upstream:
- Build websocket request from `options.OriginURL`:
  - `reference/cloudflared/carrier/websocket.go:49-56`
- Convert scheme:
  - `https -> wss`, `http -> ws`, empty -> ws
  - `reference/cloudflared/carrier/websocket.go:137-149`
- Strip WS protocol headers and set `Host`:
  - `reference/cloudflared/carrier/websocket.go:95-117`

Swift mapping:
- Scheme conversion helper:
  - `URLTools.websocketURL(from:)`
- Request header assembly abstraction:
  - `AccessRequestBuilder`

Note:
- Current package revision provides the abstraction and helpers; full production websocket carrier is an open item.

## 6. App Metadata Discovery

Upstream:
- `HEAD` request to app URL.
- Derive `aud` from login redirect `kid` query, or `CF-Access-Aud` header.
- Require `CF-Access-Domain`.
- `reference/cloudflared/token/token.go:286-331`

Swift mapping:
- `AppInfoResolver` sends `HEAD`.
- `AppInfoParser` resolves:
  - `authDomain`
  - `appAUD`
  - `appDomain`
- file: `Sources/Cloudflared/Auth/AppInfo.swift`

## 7. CLI Transfer/Login Endpoint Shape

Upstream:
- transfer login helper path:
  - `/cdn-cgi/access/cli`
- query contract includes:
  - `redirect_url`
  - `send_org_token`
  - `edge_token_transfer`
- `reference/cloudflared/token/transfer.go:85-106`

Swift mapping:
- OAuth fetch behavior is delegated behind `OAuthFlow`.
- Host app can implement browser flow semantics equivalent to transfer/login helper.

## 8. Token Persistence and Expiry

Upstream:
- parse JWT payload and delete expired token on read:
  - `reference/cloudflared/token/token.go:420-439`

Swift mapping:
- JWT expiration validator:
  - `Sources/Cloudflared/Auth/JWTValidator.swift`
- token cache read/remove flow in OAuth provider:
  - `Sources/Cloudflared/Auth/AuthProviding.swift`

## 9. Short-Lived SSH Cert Endpoint (Future)

Upstream:
- cert sign endpoint:
  - `/cdn-cgi/access/cert_sign`
  - `reference/cloudflared/sshgen/sshgen.go:29`

Swift mapping:
- Not implemented in current package revision.
- Reserved as v2 extension point.

## 10. Duplex Stream Piping Semantics

Upstream:
- concurrent bidirectional piping with explicit close-write behavior:
  - `reference/cloudflared/stream/stream.go:93-138`

Swift mapping:
- Current package provides loopback tunnel lifecycle and protocol boundary.
- Production duplex bridge implementation remains an open transport task.
