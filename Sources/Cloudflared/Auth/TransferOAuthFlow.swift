import Foundation
import TweetNacl

public protocol OAuthWebSession: Actor {
    func start(url: URL) async throws
    func stop() async
    func didCancelLogin() async -> Bool
}

public struct URLSessionHTTPClient: HTTPClient {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw Failure.protocolViolation("non-http response")
        }
        return (data, httpResponse)
    }
}

public struct TransferOAuthFlow: OAuthFlow {
    private struct OAuthAppInfo: Sendable {
        let authDomain: String
        let appDomain: String
        let appAUD: String
    }

    private struct TransferKeyPair: Sendable {
        let publicKeyID: String
        let privateKey: Data
    }

    private final class RedirectBlockingDelegate: NSObject, URLSessionTaskDelegate {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }

    private let webSession: any OAuthWebSession
    private let httpClient: any HTTPClient
    private let userAgent: String
    private let discoveryTimeout: TimeInterval
    private let pollTimeout: TimeInterval
    private let pollAttempts: Int
    private let pollDelayNanoseconds: UInt64

    public init(
        webSession: any OAuthWebSession,
        httpClient: any HTTPClient = URLSessionHTTPClient(),
        userAgent: String = "swift-cloudflared",
        discoveryTimeout: TimeInterval = 12,
        pollTimeout: TimeInterval = 60,
        pollAttempts: Int = 14,
        pollDelayNanoseconds: UInt64 = 350_000_000
    ) {
        self.webSession = webSession
        self.httpClient = httpClient
        self.userAgent = userAgent
        self.discoveryTimeout = discoveryTimeout
        self.pollTimeout = pollTimeout
        self.pollAttempts = max(1, pollAttempts)
        self.pollDelayNanoseconds = pollDelayNanoseconds
    }

    public func fetchToken(
        teamDomain: String,
        appDomain: String,
        callbackScheme: String,
        hostname: String
    ) async throws -> String {
        _ = callbackScheme

        let appURL = try URLTools.normalizeOriginURL(from: hostname)
        let appInfo = try await resolveOAuthAppInfo(
            appURL: appURL,
            teamDomainHint: teamDomain,
            appDomainHint: appDomain
        )
        let transferKeyPair = try makeTransferKeyPair()
        let authorizeURL = try buildAuthorizeURL(
            appURL: appURL,
            appAUD: appInfo.appAUD,
            transferID: transferKeyPair.publicKeyID
        )

        try await webSession.start(url: authorizeURL)

        do {
            let token = try await pollForAppToken(transferKeyPair: transferKeyPair)
            await webSession.stop()
            return token
        } catch {
            await webSession.stop()
            throw error
        }
    }

    private func resolveOAuthAppInfo(
        appURL: URL,
        teamDomainHint: String,
        appDomainHint: String
    ) async throws -> OAuthAppInfo {
        if let strict = try? await AppInfoResolver(
            client: httpClient,
            userAgent: userAgent
        ).resolve(appURL: appURL) {
            return OAuthAppInfo(
                authDomain: strict.authDomain,
                appDomain: strict.appDomain,
                appAUD: strict.appAUD
            )
        }

        let normalizedTeamHint = teamDomainHint.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedAppHint = appDomainHint.trimmingCharacters(in: .whitespacesAndNewlines)
        let appHostFallback = appURL.host?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let fallbackAppDomain = normalizedAppHint.isEmpty ? appHostFallback : normalizedAppHint

        func makeInfo(
            authDomain: String?,
            appDomainHeader: String?,
            appAUD: String?
        ) -> OAuthAppInfo? {
            let auth = (authDomain ?? normalizedTeamHint).trimmingCharacters(in: .whitespacesAndNewlines)
            let app = (appDomainHeader ?? fallbackAppDomain).trimmingCharacters(in: .whitespacesAndNewlines)
            let aud = (appAUD ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !auth.isEmpty, !app.isEmpty, !aud.isEmpty else { return nil }
            return OAuthAppInfo(authDomain: auth, appDomain: app, appAUD: aud)
        }

        func aud(from url: URL, response: HTTPURLResponse) -> String? {
            if let kid = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "kid" })?
                .value?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !kid.isEmpty {
                return kid
            }

            if let headerAUD = response.value(forHTTPHeaderField: AccessHeader.appAUD)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !headerAUD.isEmpty {
                return headerAUD
            }

            if let location = response.value(forHTTPHeaderField: "Location"),
               let locationURL = URL(string: location, relativeTo: appURL),
               let kid = URLComponents(url: locationURL, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "kid" })?
                .value?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !kid.isEmpty {
                return kid
            }

            return nil
        }

        var errors: [String] = []
        let methods = ["HEAD", "GET"]

        for method in methods {
            do {
                var request = URLRequest(url: appURL)
                request.httpMethod = method
                request.timeoutInterval = discoveryTimeout
                request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

                let (_, responseRaw) = try await URLSession.shared.data(for: request)
                guard let response = responseRaw as? HTTPURLResponse else { continue }
                guard let finalURL = response.url else { continue }

                if let resolved = makeInfo(
                    authDomain: finalURL.host,
                    appDomainHeader: response.value(forHTTPHeaderField: AccessHeader.appDomain),
                    appAUD: aud(from: finalURL, response: response)
                ) {
                    return resolved
                }
            } catch {
                errors.append("\(method)-follow: \(error.localizedDescription)")
            }
        }

        for method in methods {
            do {
                let config = URLSessionConfiguration.ephemeral
                let delegate = RedirectBlockingDelegate()
                let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
                defer { session.invalidateAndCancel() }

                var request = URLRequest(url: appURL)
                request.httpMethod = method
                request.timeoutInterval = discoveryTimeout
                request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

                let (_, responseRaw) = try await session.data(for: request)
                guard let response = responseRaw as? HTTPURLResponse else { continue }
                guard let location = response.value(forHTTPHeaderField: "Location"),
                      let locationURL = URL(string: location, relativeTo: appURL) else { continue }

                if let resolved = makeInfo(
                    authDomain: locationURL.host,
                    appDomainHeader: response.value(forHTTPHeaderField: AccessHeader.appDomain),
                    appAUD: aud(from: locationURL, response: response)
                ) {
                    return resolved
                }
            } catch {
                errors.append("\(method)-location: \(error.localizedDescription)")
            }
        }

        if !normalizedTeamHint.isEmpty {
            for method in methods {
                do {
                    var request = URLRequest(url: appURL)
                    request.httpMethod = method
                    request.timeoutInterval = discoveryTimeout
                    request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

                    let (_, responseRaw) = try await URLSession.shared.data(for: request)
                    guard let response = responseRaw as? HTTPURLResponse,
                          let finalURL = response.url,
                          let inferredAUD = aud(from: finalURL, response: response),
                          !inferredAUD.isEmpty
                    else {
                        continue
                    }

                    let appDomain = fallbackAppDomain.isEmpty ? appURL.host ?? "" : fallbackAppDomain
                    if !appDomain.isEmpty {
                        return OAuthAppInfo(
                            authDomain: normalizedTeamHint,
                            appDomain: appDomain,
                            appAUD: inferredAUD
                        )
                    }
                } catch {
                    errors.append("hint-\(method): \(error.localizedDescription)")
                }
            }
        }

        let details = errors.isEmpty ? "no Access redirect/AUD discovered" : errors.joined(separator: "; ")
        throw Failure.protocolViolation("unable to resolve Cloudflare OAuth metadata (\(details))")
    }

    private func buildAuthorizeURL(
        appURL: URL,
        appAUD: String,
        transferID: String
    ) throws -> URL {
        guard var baseComponents = URLComponents(url: appURL, resolvingAgainstBaseURL: false) else {
            throw Failure.configuration("invalid app URL for Cloudflare OAuth")
        }

        baseComponents.path = ""
        baseComponents.query = nil

        var baseItems: [URLQueryItem] = []
        setQueryItem(name: "token", value: transferID, in: &baseItems)
        setQueryItem(name: "aud", value: appAUD, in: &baseItems)
        baseComponents.queryItems = baseItems

        guard let redirectURL = baseComponents.url else {
            throw Failure.configuration("failed to build oauth redirect URL")
        }

        var cliComponents = baseComponents
        cliComponents.path = "/cdn-cgi/access/cli"

        var cliItems = baseItems
        setQueryItem(name: "redirect_url", value: redirectURL.absoluteString, in: &cliItems)
        setQueryItem(name: "send_org_token", value: "true", in: &cliItems)
        setQueryItem(name: "edge_token_transfer", value: "true", in: &cliItems)
        cliComponents.queryItems = cliItems

        guard let authorizeURL = cliComponents.url else {
            throw Failure.configuration("failed to build Cloudflare login URL")
        }

        return authorizeURL
    }

    private func setQueryItem(name: String, value: String, in items: inout [URLQueryItem]) {
        if let index = items.firstIndex(where: { $0.name == name }) {
            items[index] = URLQueryItem(name: name, value: value)
        } else {
            items.append(URLQueryItem(name: name, value: value))
        }
    }

    private func makeTransferKeyPair() throws -> TransferKeyPair {
        let pair = try NaclBox.keyPair()
        guard pair.publicKey.count == 32, pair.secretKey.count == 32 else {
            throw Failure.internalError("invalid transfer keypair length")
        }

        let publicKeyID = pair.publicKey.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")

        return TransferKeyPair(
            publicKeyID: publicKeyID,
            privateKey: pair.secretKey
        )
    }

    private func pollForAppToken(transferKeyPair: TransferKeyPair) async throws -> String {
        let transferID = transferKeyPair.publicKeyID
        let encodedTransferID = transferID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? transferID

        guard let edgePollURL = URL(string: "https://login.cloudflareaccess.org/transfer/\(encodedTransferID)") else {
            throw Failure.configuration("failed to build Cloudflare transfer URL")
        }
        guard let legacyPollURL = URL(string: "https://login.cloudflareaccess.org/\(encodedTransferID)") else {
            throw Failure.configuration("failed to build Cloudflare transfer URL")
        }

        struct TransferResponse: Decodable {
            let appToken: String?
            let token: String?
            let orgToken: String?

            enum CodingKeys: String, CodingKey {
                case appToken = "app_token"
                case token
                case orgToken = "org_token"
            }
        }

        func normalizedJWTCandidate(_ value: String?) -> String? {
            guard let value else { return nil }

            let trimmed = value
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            guard !trimmed.isEmpty else { return nil }

            if trimmed.split(separator: ".").count == 3 {
                return trimmed
            }

            let decoded = trimmed.removingPercentEncoding ?? trimmed
            guard decoded.split(separator: ".").count == 3 else { return nil }
            return decoded
        }

        func decodeBase64Data(from value: String?) -> Data? {
            guard let value else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }

            let variants = [
                trimmed,
                trimmed
                    .replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
            ]

            for variant in variants {
                var candidate = variant
                let paddingNeeded = (4 - (candidate.count % 4)) % 4
                if paddingNeeded > 0 {
                    candidate.append(String(repeating: "=", count: paddingNeeded))
                }
                if let decoded = Data(base64Encoded: candidate) {
                    return decoded
                }
            }

            return nil
        }

        func parseToken(from data: Data) -> String? {
            if let decoded = try? JSONDecoder().decode(TransferResponse.self, from: data) {
                if let appToken = normalizedJWTCandidate(decoded.appToken) {
                    return appToken
                }
                if let token = normalizedJWTCandidate(decoded.token) {
                    return token
                }
                if let orgToken = normalizedJWTCandidate(decoded.orgToken) {
                    return orgToken
                }
            }

            if let body = String(data: data, encoding: .utf8),
               let token = normalizedJWTCandidate(body) {
                return token
            }

            return nil
        }

        func decryptedTransferPayload(data: Data, response: HTTPURLResponse) -> Data? {
            guard
                let servicePublicKey = decodeBase64Data(from: response.value(forHTTPHeaderField: "service-public-key")),
                servicePublicKey.count == 32,
                let payloadEncoded = String(data: data, encoding: .utf8),
                let payload = decodeBase64Data(from: payloadEncoded),
                payload.count > 24
            else {
                return nil
            }

            let nonce = Data(payload.prefix(24))
            let boxedPayload = Data(payload.dropFirst(24))
            guard !boxedPayload.isEmpty else { return nil }

            return try? NaclBox.open(
                message: boxedPayload,
                nonce: nonce,
                publicKey: servicePublicKey,
                secretKey: transferKeyPair.privateKey
            )
        }

        func parseToken(data: Data, response: HTTPURLResponse) -> String? {
            if let token = parseToken(from: data) {
                return token
            }

            if let decrypted = decryptedTransferPayload(data: data, response: response),
               let token = parseToken(from: decrypted) {
                return token
            }

            if let body = String(data: data, encoding: .utf8),
               let decoded = decodeBase64Data(from: body),
               let token = parseToken(from: decoded) {
                return token
            }

            if let finalURL = response.url,
               let components = URLComponents(url: finalURL, resolvingAgainstBaseURL: false) {
                if let appToken = normalizedJWTCandidate(components.queryItems?.first(where: { $0.name == "app_token" })?.value) {
                    return appToken
                }
                if let token = normalizedJWTCandidate(components.queryItems?.first(where: { $0.name == "token" })?.value) {
                    return token
                }
                if let orgToken = normalizedJWTCandidate(components.queryItems?.first(where: { $0.name == "org_token" })?.value) {
                    return orgToken
                }
            }

            if let location = response.value(forHTTPHeaderField: "Location"),
               let components = URLComponents(string: location) {
                if let appToken = normalizedJWTCandidate(components.queryItems?.first(where: { $0.name == "app_token" })?.value) {
                    return appToken
                }
                if let token = normalizedJWTCandidate(components.queryItems?.first(where: { $0.name == "token" })?.value) {
                    return token
                }
                if let orgToken = normalizedJWTCandidate(components.queryItems?.first(where: { $0.name == "org_token" })?.value) {
                    return orgToken
                }
            }

            if let url = response.url {
                let headerFields = response.allHeaderFields.reduce(into: [String: String]()) { partialResult, entry in
                    guard let key = entry.key as? String else { return }
                    partialResult[key] = String(describing: entry.value)
                }
                let cookies = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)

                if let accessCookie = cookies.first(where: {
                    $0.name.caseInsensitiveCompare("CF_Authorization") == .orderedSame
                }),
                   let jwt = normalizedJWTCandidate(accessCookie.value) {
                    return jwt
                }

                if let anyJWTCookie = cookies.first(where: { normalizedJWTCandidate($0.value) != nil }),
                   let jwt = normalizedJWTCandidate(anyJWTCookie.value) {
                    return jwt
                }
            }

            return nil
        }

        var observations: [String] = []

        func record(_ value: String) {
            observations.append(value)
            if observations.count > 10 {
                observations.removeFirst(observations.count - 10)
            }
        }

        func poll(url: URL) async throws -> String? {
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.timeoutInterval = pollTimeout
            request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

            let (data, response) = try await httpClient.send(request)
            let hasServicePublicKey = (response.value(forHTTPHeaderField: "service-public-key")?.isEmpty == false)
            let parsedToken = parseToken(data: data, response: response)

            record(
                "[\(url.lastPathComponent)] status=\(response.statusCode) bytes=\(data.count) servicePublicKey=\(hasServicePublicKey) parsedJWT=\(parsedToken != nil)"
            )

            switch response.statusCode {
            case 200:
                return parsedToken
            case 204, 404:
                return nil
            case 500...599:
                throw Failure.transport(
                    "Cloudflare transfer service returned \(response.statusCode)",
                    retryable: true
                )
            default:
                return parsedToken
            }
        }

        for attempt in 0..<pollAttempts {
            if Task.isCancelled {
                throw CancellationError()
            }

            if await webSession.didCancelLogin() {
                throw Failure.auth("Cloudflare login was cancelled")
            }

            do {
                if let edgeToken = try await poll(url: edgePollURL) {
                    return edgeToken
                }
                if let legacyToken = try await poll(url: legacyPollURL) {
                    return legacyToken
                }
            } catch let urlError as URLError where urlError.code == .timedOut {
                // Transfer endpoint long-polls. Timeout per request should not abort overall auth.
            } catch {
                let nsError = error as NSError
                if nsError.domain == NSURLErrorDomain, nsError.code == NSURLErrorTimedOut {
                    // Bridged timeout. Continue polling.
                } else {
                    throw error
                }
            }

            if attempt < pollAttempts - 1, pollDelayNanoseconds > 0 {
                try await Task.sleep(nanoseconds: pollDelayNanoseconds)
            }
        }

        let details = observations.isEmpty ? "" : " (\(observations.joined(separator: " || ")))"
        throw Failure.auth("Timed out waiting for Cloudflare Access token\(details)")
    }
}
