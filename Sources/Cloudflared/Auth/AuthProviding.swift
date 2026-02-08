public protocol AuthProviding: Sendable {
    func authenticate(hostname: String, method: AuthMethod) async throws -> AuthContext
}

public protocol OAuthFlow: Sendable {
    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String
}

public struct OAuthProvider: AuthProviding {
    private let flow: any OAuthFlow
    private let tokenStore: any TokenStore
    private let validator: JWTValidator

    public init(
        flow: any OAuthFlow,
        tokenStore: any TokenStore,
        validator: JWTValidator = JWTValidator()
    ) {
        self.flow = flow
        self.tokenStore = tokenStore
        self.validator = validator
    }

    public func authenticate(hostname: String, method: AuthMethod) async throws -> AuthContext {
        guard case .oauth(let teamDomain, let appDomain, let callbackScheme) = method else {
            throw Failure.configuration("oauth provider requires oauth auth method")
        }

        let cacheKey = makeCacheKey(teamDomain: teamDomain, appDomain: appDomain, hostname: hostname)

        if let cachedToken = try await tokenStore.readToken(for: cacheKey) {
            do {
                if try !validator.isExpired(cachedToken) {
                    return .appToken(cachedToken)
                }
            } catch {
                // remove malformed token and continue with fresh auth
            }
            try await tokenStore.removeToken(for: cacheKey)
        }

        let freshToken = try await flow.fetchToken(
            teamDomain: teamDomain,
            appDomain: appDomain,
            callbackScheme: callbackScheme,
            hostname: hostname
        ).trimmingCharacters(in: .whitespacesAndNewlines)

        guard !freshToken.isEmpty else {
            throw Failure.auth("oauth flow returned empty token")
        }

        do {
            if try validator.isExpired(freshToken) {
                throw Failure.auth("oauth flow returned expired token")
            }
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.auth("oauth flow returned invalid token")
        }

        try await tokenStore.writeToken(freshToken, for: cacheKey)
        return .appToken(freshToken)
    }

    private func makeCacheKey(teamDomain: String, appDomain: String, hostname: String) -> String {
        "oauth|\(teamDomain)|\(appDomain)|\(hostname)"
    }
}

public struct ServiceTokenProvider: AuthProviding {
    public init() {}

    public func authenticate(hostname: String, method: AuthMethod) async throws -> AuthContext {
        guard case .serviceToken(_, let clientID, let clientSecret) = method else {
            throw Failure.configuration("service token provider requires serviceToken auth method")
        }

        guard !clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.auth("service token client id must not be empty")
        }

        guard !clientSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.auth("service token client secret must not be empty")
        }

        return .serviceToken(id: clientID, secret: clientSecret)
    }
}

public struct AuthMultiplexer: AuthProviding {
    private let oauthProvider: any AuthProviding
    private let serviceProvider: any AuthProviding
    private let oauthFallback: (@Sendable (String) -> AuthMethod?)?

    public init(
        oauthProvider: any AuthProviding,
        serviceProvider: any AuthProviding,
        oauthFallback: (@Sendable (String) -> AuthMethod?)? = nil
    ) {
        self.oauthProvider = oauthProvider
        self.serviceProvider = serviceProvider
        self.oauthFallback = oauthFallback
    }

    public func authenticate(hostname: String, method: AuthMethod) async throws -> AuthContext {
        switch method {
        case .oauth:
            return try await oauthProvider.authenticate(hostname: hostname, method: method)
        case .serviceToken:
            do {
                return try await serviceProvider.authenticate(hostname: hostname, method: method)
            } catch {
                guard let fallbackMethod = oauthFallback?(hostname) else {
                    throw error
                }
                return try await oauthProvider.authenticate(hostname: hostname, method: fallbackMethod)
            }
        }
    }
}
