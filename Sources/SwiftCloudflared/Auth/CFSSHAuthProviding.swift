public protocol CFSSHAuthProviding: Sendable {
    func authenticate(hostname: String, method: CFSSHAuthMethod) async throws -> CFSSHAuthContext
}

public protocol CFSSHOAuthFlow: Sendable {
    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String
}

public struct CFSSHOAuthProvider: CFSSHAuthProviding {
    private let flow: any CFSSHOAuthFlow
    private let tokenStore: any CFSSHTokenStore
    private let validator: CFSSHJWTValidator

    public init(
        flow: any CFSSHOAuthFlow,
        tokenStore: any CFSSHTokenStore,
        validator: CFSSHJWTValidator = CFSSHJWTValidator()
    ) {
        self.flow = flow
        self.tokenStore = tokenStore
        self.validator = validator
    }

    public func authenticate(hostname: String, method: CFSSHAuthMethod) async throws -> CFSSHAuthContext {
        guard case .oauth(let teamDomain, let appDomain, let callbackScheme) = method else {
            throw CFSSHFailure.configuration("oauth provider requires oauth auth method")
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
            throw CFSSHFailure.auth("oauth flow returned empty token")
        }

        do {
            if try validator.isExpired(freshToken) {
                throw CFSSHFailure.auth("oauth flow returned expired token")
            }
        } catch let failure as CFSSHFailure {
            throw failure
        } catch {
            throw CFSSHFailure.auth("oauth flow returned invalid token")
        }

        try await tokenStore.writeToken(freshToken, for: cacheKey)
        return .appToken(freshToken)
    }

    private func makeCacheKey(teamDomain: String, appDomain: String, hostname: String) -> String {
        "oauth|\(teamDomain)|\(appDomain)|\(hostname)"
    }
}

public struct CFSSHServiceTokenProvider: CFSSHAuthProviding {
    public init() {}

    public func authenticate(hostname: String, method: CFSSHAuthMethod) async throws -> CFSSHAuthContext {
        guard case .serviceToken(_, let clientID, let clientSecret) = method else {
            throw CFSSHFailure.configuration("service token provider requires serviceToken auth method")
        }

        guard !clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw CFSSHFailure.auth("service token client id must not be empty")
        }

        guard !clientSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw CFSSHFailure.auth("service token client secret must not be empty")
        }

        return .serviceToken(id: clientID, secret: clientSecret)
    }
}

public struct CFSSHAuthMultiplexer: CFSSHAuthProviding {
    private let oauthProvider: any CFSSHAuthProviding
    private let serviceProvider: any CFSSHAuthProviding
    private let oauthFallback: (@Sendable (String) -> CFSSHAuthMethod?)?

    public init(
        oauthProvider: any CFSSHAuthProviding,
        serviceProvider: any CFSSHAuthProviding,
        oauthFallback: (@Sendable (String) -> CFSSHAuthMethod?)? = nil
    ) {
        self.oauthProvider = oauthProvider
        self.serviceProvider = serviceProvider
        self.oauthFallback = oauthFallback
    }

    public func authenticate(hostname: String, method: CFSSHAuthMethod) async throws -> CFSSHAuthContext {
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
