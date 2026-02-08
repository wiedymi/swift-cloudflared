public protocol SSHAuthProviding: Sendable {
    func authenticate(hostname: String, method: SSHAuthMethod) async throws -> SSHAuthContext
}

public protocol SSHOAuthFlow: Sendable {
    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String
}

public struct SSHOAuthProvider: SSHAuthProviding {
    private let flow: any SSHOAuthFlow
    private let tokenStore: any SSHTokenStore
    private let validator: SSHJWTValidator

    public init(
        flow: any SSHOAuthFlow,
        tokenStore: any SSHTokenStore,
        validator: SSHJWTValidator = SSHJWTValidator()
    ) {
        self.flow = flow
        self.tokenStore = tokenStore
        self.validator = validator
    }

    public func authenticate(hostname: String, method: SSHAuthMethod) async throws -> SSHAuthContext {
        guard case .oauth(let teamDomain, let appDomain, let callbackScheme) = method else {
            throw SSHFailure.configuration("oauth provider requires oauth auth method")
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
            throw SSHFailure.auth("oauth flow returned empty token")
        }

        do {
            if try validator.isExpired(freshToken) {
                throw SSHFailure.auth("oauth flow returned expired token")
            }
        } catch let failure as SSHFailure {
            throw failure
        } catch {
            throw SSHFailure.auth("oauth flow returned invalid token")
        }

        try await tokenStore.writeToken(freshToken, for: cacheKey)
        return .appToken(freshToken)
    }

    private func makeCacheKey(teamDomain: String, appDomain: String, hostname: String) -> String {
        "oauth|\(teamDomain)|\(appDomain)|\(hostname)"
    }
}

public struct SSHServiceTokenProvider: SSHAuthProviding {
    public init() {}

    public func authenticate(hostname: String, method: SSHAuthMethod) async throws -> SSHAuthContext {
        guard case .serviceToken(_, let clientID, let clientSecret) = method else {
            throw SSHFailure.configuration("service token provider requires serviceToken auth method")
        }

        guard !clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SSHFailure.auth("service token client id must not be empty")
        }

        guard !clientSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SSHFailure.auth("service token client secret must not be empty")
        }

        return .serviceToken(id: clientID, secret: clientSecret)
    }
}

public struct SSHAuthMultiplexer: SSHAuthProviding {
    private let oauthProvider: any SSHAuthProviding
    private let serviceProvider: any SSHAuthProviding
    private let oauthFallback: (@Sendable (String) -> SSHAuthMethod?)?

    public init(
        oauthProvider: any SSHAuthProviding,
        serviceProvider: any SSHAuthProviding,
        oauthFallback: (@Sendable (String) -> SSHAuthMethod?)? = nil
    ) {
        self.oauthProvider = oauthProvider
        self.serviceProvider = serviceProvider
        self.oauthFallback = oauthFallback
    }

    public func authenticate(hostname: String, method: SSHAuthMethod) async throws -> SSHAuthContext {
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
