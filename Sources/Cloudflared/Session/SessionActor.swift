public struct RetryPolicy: Sendable, Equatable {
    public let maxReconnectAttempts: Int
    public let baseDelayNanoseconds: UInt64

    public init(maxReconnectAttempts: Int = 0, baseDelayNanoseconds: UInt64 = 250_000_000) {
        self.maxReconnectAttempts = max(0, maxReconnectAttempts)
        self.baseDelayNanoseconds = baseDelayNanoseconds
    }

    public func delayNanoseconds(for attempt: Int) -> UInt64 {
        baseDelayNanoseconds * UInt64(max(1, attempt))
    }
}

public actor SessionActor: Client {
    public nonisolated let state: AsyncStream<ConnectionState>

    private let authProvider: any AuthProviding
    private let tunnelProvider: any TunnelProviding
    private let retryPolicy: RetryPolicy
    private let oauthFallback: (@Sendable (String) -> AuthMethod?)?
    private let sleep: @Sendable (UInt64) async -> Void

    private var continuation: AsyncStream<ConnectionState>.Continuation?
    private var currentState: ConnectionState = .idle

    public init(
        authProvider: any AuthProviding,
        tunnelProvider: any TunnelProviding,
        retryPolicy: RetryPolicy,
        oauthFallback: (@Sendable (String) -> AuthMethod?)?,
        sleep: @escaping @Sendable (UInt64) async -> Void
    ) {
        var localContinuation: AsyncStream<ConnectionState>.Continuation?
        self.state = AsyncStream { continuation in
            continuation.yield(.idle)
            localContinuation = continuation
        }

        self.continuation = localContinuation
        self.authProvider = authProvider
        self.tunnelProvider = tunnelProvider
        self.retryPolicy = retryPolicy
        self.oauthFallback = oauthFallback
        self.sleep = sleep
        self.currentState = .idle
    }

    public nonisolated static func noopSleep(_: UInt64) async {}

    public func connect(hostname: String, method: AuthMethod) async throws -> UInt16 {
        guard canStartConnection(from: currentState) else {
            let failure = Failure.invalidState("cannot connect from state \(currentState)")
            publish(.failed(failure))
            throw failure
        }

        let originURL = try URLTools.normalizeOriginURL(from: hostname)
        let normalizedHost = originURL.host!

        do {
            return try await connectWithMethod(hostname: normalizedHost, method: method)
        } catch {
            if case .serviceToken = method, let fallbackMethod = oauthFallback?(hostname) {
                do {
                    return try await connectWithMethod(hostname: normalizedHost, method: fallbackMethod)
                } catch {
                    let failure = toFailure(error)
                    publish(.failed(failure))
                    throw failure
                }
            }

            let failure = toFailure(error)
            publish(.failed(failure))
            throw failure
        }
    }

    public func disconnect() async {
        await tunnelProvider.close()
        publish(.disconnected)
    }

    private func connectWithMethod(hostname: String, method: AuthMethod) async throws -> UInt16 {
        publish(.authenticating)
        let authContext = try await authProvider.authenticate(hostname: hostname, method: method)

        var attempt = 0
        var lastFailure = Failure.transport("connection attempts exhausted", retryable: false)
        while attempt <= retryPolicy.maxReconnectAttempts {
            publish(.connecting)
            do {
                let localPort = try await tunnelProvider.open(hostname: hostname, authContext: authContext, method: method)
                publish(.connected(localPort: localPort))
                return localPort
            } catch {
                let failure = toFailure(error)
                lastFailure = failure
                guard failure.isRetryable, attempt < retryPolicy.maxReconnectAttempts else {
                    break
                }

                attempt += 1
                publish(.reconnecting(attempt: attempt))
                await sleep(retryPolicy.delayNanoseconds(for: attempt))
            }
        }

        throw lastFailure
    }

    private func canStartConnection(from state: ConnectionState) -> Bool {
        switch state {
        case .idle, .disconnected, .failed:
            return true
        default:
            return false
        }
    }

    private func toFailure(_ error: Error) -> Failure {
        if let failure = error as? Failure {
            return failure
        }

        return .internalError(String(describing: error))
    }

    private func publish(_ newState: ConnectionState) {
        currentState = newState
        continuation?.yield(newState)
    }
}
