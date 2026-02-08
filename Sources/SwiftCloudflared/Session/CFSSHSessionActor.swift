public struct CFSSHRetryPolicy: Sendable, Equatable {
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

public actor CFSSHSessionActor: CFSSHClient {
    public nonisolated let state: AsyncStream<CFSSHConnectionState>

    private let authProvider: any CFSSHAuthProviding
    private let tunnelProvider: any CFSSHTunnelProviding
    private let retryPolicy: CFSSHRetryPolicy
    private let oauthFallback: (@Sendable (String) -> CFSSHAuthMethod?)?
    private let sleep: @Sendable (UInt64) async -> Void

    private var continuation: AsyncStream<CFSSHConnectionState>.Continuation?
    private var currentState: CFSSHConnectionState = .idle

    public init(
        authProvider: any CFSSHAuthProviding,
        tunnelProvider: any CFSSHTunnelProviding,
        retryPolicy: CFSSHRetryPolicy,
        oauthFallback: (@Sendable (String) -> CFSSHAuthMethod?)?,
        sleep: @escaping @Sendable (UInt64) async -> Void
    ) {
        var localContinuation: AsyncStream<CFSSHConnectionState>.Continuation?
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

    public func connect(hostname: String, method: CFSSHAuthMethod) async throws -> UInt16 {
        guard canStartConnection(from: currentState) else {
            let failure = CFSSHFailure.invalidState("cannot connect from state \(currentState)")
            publish(.failed(failure))
            throw failure
        }

        let originURL = try CFSSHURLTools.normalizeOriginURL(from: hostname)
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

    private func connectWithMethod(hostname: String, method: CFSSHAuthMethod) async throws -> UInt16 {
        publish(.authenticating)
        let authContext = try await authProvider.authenticate(hostname: hostname, method: method)

        var attempt = 0
        var lastFailure = CFSSHFailure.transport("connection attempts exhausted", retryable: false)
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

    private func canStartConnection(from state: CFSSHConnectionState) -> Bool {
        switch state {
        case .idle, .disconnected, .failed:
            return true
        default:
            return false
        }
    }

    private func toFailure(_ error: Error) -> CFSSHFailure {
        if let failure = error as? CFSSHFailure {
            return failure
        }

        return .internalError(String(describing: error))
    }

    private func publish(_ newState: CFSSHConnectionState) {
        currentState = newState
        continuation?.yield(newState)
    }
}
