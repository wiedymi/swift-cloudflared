public struct SSHRetryPolicy: Sendable, Equatable {
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

public actor SSHSessionActor: SSHClient {
    public nonisolated let state: AsyncStream<SSHConnectionState>

    private let authProvider: any SSHAuthProviding
    private let tunnelProvider: any SSHTunnelProviding
    private let retryPolicy: SSHRetryPolicy
    private let oauthFallback: (@Sendable (String) -> SSHAuthMethod?)?
    private let sleep: @Sendable (UInt64) async -> Void

    private var continuation: AsyncStream<SSHConnectionState>.Continuation?
    private var currentState: SSHConnectionState = .idle

    public init(
        authProvider: any SSHAuthProviding,
        tunnelProvider: any SSHTunnelProviding,
        retryPolicy: SSHRetryPolicy,
        oauthFallback: (@Sendable (String) -> SSHAuthMethod?)?,
        sleep: @escaping @Sendable (UInt64) async -> Void
    ) {
        var localContinuation: AsyncStream<SSHConnectionState>.Continuation?
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

    public func connect(hostname: String, method: SSHAuthMethod) async throws -> UInt16 {
        guard canStartConnection(from: currentState) else {
            let failure = SSHFailure.invalidState("cannot connect from state \(currentState)")
            publish(.failed(failure))
            throw failure
        }

        let originURL = try SSHURLTools.normalizeOriginURL(from: hostname)
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

    private func connectWithMethod(hostname: String, method: SSHAuthMethod) async throws -> UInt16 {
        publish(.authenticating)
        let authContext = try await authProvider.authenticate(hostname: hostname, method: method)

        var attempt = 0
        var lastFailure = SSHFailure.transport("connection attempts exhausted", retryable: false)
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

    private func canStartConnection(from state: SSHConnectionState) -> Bool {
        switch state {
        case .idle, .disconnected, .failed:
            return true
        default:
            return false
        }
    }

    private func toFailure(_ error: Error) -> SSHFailure {
        if let failure = error as? SSHFailure {
            return failure
        }

        return .internalError(String(describing: error))
    }

    private func publish(_ newState: SSHConnectionState) {
        currentState = newState
        continuation?.yield(newState)
    }
}
