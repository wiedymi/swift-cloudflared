import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public protocol SSHWebSocketClient: Sendable {
    func send(data: Data) async throws
    func receive() async throws -> Data?
    func close() async
}

public protocol SSHWebSocketDialing: Sendable {
    func connect(request: URLRequest) async throws -> any SSHWebSocketClient
}

public struct SSHURLSessionWebSocketDialer: SSHWebSocketDialing {
    private let session: URLSession

    public init(configuration: URLSessionConfiguration = .default) {
        self.session = URLSession(configuration: configuration)
    }

    public init(session: URLSession) {
        self.session = session
    }

    public func connect(request: URLRequest) async throws -> any SSHWebSocketClient {
        let task = session.webSocketTask(with: request)
        task.resume()
        return SSHURLSessionWebSocketClient(task: task)
    }
}

public final class SSHURLSessionWebSocketClient: @unchecked Sendable, SSHWebSocketClient {
    private let task: URLSessionWebSocketTask

    public init(task: URLSessionWebSocketTask) {
        self.task = task
    }

    public func send(data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            task.send(.data(data)) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    public func receive() async throws -> Data? {
        let message: URLSessionWebSocketTask.Message = try await withCheckedThrowingContinuation { continuation in
            task.receive { result in
                switch result {
                case .success(let message):
                    continuation.resume(returning: message)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }

        return Self.decode(message)
    }

    static func decode(_ message: URLSessionWebSocketTask.Message?) -> Data? {
        if case .data(let data) = message {
            return data
        }
        if case .string(let text) = message {
            return Data(text.utf8)
        }
        return nil
    }

    public func close() async {
        task.cancel(with: .normalClosure, reason: nil)
    }
}

public actor SSHCloudflareTunnelProvider: SSHTunnelProviding {
    public typealias OriginURLResolver = @Sendable (String) throws -> URL

    public struct ConnectionLimits: Sendable, Equatable {
        public let maxConcurrentConnections: Int
        public let stopAcceptingAfterFirstConnection: Bool

        public init(
            maxConcurrentConnections: Int = 1,
            stopAcceptingAfterFirstConnection: Bool = true
        ) {
            self.maxConcurrentConnections = max(1, maxConcurrentConnections)
            self.stopAcceptingAfterFirstConnection = stopAcceptingAfterFirstConnection
        }
    }

    public enum FaultInjection: Sendable, Equatable {
        case socket
        case inetPton
        case bind
        case listen
        case getsockname
    }

    private let requestBuilder: SSHAccessRequestBuilder
    private let websocketDialer: any SSHWebSocketDialing
    private let originURLResolver: OriginURLResolver
    private let connectionLimits: ConnectionLimits
    private let faultInjection: FaultInjection?

    private var listeningSocket: Int32 = -1
    private var acceptTask: Task<Void, Never>?
    private var bridgeTasks: [UUID: Task<Void, Never>] = [:]
    private var bridgeSockets: [UUID: Int32] = [:]

    public init(
        requestBuilder: SSHAccessRequestBuilder = SSHAccessRequestBuilder(),
        websocketDialer: any SSHWebSocketDialing = SSHURLSessionWebSocketDialer(),
        originURLResolver: @escaping OriginURLResolver = { hostname in
            try SSHURLTools.normalizeOriginURL(from: hostname)
        },
        connectionLimits: ConnectionLimits = ConnectionLimits(),
        faultInjection: FaultInjection? = nil
    ) {
        self.requestBuilder = requestBuilder
        self.websocketDialer = websocketDialer
        self.originURLResolver = originURLResolver
        self.connectionLimits = connectionLimits
        self.faultInjection = faultInjection
    }

    public func open(hostname: String, authContext: SSHAuthContext, method: SSHAuthMethod) async throws -> UInt16 {
        guard listeningSocket < 0 else {
            throw SSHFailure.invalidState("tunnel already open")
        }

        let originURL = try originURLResolver(hostname)
        let websocketURL = try SSHURLTools.websocketURL(from: originURL)

        let socketFD = faultInjection == .socket ? -1 : Self.systemSocket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw SSHFailure.transport("failed to create socket", retryable: true)
        }

        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) {
            setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size))
        }

        var address = sockaddr_in()
    #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(0)

        let resultIP = faultInjection == .inetPton
            ? -1
            : "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        guard resultIP == 1 else {
            _ = Self.systemClose(socketFD)
            throw SSHFailure.transport("failed to encode loopback address", retryable: false)
        }

        let bindResult: Int32
        if faultInjection == .bind {
            bindResult = -1
        } else {
            bindResult = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard bindResult == 0 else {
            _ = Self.systemClose(socketFD)
            throw SSHFailure.transport("failed to bind loopback listener", retryable: true)
        }

        let listenResult = faultInjection == .listen ? -1 : listen(socketFD, SOMAXCONN)
        guard listenResult == 0 else {
            _ = Self.systemClose(socketFD)
            throw SSHFailure.transport("failed to listen on loopback socket", retryable: true)
        }

        var boundAddress = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult: Int32
        if faultInjection == .getsockname {
            nameResult = -1
        } else {
            nameResult = withUnsafeMutablePointer(to: &boundAddress) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(socketFD, $0, &length)
                }
            }
        }
        guard nameResult == 0 else {
            _ = Self.systemClose(socketFD)
            throw SSHFailure.transport("failed to read local listener port", retryable: false)
        }

        listeningSocket = socketFD

        let requestBuilder = self.requestBuilder
        let websocketDialer = self.websocketDialer

        acceptTask = Task.detached(priority: .utility) {
            while true {
                let clientFD = Self.systemAccept(socketFD)
                if clientFD < 0 {
                    break
                }

                await self.handleAcceptedClient(
                    clientFD: clientFD,
                    listenerFD: socketFD,
                    websocketURL: websocketURL,
                    authContext: authContext,
                    method: method,
                    requestBuilder: requestBuilder,
                    websocketDialer: websocketDialer
                )
            }
        }

        return UInt16(bigEndian: boundAddress.sin_port)
    }

    public func close() async {
        if listeningSocket >= 0 {
            _ = Self.systemShutdown(listeningSocket)
            _ = Self.systemClose(listeningSocket)
            listeningSocket = -1
        }

        acceptTask?.cancel()
        acceptTask = nil

        let sockets = Array(bridgeSockets.values)
        for fd in sockets {
            _ = Self.systemShutdown(fd)
            _ = Self.systemClose(fd)
        }

        let tasks = Array(bridgeTasks.values)
        bridgeTasks.removeAll()
        bridgeSockets.removeAll()

        for task in tasks {
            task.cancel()
            _ = await task.result
        }
    }

    private func startBridge(
        clientFD: Int32,
        websocketURL: URL,
        authContext: SSHAuthContext,
        method: SSHAuthMethod,
        requestBuilder: SSHAccessRequestBuilder,
        websocketDialer: any SSHWebSocketDialing
    ) async {
        Self.configureNoSigPipeIfSupported(fd: clientFD)

        let bridgeID = UUID()
        bridgeSockets[bridgeID] = clientFD

        let bridgeTask = Task.detached(priority: .utility) { [weak self] in
            await Self.runBridge(
                clientFD: clientFD,
                websocketURL: websocketURL,
                authContext: authContext,
                method: method,
                requestBuilder: requestBuilder,
                websocketDialer: websocketDialer
            )
            await self?.bridgeFinished(id: bridgeID)
        }

        bridgeTasks[bridgeID] = bridgeTask
    }

    private func handleAcceptedClient(
        clientFD: Int32,
        listenerFD: Int32,
        websocketURL: URL,
        authContext: SSHAuthContext,
        method: SSHAuthMethod,
        requestBuilder: SSHAccessRequestBuilder,
        websocketDialer: any SSHWebSocketDialing
    ) async {
        // Cap active local clients to bound memory/file-descriptor pressure.
        guard bridgeTasks.count < connectionLimits.maxConcurrentConnections else {
            _ = Self.systemShutdown(clientFD)
            _ = Self.systemClose(clientFD)
            return
        }

        // Secure default: first accepted local client wins and listener is closed.
        if connectionLimits.stopAcceptingAfterFirstConnection {
            closeListenerIfStillOpen(expectedFD: listenerFD)
        }

        await startBridge(
            clientFD: clientFD,
            websocketURL: websocketURL,
            authContext: authContext,
            method: method,
            requestBuilder: requestBuilder,
            websocketDialer: websocketDialer
        )
    }

    private func closeListenerIfStillOpen(expectedFD: Int32) {
        guard listeningSocket == expectedFD else {
            return
        }
        _ = Self.systemShutdown(listeningSocket)
        _ = Self.systemClose(listeningSocket)
        listeningSocket = -1
    }

    private func bridgeFinished(id: UUID) {
        bridgeTasks[id] = nil
        bridgeSockets[id] = nil
    }

    private static func runBridge(
        clientFD: Int32,
        websocketURL: URL,
        authContext: SSHAuthContext,
        method: SSHAuthMethod,
        requestBuilder: SSHAccessRequestBuilder,
        websocketDialer: any SSHWebSocketDialing
    ) async {
        let request = requestBuilder.build(originURL: websocketURL, authContext: authContext)

        let websocketClient: any SSHWebSocketClient
        do {
            websocketClient = try await websocketDialer.connect(request: request)
        } catch {
            _ = systemShutdown(clientFD)
            _ = systemClose(clientFD)
            return
        }

        defer {
            _ = systemShutdown(clientFD)
            _ = systemClose(clientFD)
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await pumpClientToWebSocket(clientFD: clientFD, websocketClient: websocketClient)
            }
            group.addTask {
                await pumpWebSocketToClient(clientFD: clientFD, websocketClient: websocketClient)
            }

            _ = await group.next()
            group.cancelAll()

            _ = systemShutdown(clientFD)
            await websocketClient.close()

            while await group.next() != nil {}
        }

        await websocketClient.close()

        // Keep interface stable for future method-dependent transport decisions.
        _ = method
    }

    private static func pumpClientToWebSocket(clientFD: Int32, websocketClient: any SSHWebSocketClient) async {
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)

        while !Task.isCancelled {
            let readCount = buffer.withUnsafeMutableBytes { rawBuffer in
                read(clientFD, rawBuffer.baseAddress, rawBuffer.count)
            }

            if readCount > 0 {
                do {
                    try await websocketClient.send(data: Data(buffer[0..<readCount]))
                } catch {
                    return
                }
            } else if readCount == 0 {
                return
            } else {
                return
            }
        }
    }

    private static func pumpWebSocketToClient(clientFD: Int32, websocketClient: any SSHWebSocketClient) async {
        while !Task.isCancelled {
            let payload: Data
            do {
                guard let next = try await websocketClient.receive() else {
                    return
                }
                payload = next
            } catch {
                return
            }

            guard !payload.isEmpty else {
                continue
            }

            if !writeAll(fd: clientFD, data: payload) {
                return
            }
        }
    }

    private static func writeAll(fd: Int32, data: Data) -> Bool {
        var written = 0
        let total = data.count

        return data.withUnsafeBytes { rawBuffer in
            let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress!

            while written < total {
                let pointer = base.advanced(by: written)
                let result = write(fd, pointer, total - written)

                if result > 0 {
                    written += result
                    continue
                }

                return false
            }

            return true
        }
    }

    private nonisolated static func systemSocket(_ domain: Int32, _ type: Int32, _ proto: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.socket(domain, type, proto)
    #else
        Glibc.socket(domain, type, proto)
    #endif
    }

    private nonisolated static func systemAccept(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.accept(fd, nil, nil)
    #else
        Glibc.accept(fd, nil, nil)
    #endif
    }

    private nonisolated static func systemShutdown(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.shutdown(fd, SHUT_RDWR)
    #else
        Glibc.shutdown(fd, Int32(SHUT_RDWR))
    #endif
    }

    private nonisolated static func systemClose(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.close(fd)
    #else
        Glibc.close(fd)
    #endif
    }

    private nonisolated static func configureNoSigPipeIfSupported(fd: Int32) {
    #if canImport(Darwin)
        var value: Int32 = 1
        _ = withUnsafePointer(to: &value) {
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, $0, socklen_t(MemoryLayout<Int32>.size))
        }
    #endif
    }
}

#if DEBUG
extension SSHCloudflareTunnelProvider {
    static func _testPumpClientToWebSocket(clientFD: Int32, websocketClient: any SSHWebSocketClient) async {
        await pumpClientToWebSocket(clientFD: clientFD, websocketClient: websocketClient)
    }

    static func _testPumpWebSocketToClient(clientFD: Int32, websocketClient: any SSHWebSocketClient) async {
        await pumpWebSocketToClient(clientFD: clientFD, websocketClient: websocketClient)
    }
}
#endif
