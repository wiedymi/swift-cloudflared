import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public protocol WebSocketClient: Sendable {
    func send(data: Data) async throws
    func receive() async throws -> Data?
    func close() async
}

public protocol WebSocketDialing: Sendable {
    func connect(request: URLRequest) async throws -> any WebSocketClient
}

public struct URLSessionWebSocketDialer: WebSocketDialing {
    private let session: URLSession

    public init(configuration: URLSessionConfiguration = .default) {
        self.session = URLSession(configuration: configuration)
    }

    public init(session: URLSession) {
        self.session = session
    }

    public func connect(request: URLRequest) async throws -> any WebSocketClient {
        let task = session.webSocketTask(with: request)
        task.resume()
        return URLSessionWebSocketClient(task: task)
    }
}

public final class URLSessionWebSocketClient: @unchecked Sendable, WebSocketClient {
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

public actor CloudflareTunnelProvider: TunnelProviding {
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

    private let requestBuilder: AccessRequestBuilder
    private let websocketDialer: any WebSocketDialing
    private let originURLResolver: OriginURLResolver
    private let connectionLimits: ConnectionLimits
    private let faultInjection: FaultInjection?
    private static let ioRetryNanoseconds: UInt64 = 2_000_000

    private var listener: SocketHandle?
    private var closeTask: Task<Void, Never>?
    private var acceptTask: Task<Void, Never>?
    private var bridges: [UUID: (socket: SocketHandle, task: Task<Void, Never>)] = [:]

    public init(
        requestBuilder: AccessRequestBuilder = AccessRequestBuilder(),
        websocketDialer: any WebSocketDialing = URLSessionWebSocketDialer(),
        originURLResolver: @escaping OriginURLResolver = { hostname in
            try URLTools.normalizeOriginURL(from: hostname)
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

    public func open(hostname: String, authContext: AuthContext, method: AuthMethod) async throws -> UInt16 {
        guard listener == nil, closeTask == nil else {
            throw Failure.invalidState("tunnel already open")
        }

        let originURL = try originURLResolver(hostname)
        let websocketURL = try URLTools.websocketURL(from: originURL)

        let socketFD = faultInjection == .socket ? -1 : Self.systemSocket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw Failure.transport("failed to create socket", retryable: true)
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
            throw Failure.transport("failed to encode loopback address", retryable: false)
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
            throw Failure.transport("failed to bind loopback listener", retryable: true)
        }

        let listenResult = faultInjection == .listen ? -1 : listen(socketFD, SOMAXCONN)
        guard listenResult == 0 else {
            _ = Self.systemClose(socketFD)
            throw Failure.transport("failed to listen on loopback socket", retryable: true)
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
            throw Failure.transport("failed to read local listener port", retryable: false)
        }

        let listener = try SocketHandle(socketFD)
        self.listener = listener

        acceptTask = Task.detached(priority: .utility) {
            while !Task.isCancelled {
                guard let clientFD = listener.withFileDescriptor(Self.systemAccept) else { break }
                if clientFD >= 0 {
                    await self.handleAcceptedClient(
                        clientFD: clientFD,
                        listener: listener,
                        websocketURL: websocketURL,
                        authContext: authContext
                    )
                    continue
                }

                let errorCode = errno
                if Self.isInterrupted(errorCode) {
                    continue
                }
                if Self.isWouldBlock(errorCode) {
                    try? await Task.sleep(nanoseconds: Self.ioRetryNanoseconds)
                    continue
                }
                if Self.isListenerClosed(errorCode) {
                    break
                }

                break
            }
        }

        return UInt16(bigEndian: boundAddress.sin_port)
    }

    public func close() async {
        if let closeTask {
            await closeTask.value
            return
        }

        let listenerTask = acceptTask
        acceptTask = nil
        listenerTask?.cancel()
        listener?.close()
        listener = nil

        let activeBridges = Array(bridges.values)
        bridges.removeAll()
        for bridge in activeBridges {
            bridge.task.cancel()
            bridge.socket.shutdown()
        }

        let cleanup = Task {
            await listenerTask?.value
            for bridge in activeBridges {
                await bridge.task.value
            }
            self.closeTask = nil
        }
        closeTask = cleanup
        await cleanup.value
    }

    private func handleAcceptedClient(
        clientFD: Int32,
        listener: SocketHandle,
        websocketURL: URL,
        authContext: AuthContext
    ) {
        guard let clientSocket = try? SocketHandle(clientFD) else { return }
        guard self.listener === listener, closeTask == nil, !Task.isCancelled,
              bridges.count < connectionLimits.maxConcurrentConnections else {
            clientSocket.close()
            return
        }

        if connectionLimits.stopAcceptingAfterFirstConnection {
            acceptTask?.cancel()
            listener.close()
        }

        let bridgeID = UUID()
        let requestBuilder = self.requestBuilder
        let websocketDialer = self.websocketDialer
        let bridgeTask = Task.detached(priority: .utility) { [weak self] in
            await Self.runBridge(
                clientSocket: clientSocket,
                websocketURL: websocketURL,
                authContext: authContext,
                requestBuilder: requestBuilder,
                websocketDialer: websocketDialer
            )
            await self?.bridgeFinished(id: bridgeID)
        }
        bridges[bridgeID] = (clientSocket, bridgeTask)
    }

    private func bridgeFinished(id: UUID) {
        bridges[id] = nil
    }

    private static func runBridge(
        clientSocket: SocketHandle,
        websocketURL: URL,
        authContext: AuthContext,
        requestBuilder: AccessRequestBuilder,
        websocketDialer: any WebSocketDialing
    ) async {
        let request = requestBuilder.build(originURL: websocketURL, authContext: authContext)

        let websocketClient: any WebSocketClient
        do {
            websocketClient = try await websocketDialer.connect(request: request)
        } catch {
            clientSocket.close()
            return
        }

        defer {
            clientSocket.close()
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await pumpClientToWebSocket(clientSocket: clientSocket, websocketClient: websocketClient)
            }
            group.addTask {
                await pumpWebSocketToClient(clientSocket: clientSocket, websocketClient: websocketClient)
            }

            _ = await group.next()
            group.cancelAll()

            clientSocket.shutdown()
            await websocketClient.close()

            while await group.next() != nil {}
        }
    }

    private static func pumpClientToWebSocket(clientSocket: SocketHandle, websocketClient: any WebSocketClient) async {
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)

        while !Task.isCancelled {
            guard let readCount = clientSocket.withFileDescriptor({ fd in
                buffer.withUnsafeMutableBytes { rawBuffer in
                    read(fd, rawBuffer.baseAddress, rawBuffer.count)
                }
            }) else { return }

            if readCount > 0 {
                do {
                    try await websocketClient.send(data: Data(buffer[0..<readCount]))
                } catch {
                    return
                }
            } else if readCount == 0 {
                return
            } else {
                let errorCode = errno
                if isInterrupted(errorCode) {
                    continue
                }
                if isWouldBlock(errorCode) {
                    try? await Task.sleep(nanoseconds: ioRetryNanoseconds)
                    continue
                }
                return
            }
        }
    }

    private static func pumpWebSocketToClient(clientSocket: SocketHandle, websocketClient: any WebSocketClient) async {
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

            if !(await writeAll(socket: clientSocket, data: payload)) {
                return
            }
        }
    }

    private static func writeAll(socket: SocketHandle, data: Data) async -> Bool {
        let payload = [UInt8](data)
        var written = 0
        let total = payload.count

        while written < total {
            if Task.isCancelled {
                return false
            }

            guard let result = socket.withFileDescriptor({ fd in
                payload.withUnsafeBytes { rawBuffer -> Int in
                    guard let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                        return -1
                    }
                    let pointer = base.advanced(by: written)
                #if canImport(Darwin)
                    return Darwin.send(fd, pointer, total - written, 0)
                #else
                    return Glibc.send(fd, pointer, total - written, Int32(MSG_NOSIGNAL))
                #endif
                }
            }) else { return false }

            if result > 0 {
                written += result
                continue
            }

            if result < 0 {
                let errorCode = errno
                if isInterrupted(errorCode) {
                    continue
                }
                if isWouldBlock(errorCode) {
                    try? await Task.sleep(nanoseconds: ioRetryNanoseconds)
                    continue
                }
            }

            return false
        }

        return true
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

    private nonisolated static func systemClose(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.close(fd)
    #else
        Glibc.close(fd)
    #endif
    }

    private nonisolated static func isWouldBlock(_ errorCode: Int32) -> Bool {
        errorCode == EAGAIN || errorCode == EWOULDBLOCK
    }

    private nonisolated static func isInterrupted(_ errorCode: Int32) -> Bool {
        errorCode == EINTR
    }

    private nonisolated static func isListenerClosed(_ errorCode: Int32) -> Bool {
        errorCode == EBADF || errorCode == EINVAL
    }
}

#if DEBUG
extension CloudflareTunnelProvider {
    static func _testPumpClientToWebSocket(clientSocket: SocketHandle, websocketClient: any WebSocketClient) async {
        await pumpClientToWebSocket(clientSocket: clientSocket, websocketClient: websocketClient)
    }

    static func _testPumpWebSocketToClient(clientSocket: SocketHandle, websocketClient: any WebSocketClient) async {
        await pumpWebSocketToClient(clientSocket: clientSocket, websocketClient: websocketClient)
    }
}
#endif
