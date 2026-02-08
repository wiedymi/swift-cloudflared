import XCTest
@testable import SwiftCloudflared

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class CFSSHCloudflareTunnelProviderTests: XCTestCase {
    private struct DummyError: Error {}

    func testOpenBuildsOAuthWebSocketRequest() async throws {
        let dialer = MockWebSocketDialer()
        let provider = CFSSHCloudflareTunnelProvider(
            requestBuilder: CFSSHAccessRequestBuilder(userAgent: "ua-test"),
            websocketDialer: dialer
        )

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt-token"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: port)
        defer { _ = close(fd) }

        let gotRequest = await waitUntil {
            await dialer.latestRequest() != nil
        }
        XCTAssertTrue(gotRequest)

        let maybeRequest = await dialer.latestRequest()
        let request = try XCTUnwrap(maybeRequest)
        XCTAssertEqual(request.url?.scheme, "wss")
        XCTAssertEqual(request.url?.host, "ssh.example.com")
        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.accessToken), "jwt-token")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "ua-test")

        await provider.close()
    }

    func testOpenBuildsServiceTokenWebSocketRequest() async throws {
        let dialer = MockWebSocketDialer()
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: dialer)

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .serviceToken(id: "id-1", secret: "secret-1"),
            method: .serviceToken(teamDomain: "team", clientID: "id-1", clientSecret: "secret-1")
        )

        let fd = try makeClientSocket(port: port)
        defer { _ = close(fd) }

        let gotRequest = await waitUntil {
            await dialer.latestRequest() != nil
        }
        XCTAssertTrue(gotRequest)

        let maybeRequest = await dialer.latestRequest()
        let request = try XCTUnwrap(maybeRequest)
        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.clientID), "id-1")
        XCTAssertEqual(request.value(forHTTPHeaderField: CFSSHAccessHeader.clientSecret), "secret-1")

        await provider.close()
    }

    func testBridgeForwardsClientToWebSocket() async throws {
        let dialer = MockWebSocketDialer()
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: dialer)

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: port)
        defer { _ = close(fd) }

        let ready = await waitUntil {
            await dialer.latestClient() != nil
        }
        XCTAssertTrue(ready)

        let payload = Data("hello".utf8)
        XCTAssertTrue(writeAll(fd: fd, data: payload))

        let forwarded = await waitUntil {
            guard let client = await dialer.latestClient() else { return false }
            return client.sentFrames().contains(payload)
        }
        XCTAssertTrue(forwarded)

        await provider.close()
    }

    func testBridgeForwardsWebSocketToClient() async throws {
        let dialer = MockWebSocketDialer()
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: dialer)

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: port)
        defer { _ = close(fd) }

        let ready = await waitUntil {
            await dialer.latestClient() != nil
        }
        XCTAssertTrue(ready)

        let maybeClient = await dialer.latestClient()
        let client = try XCTUnwrap(maybeClient)
        client.enqueueIncoming(Data("world".utf8))

        let received = try XCTUnwrap(readSome(fd: fd, timeoutSeconds: 1))
        XCTAssertEqual(received, Data("world".utf8))

        await provider.close()
    }

    func testSecondOpenFails() async throws {
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: MockWebSocketDialer())
        _ = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected invalid state")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .invalidState("tunnel already open"))
        }

        await provider.close()
    }

    func testOriginResolverErrorBubblesUp() async {
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: MockWebSocketDialer(),
            originURLResolver: { _ in
                throw CFSSHFailure.configuration("bad origin")
            }
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .configuration("bad origin"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testCloseWithoutOpenIsNoOp() async {
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: MockWebSocketDialer())
        await provider.close()
    }

    func testDefaultDialerForwardsBinaryFrame() async throws {
        let server = LocalWebSocketTestServer(frames: [.binary(Data("bin".utf8))])
        let wsPort = try server.start()
        defer { server.stop() }

        let provider = CFSSHCloudflareTunnelProvider(
            originURLResolver: { _ in
                try XCTUnwrap(URL(string: "http://127.0.0.1:\(wsPort)"))
            }
        )

        let localPort = try await provider.open(
            hostname: "ignored",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: localPort)
        defer { _ = close(fd) }

        let payload = try XCTUnwrap(readSome(fd: fd, timeoutSeconds: 1))
        XCTAssertEqual(payload, Data("bin".utf8))

        XCTAssertTrue(writeAll(fd: fd, data: Data("up".utf8)))
        await provider.close()
    }

    func testDefaultDialerForwardsTextFrame() async throws {
        let server = LocalWebSocketTestServer(frames: [.text("hello")])
        let wsPort = try server.start()
        defer { server.stop() }

        let provider = CFSSHCloudflareTunnelProvider(
            originURLResolver: { _ in
                try XCTUnwrap(URL(string: "http://127.0.0.1:\(wsPort)"))
            }
        )

        let localPort = try await provider.open(
            hostname: "ignored",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: localPort)
        defer { _ = close(fd) }

        let payload = try XCTUnwrap(readSome(fd: fd, timeoutSeconds: 1))
        XCTAssertEqual(payload, Data("hello".utf8))

        await provider.close()
    }

    func testURLSessionDialerSessionInitializer() async throws {
        let server = LocalWebSocketTestServer()
        let wsPort = try server.start()
        defer { server.stop() }

        let session = URLSession(configuration: .ephemeral)
        let dialer = CFSSHURLSessionWebSocketDialer(session: session)
        let request = URLRequest(url: try XCTUnwrap(URL(string: "ws://127.0.0.1:\(wsPort)")))

        let client = try await dialer.connect(request: request)
        await client.close()
    }

    func testURLSessionClientSendFailureAfterClose() async throws {
        let server = LocalWebSocketTestServer()
        let wsPort = try server.start()
        defer { server.stop() }

        let dialer = CFSSHURLSessionWebSocketDialer(session: URLSession(configuration: .ephemeral))
        let request = URLRequest(url: try XCTUnwrap(URL(string: "ws://127.0.0.1:\(wsPort)")))

        let client = try await dialer.connect(request: request)
        await client.close()

        do {
            try await client.send(data: Data("x".utf8))
            XCTFail("expected send to fail after close")
        } catch {
            // expected
        }
    }

    func testURLSessionClientDecodeNilFallback() {
        XCTAssertNil(CFSSHURLSessionWebSocketClient.decode(nil))
    }

    func testPumpClientToWebSocketReturnsOnEOF() async throws {
        let (clientFD, peerFD) = try makeSocketPair()
        defer { _ = close(clientFD) }
        _ = close(peerFD)

        let client = ScriptedWebSocketClient()
        await CFSSHCloudflareTunnelProvider._testPumpClientToWebSocket(
            clientFD: clientFD,
            websocketClient: client
        )

        let callCount = await client.sendCallCount()
        XCTAssertEqual(callCount, 0)
    }

    func testPumpWebSocketToClientReturnsWhenCancelled() async throws {
        let (clientFD, peerFD) = try makeSocketPair()
        defer {
            _ = close(clientFD)
            _ = close(peerFD)
        }

        let client = ScriptedWebSocketClient()
        withUnsafeCurrentTask { task in
            task?.cancel()
        }

        await CFSSHCloudflareTunnelProvider._testPumpWebSocketToClient(
            clientFD: clientFD,
            websocketClient: client
        )
    }

    func testBridgeHandlesSendAndWriteFailureBranches() async throws {
        let dialer = MockWebSocketDialer()
        let scripted = ScriptedWebSocketClient(sendError: DummyError())
        await dialer.enqueueClient(scripted)

        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: dialer,
            connectionLimits: .init(maxConcurrentConnections: 2, stopAcceptingAfterFirstConnection: false)
        )

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: port)
        XCTAssertTrue(writeAll(fd: fd, data: Data("hello".utf8)))

        let sendAttempted = await waitUntil {
            await scripted.sendCallCount() > 0
        }
        XCTAssertTrue(sendAttempted)

        // Reuse another connection for empty payload + write failure path.
        let scripted2 = ScriptedWebSocketClient()
        await dialer.enqueueClient(scripted2)
        let fd2 = try makeClientSocket(port: port)

        let secondReady = await waitUntil {
            await scripted2.receiveCallCount() > 0
        }
        XCTAssertTrue(secondReady)

        scripted2.enqueueIncoming(Data())
        closeWithReset(fd2)
        scripted2.enqueueIncoming(Data("x".utf8))

        let receiveAttempted = await waitUntil {
            await scripted2.receiveCallCount() > 1
        }
        XCTAssertTrue(receiveAttempted)

        _ = close(fd)
        await provider.close()
    }

    func testDefaultStopsAcceptingAfterFirstConnection() async throws {
        let dialer = MockWebSocketDialer()
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: dialer)

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd1 = try makeClientSocket(port: port)
        defer { _ = close(fd1) }

        let firstReady = await waitUntil {
            await dialer.latestClient() != nil
        }
        XCTAssertTrue(firstReady)

        do {
            _ = try makeClientSocket(port: port)
            XCTFail("expected second connection to fail after first accept")
        } catch {
            // expected: listener closed after first accepted client
        }

        await provider.close()
    }

    func testConnectionCapRejectsExcessClients() async throws {
        let dialer = MockWebSocketDialer()
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: dialer,
            connectionLimits: .init(maxConcurrentConnections: 1, stopAcceptingAfterFirstConnection: false)
        )

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd1 = try makeClientSocket(port: port)
        defer { _ = close(fd1) }

        let firstReady = await waitUntil {
            await dialer.latestClient() != nil
        }
        XCTAssertTrue(firstReady)

        let fd2 = try makeClientSocket(port: port)
        defer { _ = close(fd2) }
        let closed = await waitUntil {
            self.readSome(fd: fd2, timeoutSeconds: 0) == nil
        }
        XCTAssertTrue(closed)

        await provider.close()
    }

    func testDialerFailureClosesAcceptedClientSocket() async throws {
        let dialer = MockWebSocketDialer(connectError: DummyError())
        let provider = CFSSHCloudflareTunnelProvider(websocketDialer: dialer)

        let port = try await provider.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        let fd = try makeClientSocket(port: port)
        defer { _ = close(fd) }

        let gotRequest = await waitUntil {
            await dialer.latestRequest() != nil
        }
        XCTAssertTrue(gotRequest)

        let closed = await waitUntil {
            self.readSome(fd: fd, timeoutSeconds: 0) == nil
        }
        XCTAssertTrue(closed)

        await provider.close()
    }

    func testFaultInjectionSocketFailure() async {
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: MockWebSocketDialer(),
            faultInjection: .socket
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("failed to create socket", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionInetPtonFailure() async {
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: MockWebSocketDialer(),
            faultInjection: .inetPton
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("failed to encode loopback address", retryable: false))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionBindFailure() async {
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: MockWebSocketDialer(),
            faultInjection: .bind
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("failed to bind loopback listener", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionListenFailure() async {
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: MockWebSocketDialer(),
            faultInjection: .listen
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("failed to listen on loopback socket", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionGetsocknameFailure() async {
        let provider = CFSSHCloudflareTunnelProvider(
            websocketDialer: MockWebSocketDialer(),
            faultInjection: .getsockname
        )

        do {
            _ = try await provider.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("failed to read local listener port", retryable: false))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    private func makeClientSocket(port: UInt16) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw CFSSHFailure.transport("failed to create client socket", retryable: true)
        }

        var address = sockaddr_in()
    #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }

        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard result == 0 else {
            _ = close(fd)
            throw CFSSHFailure.transport("failed to connect to local listener", retryable: true)
        }

        return fd
    }

    private func makeSocketPair() throws -> (Int32, Int32) {
        var fds: [Int32] = [-1, -1]
        let result = socketpair(AF_UNIX, Int32(SOCK_STREAM), 0, &fds)
        guard result == 0 else {
            throw CFSSHFailure.transport("failed to create socketpair", retryable: true)
        }
        return (fds[0], fds[1])
    }

    private func readSome(fd: Int32, timeoutSeconds: Int) -> Data? {
        var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }

        var buffer = [UInt8](repeating: 0, count: 1024)
        let count = recv(fd, &buffer, buffer.count, 0)
        guard count > 0 else {
            return nil
        }

        return Data(buffer[0..<count])
    }

    private func writeAll(fd: Int32, data: Data) -> Bool {
        var written = 0
        let total = data.count

        return data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                return false
            }

            while written < total {
                let pointer = baseAddress.advanced(by: written)
                let result = send(fd, pointer, total - written, 0)
                if result > 0 {
                    written += result
                    continue
                }
                if result < 0 && errno == EINTR {
                    continue
                }
                return false
            }

            return true
        }
    }

    private func closeWithReset(_ fd: Int32) {
        var value = linger(l_onoff: 1, l_linger: 0)
        _ = withUnsafePointer(to: &value) {
            setsockopt(fd, SOL_SOCKET, SO_LINGER, $0, socklen_t(MemoryLayout<linger>.size))
        }
        _ = close(fd)
    }

    private func waitUntil(
        timeoutNanoseconds: UInt64 = 2_000_000_000,
        pollNanoseconds: UInt64 = 20_000_000,
        condition: @escaping () async -> Bool
    ) async -> Bool {
        let start = DispatchTime.now().uptimeNanoseconds
        while DispatchTime.now().uptimeNanoseconds - start < timeoutNanoseconds {
            if await condition() {
                return true
            }
            try? await Task.sleep(nanoseconds: pollNanoseconds)
        }
        return false
    }
}

actor MockWebSocketDialer: CFSSHWebSocketDialing {
    private let connectError: Error?
    private(set) var requests: [URLRequest] = []
    private(set) var clients: [ScriptedWebSocketClient] = []
    private var queuedClients: [ScriptedWebSocketClient] = []

    init(connectError: Error? = nil) {
        self.connectError = connectError
    }

    func connect(request: URLRequest) async throws -> any CFSSHWebSocketClient {
        if let connectError {
            requests.append(request)
            throw connectError
        }

        requests.append(request)
        let client: ScriptedWebSocketClient
        if queuedClients.isEmpty {
            client = ScriptedWebSocketClient()
        } else {
            client = queuedClients.removeFirst()
        }
        clients.append(client)
        return client
    }

    func latestRequest() -> URLRequest? {
        requests.last
    }

    func latestClient() -> ScriptedWebSocketClient? {
        clients.last
    }

    func enqueueClient(_ client: ScriptedWebSocketClient) {
        queuedClients.append(client)
    }
}

final class ScriptedWebSocketClient: @unchecked Sendable, CFSSHWebSocketClient {
    private let sentQueue = DispatchQueue(label: "test.ws.sent")
    private var sentDataFrames: [Data] = []
    private var sendCalls: Int = 0

    private let receiveQueue = DispatchQueue(label: "test.ws.recv")
    private var continuation: AsyncStream<Data?>.Continuation?
    private var iterator: AsyncStream<Data?>.Iterator
    private var receiveCalls: Int = 0
    private var sendError: Error?
    private var receiveError: Error?

    init(sendError: Error? = nil, receiveError: Error? = nil) {
        self.sendError = sendError
        self.receiveError = receiveError
        var localContinuation: AsyncStream<Data?>.Continuation?
        let stream = AsyncStream<Data?> { continuation in
            localContinuation = continuation
        }
        self.continuation = localContinuation
        self.iterator = stream.makeAsyncIterator()
    }

    func send(data: Data) async throws {
        if let error = sentQueue.sync(execute: { () -> Error? in
            sendCalls += 1
            return sendError
        }) {
            throw error
        }

        sentQueue.sync {
            sentDataFrames.append(data)
        }
    }

    func receive() async throws -> Data? {
        if let error = receiveQueue.sync(execute: { () -> Error? in
            if let receiveError {
                self.receiveError = nil
                return receiveError
            }
            receiveCalls += 1
            return nil
        }) {
            throw error
        }
        return await iterator.next() ?? nil
    }

    func close() async {
        let localContinuation = receiveQueue.sync { () -> AsyncStream<Data?>.Continuation? in
            let local = continuation
            continuation = nil
            return local
        }

        localContinuation?.yield(nil)
        localContinuation?.finish()
    }

    func enqueueIncoming(_ data: Data) {
        let localContinuation = receiveQueue.sync { continuation }
        localContinuation?.yield(data)
    }

    func sentFrames() -> [Data] {
        sentQueue.sync { sentDataFrames }
    }

    func sendCallCount() async -> Int {
        sentQueue.sync { sendCalls }
    }

    func receiveCallCount() async -> Int {
        receiveQueue.sync { receiveCalls }
    }
}
