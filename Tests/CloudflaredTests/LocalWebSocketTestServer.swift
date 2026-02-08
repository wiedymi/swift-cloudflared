import Foundation
import CryptoKit
@testable import Cloudflared

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class LocalWebSocketTestServer: @unchecked Sendable {
    enum OutgoingFrame {
        case text(String)
        case binary(Data)
    }

    private let frames: [OutgoingFrame]
    private let keepOpenMillis: UInt32

    private var listenFD: Int32 = -1
    private var clientFD: Int32 = -1
    private var worker: Thread?

    init(frames: [OutgoingFrame] = [], keepOpenMillis: UInt32 = 300) {
        self.frames = frames
        self.keepOpenMillis = keepOpenMillis
    }

    func start() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw Failure.transport("failed to create test websocket socket", retryable: true)
        }

        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size))
        }

        var address = sockaddr_in()
    #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(0)
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }

        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            _ = close(fd)
            throw Failure.transport("failed to bind test websocket socket", retryable: true)
        }

        guard listen(fd, SOMAXCONN) == 0 else {
            _ = close(fd)
            throw Failure.transport("failed to listen on test websocket socket", retryable: true)
        }

        var bound = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        guard nameResult == 0 else {
            _ = close(fd)
            throw Failure.transport("failed to read test websocket port", retryable: false)
        }

        listenFD = fd

        let thread = Thread { [weak self] in
            self?.serveOneConnection()
        }
        worker = thread
        thread.start()

        return UInt16(bigEndian: bound.sin_port)
    }

    func stop() {
        if clientFD >= 0 {
            _ = shutdown(clientFD, SHUT_RDWR)
            _ = close(clientFD)
            clientFD = -1
        }

        if listenFD >= 0 {
            _ = shutdown(listenFD, SHUT_RDWR)
            _ = close(listenFD)
            listenFD = -1
        }
    }

    deinit {
        stop()
    }

    private func serveOneConnection() {
        guard listenFD >= 0 else { return }
        let accepted = accept(listenFD, nil, nil)
        guard accepted >= 0 else { return }
        clientFD = accepted

        defer {
            _ = shutdown(accepted, SHUT_RDWR)
            _ = close(accepted)
            clientFD = -1
        }

        guard let requestHeaders = readHTTPHeaders(fd: accepted),
              let key = parseHeader("Sec-WebSocket-Key", from: requestHeaders) else {
            return
        }

        let accept = websocketAccept(for: key)
        let response = "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: \(accept)\r\n\r\n"

        guard writeAll(fd: accepted, data: Data(response.utf8)) else {
            return
        }

        for frame in frames {
            let data: Data
            switch frame {
            case .text(let text):
                data = makeFrame(opcode: 0x1, payload: Data(text.utf8))
            case .binary(let payload):
                data = makeFrame(opcode: 0x2, payload: payload)
            }
            _ = writeAll(fd: accepted, data: data)
        }

        usleep(keepOpenMillis * 1000)
    }

    private func readHTTPHeaders(fd: Int32) -> String? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)

        for _ in 0..<64 {
            let count = recv(fd, &buffer, buffer.count, 0)
            guard count > 0 else { return nil }
            data.append(buffer, count: count)

            if data.range(of: Data("\r\n\r\n".utf8)) != nil {
                return String(data: data, encoding: .utf8)
            }
        }

        return nil
    }

    private func parseHeader(_ name: String, from headers: String) -> String? {
        let needle = "\(name):"
        for line in headers.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix(needle.lowercased()) {
                return line.dropFirst(needle.count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    private func websocketAccept(for key: String) -> String {
        let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        let data = Data((key + guid).utf8)
        let digest = Insecure.SHA1.hash(data: data)
        return Data(digest).base64EncodedString()
    }

    private func makeFrame(opcode: UInt8, payload: Data) -> Data {
        var frame = Data()
        frame.append(0x80 | opcode)

        if payload.count < 126 {
            frame.append(UInt8(payload.count))
        } else {
            frame.append(126)
            var size = UInt16(payload.count).bigEndian
            withUnsafeBytes(of: &size) { frame.append(contentsOf: $0) }
        }

        frame.append(payload)
        return frame
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
                return false
            }

            return true
        }
    }
}
