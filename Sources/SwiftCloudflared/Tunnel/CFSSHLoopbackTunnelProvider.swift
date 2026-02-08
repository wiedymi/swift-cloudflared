#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public actor CFSSHLoopbackTunnelProvider: CFSSHTunnelProviding {
    public enum FaultInjection: Sendable, Equatable {
        case socket
        case inetPton
        case bind
        case listen
        case getsockname
    }

    private var listeningSocket: Int32 = -1
    private let faultInjection: FaultInjection?

    public init(faultInjection: FaultInjection? = nil) {
        self.faultInjection = faultInjection
    }

    public func open(hostname: String, authContext: CFSSHAuthContext, method: CFSSHAuthMethod) async throws -> UInt16 {
        guard listeningSocket < 0 else {
            throw CFSSHFailure.invalidState("tunnel already open")
        }

        let socketFD = faultInjection == .socket ? -1 : systemSocket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw CFSSHFailure.transport("failed to create socket", retryable: true)
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
            _ = systemClose(socketFD)
            throw CFSSHFailure.transport("failed to encode loopback address", retryable: false)
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
            _ = systemClose(socketFD)
            throw CFSSHFailure.transport("failed to bind loopback listener", retryable: true)
        }

        let listenResult = faultInjection == .listen ? -1 : listen(socketFD, SOMAXCONN)
        guard listenResult == 0 else {
            _ = systemClose(socketFD)
            throw CFSSHFailure.transport("failed to listen on loopback socket", retryable: true)
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
            _ = systemClose(socketFD)
            throw CFSSHFailure.transport("failed to read local listener port", retryable: false)
        }

        listeningSocket = socketFD
        return UInt16(bigEndian: boundAddress.sin_port)
    }

    public func close() async {
        guard listeningSocket >= 0 else {
            return
        }

        _ = systemClose(listeningSocket)
        listeningSocket = -1
    }

    private func systemSocket(_ domain: Int32, _ type: Int32, _ proto: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.socket(domain, type, proto)
    #else
        Glibc.socket(domain, type, proto)
    #endif
    }

    private func systemClose(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
        Darwin.close(fd)
    #else
        Glibc.close(fd)
    #endif
    }
}
