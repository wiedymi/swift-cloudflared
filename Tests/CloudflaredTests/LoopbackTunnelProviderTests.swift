import XCTest
@testable import Cloudflared

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class LoopbackTunnelProviderTests: XCTestCase {
    func testOpenAndCloseLifecycle() async throws {
        let tunnel = LoopbackTunnelProvider()
        let port = try await tunnel.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        XCTAssertGreaterThan(port, 0)
        XCTAssertTrue(canConnect(to: port))

        await tunnel.close()
    }

    func testSecondOpenFails() async throws {
        let tunnel = LoopbackTunnelProvider()
        _ = try await tunnel.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )

        do {
            _ = try await tunnel.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected second open to fail")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .invalidState("tunnel already open"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        await tunnel.close()
    }

    func testReopenAfterClose() async throws {
        let tunnel = LoopbackTunnelProvider()
        _ = try await tunnel.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )
        await tunnel.close()

        let secondPort = try await tunnel.open(
            hostname: "ssh.example.com",
            authContext: .appToken("jwt"),
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )
        XCTAssertGreaterThan(secondPort, 0)
        await tunnel.close()
    }

    func testCloseWithoutOpenIsNoOp() async {
        let tunnel = LoopbackTunnelProvider()
        await tunnel.close()
    }

    func testFaultInjectionSocketFailure() async {
        let tunnel = LoopbackTunnelProvider(faultInjection: .socket)
        do {
            _ = try await tunnel.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .transport("failed to create socket", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionInetPtonFailure() async {
        let tunnel = LoopbackTunnelProvider(faultInjection: .inetPton)
        do {
            _ = try await tunnel.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .transport("failed to encode loopback address", retryable: false))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionBindFailure() async {
        let tunnel = LoopbackTunnelProvider(faultInjection: .bind)
        do {
            _ = try await tunnel.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .transport("failed to bind loopback listener", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionListenFailure() async {
        let tunnel = LoopbackTunnelProvider(faultInjection: .listen)
        do {
            _ = try await tunnel.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .transport("failed to listen on loopback socket", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFaultInjectionGetSockNameFailure() async {
        let tunnel = LoopbackTunnelProvider(faultInjection: .getsockname)
        do {
            _ = try await tunnel.open(
                hostname: "ssh.example.com",
                authContext: .appToken("jwt"),
                method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            )
            XCTFail("expected failure")
        } catch let failure as Failure {
            XCTAssertEqual(failure, .transport("failed to read local listener port", retryable: false))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    private func canConnect(to port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            return false
        }
        defer { _ = close(fd) }

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

        return result == 0
    }
}
