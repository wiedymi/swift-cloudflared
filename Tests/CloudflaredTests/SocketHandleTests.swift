import XCTest
@testable import Cloudflared

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class SocketHandleTests: XCTestCase {
    func testInvalidDescriptorIsRejected() {
        XCTAssertThrowsError(try SocketHandle(-1))
    }

    func testShutdownPreventsFurtherIOAndRetainsDescriptorUntilClose() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let socket = try SocketHandle(fds[0])
        defer { _ = close(fds[1]) }

        XCTAssertEqual(socket.withFileDescriptor { $0 }, fds[0])
        socket.shutdown()
        XCTAssertNil(socket.withFileDescriptor { $0 })
        XCTAssertGreaterThanOrEqual(fcntl(fds[0], F_GETFD), 0)

        socket.close()
        XCTAssertEqual(fcntl(fds[0], F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
    }

    func testRepeatedCloseDoesNotCloseAReusedDescriptor() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let socket = try SocketHandle(fds[0])
        defer { _ = close(fds[1]) }
        socket.close()

        let replacement = open("/dev/null", O_RDONLY)
        XCTAssertGreaterThanOrEqual(replacement, 0)
        guard replacement >= 0 else { return }
        defer { _ = close(replacement) }
        if replacement != fds[0] {
            XCTAssertEqual(dup2(replacement, fds[0]), fds[0])
        }
        defer { if replacement != fds[0] { _ = close(fds[0]) } }

        socket.shutdown()
        socket.close()
        XCTAssertNil(socket.withFileDescriptor { $0 })
        XCTAssertGreaterThanOrEqual(fcntl(fds[0], F_GETFD), 0)
    }
}
