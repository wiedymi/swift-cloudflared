import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// All descriptor access, shutdown, and closure use the same lock. I/O must be nonblocking.
final class SocketHandle: @unchecked Sendable {
    private enum State {
        case open(Int32)
        case shutdown(Int32)
        case closed
    }

    private let lock = NSLock()
    private var state: State

    init(_ fileDescriptor: Int32) throws {
        state = .open(fileDescriptor)
        let flags = fcntl(fileDescriptor, F_GETFL)
        guard flags >= 0, fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            close()
            throw Failure.transport("failed to configure nonblocking socket", retryable: false)
        }
    #if canImport(Darwin)
        var value: Int32 = 1
        let result = withUnsafePointer(to: &value) {
            setsockopt(fileDescriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, socklen_t(MemoryLayout<Int32>.size))
        }
        guard result == 0 else {
            close()
            throw Failure.transport("failed to suppress socket SIGPIPE", retryable: false)
        }
    #endif
    }

    deinit {
        close()
    }

    func withFileDescriptor<T>(_ operation: (Int32) -> T) -> T? {
        lock.lock()
        defer { lock.unlock() }
        guard case .open(let fileDescriptor) = state else { return nil }
        return operation(fileDescriptor)
    }

    func shutdown() {
        lock.lock()
        defer { lock.unlock() }
        guard case .open(let fileDescriptor) = state else { return }
        state = .shutdown(fileDescriptor)
        Self.systemShutdown(fileDescriptor)
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        let fileDescriptor: Int32
        switch state {
        case .open(let fd):
            fileDescriptor = fd
            Self.systemShutdown(fd)
        case .shutdown(let fd):
            fileDescriptor = fd
        case .closed:
            return
        }
        state = .closed
    #if canImport(Darwin)
        _ = Darwin.close(fileDescriptor)
    #else
        _ = Glibc.close(fileDescriptor)
    #endif
    }

    private static func systemShutdown(_ fileDescriptor: Int32) {
    #if canImport(Darwin)
        _ = Darwin.shutdown(fileDescriptor, SHUT_RDWR)
    #else
        _ = Glibc.shutdown(fileDescriptor, Int32(SHUT_RDWR))
    #endif
    }
}
