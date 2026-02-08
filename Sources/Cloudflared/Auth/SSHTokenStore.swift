import Foundation

public protocol SSHTokenStore: Sendable {
    func readToken(for key: String) async throws -> String?
    func writeToken(_ token: String, for key: String) async throws
    func removeToken(for key: String) async throws
}

public actor SSHInMemoryTokenStore: SSHTokenStore {
    private var storage: [String: String]

    public init(initialStorage: [String: String] = [:]) {
        self.storage = initialStorage
    }

    public func readToken(for key: String) async throws -> String? {
        storage[key]
    }

    public func writeToken(_ token: String, for key: String) async throws {
        storage[key] = token
    }

    public func removeToken(for key: String) async throws {
        storage.removeValue(forKey: key)
    }
}
