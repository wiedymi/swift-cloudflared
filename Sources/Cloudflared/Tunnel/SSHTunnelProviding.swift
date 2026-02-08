public protocol SSHTunnelProviding: Sendable {
    func open(hostname: String, authContext: SSHAuthContext, method: SSHAuthMethod) async throws -> UInt16
    func close() async
}
