public protocol TunnelProviding: Sendable {
    func open(hostname: String, authContext: AuthContext, method: AuthMethod) async throws -> UInt16
    func close() async
}
