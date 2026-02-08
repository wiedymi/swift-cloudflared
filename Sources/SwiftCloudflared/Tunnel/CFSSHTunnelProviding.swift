public protocol CFSSHTunnelProviding: Sendable {
    func open(hostname: String, authContext: CFSSHAuthContext, method: CFSSHAuthMethod) async throws -> UInt16
    func close() async
}
