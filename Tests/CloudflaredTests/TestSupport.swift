import Foundation
@testable import Cloudflared

struct FixedClock: SSHClock {
    let now: Date
}

func makeJWT(expiration: TimeInterval) -> String {
    let header = ["alg": "none", "typ": "JWT"]
    let payload = ["exp": Int(expiration)]

    let headerData = try! JSONSerialization.data(withJSONObject: header, options: [])
    let payloadData = try! JSONSerialization.data(withJSONObject: payload, options: [])

    let encodedHeader = base64URLEncode(headerData)
    let encodedPayload = base64URLEncode(payloadData)

    return "\(encodedHeader).\(encodedPayload).sig"
}

func makeInvalidJWTWithoutExp() -> String {
    let header = ["alg": "none", "typ": "JWT"]
    let payload = ["sub": "abc"]

    let headerData = try! JSONSerialization.data(withJSONObject: header, options: [])
    let payloadData = try! JSONSerialization.data(withJSONObject: payload, options: [])

    let encodedHeader = base64URLEncode(headerData)
    let encodedPayload = base64URLEncode(payloadData)

    return "\(encodedHeader).\(encodedPayload).sig"
}

private func base64URLEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

actor MockOAuthFlow: SSHOAuthFlow {
    var token: String
    var error: Error?
    private(set) var callCount: Int

    init(token: String, error: Error? = nil, callCount: Int = 0) {
        self.token = token
        self.error = error
        self.callCount = callCount
    }

    func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String {
        callCount += 1
        if let error {
            throw error
        }
        return token
    }
}

struct ClosureAuthProvider: SSHAuthProviding {
    let handler: @Sendable (String, SSHAuthMethod) async throws -> SSHAuthContext

    func authenticate(hostname: String, method: SSHAuthMethod) async throws -> SSHAuthContext {
        try await handler(hostname, method)
    }
}

enum TunnelOpenOutcome: Sendable, Equatable {
    case success(UInt16)
    case failure(SSHFailure)
}

actor ScriptedTunnelProvider: SSHTunnelProviding {
    private var outcomes: [TunnelOpenOutcome]
    private(set) var openCalls: Int = 0
    private(set) var closeCalls: Int = 0

    init(outcomes: [TunnelOpenOutcome]) {
        self.outcomes = outcomes
    }

    func open(hostname: String, authContext: SSHAuthContext, method: SSHAuthMethod) async throws -> UInt16 {
        openCalls += 1
        if outcomes.isEmpty {
            return 2222
        }

        let next = outcomes.removeFirst()
        switch next {
        case .success(let port):
            return port
        case .failure(let failure):
            throw failure
        }
    }

    func close() async {
        closeCalls += 1
    }
}

func collectStates(from stream: AsyncStream<SSHConnectionState>, count: Int) async -> [SSHConnectionState] {
    var iterator = stream.makeAsyncIterator()
    var states: [SSHConnectionState] = []
    while states.count < count, let state = await iterator.next() {
        states.append(state)
    }
    return states
}
