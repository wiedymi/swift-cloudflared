import Foundation

public protocol SSHClock: Sendable {
    var now: Date { get }
}

public struct SSHSystemClock: SSHClock {
    public init() {}

    public var now: Date {
        Date()
    }
}

public struct SSHJWTValidator: Sendable {
    private let clock: any SSHClock

    public init(clock: any SSHClock = SSHSystemClock()) {
        self.clock = clock
    }

    public func isExpired(_ token: String) throws -> Bool {
        try expirationDate(from: token) <= clock.now
    }

    public func expirationDate(from token: String) throws -> Date {
        let parts = token.split(separator: ".")
        guard parts.count >= 2 else {
            throw SSHFailure.auth("token is not a JWT")
        }

        let payloadData = try decodeBase64URL(String(parts[1]))
        let payload = try JSONSerialization.jsonObject(with: payloadData, options: [])

        guard
            let object = payload as? [String: Any],
            let exp = object["exp"] as? TimeInterval
        else {
            throw SSHFailure.auth("token missing exp claim")
        }

        return Date(timeIntervalSince1970: exp)
    }

    private func decodeBase64URL(_ value: String) throws -> Data {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }

        guard let data = Data(base64Encoded: base64) else {
            throw SSHFailure.auth("invalid JWT payload encoding")
        }

        return data
    }
}
