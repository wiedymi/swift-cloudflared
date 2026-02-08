import Foundation

public protocol TokenClock: Sendable {
    var now: Date { get }
}

public struct SystemClock: TokenClock {
    public init() {}

    public var now: Date {
        Date()
    }
}

public struct JWTValidator: Sendable {
    private let clock: any TokenClock

    public init(clock: any TokenClock = SystemClock()) {
        self.clock = clock
    }

    public func isExpired(_ token: String) throws -> Bool {
        try expirationDate(from: token) <= clock.now
    }

    public func expirationDate(from token: String) throws -> Date {
        let parts = token.split(separator: ".")
        guard parts.count >= 2 else {
            throw Failure.auth("token is not a JWT")
        }

        let payloadData = try decodeBase64URL(String(parts[1]))
        let payload = try JSONSerialization.jsonObject(with: payloadData, options: [])

        guard
            let object = payload as? [String: Any],
            let exp = object["exp"] as? TimeInterval
        else {
            throw Failure.auth("token missing exp claim")
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
            throw Failure.auth("invalid JWT payload encoding")
        }

        return data
    }
}
