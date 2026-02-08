import Foundation

public enum SSHURLTools {
    public static func normalizeOriginURL(from hostname: String) throws -> URL {
        let trimmed = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw SSHFailure.configuration("hostname must not be empty")
        }

        let candidate: String
        if trimmed.contains("://") {
            candidate = trimmed
        } else {
            candidate = "https://\(trimmed)"
        }

        guard var components = URLComponents(string: candidate) else {
            throw SSHFailure.configuration("hostname is not a valid URL")
        }

        guard let host = components.host, !host.isEmpty else {
            throw SSHFailure.configuration("hostname is missing host")
        }

        components.scheme = "https"

        return components.url!
    }

    public static func websocketURL(from originURL: URL) throws -> URL {
        var components = URLComponents(url: originURL, resolvingAgainstBaseURL: false)!

        switch components.scheme?.lowercased() {
        case "https":
            components.scheme = "wss"
        case "http":
            components.scheme = "ws"
        case "wss", "ws":
            break
        case nil:
            components.scheme = "ws"
        default:
            let unsupportedScheme = components.scheme!
            throw SSHFailure.protocolViolation("unsupported scheme \(unsupportedScheme)")
        }

        return components.url!
    }

    public static func isAccessLoginRedirect(statusCode: Int, location: URL?) -> Bool {
        guard statusCode == 302, let location else {
            return false
        }

        return location.path.hasPrefix(SSHAccessPath.login)
    }
}
