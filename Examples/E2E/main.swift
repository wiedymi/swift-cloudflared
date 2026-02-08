import Foundation
import SwiftCloudflared

#if canImport(Darwin)
import Darwin
#endif
#if canImport(AppKit)
import AppKit
#endif

@main
struct SwiftCloudflaredE2ECLI {
    private enum AuthChoice: String {
        case oauth = "1"
        case serviceToken = "2"
    }

    private struct ManualOAuthFlow: CFSSHOAuthFlow {
        func fetchToken(teamDomain: String, appDomain: String, callbackScheme: String, hostname: String) async throws -> String {
            let originURL = try CFSSHURLTools.normalizeOriginURL(from: hostname)

            print("")
            print("Open this protected app URL in your browser and complete Cloudflare Access login:")
            print(originURL.absoluteString)
            SwiftCloudflaredE2ECLI.openBrowserIfPossible(originURL)
            print("")
            print("After login, copy the `CF_Authorization` cookie value for \(originURL.host ?? hostname)")
            print("from browser developer tools and paste it below.")
            let token = try SwiftCloudflaredE2ECLI.promptSecretRequired("CF_Authorization JWT (input hidden): ")
                .trimmingCharacters(in: .whitespacesAndNewlines)

            guard !token.isEmpty else {
                throw CFSSHFailure.auth("oauth token input was empty")
            }

            return token
        }
    }

    static func main() async {
        do {
            try await run()
        } catch let failure as CFSSHFailure {
            fputs("Error: \(failure)\n", stderr)
            Foundation.exit(1)
        } catch {
            fputs("Unexpected error: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    private static func run() async throws {
        print("swift-cloudflared e2e")
        print("---------------------")

        let hostname = try promptRequired("Cloudflare-protected hostname (e.g. ssh.example.com): ")
        let authChoice = try promptAuthChoice()

        let authProvider: any CFSSHAuthProviding
        let method: CFSSHAuthMethod

        switch authChoice {
        case .oauth:
            let oauthProvider = CFSSHOAuthProvider(
                flow: ManualOAuthFlow(),
                tokenStore: CFSSHInMemoryTokenStore()
            )
            authProvider = oauthProvider
            method = try await resolveOAuthMethod(hostname: hostname)

        case .serviceToken:
            let clientID = try promptRequired("Service token client ID: ")
            let clientSecret = try promptSecretRequired("Service token client secret: ")

            authProvider = CFSSHServiceTokenProvider()
            method = .serviceToken(teamDomain: "local", clientID: clientID, clientSecret: clientSecret)
        }

        let session = CFSSHSessionActor(
            authProvider: authProvider,
            tunnelProvider: CFSSHCloudflareTunnelProvider(),
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 2, baseDelayNanoseconds: 500_000_000),
            oauthFallback: nil,
            sleep: { delay in
                try? await Task.sleep(nanoseconds: delay)
            }
        )

        let stateTask = Task {
            for await state in session.state {
                print("state: \(describe(state))")
            }
        }

        do {
            let localPort = try await session.connect(hostname: hostname, method: method)
            print("")
            print("Tunnel ready")
            print("Local endpoint: 127.0.0.1:\(localPort)")
            let probe = try runTunnelProbe(localPort: localPort)
            switch probe {
            case .banner(let text):
                print("Probe OK: received banner bytes")
                print("Banner: \(text)")
            case .openWithoutData:
                print("Probe inconclusive: socket stayed open but no immediate data")
            }

            print("SSH test: ssh <user>@127.0.0.1 -p \(localPort)")
            print("libssh2 target: host=127.0.0.1, port=\(localPort)")
            print("")
            _ = prompt("Press ENTER to close tunnel...")
        } catch {
            await session.disconnect()
            stateTask.cancel()
            throw error
        }

        await session.disconnect()
        stateTask.cancel()
    }

    private struct URLSessionHTTPClient: CFSSHHTTPClient {
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw CFSSHFailure.protocolViolation("non-http response while resolving app info")
            }
            return (data, http)
        }
    }

    private static func resolveOAuthMethod(hostname: String) async throws -> CFSSHAuthMethod {
        let originURL = try CFSSHURLTools.normalizeOriginURL(from: hostname)
        let resolver = CFSSHAppInfoResolver(client: URLSessionHTTPClient(), userAgent: "swift-cloudflared-e2e")

        if let appInfo = try? await resolver.resolve(appURL: originURL) {
            return .oauth(
                teamDomain: appInfo.authDomain,
                appDomain: appInfo.appDomain,
                callbackScheme: "cloudflared"
            )
        }

        return .oauth(
            teamDomain: originURL.host ?? hostname,
            appDomain: originURL.host ?? hostname,
            callbackScheme: "cloudflared"
        )
    }

    private static func describe(_ state: CFSSHConnectionState) -> String {
        switch state {
        case .idle:
            return "idle"
        case .authenticating:
            return "authenticating"
        case .connecting:
            return "connecting"
        case .connected(let localPort):
            return "connected(localPort: \(localPort))"
        case .reconnecting(let attempt):
            return "reconnecting(attempt: \(attempt))"
        case .disconnected:
            return "disconnected"
        case .failed(let failure):
            return "failed(\(failure))"
        }
    }

    private static func promptAuthChoice() throws -> AuthChoice {
        print("")
        print("Auth mode:")
        print("  1) OAuth (browser login + paste token)")
        print("  2) Service token")

        while true {
            let value = prompt("Choose [1/2]: ").trimmingCharacters(in: .whitespacesAndNewlines)
            if let choice = AuthChoice(rawValue: value) {
                return choice
            }
            print("Invalid choice.")
        }
    }

    private static func prompt(_ question: String) -> String {
        print(question, terminator: "")
        fflush(stdout)
        return readLine() ?? ""
    }

    private static func promptRequired(_ question: String) throws -> String {
        while true {
            let value = prompt(question).trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty {
                return value
            }
            print("Value is required.")
        }
    }

    private static func promptSecretRequired(_ question: String) throws -> String {
    #if canImport(Darwin)
        if isatty(STDIN_FILENO) == 1 && isatty(STDERR_FILENO) == 1 {
            if let valuePtr = getpass(question), !String(cString: valuePtr).isEmpty {
                return String(cString: valuePtr)
            }
            print("Value is required.")
        }
    #endif
        return try promptRequired(question)
    }

    private static func openBrowserIfPossible(_ url: URL) {
    #if canImport(AppKit)
        _ = NSWorkspace.shared.open(url)
    #else
        _ = url
    #endif
    }

    private enum ProbeResult {
        case banner(String)
        case openWithoutData
    }

    private static func runTunnelProbe(localPort: UInt16) throws -> ProbeResult {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw CFSSHFailure.transport("probe failed to create socket", retryable: true)
        }
        defer { _ = close(fd) }

        var address = sockaddr_in()
    #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = localPort.bigEndian

        let pton = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        guard pton == 1 else {
            throw CFSSHFailure.transport("probe failed to encode loopback", retryable: false)
        }

        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            throw CFSSHFailure.transport("probe failed to connect to local tunnel", retryable: true)
        }

        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }

        var buffer = [UInt8](repeating: 0, count: 1024)
        let count = recv(fd, &buffer, buffer.count, 0)

        if count > 0 {
            let text = String(decoding: buffer[0..<count], as: UTF8.self)
            return .banner(text.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        if count == 0 {
            throw CFSSHFailure.transport(
                "probe socket closed immediately; Cloudflare auth/upstream connection likely failed",
                retryable: false
            )
        }

        if errno == EWOULDBLOCK || errno == EAGAIN {
            return .openWithoutData
        }

        throw CFSSHFailure.transport("probe recv failed with errno \(errno)", retryable: true)
    }
}
