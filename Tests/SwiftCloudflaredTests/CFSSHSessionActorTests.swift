import XCTest
@testable import SwiftCloudflared

final class CFSSHSessionActorTests: XCTestCase {
    func testNoopSleepAndExplicitInitializer() async throws {
        await CFSSHSessionActor.noopSleep(1)

        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: ScriptedTunnelProvider(outcomes: [.success(3333)]),
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        let port = try await session.connect(
            hostname: "ssh.example.com",
            method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
        )
        XCTAssertEqual(port, 3333)
    }

    func testConnectAndDisconnectSuccess() async throws {
        let tunnel = ScriptedTunnelProvider(outcomes: [.success(4222)])
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: tunnel,
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        let collectorTask = Task {
            await collectStates(from: session.state, count: 5)
        }

        let port = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
        XCTAssertEqual(port, 4222)

        await session.disconnect()

        let states = await collectorTask.value
        XCTAssertEqual(
            states,
            [.idle, .authenticating, .connecting, .connected(localPort: 4222), .disconnected]
        )
        let closeCalls = await tunnel.closeCalls
        XCTAssertEqual(closeCalls, 1)
    }

    func testConnectRejectsInvalidStateWhenAlreadyConnected() async throws {
        let tunnel = ScriptedTunnelProvider(outcomes: [.success(4222)])
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: tunnel,
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        _ = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))

        do {
            _ = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
            XCTFail("expected invalid state")
        } catch let failure as CFSSHFailure {
            if case .invalidState = failure {
                return
            }
            XCTFail("unexpected failure: \(failure)")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testInvalidHostnameFailsEarly() async {
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: ScriptedTunnelProvider(outcomes: []),
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        do {
            _ = try await session.connect(hostname: " ", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .configuration("hostname must not be empty"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testServiceTokenFallbackToOAuth() async throws {
        let tunnel = ScriptedTunnelProvider(outcomes: [.success(5222)])
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, method in
                switch method {
                case .serviceToken:
                    throw CFSSHFailure.auth("service token rejected")
                case .oauth:
                    return .appToken("oauth-jwt")
                }
            },
            tunnelProvider: tunnel,
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: { _ in
                .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            },
            sleep: { _ in }
        )

        let collectorTask = Task {
            await collectStates(from: session.state, count: 5)
        }

        let port = try await session.connect(
            hostname: "ssh.example.com",
            method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
        )

        XCTAssertEqual(port, 5222)

        let states = await collectorTask.value
        XCTAssertEqual(states, [.idle, .authenticating, .authenticating, .connecting, .connected(localPort: 5222)])
    }

    func testServiceTokenFallbackFailurePublishesFailedState() async {
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, method in
                switch method {
                case .serviceToken:
                    throw CFSSHFailure.auth("service token rejected")
                case .oauth:
                    throw CFSSHFailure.auth("oauth rejected")
                }
            },
            tunnelProvider: ScriptedTunnelProvider(outcomes: []),
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: { _ in
                .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb")
            },
            sleep: { _ in }
        )

        let collectorTask = Task {
            await collectStates(from: session.state, count: 4)
        }

        do {
            _ = try await session.connect(
                hostname: "ssh.example.com",
                method: .serviceToken(teamDomain: "team", clientID: "id", clientSecret: "secret")
            )
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .auth("oauth rejected"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        let states = await collectorTask.value
        XCTAssertEqual(states, [.idle, .authenticating, .authenticating, .failed(.auth("oauth rejected"))])
    }

    func testRetryThenConnectSuccess() async throws {
        let tunnel = ScriptedTunnelProvider(outcomes: [
            .failure(.transport("temporary", retryable: true)),
            .success(6222),
        ])
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: tunnel,
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 1, baseDelayNanoseconds: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        let collectorTask = Task {
            await collectStates(from: session.state, count: 6)
        }

        let port = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
        XCTAssertEqual(port, 6222)

        let states = await collectorTask.value
        XCTAssertEqual(states, [.idle, .authenticating, .connecting, .reconnecting(attempt: 1), .connecting, .connected(localPort: 6222)])
        let openCalls = await tunnel.openCalls
        XCTAssertEqual(openCalls, 2)
    }

    func testRetryExhaustionFails() async {
        let tunnel = ScriptedTunnelProvider(outcomes: [
            .failure(.transport("temporary", retryable: true)),
            .failure(.transport("still temporary", retryable: true)),
        ])
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: tunnel,
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 1, baseDelayNanoseconds: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        let collectorTask = Task {
            await collectStates(from: session.state, count: 5)
        }

        do {
            _ = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("still temporary", retryable: true))
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        let states = await collectorTask.value
        XCTAssertEqual(states, [.idle, .authenticating, .connecting, .reconnecting(attempt: 1), .connecting])
    }

    func testNonRetryableTransportFailsImmediately() async {
        let tunnel = ScriptedTunnelProvider(outcomes: [
            .failure(.transport("fatal", retryable: false)),
        ])
        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in .appToken("jwt") },
            tunnelProvider: tunnel,
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 3, baseDelayNanoseconds: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        let collectorTask = Task {
            await collectStates(from: session.state, count: 4)
        }

        do {
            _ = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            XCTAssertEqual(failure, .transport("fatal", retryable: false))
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        let states = await collectorTask.value
        XCTAssertEqual(states, [.idle, .authenticating, .connecting, .failed(.transport("fatal", retryable: false))])
    }

    func testUnhandledErrorGetsWrappedAsInternalError() async {
        enum DummyError: Error {
            case boom
        }

        let session = CFSSHSessionActor(
            authProvider: ClosureAuthProvider { _, _ in throw DummyError.boom },
            tunnelProvider: ScriptedTunnelProvider(outcomes: []),
            retryPolicy: CFSSHRetryPolicy(maxReconnectAttempts: 0),
            oauthFallback: nil,
            sleep: { _ in }
        )

        do {
            _ = try await session.connect(hostname: "ssh.example.com", method: .oauth(teamDomain: "team", appDomain: "app", callbackScheme: "cb"))
            XCTFail("expected failure")
        } catch let failure as CFSSHFailure {
            if case .internalError = failure {
                return
            }
            XCTFail("unexpected failure: \(failure)")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
