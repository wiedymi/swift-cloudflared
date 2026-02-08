import Foundation
#if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))
import Security

public actor CFSSHKeychainTokenStore: CFSSHTokenStore {
    private let service: String
    private let accessibility: CFString
    private let useDataProtectionKeychain: Bool

    #if os(macOS)
    public init(
        service: String = "com.swift-cloudflared.tokens",
        accessibility: CFString = kSecAttrAccessibleAfterFirstUnlock,
        useDataProtectionKeychain: Bool = true
    ) {
        self.service = service
        self.accessibility = accessibility
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }
    #else
    public init(
        service: String = "com.swift-cloudflared.tokens",
        accessibility: CFString = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        useDataProtectionKeychain: Bool = false
    ) {
        self.service = service
        self.accessibility = accessibility
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }
    #endif

    public func readToken(for key: String) async throws -> String? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data, let token = String(data: data, encoding: .utf8) else {
                throw CFSSHFailure.internalError("failed to decode token from keychain")
            }
            return token
        case errSecItemNotFound:
            return nil
        default:
            throw CFSSHFailure.internalError("keychain read failed: \(status)")
        }
    }

    public func writeToken(_ token: String, for key: String) async throws {
        guard let tokenData = token.data(using: .utf8) else {
            throw CFSSHFailure.configuration("unable to encode token")
        }

        let query = baseQuery(for: key)
        SecItemDelete(query as CFDictionary)

        var insert = query
        insert[kSecValueData as String] = tokenData
        insert[kSecAttrAccessible as String] = accessibility

        let status = SecItemAdd(insert as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CFSSHFailure.internalError("keychain write failed: \(status)")
        }
    }

    public func removeToken(for key: String) async throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CFSSHFailure.internalError("keychain delete failed: \(status)")
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]

    #if os(macOS)
        if useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }
    #endif

        return query
    }

}
#endif
