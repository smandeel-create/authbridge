import Foundation
import CryptoKit
import Security
import LocalAuthentication

struct PairedMac: Codable {
    /// Mac addresses to try, in order. The host used for pairing (usually the LAN address) comes first;
    /// extra ones (e.g. a Tailscale name like `my-mac` or a 100.x address) follow.
    var hosts: [String]
    var deviceId: String
    var macAgreePub: String   // b64 raw X25519
    var macName: String

    /// The pairing (first) host.
    var host: String { hosts.first ?? "" }

    init(hosts: [String], deviceId: String, macAgreePub: String, macName: String) {
        self.hosts = PairedMac.clean(hosts); self.deviceId = deviceId
        self.macAgreePub = macAgreePub; self.macName = macName
    }

    /// Trim, drop empties and duplicates (case-insensitive), keep order.
    static func clean(_ list: [String]) -> [String] {
        var seen = Set<String>(), out: [String] = []
        for h in list {
            let t = h.trimmingCharacters(in: .whitespacesAndNewlines)
            if !t.isEmpty, seen.insert(t.lowercased()).inserted { out.append(t) }
        }
        return out
    }

    private enum CodingKeys: String, CodingKey { case hosts, host, deviceId, macAgreePub, macName }

    // Migration: pairing data saved before multi-host support has a single `host`.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        var list = try c.decodeIfPresent([String].self, forKey: .hosts) ?? []
        if list.isEmpty, let h = try c.decodeIfPresent(String.self, forKey: .host) { list = [h] }
        hosts = PairedMac.clean(list)
        deviceId = try c.decode(String.self, forKey: .deviceId)
        macAgreePub = try c.decode(String.self, forKey: .macAgreePub)
        macName = try c.decode(String.self, forKey: .macName)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(hosts, forKey: .hosts)
        try c.encode(host, forKey: .host)   // keeps older builds able to read it
        try c.encode(deviceId, forKey: .deviceId)
        try c.encode(macAgreePub, forKey: .macAgreePub)
        try c.encode(macName, forKey: .macName)
    }
}

enum KeysError: Error { case keychain(OSStatus), notFound, cancelled }

enum Keys {
    private static let seService = "authbridge.se"
    private static let agreeService = "authbridge.agree"
    private static let shareService = "authbridge.share"
    private static let pairedKey = "authbridge.paired"
    private static let labelsKey = "authbridge.labels"
    private static let lastHostKey = "authbridge.lastHost"

    // MARK: generic keychain helpers (no user-presence)
    private static func plainGet(service: String, account: String) -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service, kSecAttrAccount as String: account,
                                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    private static func plainSet(service: String, account: String, data: Data) throws {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeysError.keychain(st) }
    }

    // MARK: signing key (Secure Enclave; software fallback on Simulator only)
    static func signingKey() throws -> any SigningKeyProtocol {
        #if targetEnvironment(simulator)
        if let d = plainGet(service: seService, account: "sim"),
           let k = try? P256.Signing.PrivateKey(rawRepresentation: d) { return k }
        let k = P256.Signing.PrivateKey()
        try plainSet(service: seService, account: "sim", data: k.rawRepresentation)
        return k
        #else
        if let d = plainGet(service: seService, account: "se"),
           let k = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d) { return k }
        let k = try SecureEnclave.P256.Signing.PrivateKey()
        try plainSet(service: seService, account: "se", data: k.dataRepresentation)
        return k
        #endif
    }

    static func signPubSPKI() throws -> Data { try signingKey().spki }

    static func sign(_ message: Data) throws -> Data { try signingKey().derSignature(message) }

    // MARK: X25519 agreement key
    static func agreePub() throws -> Data {
        if let d = plainGet(service: agreeService, account: "x25519"),
           let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: d) {
            return k.publicKey.rawRepresentation
        }
        let k = Curve25519.KeyAgreement.PrivateKey()
        try plainSet(service: agreeService, account: "x25519", data: k.rawRepresentation)
        return k.publicKey.rawRepresentation
    }

    // MARK: paired Mac
    static var paired: PairedMac? {
        get {
            guard let d = UserDefaults.standard.data(forKey: pairedKey) else { return nil }
            return try? JSONDecoder().decode(PairedMac.self, from: d)
        }
        set {
            if let v = newValue, let d = try? JSONEncoder().encode(v) {
                UserDefaults.standard.set(d, forKey: pairedKey)
            } else {
                UserDefaults.standard.removeObject(forKey: pairedKey)
            }
        }
    }

    /// The Mac address that last answered (tried first next time). Not secret.
    static var lastGoodHost: String? {
        get { UserDefaults.standard.string(forKey: lastHostKey) }
        set { UserDefaults.standard.set(newValue, forKey: lastHostKey) }
    }

    // MARK: local labels (domain -> username); no passwords
    static var labels: [String: String] {
        get { UserDefaults.standard.dictionary(forKey: labelsKey) as? [String: String] ?? [:] }
        set { UserDefaults.standard.set(newValue, forKey: labelsKey) }
    }

    // MARK: key shares (userPresence-protected)
    static func storeShare(recordId: String, share: Data) throws {
        deleteShare(recordId: recordId)
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, nil) else {
            throw KeysError.keychain(errSecParam)
        }
        let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                  kSecAttrService as String: shareService, kSecAttrAccount as String: recordId,
                                  kSecAttrAccessControl as String: ac, kSecValueData as String: share]
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeysError.keychain(st) }
    }

    /// Blocking: shows the Face ID / passcode prompt. Call off the main thread.
    static func readShare(recordId: String, domain: String, reason: String? = nil) throws -> Data {
        let ctx = LAContext()
        ctx.localizedReason = reason ?? "Approve login to \(domain)"
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: shareService, kSecAttrAccount as String: recordId,
                                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
                                kSecUseAuthenticationContext as String: ctx]
        var out: AnyObject?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecSuccess, let d = out as? Data { return d }
        if st == errSecItemNotFound { throw KeysError.notFound }
        if st == errSecUserCanceled || st == errSecAuthFailed { throw KeysError.cancelled }
        throw KeysError.keychain(st)
    }

    static func deleteShare(recordId: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: shareService, kSecAttrAccount as String: recordId]
        SecItemDelete(q as CFDictionary)
    }

    static func deleteAllShares() {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: shareService]
        SecItemDelete(q as CFDictionary)
    }
}

protocol SigningKeyProtocol {
    var spki: Data { get }
    func derSignature(_ message: Data) throws -> Data
}
extension P256.Signing.PrivateKey: SigningKeyProtocol {
    var spki: Data { publicKey.derRepresentation }
    func derSignature(_ message: Data) throws -> Data { try signature(for: message).derRepresentation }
}
extension SecureEnclave.P256.Signing.PrivateKey: SigningKeyProtocol {
    var spki: Data { publicKey.derRepresentation }
    func derSignature(_ message: Data) throws -> Data { try signature(for: message).derRepresentation }
}
