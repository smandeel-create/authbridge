import Foundation
import CryptoKit

/// Pure crypto helpers (no UIKit). Compiles on iOS and macOS.
enum ABCrypto {
    struct Sealed: Codable, Equatable {
        let epk: String
        let nonce: String
        let ct: String
    }

    enum CryptoError: Error { case badKey }

    /// seal(recipient_x25519_pub, plaintext, aad) per SPEC.
    static func seal(recipientPub: Data, plaintext: Data, aad: Data) throws -> Sealed {
        guard let recipient = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPub) else {
            throw CryptoError.badKey
        }
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let epkRaw = eph.publicKey.rawRepresentation
        let ss = try eph.sharedSecretFromKeyAgreement(with: recipient)
        let key = ss.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: epkRaw + recipient.rawRepresentation,
            sharedInfo: Data("authbridge-seal-v1".utf8),
            outputByteCount: 32)
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: ChaChaPoly.Nonce(), authenticating: aad)
        // box.combined is nonce||ct||tag; we emit nonce separately and ct = ciphertext||tag.
        return Sealed(epk: epkRaw.base64EncodedString(),
                      nonce: Data(box.nonce).base64EncodedString(),
                      ct: (box.ciphertext + box.tag).base64EncodedString())
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func randomBytes(_ n: Int) -> Data {
        Data((0..<n).map { _ in UInt8.random(in: 0...255) }) // SystemRandomNumberGenerator is a CSPRNG
    }

    /// utf8(METHOD \n PATH \n TS \n NONCE \n hex(sha256(body)))
    static func signingString(method: String, path: String, ts: String, nonce: String, body: Data) -> Data {
        Data("\(method)\n\(path)\n\(ts)\n\(nonce)\n\(sha256Hex(body))".utf8)
    }

    /// `signer` takes the message bytes and returns a DER ECDSA-SHA256 signature.
    static func signedHeaders(deviceId: String, method: String, path: String, body: Data,
                              tsMillis: Int64? = nil, nonce: Data? = nil,
                              signer: (Data) throws -> Data) throws -> [String: String] {
        let ts = String(tsMillis ?? Int64(Date().timeIntervalSince1970 * 1000))
        let nonceB64 = (nonce ?? randomBytes(16)).base64EncodedString()
        let msg = signingString(method: method, path: path, ts: ts, nonce: nonceB64, body: body)
        let sig = try signer(msg)
        return ["X-AB-Device": deviceId, "X-AB-Ts": ts, "X-AB-Nonce": nonceB64,
                "X-AB-Sig": sig.base64EncodedString()]
    }
}
