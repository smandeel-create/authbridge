import Foundation
import CryptoKit

// macOS harness: deterministic-key test vectors for ABCrypto. Prints JSON to stdout.
let recipientPrivRaw = Data((0..<32).map { UInt8(0xA0 &+ $0) })
let recipient = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivRaw)
let aad = "req-1234"
let plaintext = Data("test share 0123456789abcdef".utf8)
let sealed = try! ABCrypto.seal(recipientPub: recipient.publicKey.rawRepresentation,
                                plaintext: plaintext, aad: Data(aad.utf8))

// Fixed software signing key (P-256 scalar must be < group order; this one is).
let signRaw = Data((0..<32).map { UInt8(0x11 &+ $0) })
let signKey = try! P256.Signing.PrivateKey(rawRepresentation: signRaw)
let body = Data("{\"request_id\":\"abc\",\"decision\":\"deny\"}".utf8)
let msg = ABCrypto.signingString(method: "POST", path: "/v1/approve", ts: "1760000000000",
                                 nonce: Data(repeating: 7, count: 16).base64EncodedString(), body: body)
let sig = try! signKey.signature(for: msg).derRepresentation

let out: [String: Any] = [
    "recipient_priv_raw_b64": recipientPrivRaw.base64EncodedString(),
    "recipient_pub_b64": recipient.publicKey.rawRepresentation.base64EncodedString(),
    "aad": aad,
    "plaintext_b64": plaintext.base64EncodedString(),
    "sealed": ["epk": sealed.epk, "nonce": sealed.nonce, "ct": sealed.ct],
    "sign": [
        "pub_spki_b64": signKey.publicKey.derRepresentation.base64EncodedString(),
        "message_b64": msg.base64EncodedString(),
        "sig_der_b64": sig.base64EncodedString(),
    ],
]
let data = try! JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys])
print(String(data: data, encoding: .utf8)!)
