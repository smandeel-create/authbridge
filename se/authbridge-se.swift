import Foundation
import CryptoKit

let dir: URL = {
    if let h = ProcessInfo.processInfo.environment["AUTHBRIDGE_HOME"] { return URL(fileURLWithPath: h) }
    return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".authbridge")
}()
let blobURL = dir.appendingPathComponent("se-key.blob")

func fail(_ m: String) -> Never {
    FileHandle.standardError.write((m + "\n").data(using: .utf8)!)
    exit(1)
}

func loadKey() -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    guard let data = try? Data(contentsOf: blobURL) else { fail("no key blob; run init") }
    do { return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data) }
    catch { fail("cannot load SE key: \(error)") }
}

guard SecureEnclave.isAvailable else { fail("Secure Enclave not available") }
let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: authbridge-se init|pubkey|derive <peer_x963_b64>") }

switch args[1] {
case "init":
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    if !FileManager.default.fileExists(atPath: blobURL.path) {
        do {
            let k = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            try k.dataRepresentation.write(to: blobURL, options: .atomic)
            chmod(blobURL.path, 0o600)
        } catch { fail("key creation failed: \(error)") }
    }
    print(loadKey().publicKey.x963Representation.base64EncodedString())
case "pubkey":
    print(loadKey().publicKey.x963Representation.base64EncodedString())
case "derive":
    guard args.count == 3, let d = Data(base64Encoded: args[2]) else { fail("bad peer key") }
    do {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: d)
        let ss = try loadKey().sharedSecretFromKeyAgreement(with: peer)
        let raw = ss.withUnsafeBytes { Data($0) }
        print(raw.base64EncodedString())
    } catch { fail("derive failed: \(error)") }
default:
    fail("unknown command")
}
