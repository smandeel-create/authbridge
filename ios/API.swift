import Foundation
import Network

struct PendingRequest: Decodable, Identifiable, Hashable {
    let id: String
    let domain: String
    let task: String
    let recordId: String?
    let needsEnroll: Bool?
    let kind: String?
    let parentId: String?
    let reason: String?
    let searched: [String]?
    var isCode: Bool { kind == "code" }
}
struct RecordInfo: Decodable, Identifiable, Hashable {
    let recordId: String
    let domain: String
    let stale: Bool
    var id: String { recordId }
}
struct PairResponse: Decodable { let deviceId: String; let macAgreePub: String; let macName: String }

enum APIError: LocalizedError {
    case notPaired, badURL, http(Int), transport(String)
    var errorDescription: String? {
        switch self {
        case .notPaired: return "Not paired with a Mac."
        case .badURL: return "Invalid host."
        case .http(let c): return c == 401 || c == 403 ? "Mac rejected the request (\(c))." : "Mac returned HTTP \(c)."
        case .transport(let m): return m
        }
    }
}

enum API {
    private static let enc: JSONEncoder = { let e = JSONEncoder(); e.keyEncodingStrategy = .convertToSnakeCase; return e }()
    private static let dec: JSONDecoder = { let d = JSONDecoder(); d.keyDecodingStrategy = .convertFromSnakeCase; return d }()

    private static func url(host: String, path: String) throws -> URL {
        let h = host.trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty, let u = URL(string: "http://\(h):47900\(path)") else { throw APIError.badURL }
        return u
    }

    private static func run(_ req: URLRequest) async throws -> Data {
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            guard (200..<300).contains(code) else { throw APIError.http(code) }
            return data
        } catch let e as APIError { throw e
        } catch { throw APIError.transport(error.localizedDescription) }
    }

    // MARK: host selection (LAN first, then e.g. Tailscale)

    private static let port: UInt16 = 47900
    private static let connectTimeout: TimeInterval = 2.5
    /// Within this window after a success, the remembered host is used without a TCP probe first.
    private static let trustWindow: TimeInterval = 15
    @MainActor private static var lastSuccess: (host: String, at: Date)?

    /// TCP connect to host:47900 with a short deadline. True when the Mac's port accepts a connection.
    static func probe(_ host: String, timeout: TimeInterval = connectTimeout) async -> Bool {
        let h = host.trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty, let p = NWEndpoint.Port(rawValue: port) else { return false }
        let params = NWParameters.tcp
        if let tcp = params.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
            tcp.connectionTimeout = Int(timeout.rounded(.up))
        }
        let conn = NWConnection(host: NWEndpoint.Host(h), port: p, using: params)
        let queue = DispatchQueue(label: "authbridge.probe")
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            var done = false   // only touched on `queue`
            func finish(_ ok: Bool) {
                guard !done else { return }
                done = true
                conn.stateUpdateHandler = nil
                conn.cancel()
                cont.resume(returning: ok)
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                case .waiting: finish(false)   // no route / DNS failure: don't wait for the network to change
                default: break
                }
            }
            conn.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    /// Hosts in the order to try: the last one that worked first, then the configured order.
    private static func ordered(_ hosts: [String]) -> [String] {
        guard let last = Keys.lastGoodHost, let i = hosts.firstIndex(where: { $0.caseInsensitiveCompare(last) == .orderedSame })
        else { return hosts }
        var h = hosts; h.insert(h.remove(at: i), at: 0); return h
    }

    /// First host (in `ordered` order, minus `excluding`) whose port accepts a TCP connection.
    private static func reachableHost(_ hosts: [String], excluding: String? = nil) async -> String? {
        for h in ordered(hosts) where h != excluding {
            if await probe(h) { return h }
        }
        return nil
    }

    @MainActor private static func remember(_ host: String) {
        lastSuccess = (host, Date())
        if Keys.lastGoodHost != host { Keys.lastGoodHost = host }
    }
    @MainActor private static func forget() { lastSuccess = nil }
    @MainActor private static func trusted(_ hosts: [String]) -> String? {
        guard let s = lastSuccess, Date().timeIntervalSince(s.at) < trustWindow,
              hosts.contains(s.host) else { return nil }
        return s.host
    }

    /// The request certainly never reached the Mac (safe to resend elsewhere, even for a POST).
    private static func notDelivered(_ e: Error) -> Bool {
        guard let u = e as? URLError else { return false }
        switch u.code {
        case .cannotConnectToHost, .cannotFindHost, .dnsLookupFailed, .notConnectedToInternet: return true
        default: return false
        }
    }
    /// A transport failure that suggests this host is no longer the right one.
    private static func hostLooksDown(_ e: Error) -> Bool {
        guard let u = e as? URLError else { return false }
        return notDelivered(u) || u.code == .timedOut || u.code == .networkConnectionLost
    }

    private static func send(_ method: String, _ path: String, body: Data, host: String, deviceId: String) async throws -> (Data, Int) {
        var req = URLRequest(url: try url(host: host, path: path), timeoutInterval: 10)
        req.httpMethod = method
        if !body.isEmpty { req.httpBody = body; req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        // Signed fresh per attempt (new ts/nonce). PATH excludes the host, so the signature is host-independent.
        let headers = try ABCrypto.signedHeaders(deviceId: deviceId, method: method, path: path, body: body) {
            try Keys.sign($0)
        }
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, resp) = try await URLSession.shared.data(for: req)
        return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
    }

    /// Signed request to the paired Mac, over whichever of its addresses answers.
    private static func signed(_ method: String, _ path: String, body: Data = Data()) async throws -> Data {
        guard let p = Keys.paired else { throw APIError.notPaired }
        let hosts = p.hosts
        guard !hosts.isEmpty else { throw APIError.badURL }

        // Pick a host: the recently-working one straight away, otherwise probe in order.
        var host = await trusted(hosts)
        if host == nil { host = await reachableHost(hosts) }
        // Nothing answered the probe: still try the preferred host so URLSession reports the real
        // error (and a first-run Local Network prompt, which a probe can't wait for, gets a chance).
        guard var h = host ?? ordered(hosts).first else { throw APIError.badURL }

        var retried = false
        while true {
            do {
                let (data, code) = try await send(method, path, body: body, host: h, deviceId: p.deviceId)
                await remember(h)   // any HTTP answer means this address reaches the daemon
                guard (200..<300).contains(code) else { throw APIError.http(code) }
                return data
            } catch let e as APIError { throw e
            } catch {
                if hostLooksDown(error) { await forget() }
                // Fail over once, only when the request can't have been processed (or it's a GET).
                let safe = notDelivered(error) || (method == "GET" && hostLooksDown(error))
                if !retried, safe, let next = await reachableHost(hosts, excluding: h) {
                    retried = true; h = next; continue
                }
                throw APIError.transport(error.localizedDescription)
            }
        }
    }

    static func pair(host: String, code: String, deviceName: String) async throws -> PairResponse {
        struct Body: Encodable { let code, deviceName, signPub, agreePub: String }
        let body = try enc.encode(Body(code: code, deviceName: deviceName,
                                       signPub: try Keys.signPubSPKI().base64EncodedString(),
                                       agreePub: try Keys.agreePub().base64EncodedString()))
        var req = URLRequest(url: try url(host: host, path: "/v1/pair"), timeoutInterval: 10)
        req.httpMethod = "POST"; req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try dec.decode(PairResponse.self, from: try await run(req))
    }

    static func pending() async throws -> [PendingRequest] {
        struct R: Decodable { let requests: [PendingRequest] }
        return try dec.decode(R.self, from: try await signed("GET", "/v1/pending")).requests
    }

    struct RequestState: Decodable { let state: String; let resolvedBy: String? }

    static func requestState(id: String) async throws -> RequestState {
        try dec.decode(RequestState.self, from: try await signed("GET", "/v1/requests/\(id)"))
    }

    static func approve(requestId: String, approve: Bool, recordId: String?, sealed: ABCrypto.Sealed?,
                        decision: String? = nil) async throws {
        struct B: Encodable { let requestId, decision: String; let recordId: String?; let sealedShare: ABCrypto.Sealed? }
        let body = try enc.encode(B(requestId: requestId, decision: decision ?? (approve ? "approve" : "deny"),
                                    recordId: recordId, sealedShare: sealed))
        _ = try await signed("POST", "/v1/approve", body: body)
    }

    /// Answer a code request. `sealed` is nil for cancel.
    static func code(requestId: String, submit: Bool, sealed: ABCrypto.Sealed?) async throws {
        struct B: Encodable { let requestId, decision: String; let sealed: ABCrypto.Sealed? }
        _ = try await signed("POST", "/v1/code", body: try enc.encode(B(requestId: requestId, decision: submit ? "submit" : "cancel", sealed: sealed)))
    }

    static func enroll(sealed: ABCrypto.Sealed) async throws -> (recordId: String, domain: String) {
        struct B: Encodable { let sealed: ABCrypto.Sealed }
        struct R: Decodable { let recordId: String; let domain: String }
        let r = try dec.decode(R.self, from: try await signed("POST", "/v1/enroll", body: try enc.encode(B(sealed: sealed))))
        return (r.recordId, r.domain)
    }

    static func updateRecord(recordId: String, sealed: ABCrypto.Sealed) async throws {
        struct B: Encodable { let sealed: ABCrypto.Sealed }
        let id = recordId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? recordId
        _ = try await signed("POST", "/v1/records/\(id)/update", body: try enc.encode(B(sealed: sealed)))
    }

    static func records() async throws -> [RecordInfo] {
        struct R: Decodable { let records: [RecordInfo] }
        return try dec.decode(R.self, from: try await signed("GET", "/v1/records")).records
    }

    static func deleteRecord(_ id: String) async throws {
        let enc = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await signed("DELETE", "/v1/records/\(enc)")
    }

    static func pushToken(_ token: String) async throws {
        struct B: Encodable { let token, env: String }
        _ = try await signed("POST", "/v1/push-token", body: try enc.encode(B(token: token, env: "development")))
    }

    static func wipe() async throws { _ = try await signed("POST", "/v1/wipe") }
}
