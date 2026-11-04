import SwiftUI
import UIKit
import UserNotifications

@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()
    @Published var paired: PairedMac? = Keys.paired
    @Published var pending: [PendingRequest] = []
    @Published var records: [RecordInfo] = []
    @Published var labels: [String: String] = Keys.labels
    @Published var error: String?
    @Published var tab = 0
    @Published var path: [PendingRequest] = []
    private var pushToken: String?
    private var sentPushToken: String?

    /// Non-secret local label key for a site's email (same dictionary as the username labels).
    static func emailLabelKey(_ domain: String) -> String { "email:" + domain }

    func report(_ e: Error) { error = e.localizedDescription }

    func pair(host: String, code: String) async -> Bool {
        do {
            let r = try await API.pair(host: host, code: code, deviceName: UIDevice.current.name)
            // The pairing host goes first; extra addresses from an earlier pairing (e.g. Tailscale) are kept.
            let p = PairedMac(hosts: [host] + (paired?.hosts ?? []), deviceId: r.deviceId,
                              macAgreePub: r.macAgreePub, macName: r.macName)
            Keys.paired = p; paired = p; error = nil
            Keys.lastGoodHost = p.host
            sentPushToken = nil
            setupPush()
            return true
        } catch { report(error); return false }
    }

    /// Replace the list of Mac addresses (order = try order). Keeps at least one.
    func setHosts(_ hosts: [String]) {
        guard var p = paired else { return }
        let clean = PairedMac.clean(hosts)
        guard !clean.isEmpty else { return }
        p.hosts = clean
        Keys.paired = p; paired = p
    }

    func unpair() {
        Keys.lastGoodHost = nil
        Keys.paired = nil; paired = nil; pending = []; records = []; path = []; sentPushToken = nil
    }

    /// Ask for notification permission and register with APNs (only when paired).
    func setupPush() {
        guard paired != nil else { return }
        Task {
            let granted = (try? await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])) ?? false
            if granted { UIApplication.shared.registerForRemoteNotifications() }
        }
    }

    func pushTokenChanged(_ hex: String) {
        pushToken = hex
        Task { await sendPushToken() }
    }

    func sendPushToken() async {
        guard paired != nil, let t = pushToken, t != sentPushToken else { return }
        do { try await API.pushToken(t); sentPushToken = t } catch { /* retried on next launch/active */ }
    }

    /// Notification tap: show the request's approve screen.
    func openRequest(id: String) async {
        tab = 0
        await refreshPending()
        if let r = pending.first(where: { $0.id == id }) { path = [r] }
    }

    /// After answering a request, open the next one still waiting (a queue), or go back to the list.
    func advance(from id: String) {
        if let next = pending.first(where: { $0.id != id }) { path = [next] } else { path = [] }
    }

    func refreshPending() async {
        guard paired != nil else { return }
        do { pending = try await API.pending(); error = nil } catch { if !(error is CancellationError) { report(error) } }
    }

    func refreshRecords() async {
        guard paired != nil else { return }
        do { records = try await API.records(); error = nil } catch { if !(error is CancellationError) { report(error) } }
    }

    private func approveWithShare(_ req: PendingRequest, recordId rid: String) async throws {
        guard let mac = paired, let macPub = Data(base64Encoded: mac.macAgreePub) else { error = "Request has no record."; return }
        let domain = req.domain
        let share = try await Task.detached { try Keys.readShare(recordId: rid, domain: domain) }.value
        let sealed = try ABCrypto.seal(recipientPub: macPub, plaintext: share, aad: Data(req.id.utf8))
        try await API.approve(requestId: req.id, approve: true, recordId: rid, sealed: sealed)
    }

    /// First login for a site: enroll the login, then approve with the new record (Face ID reads the share).
    /// Returns true when the request was answered.
    func enrollAndApprove(_ req: PendingRequest, username: String, password: String, email: String = "") async -> Bool {
        guard let rid = await enrollRecord(domain: req.domain, username: username, password: password, email: email) else { return false }
        do {
            try await approveWithShare(req, recordId: rid)
            error = nil
            await refreshPending()
            advance(from: req.id)
            return true
        } catch KeysError.cancelled { return false
        } catch { report(error); return false }
    }

    /// Send (or cancel) a verification code. The code is only in the sealed envelope; never stored.
    func answerCode(_ req: PendingRequest, code: String?) async -> Bool {
        do {
            if let code {
                guard let mac = paired, let macPub = Data(base64Encoded: mac.macAgreePub) else { error = "Not paired."; return false }
                struct Payload: Encodable { let code: String }
                let json = try JSONEncoder().encode(Payload(code: code))
                let sealed = try ABCrypto.seal(recipientPub: macPub, plaintext: json, aad: Data("code|\(req.id)".utf8))
                try await API.code(requestId: req.id, submit: true, sealed: sealed)
            } else {
                try await API.code(requestId: req.id, submit: false, sealed: nil)
            }
            error = nil
            await refreshPending()
            advance(from: req.id)
            return true
        } catch APIError.http(400) { error = "That code isn't valid (4-10 letters or digits)."; return false
        } catch APIError.http(404) { error = "That request has expired."; await refreshPending(); advance(from: req.id); return true
        } catch { report(error); return false }
    }

    func noCredential(_ req: PendingRequest) async {
        do {
            try await API.approve(requestId: req.id, approve: false, recordId: nil, sealed: nil, decision: "no_credential")
            error = nil
            await refreshPending()
            advance(from: req.id)
        } catch { report(error) }
    }

    func decide(_ req: PendingRequest, approve: Bool) async {
        do {
            if approve {
                guard let rid = req.recordId else { error = "Request has no record."; return }
                try await approveWithShare(req, recordId: rid)
            } else {
                try await API.approve(requestId: req.id, approve: false, recordId: req.recordId, sealed: nil)
            }
            error = nil
            await refreshPending()
            advance(from: req.id)
        } catch KeysError.cancelled { /* user cancelled Face ID */
        } catch KeysError.notFound {
            error = "This phone has no key share for that site. Refresh it in Sites, or deny."
        } catch { report(error) }
    }

    /// Returns true on success.
    func enroll(domain: String, username: String, password: String, email: String = "") async -> Bool {
        await enrollRecord(domain: domain, username: username, password: password, email: email) != nil
    }

    /// Returns the new record id on success.
    func enrollRecord(domain: String, username: String, password: String, email: String = "") async -> String? {
        guard let mac = paired, let macPub = Data(base64Encoded: mac.macAgreePub) else { error = "Not paired."; return nil }
        let recordId = UUID().uuidString
        let cleanEmail = email.trimmingCharacters(in: .whitespaces)
        let share = ABCrypto.randomBytes(32)
        let dom = domain.trimmingCharacters(in: .whitespaces).lowercased()
        let oldIds = records.filter { $0.domain.lowercased() == dom }.map(\.recordId)
        do {
            struct Payload: Encodable { let recordId, domain, username, password, share: String; let email: String? }
            let enc = JSONEncoder(); enc.keyEncodingStrategy = .convertToSnakeCase
            let json = try enc.encode(Payload(recordId: recordId, domain: dom, username: username,
                                              password: password, share: share.base64EncodedString(),
                                              email: cleanEmail.isEmpty ? nil : cleanEmail))
            let sealed = try ABCrypto.seal(recipientPub: macPub, plaintext: json, aad: Data("enroll".utf8))
            let r = try await API.enroll(sealed: sealed)
            try Keys.storeShare(recordId: r.recordId, share: share)
            for o in oldIds where o != r.recordId { Keys.deleteShare(recordId: o) }
            labels[r.domain] = username; labels[Self.emailLabelKey(r.domain)] = cleanEmail.isEmpty ? nil : cleanEmail; Keys.labels = labels
            error = nil
            await refreshRecords()
            return r.recordId
        } catch { report(error); return nil }
    }

    /// Edit username/email of an existing record without the password (Face ID reads the share). True on success.
    func updateDetails(domain: String, username: String, email: String) async -> Bool {
        guard let mac = paired, let macPub = Data(base64Encoded: mac.macAgreePub) else { error = "Not paired."; return false }
        let dom = domain.trimmingCharacters(in: .whitespaces).lowercased()
        guard let rec = records.first(where: { $0.domain.lowercased() == dom }) else { error = "Unknown site."; return false }
        let cleanEmail = email.trimmingCharacters(in: .whitespaces)
        let rid = rec.recordId
        do {
            let share = try await Task.detached { try Keys.readShare(recordId: rid, domain: dom, reason: "Update login for \(dom)") }.value
            struct Payload: Encodable { let share, username, email: String }
            let enc = JSONEncoder(); enc.keyEncodingStrategy = .convertToSnakeCase
            let json = try enc.encode(Payload(share: share.base64EncodedString(), username: username, email: cleanEmail))
            let sealed = try ABCrypto.seal(recipientPub: macPub, plaintext: json, aad: Data("update|\(rid)".utf8))
            try await API.updateRecord(recordId: rid, sealed: sealed)
            labels[rec.domain] = username; labels[Self.emailLabelKey(rec.domain)] = cleanEmail.isEmpty ? nil : cleanEmail; Keys.labels = labels
            error = nil
            await refreshRecords()
            return true
        } catch KeysError.cancelled { return false
        } catch KeysError.notFound { error = "This phone has no key share for that site. Enter the password to replace it."; return false
        } catch { report(error); return false }
    }

    func delete(_ rec: RecordInfo) async {
        do {
            try await API.deleteRecord(rec.recordId)
            Keys.deleteShare(recordId: rec.recordId)
            labels[rec.domain] = nil; labels[Self.emailLabelKey(rec.domain)] = nil; Keys.labels = labels
            await refreshRecords()
        } catch { report(error) }
    }

    func wipeAll() async {
        do {
            try await API.wipe()
            Keys.deleteAllShares(); labels = [:]; Keys.labels = [:]
            await refreshRecords()
        } catch { report(error) }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var phase

    var body: some View {
        Group {
            if model.paired == nil {
                PairView()
            } else {
                TabView(selection: $model.tab) {
                    RequestsView().tabItem { Label("Requests", systemImage: "faceid") }.tag(0)
                    SitesView().tabItem { Label("Sites", systemImage: "globe") }.tag(1)
                }
            }
        }
        .onChange(of: phase) { _, p in if p == .active { Task { await model.refreshPending(); await model.sendPushToken() } } }
        .onOpenURL { _ in
            model.tab = 0
            Task { await model.refreshPending() }
        }
    }
}

struct PairView: View {
    @EnvironmentObject var model: AppModel
    @State private var host = ""
    @State private var code = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Mac") {
                    TextField("192.168.1.x or Tailscale name", text: $host)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Section("Pairing code") {
                    TextField("8-digit code", text: $code).keyboardType(.numberPad)
                }
                if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
                Section {
                    Button(busy ? "Pairing..." : "Pair") {
                        busy = true
                        Task { _ = await model.pair(host: host, code: code); busy = false }
                    }.disabled(busy || host.isEmpty || code.count != 8)
                } footer: { Text("Run `authbridge pair` on your Mac to get a code.") }
            }
            .navigationTitle("Pair with Mac")
        }
    }
}

struct RequestsView: View {
    @EnvironmentObject var model: AppModel
    @State private var showEmails = false
    @State private var showHosts = false

    var body: some View {
        NavigationStack(path: $model.path) {
            List {
                if let e = model.error { Text(e).foregroundStyle(.red) }
                if model.pending.isEmpty {
                    Text("No pending requests").foregroundStyle(.secondary)
                }
                ForEach(model.pending) { r in
                    NavigationLink(value: r) {
                        VStack(alignment: .leading) {
                            Text(r.isCode ? "Code for \(r.domain)" : r.domain).font(.headline)
                            Text(r.isCode ? "Enter the verification code" : r.task).font(.subheadline).foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                }
            }
            .navigationTitle("Requests")
            .navigationDestination(for: PendingRequest.self) { RequestDetail(req: $0) }
            .refreshable { await model.refreshPending() }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button { showHosts = true } label: { Label("Mac addresses…", systemImage: "network") }
                        Button { showEmails = true } label: { Label("Your email addresses…", systemImage: "envelope") }
                        Button("Unpair", role: .destructive) { model.unpair() }
                    } label: { Image(systemName: "ellipsis.circle") }
                }
            }
            .sheet(isPresented: $showHosts) { MacAddressesView() }
            .sheet(isPresented: $showEmails) { MyEmailsView() }
        }
        .task {
            // Runs while visible; cancelled automatically on disappear.
            while !Task.isCancelled {
                // Don't refresh under an open request screen: re-rendering it can drop an AutoFilled code.
                if model.path.isEmpty { await model.refreshPending() }
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }
}

/// Your own email addresses, offered as quick-fill buttons when saving a site.
struct MyEmailsView: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage(MyEmails.key) private var raw = ""
    @State private var newEmail = ""

    private var emails: [String] { MyEmails.parse(raw) }
    private func save(_ l: [String]) { raw = l.joined(separator: "\n") }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(emails, id: \.self) { e in Text(e).font(.body.monospaced()) }
                        .onDelete { idx in var l = emails; l.remove(atOffsets: idx); save(l) }
                        .onMove { from, to in var l = emails; l.move(fromOffsets: from, toOffset: to); save(l) }
                } header: {
                    Text("Saved addresses")
                } footer: {
                    Text("Shown as quick-fill buttons when you save a site's login. Swipe to delete.")
                }
                Section {
                    TextField("you@example.com", text: $newEmail)
                        .textContentType(.emailAddress).keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .onSubmit(add)
                    Button("Add", action: add)
                        .disabled(newEmail.trimmingCharacters(in: .whitespaces).isEmpty)
                } header: {
                    Text("Add address")
                }
            }
            .navigationTitle("Your email addresses")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { EditButton() }
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }

    private func add() {
        let e = newEmail.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !e.isEmpty, !emails.contains(e) else { newEmail = ""; return }
        save(emails + [e]); newEmail = ""
    }
}

/// Addresses the app tries, in order, to reach the Mac (LAN first, then e.g. a Tailscale name).
struct MacAddressesView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var newHost = ""
    @State private var status: [String: Bool] = [:]

    private var hosts: [String] { model.paired?.hosts ?? [] }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(hosts, id: \.self) { h in
                        HStack {
                            Text(h).font(.body.monospaced())
                            if h == hosts.first { Text("paired").font(.caption).foregroundStyle(.secondary) }
                            Spacer()
                            if let ok = status[h] {
                                Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle")
                                    .foregroundStyle(ok ? .green : .secondary)
                            }
                        }
                    }
                    .onDelete { idx in
                        var l = hosts; l.remove(atOffsets: idx)
                        if !l.isEmpty { model.setHosts(l) }
                    }
                    .onMove { from, to in var l = hosts; l.move(fromOffsets: from, toOffset: to); model.setHosts(l) }
                } header: {
                    Text("Tried in order")
                } footer: {
                    Text("The app uses the address that last worked and falls back to the others. Swipe to delete (at least one stays).")
                }
                Section {
                    TextField("my-mac or 100.x.y.z", text: $newHost)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .onSubmit(add)
                    Button("Add", action: add)
                        .disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                } header: {
                    Text("Add address")
                } footer: {
                    Text("For use away from home: the Mac's Tailscale name (MagicDNS) or its 100.x address. Tailscale must be on on this iPhone.")
                }
                Section {
                    Button("Test addresses") { Task { await test() } }
                }
            }
            .navigationTitle("Mac addresses")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { EditButton() }
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .task { await test() }
        }
    }

    private func add() {
        let h = newHost.trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty else { return }
        model.setHosts(hosts + [h]); newHost = ""
        Task { status[h] = await API.probe(h) }
    }

    private func test() async {
        for h in hosts { status[h] = await API.probe(h) }
    }
}

struct RequestDetail: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let req: PendingRequest
    @State private var busy = false
    @State private var username = ""
    @State private var password = ""
    @State private var email = ""

    var body: some View {
        if req.isCode { CodeRequestView(req: req) }
        else if req.needsEnroll == true { enrollBody } else { normalBody }
    }

    private var enrollBody: some View {
        Form {
            Section {
                Text(req.domain).font(.title2.bold())
                Text("First login for this site").foregroundStyle(.secondary)
                if !req.task.isEmpty { Text(req.task).font(.footnote).foregroundStyle(.secondary) }
            }
            Section("Login") {
                TextField("Username", text: $username)
                    // No autocorrectionDisabled(): it can suppress the QuickType bar that carries AutoFill.
                    .textContentType(.username).keyboardType(.emailAddress).textInputAutocapitalization(.never)
                SecureField("Password", text: $password).textContentType(.password)
                EmailField(email: $email)
            }
            if let e = model.error { Section { Text(e).foregroundStyle(.red).font(.footnote) } }
            Section {
                Button("Save & approve") {
                    busy = true
                    let u = username, pw = password, em = email
                    Task {
                        let ok = await model.enrollAndApprove(req, username: u, password: pw, email: em)
                        busy = false
                        if ok { password = "" }
                    }
                }.disabled(busy || username.isEmpty || password.isEmpty)
                Button("I don't have a login here") {
                    busy = true
                    Task { await model.noCredential(req); password = ""; busy = false }
                }.disabled(busy)
                Button("Deny", role: .destructive) {
                    busy = true
                    Task { await model.decide(req, approve: false); password = ""; busy = false }
                }.disabled(busy)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { password = "" }
    }

    private var normalBody: some View {
        VStack(spacing: 24) {
            Spacer()
            Text(req.domain).font(.system(size: 34, weight: .bold)).multilineTextAlignment(.center)
                .minimumScaleFactor(0.5)
            Text(req.task).font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center)
            if let e = model.error { Text(e).foregroundStyle(.red).font(.footnote) }
            Spacer()
            Button {
                busy = true
                Task { await model.decide(req, approve: true); busy = false }
            } label: { Text("Approve").frame(maxWidth: .infinity).padding(.vertical, 6) }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(busy)
            Button(role: .destructive) {
                busy = true
                Task { await model.decide(req, approve: false); busy = false }
            } label: { Text("Deny").frame(maxWidth: .infinity).padding(.vertical, 6) }
                .buttonStyle(.bordered).controlSize(.large).disabled(busy)
        }
        .padding()
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// Asks for a verification code. The .oneTimeCode content type makes iOS offer SMS / Mail codes in the QuickType bar.
struct CodeRequestView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let req: PendingRequest
    @State private var code = ""
    @State private var busy = false
    @State private var banner: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            if let b = banner { Text(b).font(.title3.bold()).foregroundStyle(.green).multilineTextAlignment(.center) }
            Text(req.domain).font(.system(size: 34, weight: .bold)).multilineTextAlignment(.center).minimumScaleFactor(0.5)
            Text(req.reason == "follow_up" ? "Enter the code the site just sent (text message or app)" : "Enter the code from the email or text message")
                .font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center)
            if req.reason == "email_not_found", let s = req.searched, !s.isEmpty {
                Text("Not found yet in \(s.joined(separator: ", ")) (inbox and junk)").font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            TextField("Code", text: $code)
                .textContentType(.oneTimeCode)
                .textInputAutocapitalization(.never)
                .keyboardType(.asciiCapable)
                .font(.system(size: 28, weight: .semibold, design: .monospaced))
                .multilineTextAlignment(.center)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                // AutoFill ("From Messages") inserts the whole code in one change: submit it straight away.
                .onChange(of: code) { old, new in
                    let t = new.trimmingCharacters(in: .whitespaces)
                    if old.isEmpty && t.count >= 4 && !busy { submit() }
                }
            if let e = model.error { Text(e).foregroundStyle(.red).font(.footnote) }
            Spacer()
            Button { submit() } label: { Text("Submit").frame(maxWidth: .infinity).padding(.vertical, 6) }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(busy || code.trimmingCharacters(in: .whitespaces).count < 4)
            Button(role: .destructive) {
                busy = true
                Task {
                    let ok = await model.answerCode(req, code: nil)
                    busy = false
                    if ok { code = "" }
                }
            } label: { Text("Cancel").frame(maxWidth: .infinity).padding(.vertical, 6) }
                .buttonStyle(.bordered).controlSize(.large).disabled(busy)
        }
        .padding()
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { focused = true }
        .onDisappear { code = "" }
        .task { await watchState() }
    }

    /// Polls the request every 2 s: if the Mac found the code in email (or the request expired) tell the user, then move on.
    private func watchState() async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if Task.isCancelled { return }
            guard let st = try? await API.requestState(id: req.id) else { continue }
            if st.state == "resolved" && st.resolvedBy == "email" { banner = "Code found in email ✓" }
            else if st.state == "expired" { banner = "This request has expired" }
            else { continue }
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            if Task.isCancelled { return }
            await model.refreshPending()
            model.advance(from: req.id)
            return
        }
    }

    private func submit() {
        busy = true
        let c = code
        Task {
            let ok = await model.answerCode(req, code: c)
            busy = false
            if ok { code = "" }
        }
    }
}

struct SiteDraft: Identifiable { let id = UUID(); var domain = ""; var username = ""; var email = ""; var isEdit = false }

/// Your own email addresses (Settings: "Your email addresses"), stored newline-joined in UserDefaults `ab.myEmails`.
enum MyEmails {
    static let key = "ab.myEmails"
    static func parse(_ raw: String) -> [String] {
        raw.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

/// Optional account email (for sites whose sign-in field wants an email) plus quick-fill buttons for the
/// addresses saved under "Your email addresses".
struct EmailField: View {
    @Binding var email: String
    @AppStorage(MyEmails.key) private var myEmailsRaw = ""
    var body: some View {
        TextField("Email (if the site signs in by email)", text: $email)
            // No autocorrectionDisabled(): it can suppress the QuickType bar that carries AutoFill.
            .textContentType(.emailAddress).keyboardType(.emailAddress).textInputAutocapitalization(.never)
        let mine = MyEmails.parse(myEmailsRaw)
        if !mine.isEmpty {
            HStack {
                ForEach(mine, id: \.self) { e in Button(e) { email = e } }
            }
            .buttonStyle(.bordered).controlSize(.small).font(.caption)
        }
    }
}

struct SitesView: View {
    @EnvironmentObject var model: AppModel
    @State private var draft: SiteDraft?
    @State private var confirmWipe = false

    var body: some View {
        NavigationStack {
            List {
                if let e = model.error { Text(e).foregroundStyle(.red) }
                ForEach(model.records) { rec in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(rec.domain).font(.headline)
                            if let u = model.labels[rec.domain] { Text(u).font(.subheadline).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        if rec.stale {
                            Text("Stale").font(.caption.bold()).padding(.horizontal, 8).padding(.vertical, 3)
                                .background(Color.orange.opacity(0.25), in: Capsule())
                            Button("Refresh") {
                                draft = SiteDraft(domain: rec.domain, username: model.labels[rec.domain] ?? "", email: model.labels[AppModel.emailLabelKey(rec.domain)] ?? "")
                            }.buttonStyle(.bordered)
                        }
                    }
                    // Tap to edit: saving re-enrolls and replaces the record for that domain.
                    .contentShape(Rectangle())
                    .onTapGesture { draft = SiteDraft(domain: rec.domain, username: model.labels[rec.domain] ?? "", email: model.labels[AppModel.emailLabelKey(rec.domain)] ?? "", isEdit: true) }
                    .swipeActions { Button("Delete", role: .destructive) { Task { await model.delete(rec) } } }
                    .swipeActions(edge: .leading) {
                        Button("Edit") { draft = SiteDraft(domain: rec.domain, username: model.labels[rec.domain] ?? "", email: model.labels[AppModel.emailLabelKey(rec.domain)] ?? "", isEdit: true) }.tint(.blue)
                    }
                }
                if !model.records.isEmpty {
                    Button("Wipe all", role: .destructive) { confirmWipe = true }
                }
            }
            .navigationTitle("Sites")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { draft = SiteDraft() } label: { Image(systemName: "plus") }
                }
            }
            .refreshable { await model.refreshRecords() }
            .task { await model.refreshRecords() }
            .sheet(item: $draft) { d in AddSiteSheet(draft: d) }
            .confirmationDialog("Delete every stored login on the Mac and this phone?",
                                isPresented: $confirmWipe, titleVisibility: .visible) {
                Button("Wipe all", role: .destructive) { Task { await model.wipeAll() } }
            }
        }
    }
}

struct AddSiteSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State var draft: SiteDraft
    @State private var password = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if draft.isEdit {
                        Text(draft.domain).foregroundStyle(.secondary)
                    } else {
                        TextField("example.com", text: $draft.domain)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                } header: {
                    Text("Site")
                } footer: {
                    Text("Also covers subdomains, e.g. account.\(draft.domain.isEmpty ? "example.com" : draft.domain)")
                }
                Section {
                    TextField("Username", text: $draft.username)
                        // No autocorrectionDisabled(): it can suppress the QuickType bar that carries AutoFill.
                        .textContentType(.username).keyboardType(.emailAddress).textInputAutocapitalization(.never)
                    SecureField("Password", text: $password).textContentType(.password)
                    EmailField(email: $draft.email)
                } header: {
                    Text("Login")
                } footer: {
                    if draft.isEdit {
                        Text("Leave Password empty to keep the saved one (Face ID required to change details), or AutoFill a new password to replace it.")
                    }
                }
                if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
            }
            .navigationTitle(draft.isEdit ? "Edit \(draft.domain)" : (draft.domain.isEmpty ? "Add site" : "Save login"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { password = ""; dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        busy = true
                        let pw = password
                        Task {
                            let ok = (draft.isEdit && pw.isEmpty)
                                ? await model.updateDetails(domain: draft.domain, username: draft.username, email: draft.email)
                                : await model.enroll(domain: draft.domain, username: draft.username, password: pw, email: draft.email)
                            busy = false
                            if ok { password = ""; dismiss() }
                        }
                    }.disabled(busy || draft.domain.isEmpty || draft.username.isEmpty || (password.isEmpty && !draft.isEdit))
                }
            }
            .onDisappear { password = "" }
        }
    }
}
