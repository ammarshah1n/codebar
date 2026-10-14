import SwiftUI
import AppKit
import Vision
import UniformTypeIdentifiers

// MARK: - Model

@MainActor
final class Model: ObservableObject {
    @Published var accounts: [OTPAccount] = []
    @Published var locked = false
    @Published var loaded = false          // true only after a successful load
    @Published var error: String?
    @Published var showImport = false
    let demo: Bool
    private let store: CodeStore?
    var dialogActive = false               // file dialog open
    private var clipboardCount: Int?
    private var observers: [NSObjectProtocol] = []

    init() {
        demo = CommandLine.arguments.contains("--demo")
        store = demo ? nil : CodeStore(service: CommandLine.arguments.contains("--test-ui") ? "io.github.ammarshah1n.codebar.ui-test" : "io.github.ammarshah1n.codebar")
        reload()
        let ws = NSWorkspace.shared.notificationCenter
        for n in [NSWorkspace.willSleepNotification, NSWorkspace.sessionDidResignActiveNotification,
                  NSWorkspace.screensDidSleepNotification] {
            observers.append(ws.addObserver(forName: n, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock(force: true) }
            })
        }
        observers.append(NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.lock(force: false) }
        })
    }

    var canImport: Bool { loaded && !demo && !locked }

    func reload() {
        if demo {
            // RFC test secrets only. Demo mode never opens the real Keychain store.
            accounts = ["GitHub", "Google", "Cloudflare"].enumerated().map { index, issuer in
                OTPAccount(id: UUID(), name: "hello@example.com", issuer: issuer,
                           secret: Data("12345678901234567890\(index)".utf8),
                           algorithm: "SHA1", digits: 6, period: 30)
            }
            loaded = true; locked = false; error = nil
            return
        }
        do {
            accounts = try store!.load()
            loaded = true; locked = false; error = nil
        } catch {
            accounts = []; loaded = false; locked = true
            self.error = "Could not read the Keychain store. Nothing was changed. (\(error.localizedDescription))"
        }
    }

    /// Auto-lock never fires while the import sheet or a file dialog is active (unless sleep/session loss).
    func lock(force: Bool) {
        if !force && (showImport || dialogActive) { return }
        if force { showImport = false }
        accounts = []
        locked = true
    }

    func save(_ incoming: [OTPAccount]) throws -> Int {
        guard canImport, let store else { throw ImportFailure.msg("Import is unavailable.") }
        let n = try store.merge(incoming)
        accounts = try store.load()
        return n
    }

    func copy(_ code: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(code, forType: .string)
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        clipboardCount = count
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard self?.clipboardCount == count, NSPasteboard.general.changeCount == count else { return }
            NSPasteboard.general.clearContents()
        }
    }
}

enum ImportFailure: LocalizedError {
    case msg(String)
    var errorDescription: String? { if case .msg(let s) = self { return s }; return nil }
}

// MARK: - App

@main
struct CodebarApp: App {
    @StateObject private var model: Model

    init() {
        if CommandLine.arguments.contains("--self-test") {
            do { try runSelfTests(); print("self-test: pass"); exit(0) }
            catch { print("self-test: error"); exit(1) }
        }
        _model = StateObject(wrappedValue: Model())
    }

    var body: some Scene {
        WindowGroup("Codebar") {
            ContentView().environmentObject(model).frame(minWidth: 560, minHeight: 400)
        }.defaultSize(width: 620, height: 440)
    }
}

// MARK: - Main view

struct ContentView: View {
    @EnvironmentObject var model: Model
    @State private var search = ""

    var filtered: [OTPAccount] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let list = model.accounts.sorted { ($0.issuer + $0.name).lowercased() < ($1.issuer + $1.name).lowercased() }
        return q.isEmpty ? list : list.filter { ($0.issuer + " " + $0.name).lowercased().contains(q) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Search", text: $search).textFieldStyle(.roundedBorder).disabled(model.locked)
                if model.locked {
                    Button("Unlock") { model.reload() }
                } else {
                    Button("Lock") { model.lock(force: true) }
                }
                Button("Import…") { model.showImport = true }.disabled(!model.canImport)
            }.padding(10)
            if model.demo { Text("DEMO MODE — synthetic data, nothing saved").font(.caption).foregroundColor(.orange) }
            if CommandLine.arguments.contains("--test-ui") { Text("TEST STORE — separate from your accounts").font(.caption).foregroundColor(.orange) }
            if let e = model.error {
                Text(e).foregroundColor(.red).padding(10).frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            if model.locked {
                Spacer(); Text("Locked").font(.title2).foregroundColor(.secondary); Spacer()
            } else if filtered.isEmpty {
                Spacer()
                Text(model.accounts.isEmpty ? "No accounts. Use Import… to add them." : "No matches.")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    List(filtered) { a in AccountRow(account: a, date: ctx.date) }
                }
            }
        }
        .sheet(isPresented: $model.showImport) { ImportSheet().environmentObject(model) }
    }
}

struct AccountRow: View {
    @EnvironmentObject var model: Model
    let account: OTPAccount
    let date: Date

    var body: some View {
        let code = account.code(at: date)
        let period = max(account.period, 1)
        let remaining = period - Int(date.timeIntervalSince1970) % period
        let h = code.count / 2
        let shown = code.count % 2 == 0 && code.count > 4 ? String(code.prefix(h)) + " " + String(code.dropFirst(h)) : code
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(account.issuer.isEmpty ? account.name : account.issuer).font(.headline)
                if !account.issuer.isEmpty { Text(account.name).font(.subheadline).foregroundColor(.secondary) }
            }
            Spacer()
            Text(shown).font(.system(size: 30, weight: .medium, design: .monospaced))
                .foregroundColor(remaining <= 5 ? .red : .primary)
            Text("\(remaining)s").font(.system(.body, design: .monospaced)).foregroundColor(.secondary)
                .frame(width: 36, alignment: .trailing)
            Button("Copy") { model.copy(code) }
        }.padding(.vertical, 6)
    }
}

// MARK: - Import

struct ImportSheet: View {
    @EnvironmentObject var model: Model
    @Environment(\.dismiss) var dismiss
    @State private var text = ""
    @State private var transfer: Transfer?
    @State private var error: String?
    @State private var status: String?
    @State private var saved = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("One-time import from Google Authenticator").font(.title3.bold())
            Text("""
            1. In Google Authenticator on your phone: Menu > Transfer accounts > Export accounts.
            2. Screenshot or photograph each QR code. Import EVERY QR — large exports are split into several.
            3. Add them here one image at a time (or paste the transfer link).
            Your phone is not changed and there is no ongoing Google sync; this is a copy stored in this Mac's Keychain.
            QR images contain your secrets. Keep them local, never send them in chat, and remove temporary copies after import.
            """).font(.callout).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Choose QR image…") { pickImage() }
                Button("Paste image") { pasteImage() }
            }
            HStack {
                SecureField("Or paste otpauth-migration:// text", text: $text)
                Button("Read text") { readText() }.disabled(text.isEmpty)
            }
            if let error { Text(error).foregroundColor(.red).fixedSize(horizontal: false, vertical: true) }
            if let status { Text(status).foregroundColor(.green).fixedSize(horizontal: false, vertical: true) }
            if let t = transfer {
                Divider()
                Text("QR \(t.batchIndex + 1) of \(t.batchSize) — \(t.accounts.count) account(s):").bold()
                ScrollView {
                    VStack(alignment: .leading) {
                        ForEach(t.accounts) { a in
                            Text(a.issuer.isEmpty ? a.name : "\(a.issuer) — \(a.name)")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(maxHeight: 140)
                if t.batchSize > 1 { Text("Remember to import the other \(t.batchSize - 1) QR code(s) too.").font(.callout) }
                Button("Save to Keychain") { save(t) }.disabled(saved)
            }
            HStack { Spacer(); Button("Close") { dismiss() }.keyboardShortcut(.cancelAction) }
        }
        .padding(20).frame(width: 520)
        .onDisappear { text = "" }
    }

    private func reset() { error = nil; status = nil; transfer = nil; saved = false }

    private func pickImage() {
        reset()
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.png, .jpeg]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        model.dialogActive = true
        let r = panel.runModal()
        model.dialogActive = false
        guard r == .OK, let url = panel.url else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil),
              let img = CGImageSourceCreateThumbnailAtIndex(src, 0, [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceThumbnailMaxPixelSize: 4096,
                kCGImageSourceCreateThumbnailWithTransform: true
              ] as CFDictionary) else {
            error = "Could not read that image."; return
        }
        decode(img)
    }

    private func pasteImage() {
        reset()
        guard let img = (NSPasteboard.general.readObjects(forClasses: [NSImage.self]) as? [NSImage])?.first,
              let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            error = "No image on the clipboard."; return
        }
        decode(cg)
    }

    private func decode(_ img: CGImage) {
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr]
        do { try VNImageRequestHandler(cgImage: img, options: [:]).perform([req]) }
        catch { self.error = "QR detection failed: \(error.localizedDescription)"; return }
        let payloads = (req.results ?? []).compactMap { $0.payloadStringValue }
        switch payloads.count {
        case 0: error = "No QR code found. Use a sharp, full-size screenshot with one QR code."
        case 1: parse(payloads[0])
        default: error = "Found \(payloads.count) QR codes in this image. Crop or screenshot ONE QR code at a time and try again. Nothing was imported."
        }
    }

    private func readText() {
        reset()
        parse(text.trimmingCharacters(in: .whitespacesAndNewlines))
        text = ""
    }

    private func parse(_ s: String) {
        do {
            let t = try Importer.parse(s)
            if t.accounts.isEmpty { error = "That QR contains no accounts."; return }
            transfer = t
        } catch {
            self.error = "Not a valid Google Authenticator export: \(error.localizedDescription)"
        }
    }

    private func save(_ t: Transfer) {
        do {
            let n = try model.save(t.accounts)
            saved = true
            status = "Saved \(n) new account(s). Duplicates skipped."
            error = nil
        } catch {
            self.error = "Could not finish saving or reloading. Reopen the app before retrying; duplicate imports are safe. (\(error.localizedDescription))"
        }
    }
}
