import CertKeeperCore
import ServiceManagement
import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            ACMESettings().tabItem { Label("Let's Encrypt", systemImage: "checkmark.seal") }
            CloudflareSettings().tabItem { Label("Cloudflare", systemImage: "cloud") }
            ScheduleSettings().tabItem { Label("Schedule", systemImage: "clock") }
        }
        .frame(width: 540, height: 400)
    }
}

struct ACMESettings: View {
    @Environment(AppModel.self) private var model
    @State private var tosURL: URL?

    var body: some View {
        @Bindable var model = model
        Form {
            TextField("Account email", text: $model.inventory.settings.acmeEmail, prompt: Text("you@example.com"))
            Picker("Environment", selection: $model.inventory.settings.useStaging) {
                Text("Staging (untrusted test certificates)").tag(true)
                Text("Production").tag(false)
            }
            .help("Staging issues untrusted test certificates with generous limits; production issues real ones")
            Text("Use staging until deployments work end to end — production has strict rate limits. Switching environments uses a separate ACME account and reissues on the next pass.")
                .font(.caption).foregroundStyle(.secondary)
            Toggle(isOn: $model.inventory.settings.acceptedTermsOfService) {
                HStack(spacing: 4) {
                    Text("I agree to the Let's Encrypt")
                    Link("Subscriber Agreement", destination: tosURL ?? URL(string: "https://letsencrypt.org/repository/")!)
                        .help("Open the Let's Encrypt Subscriber Agreement in your browser")
                }
            }
            .help("Let's Encrypt requires agreeing to its Subscriber Agreement before issuing certificates")
            LabeledContent("Account") {
                Text(model.inventory.acmeAccounts[model.inventory.settings.directoryURL.absoluteString] ?? "Created on first issuance")
                    .font(.caption).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
            }
        }
        .formStyle(.grouped)
        .task {
            if let key = Keychain.get(.acmeAccountKey) ?? Optional(ACMEClient.newAccountKeyPEM()),
               let client = try? ACMEClient(directoryURL: model.inventory.settings.directoryURL, accountKeyPEM: key, accountURL: nil) {
                tosURL = try? await client.termsOfService()
            }
        }
    }
}

struct CloudflareSettings: View {
    @State private var token = ""
    @State private var stored = Keychain.get(.cloudflareToken) != nil
    @State private var status: String?
    @State private var working = false

    var body: some View {
        Form {
            SecureField("API token", text: $token, prompt: Text(stored ? "•••••••• (saved in Keychain)" : "Paste token"))
            Text("Create a scoped API token with **Zone › Zone › Read** and **Zone › DNS › Edit** for the zones you'll issue certificates in. The token is stored only in your login Keychain.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Save") {
                    do {
                        try Keychain.set(token.trimmingCharacters(in: .whitespacesAndNewlines), for: .cloudflareToken)
                        token = ""
                        stored = true
                        status = "Saved."
                    } catch { status = error.localizedDescription }
                }
                .disabled(token.isEmpty)
                .help("Store this token in your login Keychain")
                Button("Verify") { Task { await verify() } }
                    .disabled(!stored && token.isEmpty || working)
                    .help("Check the token with Cloudflare and list the zones it can access")
                if stored {
                    Button("Remove", role: .destructive) {
                        Keychain.delete(.cloudflareToken)
                        stored = false
                        status = "Removed."
                    }
                    .help("Delete the saved token from the Keychain")
                }
                if working { ProgressView().controlSize(.small) }
            }
            if let status { Text(status).font(.caption).textSelection(.enabled) }
        }
        .formStyle(.grouped)
    }

    func verify() async {
        working = true
        defer { working = false }
        let t = token.isEmpty ? (Keychain.get(.cloudflareToken) ?? "") : token
        let client = CloudflareClient(token: t)
        do {
            let v = try await client.verifyToken()
            let owner = v.accountName.map { " (account token for \($0))" } ?? ""
            status = "Token is \(v.status)\(owner). Zones: \(v.zones.map(\.name).joined(separator: ", "))"
        } catch {
            status = error.localizedDescription
        }
    }
}

struct ScheduleSettings: View {
    @Environment(AppModel.self) private var model
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?

    var body: some View {
        @Bindable var model = model
        Form {
            Stepper("Renew when fewer than \(model.inventory.settings.renewDaysBeforeExpiry) days remain",
                    value: $model.inventory.settings.renewDaysBeforeExpiry, in: 1...60)
                .help("Default renewal window; each certificate can override it")
            Stepper("Check every \(model.inventory.settings.checkIntervalHours) hours",
                    value: $model.inventory.settings.checkIntervalHours, in: 1...72)
                .help("How often the automatic rotation pass runs while CertKeeper is open")
            Toggle("Deploy automatically after renewal or drift", isOn: $model.inventory.settings.autoDeploy)
                .help("Install renewed certificates, and fix deployments serving the wrong one, without asking")
            Stepper("Wait up to \(model.inventory.settings.dnsPropagationTimeout)s for DNS propagation",
                    value: $model.inventory.settings.dnsPropagationTimeout, in: 60...1800, step: 60)
                .help("How long to wait for Cloudflare's challenge record to appear in public DNS before giving up")
            LabeledContent("Keep activity for") {
                HStack(spacing: 6) {
                    TextField("", value: Binding(
                        get: { model.inventory.settings.effectiveLogRetentionDays },
                        set: { model.inventory.settings.logRetentionDays = min(max($0, AppSettings.logRetentionRange.lowerBound),
                                                                                AppSettings.logRetentionRange.upperBound) }
                    ), format: .number)
                    .multilineTextAlignment(.trailing)
                    .frame(width: 56)
                    .help("Days to keep activity log entries (1–365)")
                    Stepper("", value: Binding(
                        get: { model.inventory.settings.effectiveLogRetentionDays },
                        set: { model.inventory.settings.logRetentionDays = $0 }
                    ), in: AppSettings.logRetentionRange)
                    .labelsHidden()
                    .help("Keep activity log entries for more or fewer days")
                    Text(model.inventory.settings.effectiveLogRetentionDays == 1 ? "day" : "days")
                }
            }
            .onChange(of: model.inventory.settings.logRetentionDays) { _, _ in model.pruneLog() }
            Toggle("Open at login", isOn: $launchAtLogin)
                .help("Start CertKeeper when you log in, so rotation keeps running")
                .onChange(of: launchAtLogin) { _, on in
                    do {
                        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                        loginError = nil
                    } catch {
                        loginError = error.localizedDescription
                    }
                }
            if let loginError { Text(loginError).font(.caption).foregroundStyle(.red) }
            Text("Rotation runs while CertKeeper is open (it stays in the menu bar when the window is closed).")
                .font(.caption).foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
    }
}
