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
        .frame(width: 540, height: 360)
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
            Text("Use staging until deployments work end to end — production has strict rate limits. Switching environments uses a separate ACME account and reissues on the next pass.")
                .font(.caption).foregroundStyle(.secondary)
            Toggle(isOn: $model.inventory.settings.acceptedTermsOfService) {
                HStack(spacing: 4) {
                    Text("I agree to the Let's Encrypt")
                    Link("Subscriber Agreement", destination: tosURL ?? URL(string: "https://letsencrypt.org/repository/")!)
                }
            }
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
                Button("Verify") { Task { await verify() } }
                    .disabled(!stored && token.isEmpty || working)
                if stored {
                    Button("Remove", role: .destructive) {
                        Keychain.delete(.cloudflareToken)
                        stored = false
                        status = "Removed."
                    }
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
            Stepper("Check every \(model.inventory.settings.checkIntervalHours) hours",
                    value: $model.inventory.settings.checkIntervalHours, in: 1...72)
            Toggle("Deploy automatically after renewal or drift", isOn: $model.inventory.settings.autoDeploy)
            Stepper("Wait up to \(model.inventory.settings.dnsPropagationTimeout)s for DNS propagation",
                    value: $model.inventory.settings.dnsPropagationTimeout, in: 60...1800, step: 60)
            Toggle("Open at login", isOn: $launchAtLogin)
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
