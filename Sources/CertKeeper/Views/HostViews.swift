import CertKeeperCore
import SwiftUI

struct HostDetailView: View {
    @Environment(AppModel.self) private var model
    let hostID: UUID
    @State private var editing = false
    @State private var connectionResult: String?
    @State private var testing = false
    @State private var editingDeployment: Deployment?

    var body: some View {
        if let host = model.host(hostID) {
            Form {
                Section {
                    if host.isDeviceAPI {
                        LabeledContent("Device API", value: "https://\(host.address)\(host.port == 443 ? "" : ":\(host.port)")")
                        LabeledContent("API token", value: model.hasHostPassword(hostID) ? "Saved in Keychain" : "Not set")
                        LabeledContent("Pinned certificate", value: host.apiPinnedSHA256.isEmpty
                                       ? "None (only certificates this Mac trusts)"
                                       : DeviceAPI.formatFingerprint(host.apiPinnedSHA256))
                    } else {
                        LabeledContent("SSH", value: "\(host.username)@\(host.address):\(host.port)")
                        LabeledContent("Authentication", value: authDescription(host))
                        LabeledContent("Privilege", value: host.useSudo ? (model.hasHostPassword(hostID) ? "sudo (password if required)" : "sudo -n") : "direct")
                    }
                    if !host.notes.isEmpty { LabeledContent("System", value: host.notes) }
                    if let seen = host.lastSeen { LabeledContent("Last contact", value: seen.relative) }
                    if let connectionResult {
                        Text(connectionResult).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }

                Section {
                    if host.lastDiscovery.isEmpty {
                        Text(host.isDeviceAPI
                             ? "Run discovery to read the certificate the device's web interface is serving."
                             : "Run discovery to find nginx, Apache, Proxmox, TrueNAS, UniFi OS and OPNsense certificates on this host.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(host.lastDiscovery) { ep in
                        DiscoveredRow(endpoint: ep, hostID: hostID)
                    }
                } header: {
                    HStack {
                        Text("Discovered certificates")
                        Spacer()
                        if model.busy.contains(hostID) { ProgressView().controlSize(.small) }
                        Button("Discover", systemImage: "magnifyingglass") { Task { await model.discover(hostID) } }
                            .disabled(model.busy.contains(hostID))
                            .help(host.isDeviceAPI ? "Ask the device which certificate it serves" : "Scan this host over SSH for certificates in use by its services")
                    }
                }

                Section {
                    let deps = model.deployments(onHost: hostID)
                    if deps.isEmpty { Text("Nothing managed on this host yet.").foregroundStyle(.secondary) }
                    ForEach(deps) { d in DeploymentRow(deployment: d, showHost: false) { editingDeployment = d } }
                } header: {
                    HStack {
                        Text("Managed deployments")
                        Spacer()
                        Button("Add Deployment", systemImage: "plus") {
                            if let c = model.inventory.certificates.first {
                                editingDeployment = Deployment(certificateID: c.id, hostID: hostID, kind: host.isDeviceAPI ? .deviceAPI : .nginx)
                            }
                        }
                        .disabled(model.inventory.certificates.isEmpty)
                        .help("Install one of your certificates on this host")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(host.name)
            .toolbar {
                ToolbarItemGroup {
                    Button("Test Connection", systemImage: "bolt.horizontal") {
                        testing = true
                        Task {
                            connectionResult = await model.testConnection(hostID)
                            testing = false
                        }
                    }
                    .disabled(testing)
                    .help(host.isDeviceAPI ? "Call the device's API with the saved token" : "Connect over SSH and report the user and system")
                    Button("Edit", systemImage: "pencil") { editing = true }
                        .help("Change this host's address, login and sudo settings")
                }
            }
            .sheet(isPresented: $editing) {
                HostEditor(host: host) { updated in
                    if let i = model.inventory.hosts.firstIndex(where: { $0.id == updated.id }) {
                        model.inventory.hosts[i] = updated
                    }
                }
                .environment(model)
            }
            .sheet(item: $editingDeployment) { DeploymentEditor(deployment: $0) }
        }
    }
}

func authDescription(_ host: ManagedHost) -> String {
    let key = host.identityFile.isEmpty ? "ssh-agent / ~/.ssh/config keys" : host.identityFile
    return host.passwordLogin ? "\(key), then password" : key
}

struct DiscoveredRow: View {
    @Environment(AppModel.self) private var model
    let endpoint: DiscoveredEndpoint
    let hostID: UUID

    var adopted: Bool { model.isManaged(endpoint, hostID: hostID) }

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(endpoint.kind.displayName)\(endpoint.label.isEmpty ? "" : " — \(endpoint.label)")")
                if !endpoint.certPath.isEmpty { Text(endpoint.certPath).font(.caption).foregroundStyle(.secondary) }
                if let s = endpoint.summary {
                    Text("\(s.dnsNames.joined(separator: ", ")) · expires \(s.notAfter.formatted(date: .abbreviated, time: .omitted)) · \(s.issuer)")
                        .font(.caption).foregroundStyle(s.daysRemaining < 30 ? .orange : .secondary)
                        .lineLimit(2)
                } else {
                    Text("Could not read certificate").font(.caption).foregroundStyle(.red)
                }
                if let note = endpoint.note {
                    Label(note, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if adopted {
                let monitored = model.deployments(onHost: hostID).contains { d in
                    d.kind == endpoint.kind && model.certificate(d.certificateID)?.isMonitored == true
                }
                Label(monitored ? "Monitored" : "Managed", systemImage: monitored ? "eye" : "checkmark")
                    .font(.caption).foregroundStyle(monitored ? Color.purple : Color.green)
            } else {
                AdoptControl(endpoint: endpoint, hostID: hostID)
            }
        }
    }
}

/// "Adopt" button that says which certificate it will use, with a menu to pick another.
struct AdoptControl: View {
    @Environment(AppModel.self) private var model
    let endpoint: DiscoveredEndpoint
    let hostID: UUID

    var body: some View {
        let names = AppModel.dnsNames(of: endpoint)
        let automatic = model.automaticAdoptionTarget(for: endpoint)
        let candidates = model.adoptionCandidates(for: endpoint)
        let others = model.inventory.certificates.filter { c in !candidates.contains { $0.id == c.id } }

        VStack(alignment: .trailing, spacing: 2) {
            Menu {
                if !candidates.isEmpty {
                    Section("Covers all names") {
                        ForEach(candidates) { c in
                            Button("\(c.name) — \(describe(model.coverage(of: c, for: names)))") {
                                model.adopt(endpoint, hostID: hostID, target: .existing(c.id))
                            }
                            .help("Deploy \(c.name) here")
                        }
                    }
                }
                if !others.isEmpty {
                    Section("Doesn't cover all names") {
                        ForEach(others) { c in
                            Button("\(c.name) — \(describe(model.coverage(of: c, for: names)))") {
                                model.adopt(endpoint, hostID: hostID, target: .existing(c.id))
                            }
                            .help("Deploy \(c.name) here, although it doesn't cover every name this service uses")
                        }
                    }
                }
                Divider()
                Button("New certificate for \(names.joined(separator: ", "))") {
                    model.adopt(endpoint, hostID: hostID, target: .new)
                }
                .help("Create a managed certificate with these names and deploy it here")
                Button("Monitor only (renewed by something else)") {
                    model.adopt(endpoint, hostID: hostID, target: .monitor)
                }
                .help("Watch this certificate's expiry without CertKeeper renewing or deploying it")
            } label: {
                Text(monitorSuggested ? "Monitor" : "Adopt")
            } primaryAction: {
                model.adopt(endpoint, hostID: hostID, target: monitorSuggested ? .monitor : .automatic)
            }
            .menuStyle(.button)
            .fixedSize()
            .disabled(names.isEmpty)

            Text(monitorSuggested ? "renewed by the device itself" : (automatic.map { "uses \($0.name)" } ?? "creates a new certificate"))
                .font(.caption2).foregroundStyle(.secondary)
        }
        .help(monitorSuggested
              ? "Click to monitor this certificate, which the device renews itself. Use the menu for other options."
              : automatic.map { "Click to deploy the managed certificate “\($0.name)” here. Use the menu to choose another." }
                ?? "No managed certificate covers these names — clicking creates one. Use the menu to attach an existing one instead.")
    }

    /// The device renews this certificate itself (e.g. UniFi OS's own ACME client), so watch it rather
    /// than deploy over it.
    var monitorSuggested: Bool { endpoint.options?["monitor_suggested"] == "true" }

    func describe(_ coverage: AppModel.Coverage) -> String {
        switch coverage {
        case .exact: "same names"
        case .covers(let extra): extra == 0 ? "covers by wildcard" : "covers, plus \(extra) more name\(extra == 1 ? "" : "s")"
        case .missing(let names): "missing \(names.joined(separator: ", "))"
        }
    }
}

struct HostEditor: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppModel.self) private var model
    @State var host: ManagedHost
    let onSave: (ManagedHost) -> Void
    /// The SSH password, or a Device API host's API token (both stored as the host's Keychain password).
    @State private var password = ""
    @State private var hasStoredPassword = false
    @State private var removePassword = false
    @State private var error: String?
    @State private var fetchedFingerprint: String?
    @State private var fetching = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Picker("Connection", selection: $host.connection) {
                    ForEach(HostConnection.allCases) { Text($0.displayName).tag($0) }
                }
                .help("SSH for servers; Device API for devices that install certificates through their own HTTPS API")
                .onChange(of: host.connection) { _, new in
                    if new == .deviceAPI && host.port == 22 { host.port = 443 }
                    if new == .ssh && host.port == 443 { host.port = 22 }
                }
                TextField("Name", text: $host.name, prompt: Text(host.isDeviceAPI ? "amoled" : "pve1"))
                TextField("Address", text: $host.address,
                          prompt: Text(host.isDeviceAPI ? "amoled.example.com (the name on its certificate)" : "pve1.lan or an ~/.ssh/config alias"))
                TextField("Port", value: $host.port, format: .number.grouping(.never))
                if host.isDeviceAPI {
                    deviceAPISections
                } else {
                    sshSections
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                    .help("Close without saving changes")
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(host.address.isEmpty)
                    .help(host.isDeviceAPI ? "Save this device; a token you typed goes to the Keychain"
                                           : "Save this host; a password you typed goes to the Keychain")
            }
            .padding()
        }
        .frame(width: 560, height: 600)
        .onAppear { hasStoredPassword = model.hasHostPassword(host.id) }
    }

    private func save() {
        if host.name.isEmpty { host.name = host.address }
        do {
            if !password.isEmpty { try model.setHostPassword(password, for: host.id) }
            else if removePassword { try model.setHostPassword(nil, for: host.id) }
        } catch {
            self.error = error.localizedDescription
            return
        }
        if !model.hasHostPassword(host.id) { host.passwordLogin = false }
        if host.isDeviceAPI {
            host.passwordLogin = false
            host.useSudo = false
            host.apiPinnedSHA256 = DeviceAPI.normalizeFingerprint(host.apiPinnedSHA256)
        }
        onSave(host)
        dismiss()
    }

    private var secretPrompt: String {
        hasStoredPassword && !removePassword ? "•••••••• (saved in Keychain)" : (host.isDeviceAPI ? "ckd_… from the device's web settings" : "Optional")
    }

    @ViewBuilder private var secretField: some View {
        HStack {
            SecureField(host.isDeviceAPI ? "Token" : "Password", text: $password, prompt: Text(secretPrompt))
            if hasStoredPassword && !removePassword {
                Button("Remove") { removePassword = true; password = "" }
                    .help("Delete the saved secret from the Keychain when you save")
            }
        }
    }

    @ViewBuilder private var sshSections: some View {
        TextField("Username", text: $host.username)
        HStack {
            TextField("Identity file", text: $host.identityFile, prompt: Text("Optional — default uses ssh-agent"))
            Button("Choose…") {
                let panel = NSOpenPanel()
                panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
                panel.showsHiddenFiles = true
                if panel.runModal() == .OK, let url = panel.url { host.identityFile = url.path }
            }
            .help("Pick an SSH private key file")
        }
        Section("Password") {
            secretField
            Toggle("Allow password login", isOn: $host.passwordLogin)
                .disabled(password.isEmpty && (!hasStoredPassword || removePassword))
                .help("Log in with the saved password if key authentication fails")
            Toggle("Use sudo for install commands", isOn: $host.useSudo)
                .help("Run discovery and installs as root through sudo, using the saved password if needed")
            Text("Keys are always tried first. The password is used for SSH login when allowed, and for sudo when the account doesn't have passwordless sudo. It's kept in your login Keychain. New host keys are trusted on first use and pinned in ~/.ssh/known_hosts.")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
        }
    }

    @ViewBuilder private var deviceAPISections: some View {
        Section("API token") {
            secretField
            Text("Create the token in the device's web settings under Security › API token. It can only read and replace the HTTPS certificate, and it's kept in your login Keychain.")
                .font(.caption).foregroundStyle(.secondary)
        }
        Section("Certificate pinning") {
            HStack {
                TextField("SHA-256", text: $host.apiPinnedSHA256, prompt: Text("Fingerprint of the device's self-signed certificate"))
                    .font(.body.monospaced())
                Button(fetching ? "Fetching…" : "Fetch") {
                    fetching = true
                    error = nil
                    Task {
                        do { fetchedFingerprint = try await model.fetchFingerprint(address: host.address, port: host.port) }
                        catch { self.error = error.localizedDescription }
                        fetching = false
                    }
                }
                .disabled(host.address.isEmpty || fetching)
                .help("Read the fingerprint of the certificate the device presents now")
            }
            if let fetchedFingerprint {
                VStack(alignment: .leading, spacing: 6) {
                    Text("The device presents:").font(.caption)
                    Text(DeviceAPI.formatFingerprint(fetchedFingerprint)).font(.caption.monospaced()).textSelection(.enabled)
                    Text("Only pin it if it matches the SHA-256 shown in the device's web settings (Security › HTTPS certificate).")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Pin This Fingerprint") { host.apiPinnedSHA256 = fetchedFingerprint }
                        .help("Trust this self-signed certificate for this device")
                }
            }
            Text("Until a trusted certificate is installed the device serves a self-signed one. CertKeeper only sends the token and private keys to a certificate this Mac trusts or to the pinned one.")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
        }
    }
}
