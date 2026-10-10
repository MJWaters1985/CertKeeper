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
                    LabeledContent("SSH", value: "\(host.username)@\(host.address):\(host.port)")
                    LabeledContent("Authentication", value: authDescription(host))
                    LabeledContent("Privilege", value: host.useSudo ? (model.hasHostPassword(hostID) ? "sudo (password if required)" : "sudo -n") : "direct")
                    if !host.notes.isEmpty { LabeledContent("System", value: host.notes) }
                    if let seen = host.lastSeen { LabeledContent("Last contact", value: seen.relative) }
                    if let connectionResult {
                        Text(connectionResult).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }

                Section {
                    if host.lastDiscovery.isEmpty {
                        Text("Run discovery to find nginx, Apache, Proxmox, TrueNAS, UniFi OS and OPNsense certificates on this host.")
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
                                editingDeployment = Deployment(certificateID: c.id, hostID: hostID, kind: .nginx)
                            }
                        }
                        .disabled(model.inventory.certificates.isEmpty)
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
                    Button("Edit", systemImage: "pencil") { editing = true }
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
                Label("Managed", systemImage: "checkmark").font(.caption).foregroundStyle(.green)
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
                        }
                    }
                }
                if !others.isEmpty {
                    Section("Doesn't cover all names") {
                        ForEach(others) { c in
                            Button("\(c.name) — \(describe(model.coverage(of: c, for: names)))") {
                                model.adopt(endpoint, hostID: hostID, target: .existing(c.id))
                            }
                        }
                    }
                }
                Divider()
                Button("New certificate for \(names.joined(separator: ", "))") {
                    model.adopt(endpoint, hostID: hostID, target: .new)
                }
                Button("Monitor only (renewed by something else)") {
                    model.adopt(endpoint, hostID: hostID, target: .monitor)
                }
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
        .help(automatic.map { "Click to deploy the managed certificate “\($0.name)” here. Use the menu to choose another." }
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
    @State private var password = ""
    @State private var hasStoredPassword = false
    @State private var removePassword = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            Form {
                TextField("Name", text: $host.name, prompt: Text("pve1"))
                TextField("Address", text: $host.address, prompt: Text("pve1.lan or an ~/.ssh/config alias"))
                TextField("Port", value: $host.port, format: .number.grouping(.never))
                TextField("Username", text: $host.username)
                HStack {
                    TextField("Identity file", text: $host.identityFile, prompt: Text("Optional — default uses ssh-agent"))
                    Button("Choose…") {
                        let panel = NSOpenPanel()
                        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
                        panel.showsHiddenFiles = true
                        if panel.runModal() == .OK, let url = panel.url { host.identityFile = url.path }
                    }
                }
                Section("Password") {
                    HStack {
                        SecureField("Password", text: $password,
                                    prompt: Text(hasStoredPassword && !removePassword ? "•••••••• (saved in Keychain)" : "Optional"))
                        if hasStoredPassword && !removePassword {
                            Button("Remove") { removePassword = true; password = "" }
                        }
                    }
                    Toggle("Allow password login", isOn: $host.passwordLogin)
                        .disabled(password.isEmpty && (!hasStoredPassword || removePassword))
                    Toggle("Use sudo for install commands", isOn: $host.useSudo)
                    Text("Keys are always tried first. The password is used for SSH login when allowed, and for sudo when the account doesn't have passwordless sudo. It's kept in your login Keychain. New host keys are trusted on first use and pinned in ~/.ssh/known_hosts.")
                        .font(.caption).foregroundStyle(.secondary)
                    if let error { Text(error).font(.caption).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    if host.name.isEmpty { host.name = host.address }
                    do {
                        if !password.isEmpty { try model.setHostPassword(password, for: host.id) }
                        else if removePassword { try model.setHostPassword(nil, for: host.id) }
                    } catch {
                        self.error = error.localizedDescription
                        return
                    }
                    if !model.hasHostPassword(host.id) { host.passwordLogin = false }
                    onSave(host)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(host.address.isEmpty)
            }
            .padding()
        }
        .frame(width: 540, height: 540)
        .onAppear { hasStoredPassword = model.hasHostPassword(host.id) }
    }
}
