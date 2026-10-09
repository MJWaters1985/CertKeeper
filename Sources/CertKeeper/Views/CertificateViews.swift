import AppKit
import CertKeeperCore
import SwiftUI

struct CertificateDetailView: View {
    @Environment(AppModel.self) private var model
    let certID: UUID
    @State private var domainsText = ""
    @State private var editingDeployment: Deployment?
    @State private var confirmIssue = false

    private var index: Int? { model.inventory.certificates.firstIndex { $0.id == certID } }

    var body: some View {
        @Bindable var model = model
        if let i = index {
            let cert = model.inventory.certificates[i]
            Form {
                Section {
                    LabeledContent("Status") { StatusBadge(status: model.status(of: cert)) }
                    if let cur = cert.current {
                        LabeledContent("Expires", value: cur.notAfter.formatted(date: .long, time: .shortened))
                        LabeledContent("Issued by", value: cur.issuer)
                        LabeledContent("SHA-256") {
                            Text(cur.sha256).font(.caption.monospaced()).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                        }
                        if let issued = cert.lastIssued { LabeledContent("Last issued", value: issued.relative) }
                    }
                    if let err = cert.lastError {
                        Text(err).font(.caption).foregroundStyle(.red).textSelection(.enabled)
                    }
                }

                Section("Definition") {
                    TextField("Name", text: $model.inventory.certificates[i].name)
                    VStack(alignment: .leading) {
                        TextField("Domains", text: $domainsText, prompt: Text("example.com, *.example.com"), axis: .vertical)
                            .onSubmit(applyDomains)
                        HStack {
                            Text("Comma or newline separated. Wildcards use DNS-01 via Cloudflare.")
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Button("Apply", action: applyDomains).disabled(parse(domainsText) == cert.domains)
                        }
                    }
                    Picker("Key type", selection: $model.inventory.certificates[i].keyAlgorithm) {
                        ForEach(KeyAlgorithm.allCases) { Text($0.rawValue).tag($0) }
                    }
                    Toggle("Renew automatically", isOn: $model.inventory.certificates[i].autoRenew)
                    Stepper(value: Binding(
                        get: { cert.renewDaysBeforeExpiry ?? model.inventory.settings.renewDaysBeforeExpiry },
                        set: { model.inventory.certificates[i].renewDaysBeforeExpiry = $0 }
                    ), in: 1...60) {
                        LabeledContent("Renew when fewer than",
                                       value: "\(model.renewalWindow(for: cert)) days remain\(cert.renewDaysBeforeExpiry == nil ? " (default)" : "")")
                    }
                }

                Section {
                    let deployments = model.deployments(for: certID)
                    if deployments.isEmpty {
                        Text("Not deployed anywhere yet. Add a deployment, or adopt this certificate from a host's discovery results.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(deployments) { d in
                        DeploymentRow(deployment: d, showHost: true) { editingDeployment = d }
                    }
                } header: {
                    HStack {
                        Text("Deployments")
                        Spacer()
                        Button("Add Deployment", systemImage: "plus") {
                            editingDeployment = Deployment(certificateID: certID, hostID: model.inventory.hosts.first?.id ?? UUID(), kind: .nginx)
                        }
                        .disabled(model.inventory.hosts.isEmpty)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(cert.name)
            .onAppear { domainsText = cert.domains.joined(separator: ", ") }
            .toolbar {
                ToolbarItemGroup {
                    if model.busy.contains(certID) { ProgressView().controlSize(.small) }
                    Button(cert.current == nil ? "Issue" : "Renew Now", systemImage: "arrow.triangle.2.circlepath") {
                        if model.needsIssuance(cert) { Task { await model.issue(certID) } } else { confirmIssue = true }
                    }
                    .disabled(model.busy.contains(certID) || cert.domains.isEmpty)
                    Button("Deploy All", systemImage: "square.and.arrow.up.on.square") {
                        Task { for d in model.deployments(for: certID) where d.enabled { await model.deploy(d.id) } }
                    }
                    .disabled(cert.current == nil)
                    Button("Export…", systemImage: "square.and.arrow.down") { export(cert) }
                        .disabled(cert.current == nil)
                }
            }
            .confirmationDialog("This certificate is still valid for \(cert.current?.daysRemaining ?? 0) days.",
                                isPresented: $confirmIssue) {
                Button("Renew Anyway") { Task { await model.issue(certID) } }
            } message: {
                Text("Let's Encrypt rate-limits duplicate certificates (5 per week for the same names). Renew only if you need to.")
            }
            .sheet(item: $editingDeployment) { d in
                DeploymentEditor(deployment: d)
            }
        }
    }

    func parse(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " })
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }

    func applyDomains() {
        guard let i = index else { return }
        model.inventory.certificates[i].domains = parse(domainsText)
    }

    func export(_ cert: ManagedCertificate) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Export Here"
        panel.message = "Writes cert.pem, chain.pem, fullchain.pem and privkey.pem"
        guard panel.runModal() == .OK, let dir = panel.url else { return }
        do {
            try cert.leafPEM?.write(to: dir.appendingPathComponent("cert.pem"), atomically: true, encoding: .utf8)
            try cert.chainPEM?.write(to: dir.appendingPathComponent("chain.pem"), atomically: true, encoding: .utf8)
            try cert.fullchainPEM?.write(to: dir.appendingPathComponent("fullchain.pem"), atomically: true, encoding: .utf8)
            if let key = Keychain.get(.certificateKey(cert.id)) {
                let url = dir.appendingPathComponent("privkey.pem")
                try key.write(to: url, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
            model.log(.info, "Exported \(cert.name) to \(dir.path)")
        } catch {
            model.log(.error, "Export failed", detail: error.localizedDescription)
        }
    }
}

struct DeploymentRow: View {
    @Environment(AppModel.self) private var model
    let deployment: Deployment
    let showHost: Bool
    let onEdit: () -> Void

    var body: some View {
        let host = model.host(deployment.hostID)
        let cert = model.certificate(deployment.certificateID)
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(showHost ? "\(host?.name ?? "Unknown host") · \(deployment.kind.displayName)"
                              : "\(cert?.name ?? "Unknown certificate") · \(deployment.kind.displayName)")
                Group {
                    if deployment.kind.usesFilePaths && !deployment.certPath.isEmpty {
                        Text(deployment.certPath)
                    } else if !deployment.verifyEndpoint.isEmpty {
                        Text(deployment.verifyEndpoint)
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
                if let exp = deployment.deployedNotAfter {
                    Text("Serving cert expiring \(exp.formatted(date: .abbreviated, time: .omitted))\(deployment.lastChecked.map { " · checked \($0.relative)" } ?? "")")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            DeploymentStateBadge(deployment: deployment)
            Menu {
                Button("Deploy Now") { Task { await model.deploy(deployment.id) } }
                    .disabled(cert?.current == nil)
                Button("Check What's Live") { Task { await model.check(deployment.id, logResult: true) } }
                Button("Edit…", action: onEdit)
                Divider()
                Button("Remove", role: .destructive) { model.deleteDeployment(deployment.id) }
            } label: { Image(systemName: "ellipsis.circle") }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .disabled(model.busy.contains(deployment.id))
        }
        .contentShape(Rectangle())
        .onTapGesture(count: 2, perform: onEdit)
    }
}

struct DeploymentEditor: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State var deployment: Deployment
    @State private var customizeScript = false
    @State private var script = ""
    @State private var pfxPassword = ""
    @State private var saveError: String?

    var isNew: Bool { !model.inventory.deployments.contains { $0.id == deployment.id } }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Picker("Certificate", selection: $deployment.certificateID) {
                    ForEach(model.inventory.certificates) { Text($0.name).tag($0.id) }
                }
                Picker("Host", selection: $deployment.hostID) {
                    ForEach(model.inventory.hosts) { Text($0.name).tag($0.id) }
                }
                Picker("Target", selection: $deployment.kind) {
                    ForEach(DeploymentKind.allCases) { Text($0.displayName).tag($0) }
                }
                if deployment.kind == .pihole {
                    TextField("TLS file", text: $deployment.certPath, prompt: Text("/etc/pihole/tls.pem"))
                    Toggle("Set Pi-hole's web domain to \(model.certificate(deployment.certificateID)?.domains.first ?? "the certificate's first name")",
                           isOn: Binding(get: { deployment.flag(.piholeSetDomain) },
                                         set: { deployment.options[DeploymentOption.piholeSetDomain.rawValue] = $0 ? "true" : "false" }))
                    VStack(alignment: .leading) {
                        TextField("Docker container", text: option(.restartTarget), prompt: Text("Leave empty for a native install"))
                        Text("For a container, the TLS file is its path on the host.").font(.caption).foregroundStyle(.secondary)
                    }
                } else if deployment.kind.usesFilePaths {
                    TextField("Certificate file", text: $deployment.certPath, prompt: Text("/etc/ssl/certs/site.pem"))
                    if !deployment.isPKCS12 {
                    TextField("Private key file", text: $deployment.keyPath, prompt: Text("/etc/ssl/private/site.key"))
                    TextField("Chain file (optional)", text: $deployment.chainPath, prompt: Text("empty = full chain goes in the certificate file"))
                    }
                }
                if deployment.kind == .truenas {
                    Toggle("Use for the TrueNAS web UI", isOn: Binding(
                        get: { deployment.flag(.truenasUI) },
                        set: { deployment.options[DeploymentOption.truenasUI.rawValue] = $0 ? "true" : "false" }))
                    VStack(alignment: .leading) {
                        TextField("Catalog apps", text: option(.truenasApps), prompt: Text("nextcloud, minio"))
                        Text("Apps to point at this certificate. Apps already using an older copy of it are updated automatically. Requires TrueNAS 24.10 or later.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if deployment.kind == .containerApp {
                    Picker("File format", selection: option(.certFormat)) {
                        Text("PEM (certificate + key files)").tag("pem")
                        Text("PKCS#12 (.pfx, e.g. Jellyfin)").tag("pkcs12")
                    }
                    if deployment.isPKCS12 {
                        SecureField(".pfx password", text: $pfxPassword, prompt: Text("Optional — must match the app's setting; kept in the Keychain"))
                    }
                    VStack(alignment: .leading) {
                        TextField("Restart", text: option(.restartTarget), prompt: Text("systemd:unit.service, TrueNAS app, container or Compose project"))
                        Text("Leave empty to only install the files.").font(.caption).foregroundStyle(.secondary)
                    }
                    TextField("Reload command (optional)", text: option(.reloadCommand), prompt: Text("overrides the restart, e.g. docker exec proxy nginx -s reload"))
                }
                if deployment.kind == .nginx {
                    VStack(alignment: .leading) {
                        TextField("nginx config (-c)", text: option(.nginxConf), prompt: Text("Leave empty for the system nginx"))
                        TextField("nginx prefix (-p)", text: option(.nginxPrefix), prompt: Text("Optional"))
                        Text("For a separate nginx instance, such as a KVM's web UI. Discovery fills these in.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if deployment.kind.usesFilePaths {
                    TextField("File owner (optional)", text: option(.fileOwner), prompt: Text("user:group, e.g. 568:568 for TrueNAS apps"))
                }
                TextField("Verify TLS endpoint", text: $deployment.verifyEndpoint, prompt: Text("host.example.com:443 (optional)"))
                Toggle("Enabled", isOn: $deployment.enabled)
                Section {
                    Toggle("Customize install script", isOn: $customizeScript)
                    if customizeScript {
                        TextEditor(text: $script)
                            .font(.system(.caption, design: .monospaced))
                            .frame(minHeight: 260)
                        HStack {
                            Text("Runs with sh as \(model.host(deployment.hostID)?.username ?? "the SSH user"). Variables: $CERT $CHAIN $FULLCHAIN $KEY $TARGET_CERT $TARGET_KEY $TARGET_CHAIN $CERT_NAME $DOMAINS; helpers ck_install, ck_rollback.")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Reset") { script = DeployScripts.template(for: deployment.kind) }
                        }
                    }
                } footer: {
                    if !customizeScript {
                        Text(scriptSummary(deployment.kind)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            HStack {
                if let saveError { Text(saveError).font(.caption).foregroundStyle(.red) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(isNew ? "Add" : "Save", action: save).keyboardShortcut(.defaultAction)
                    .disabled(deployment.kind.usesFilePaths && deployment.kind != .custom && deployment.certPath.isEmpty
                              || deployment.kind == .containerApp && !deployment.isPKCS12 && deployment.keyPath.isEmpty
                              || deployment.kind == .truenas && !deployment.flag(.truenasUI) && deployment.truenasApps.isEmpty)
            }
            .padding()
        }
        .frame(width: 620, height: customizeScript ? 780 : 600)
        .onAppear {
            customizeScript = deployment.scriptOverride != nil
            pfxPassword = model.secret(.pfxPassword, for: deployment.id)
            script = deployment.scriptOverride ?? DeployScripts.template(for: deployment.kind)
        }
        .onChange(of: deployment.kind) { _, kind in
            if deployment.scriptOverride == nil { script = DeployScripts.template(for: kind) }
            if kind == .custom { customizeScript = true }
            if kind == .pihole && deployment.certPath.isEmpty { deployment.certPath = "/etc/pihole/tls.pem" }
        }
    }

    func option(_ key: DeploymentOption) -> Binding<String> {
        Binding(get: { deployment.options[key.rawValue] ?? key.defaultValue },
                set: { deployment.options[key.rawValue] = $0.trimmingCharacters(in: .whitespaces) })
    }

    func save() {
        do {
            try model.setSecret(deployment.isPKCS12 ? pfxPassword : "", .pfxPassword, for: deployment.id)
        } catch {
            saveError = error.localizedDescription
            return
        }
        deployment.options[DeploymentOption.pfxPassword.rawValue] = nil
        deployment.scriptOverride = customizeScript ? script : nil
        if let i = model.inventory.deployments.firstIndex(where: { $0.id == deployment.id }) {
            if model.inventory.deployments[i].certificateID != deployment.certificateID { deployment.deployedSHA256 = nil }
            model.inventory.deployments[i] = deployment
        } else {
            model.addDeployment(deployment)
            Task { await model.check(deployment.id) }
        }
        dismiss()
    }

    func scriptSummary(_ kind: DeploymentKind) -> String {
        switch kind {
        case .nginx: "Backs up and replaces the files, runs nginx -t (rolling back on failure), then reloads nginx."
        case .apache: "Backs up and replaces the files, runs apachectl -t (rolling back on failure), then reloads Apache."
        case .proxmox: "Installs as the node's custom certificate with pvenode cert set and restarts pveproxy."
        case .truenas: "Imports through midclt, assigns it to the web UI and/or catalog apps (apps still on an older copy are updated automatically), then deletes old copies nothing uses. Requires root or sudo."
        case .unifiOS: "Replaces unifi-core.crt/.key (auto-detected under /data/unifi-core/config) and restarts unifi-core."
        case .opnsense: "Imports into System › Trust (reusing the previous CertKeeper entry), assigns it to the web GUI and restarts it."
        case .pihole: "Writes the key and certificate chain into Pi-hole's TLS file, optionally sets webserver.domain, then restarts pihole-FTL (or the container)."
        case .containerApp: "Writes the certificate files (or a .pfx) the app reads, then restarts it: a systemd unit, TrueNAS app, Docker container or Compose project."
        case .custom: "Runs your script."
        }
    }
}

struct NewCertificateSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var domains = ""
    @State private var algorithm: KeyAlgorithm = .ecdsaP256
    let onCreate: (ManagedCertificate) -> Void

    var parsed: [String] {
        domains.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " })
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                TextField("Domains", text: $domains, prompt: Text("nas.example.com, *.lab.example.com"), axis: .vertical)
                TextField("Name", text: $name, prompt: Text(parsed.first ?? "Optional"))
                Picker("Key type", selection: $algorithm) {
                    ForEach(KeyAlgorithm.allCases) { Text($0.rawValue).tag($0) }
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Create") {
                    var c = ManagedCertificate(name: name.isEmpty ? parsed[0] : name, domains: parsed)
                    c.keyAlgorithm = algorithm
                    onCreate(c)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(parsed.isEmpty)
            }
            .padding()
        }
        .frame(width: 480, height: 260)
    }
}
