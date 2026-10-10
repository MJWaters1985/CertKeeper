import CertKeeperCore
import SwiftUI

enum SidebarItem: Hashable {
    case overview
    case certificate(UUID)
    case host(UUID)
    case activity
}

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: SidebarItem? = .overview
    @State private var showingAddHost = false
    @State private var showingAddCert = false

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Overview", systemImage: "square.grid.2x2").tag(SidebarItem.overview)
                Label("Activity", systemImage: "list.bullet.rectangle").tag(SidebarItem.activity)

                Section("Certificates") {
                    ForEach(model.inventory.certificates) { cert in
                        HStack {
                            Label(cert.name, systemImage: "checkmark.seal")
                            Spacer()
                            StatusBadge(status: model.status(of: cert), compact: true)
                        }
                        .tag(SidebarItem.certificate(cert.id))
                        .contextMenu {
                            Button("Delete", role: .destructive) { model.deleteCertificate(cert.id) }
                        }
                    }
                }
                Section("Hosts") {
                    ForEach(model.inventory.hosts) { host in
                        Label(host.name, systemImage: "server.rack")
                            .tag(SidebarItem.host(host.id))
                            .contextMenu {
                                Button("Delete", role: .destructive) { model.deleteHost(host.id) }
                            }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .toolbar {
                ToolbarItem {
                    Menu {
                        Button("New Certificate…") { showingAddCert = true }
                        Button("New Host…") { showingAddHost = true }
                    } label: { Label("Add", systemImage: "plus") }
                }
            }
        } detail: {
            switch selection {
            case .certificate(let id) where model.certificate(id) != nil:
                CertificateDetailView(certID: id).id(id)
            case .host(let id) where model.host(id) != nil:
                HostDetailView(hostID: id).id(id)
            case .activity:
                ActivityView()
            default:
                OverviewView(selection: $selection)
            }
        }
        .sheet(isPresented: $showingAddHost) {
            HostEditor(host: ManagedHost(name: "", address: "")) { host in
                model.addHost(host)
                selection = .host(host.id)
            }
            .environment(model)
        }
        .sheet(isPresented: $showingAddCert) {
            NewCertificateSheet { cert in
                model.addCertificate(cert)
                selection = .certificate(cert.id)
            }
        }
        .alert("Storage problem", isPresented: .constant(model.loadError != nil)) {
            Button("OK") { model.loadError = nil }
        } message: { Text(model.loadError ?? "") }
    }
}

// MARK: - Shared bits

struct StatusBadge: View {
    let status: AppModel.CertStatus
    var compact = false

    var body: some View {
        let (text, color): (String, Color) = switch status {
        case .notIssued: ("Not issued", .secondary)
        case .valid(let d): (compact ? "\(d)d" : "Valid · \(d) days", .green)
        case .renewDue(let d): (compact ? "\(d)d" : "Renewal due · \(d) days", .orange)
        case .expired: ("Expired", .red)
        case .domainsChanged: ("Names changed", .orange)
        }
        Text(text)
            .font(compact ? .caption2.monospacedDigit() : .caption.weight(.medium))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}

struct DeploymentStateBadge: View {
    @Environment(AppModel.self) private var model
    let deployment: Deployment

    var body: some View {
        if model.busy.contains(deployment.id) {
            ProgressView().controlSize(.small)
        } else if !deployment.enabled {
            Text("Disabled").font(.caption).foregroundStyle(.secondary)
        } else if let attention = deployment.attention {
            Label("Needs attention", systemImage: "exclamationmark.octagon.fill").font(.caption).foregroundStyle(.red)
                .help(attention)
        } else if deployment.lastError != nil {
            Label("Error", systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.red)
                .help(deployment.lastError ?? "")
        } else if model.certificate(deployment.certificateID)?.current == nil {
            Text("Awaiting issuance").font(.caption).foregroundStyle(.secondary)
        } else if model.needsDeployment(deployment) {
            Label("Out of date", systemImage: "arrow.triangle.2.circlepath").font(.caption).foregroundStyle(.orange)
        } else if deployment.servedChainComplete == false {
            Label("Incomplete chain", systemImage: "link.badge.plus").font(.caption).foregroundStyle(.orange)
                .help("\(deployment.verifyEndpoint) doesn't send the intermediate certificate. Browsers often cope, but curl, apps and some phones will reject it. Try Deploy Now.")
        } else {
            Label("Current", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(.green)
        }
    }
}

extension Date {
    var relative: String { formatted(.relative(presentation: .named)) }
}
