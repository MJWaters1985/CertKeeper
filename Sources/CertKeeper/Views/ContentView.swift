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
                    ForEach(model.sortedCertificates) { cert in
                        HStack {
                            Label(cert.name, systemImage: "checkmark.seal")
                            Spacer()
                            StatusBadge(status: model.status(of: cert), compact: true, monitored: cert.isMonitored)
                        }
                        .tag(SidebarItem.certificate(cert.id))
                        .contextMenu {
                            Button("Delete", role: .destructive) { model.deleteCertificate(cert.id) }
                        }
                    }
                }
                Section("Hosts") {
                    ForEach(model.sortedHosts) { host in
                        HStack {
                            Label(host.name, systemImage: "server.rack")
                            Spacer()
                            HostHealthIndicator(hostID: host.id)
                        }
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
    var monitored = false

    var body: some View {
        let (text, color): (String, Color) = switch status {
        case .notIssued: (monitored ? "Not checked yet" : "Not issued", .secondary)
        case .valid(let d): (compact ? "\(d)d" : (monitored ? "Monitored · \(d) days" : "Valid · \(d) days"), .green)
        case .renewDue(let d): (compact ? "\(d)d" : (monitored ? "Expiring · \(d) days" : "Renewal due · \(d) days"), .orange)
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
        } else {
            switch model.state(of: deployment) {
            case .disabled:
                Text("Disabled").font(.caption).foregroundStyle(.secondary)
            case .attention(let message):
                Label("Needs attention", systemImage: "exclamationmark.octagon.fill").font(.caption).foregroundStyle(.red)
                    .help(message)
            case .error(let message):
                Label("Error", systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.red)
                    .help(message)
            case .awaitingIssuance:
                Text("Awaiting issuance").font(.caption).foregroundStyle(.secondary)
            case .outOfDate:
                Label("Out of date", systemImage: "arrow.triangle.2.circlepath").font(.caption).foregroundStyle(.orange)
            case .incompleteChain:
                Label("Incomplete chain", systemImage: "link.badge.plus").font(.caption).foregroundStyle(.orange)
                    .help("\(deployment.verifyEndpoint) doesn't send the intermediate certificate. Browsers often cope, but curl, apps and some phones will reject it. Try Deploy Now.")
            case .current:
                Label("Current", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(.green)
            case .notCheckedYet:
                Text("Not checked yet").font(.caption).foregroundStyle(.secondary)
            case .watching(let days):
                Label("Monitored · \(days)d", systemImage: "eye.fill").font(.caption).foregroundStyle(.green)
                    .help(deployment.verifyEndpoint.isEmpty
                          ? "Renewed by another system; CertKeeper reads the certificate in use on the host."
                          : "Renewed by another system; CertKeeper watches what \(deployment.verifyEndpoint) serves.")
            case .expiringSoon(let days):
                Label("Expires in \(days)d", systemImage: "eye.trianglebadge.exclamationmark.fill").font(.caption).foregroundStyle(.orange)
                    .help("Monitored, not renewed by CertKeeper. The system that renews it seems to have stopped.")
            case .expired:
                Label("Expired", systemImage: "xmark.octagon.fill").font(.caption).foregroundStyle(.red)
            }
        }
    }
}

/// Sidebar indicator: whether every managed deployment on a host is current.
struct HostHealthIndicator: View {
    @Environment(AppModel.self) private var model
    let hostID: UUID

    var body: some View {
        let busy = model.busy.contains(hostID) || model.deployments(onHost: hostID).contains { model.busy.contains($0.id) }
        let health = model.health(ofHost: hostID)
        Group {
            if busy {
                ProgressView().controlSize(.mini)
            } else {
                switch health.level {
                case .unmanaged:
                    Image(systemName: "minus.circle").foregroundStyle(.tertiary)
                case .current:
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                case .pending:
                    Image(systemName: "clock.fill").foregroundStyle(.secondary)
                case .warning:
                    Image(systemName: "arrow.triangle.2.circlepath.circle.fill").foregroundStyle(.orange)
                case .problem:
                    Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                }
            }
        }
        .font(.callout)
        .help(busy ? "Working…" : health.summary)
        .accessibilityLabel(busy ? "Working" : health.summary)
    }
}

extension Date {
    var relative: String { formatted(.relative(presentation: .named)) }
}
