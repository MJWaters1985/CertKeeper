import CertKeeperCore
import SwiftUI

struct OverviewView: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: SidebarItem?

    var body: some View {
        let certs = model.inventory.certificates
        let deps = model.inventory.deployments
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if !model.inventory.settings.acceptedTermsOfService || Keychain.get(.cloudflareToken) == nil {
                    SetupBanner()
                }
                HStack(spacing: 12) {
                    Tile(title: "Certificates", value: "\(certs.count)", systemImage: "checkmark.seal")
                    Tile(title: "Need renewal", value: "\(certs.filter(model.needsIssuance).count)",
                         systemImage: "clock.badge.exclamationmark", tint: certs.contains(where: model.needsIssuance) ? .orange : nil)
                    Tile(title: "Deployments", value: "\(deps.count)", systemImage: "shippingbox")
                    Tile(title: "Out of date", value: "\(deps.filter(model.needsDeployment).count)",
                         systemImage: "arrow.triangle.2.circlepath", tint: deps.contains(where: model.needsDeployment) ? .orange : nil)
                    Tile(title: "Hosts", value: "\(model.inventory.hosts.count)", systemImage: "server.rack")
                }

                HStack {
                    Text("Expiry timeline").font(.headline)
                    Spacer()
                    if let last = model.lastMaintenance {
                        Text("Last pass \(last.relative)").font(.caption).foregroundStyle(.secondary)
                    }
                    Button {
                        Task { await model.runMaintenance() }
                    } label: {
                        Label(model.maintenanceRunning ? "Running…" : "Run Rotation Pass", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.maintenanceRunning)
                }

                if certs.isEmpty {
                    ContentUnavailableView("No certificates yet",
                                           systemImage: "checkmark.seal",
                                           description: Text("Add a host and run discovery to adopt existing certificates, or create a new certificate with +."))
                } else {
                    Table(certs.sorted { ($0.current?.notAfter ?? .distantPast) < ($1.current?.notAfter ?? .distantPast) }) {
                        TableColumn("Certificate") { c in
                            Button(c.name) { selection = .certificate(c.id) }.buttonStyle(.link)
                        }
                        TableColumn("Names") { c in Text(c.domains.joined(separator: ", ")).lineLimit(1) }
                        TableColumn("Expires") { c in Text(c.current?.notAfter.formatted(date: .abbreviated, time: .omitted) ?? "—") }
                            .width(110)
                        TableColumn("Status") { c in StatusBadge(status: model.status(of: c)) }.width(170)
                        TableColumn("Deployed") { c in
                            let ds = model.deployments(for: c.id)
                            let current = ds.filter { !model.needsDeployment($0) && $0.enabled }.count
                            Text("\(current)/\(ds.filter(\.enabled).count) current").foregroundStyle(current == ds.filter(\.enabled).count ? Color.secondary : Color.orange)
                        }.width(110)
                    }
                    .frame(minHeight: 260)
                }
            }
            .padding(20)
        }
        .navigationTitle("Overview")
    }
}

struct SetupBanner: View {
    @Environment(\.openSettings) private var openSettings
    var body: some View {
        HStack {
            Image(systemName: "gearshape.2").font(.title2)
            VStack(alignment: .leading) {
                Text("Finish setup").font(.headline)
                Text("Add your Cloudflare API token and ACME account details before issuing certificates.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Open Settings") { openSettings() }
        }
        .padding()
        .background(.yellow.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct Tile: View {
    let title: String
    let value: String
    let systemImage: String
    var tint: Color?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: systemImage).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(size: 28, weight: .semibold, design: .rounded)).foregroundStyle(tint ?? .primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct ActivityView: View {
    @Environment(AppModel.self) private var model
    @State private var expanded: Set<UUID> = []

    var body: some View {
        List(model.inventory.log) { entry in
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    icon(entry.level)
                    Text(entry.message)
                    Spacer()
                    Text(entry.date.formatted(date: .abbreviated, time: .standard))
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let detail = entry.detail, !detail.isEmpty {
                    if expanded.contains(entry.id) {
                        Text(detail).font(.caption.monospaced()).textSelection(.enabled)
                            .padding(6).frame(maxWidth: .infinity, alignment: .leading)
                            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                    } else {
                        Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            .contentShape(Rectangle())
            .onTapGesture {
                if expanded.contains(entry.id) { expanded.remove(entry.id) } else { expanded.insert(entry.id) }
            }
        }
        .overlay {
            if model.inventory.log.isEmpty { ContentUnavailableView("No activity yet", systemImage: "list.bullet.rectangle") }
        }
        .toolbar {
            Button("Clear", systemImage: "trash") { model.inventory.log.removeAll() }
        }
        .navigationTitle("Activity")
    }

    @ViewBuilder func icon(_ level: LogEntry.Level) -> some View {
        switch level {
        case .info: Image(systemName: "info.circle").foregroundStyle(.blue)
        case .success: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .warning: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        case .error: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        }
    }
}
