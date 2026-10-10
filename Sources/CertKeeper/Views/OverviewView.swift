import CertKeeperCore
import SwiftUI

struct OverviewView: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: SidebarItem?

    var body: some View {
        let certs = model.inventory.certificates
        let deps = model.inventory.deployments
        // The table scrolls itself and fills whatever space the window leaves below the header, so it
        // isn't wrapped in a ScrollView (a Table inside one can't take the available height).
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
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(certs.sorted { ($0.current?.notAfter ?? .distantPast) < ($1.current?.notAfter ?? .distantPast) }) {
                    TableColumn("Certificate") { c in
                        Button(c.name) { selection = .certificate(c.id) }.buttonStyle(.link)
                    }
                    .width(min: 140, ideal: 200)
                    TableColumn("Names") { c in Text(c.domains.joined(separator: ", ")).lineLimit(1).truncationMode(.middle) }
                        .width(min: 160, ideal: 280)
                    TableColumn("Expires") { c in Text(c.current?.notAfter.formatted(date: .abbreviated, time: .omitted) ?? "—") }
                        .width(min: 90, ideal: 110, max: 150)
                    TableColumn("Valid For") { c in ValidForCell(status: model.status(of: c), days: c.current?.daysRemaining) }
                        .width(min: 70, ideal: 90, max: 130)
                    TableColumn("Status") { c in ManagementBadge(monitored: c.isMonitored) }
                        .width(min: 100, ideal: 115, max: 150)
                    TableColumn("Deployed") { c in
                        let ds = model.deployments(for: c.id)
                        let current = ds.filter { !model.needsDeployment($0) && $0.enabled }.count
                        Text("\(current)/\(ds.filter(\.enabled).count) current").foregroundStyle(current == ds.filter(\.enabled).count ? Color.secondary : Color.orange)
                    }
                    .width(min: 90, ideal: 110, max: 150)
                }
                .frame(maxWidth: .infinity, minHeight: 180, maxHeight: .infinity)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
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

/// Days of validity left, coloured by the certificate's renewal status.
struct ValidForCell: View {
    let status: AppModel.CertStatus
    let days: Int?

    var body: some View {
        let color: Color = switch status {
        case .valid: .green
        case .renewDue, .domainsChanged: .orange
        case .expired: .red
        case .notIssued: .secondary
        }
        Group {
            if case .expired = status {
                Text("Expired")
            } else if let days, status != .notIssued {
                Text("\(days) \(days == 1 ? "day" : "days")").monospacedDigit()
            } else {
                Text("—")
            }
        }
        .foregroundStyle(color)
    }
}

/// Whether CertKeeper manages a certificate or only monitors one another system renews.
struct ManagementBadge: View {
    let monitored: Bool

    var body: some View {
        Label(monitored ? "Monitored" : "Managed", systemImage: monitored ? "eye" : "arrow.triangle.2.circlepath")
            .font(.caption.weight(.medium))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background((monitored ? Color.purple : Color.blue).opacity(0.15), in: Capsule())
            .foregroundStyle(monitored ? Color.purple : Color.blue)
            .help(monitored ? "Renewed by another system; CertKeeper watches it and warns before it expires."
                            : "CertKeeper issues, renews and deploys it.")
    }
}
