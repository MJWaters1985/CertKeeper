import AppKit
import CertKeeperCore
import SwiftUI

@main
enum Entry {
    static func main() {
        // ssh invokes this binary as SSH_ASKPASS for password logins: answer and exit without UI.
        let env = ProcessInfo.processInfo.environment
        if env[AskPass.hostVariable] != nil {
            let prompt = CommandLine.arguments.dropFirst().joined(separator: " ")
            guard let password = AskPass.response(prompt: prompt, environment: env) else { exit(1) }
            FileHandle.standardOutput.write(Data((password + "\n").utf8))
            exit(0)
        }
        SSHRunner.ignoreSIGPIPE()
        CertKeeperApp.main()
    }
}

struct CertKeeperApp: App {
    @State private var model = AppModel()

    init() {
        // Needed when launched as a bare executable (swift run); harmless inside the .app bundle.
        NSApplication.shared.setActivationPolicy(.regular)
    }

    var body: some Scene {
        Window("CertKeeper", id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 960, minHeight: 600)
                .task { model.startScheduler() }
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About CertKeeper") { AboutPanel.show() }.help("Version, copyright and what CertKeeper does")
            }
            CommandGroup(replacing: .importExport) {
                Button("Export Configuration…") { ConfigTransferUI.export(model) }
                    .help("Save hosts, certificates, deployments and settings to a file")
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                Button("Import Configuration…") { ConfigTransferUI.import(model) }
                    .help("Replace the configuration with one from an exported file")
                    .keyboardShortcut("i", modifiers: [.command, .shift])
            }
            CommandMenu("Certificates") {
                Button("Run Rotation Pass Now") { Task { await model.runMaintenance() } }
                    .help("Renew what's due, check every deployment, and redeploy any that are out of date")
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(model.maintenanceRunning)
            }
        }

        Settings {
            SettingsView()
                .environment(model)
        }

        MenuBarExtra {
            MenuBarContent()
                .environment(model)
        } label: {
            Image(systemName: model.inventory.certificates.contains { model.needsIssuance($0) } || model.inventory.deployments.contains(where: model.needsDeployment)
                  ? "lock.trianglebadge.exclamationmark" : "lock.shield")
                .help("CertKeeper: certificate expiry and rotation")
        }
    }
}

struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let soonest = model.inventory.certificates.compactMap { c in c.current.map { (c, $0) } }
            .sorted { $0.1.notAfter < $1.1.notAfter }.prefix(5)
        ForEach(Array(soonest), id: \.0.id) { cert, summary in
            Text("\(cert.name) — \(summary.daysRemaining)d")
        }
        if soonest.isEmpty { Text("No issued certificates") }
        Divider()
        Button(model.maintenanceRunning ? "Rotation running…" : "Run Rotation Pass") {
            Task { await model.runMaintenance() }
        }
        .disabled(model.maintenanceRunning)
        .help("Renew what's due, check every deployment, and redeploy any that are out of date")
        Button("Open CertKeeper") {
            openWindow(id: "main")
            NSApp.activate()
        }
        .help("Show the main window")
        Divider()
        Button("Quit") { NSApp.terminate(nil) }
            .help("Quit CertKeeper; automatic rotation stops until it's opened again")
    }
}

/// The standard About panel, with a summary of the app. The copyright line comes from
/// NSHumanReadableCopyright in Info.plist.
enum AboutPanel {
    static let summary = """
    CertKeeper ensures the TLS certificates on your servers and devices are current. It issues \
    certificates from Let's Encrypt, proving domain ownership through Cloudflare DNS, and installs them \
    over SSH on nginx, Apache, Proxmox VE, TrueNAS and its apps, UniFi OS, OPNsense, Pi-hole and more.

    An inventory tracks every certificate and where it's deployed, so CertKeeper renews and redeploys \
    only when needed, and confirms what each service actually serves. Certificates renewed by other \
    systems can be monitored for expiry. Secrets stay in your macOS Keychain.
    """

    static func show() {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        paragraph.paragraphSpacing = 6
        let credits = NSAttributedString(string: summary, attributes: [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.labelColor,  // follows light/dark mode
            .paragraphStyle: paragraph,
        ])
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits])
        NSApp.activate()
    }
}
