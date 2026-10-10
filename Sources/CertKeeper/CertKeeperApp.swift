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
            CommandMenu("Certificates") {
                Button("Run Rotation Pass Now") { Task { await model.runMaintenance() } }
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
        Button("Open CertKeeper") {
            openWindow(id: "main")
            NSApp.activate()
        }
        Divider()
        Button("Quit") { NSApp.terminate(nil) }
    }
}
