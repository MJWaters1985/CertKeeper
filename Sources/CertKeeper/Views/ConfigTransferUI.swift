import AppKit
import CertKeeperCore
import UniformTypeIdentifiers

/// File › Export Configuration… / Import Configuration…, using standard AppKit panels and alerts.
@MainActor
enum ConfigTransferUI {
    // MARK: Export

    static func export(_ model: AppModel) {
        guard let password = askExportSecrets() else { return }  // nil = cancelled
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        let day = Date().formatted(.iso8601.year().month().day())
        panel.nameFieldStringValue = "CertKeeper Configuration \(day).json"
        panel.message = password.isEmpty ? "The file won't contain any passwords or private keys."
                                         : "Passwords and private keys are encrypted with your password."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try model.exportConfiguration(password: password.isEmpty ? nil : password)
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            model.log(.info, "Exported configuration", detail: "\(url.path)\(password.isEmpty ? "" : " (with encrypted secrets)")")
        } catch {
            show("Couldn't export the configuration", error.localizedDescription, style: .warning)
        }
    }

    /// Returns "" for no secrets, the password to encrypt them with, or nil if cancelled.
    private static func askExportSecrets() -> String? {
        let options = ExportSecretsAccessory()
        while true {
            let alert = NSAlert()
            alert.messageText = "Export Configuration"
            alert.informativeText = "Exports hosts, certificates, deployments and settings. Secrets are only included if you choose."
            alert.accessoryView = options.view
            alert.addButton(withTitle: "Continue…")
            alert.addButton(withTitle: "Cancel")
            alert.window.initialFirstResponder = options.include
            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            guard options.includeSecrets else { return "" }
            if options.password.stringValue.count < 8 {
                show("Password too short", "Use at least 8 characters.", style: .warning)
            } else if options.password.stringValue != options.confirm.stringValue {
                show("Passwords don't match", "Type the same password in both fields.", style: .warning)
            } else {
                return options.password.stringValue
            }
        }
    }

    // MARK: Import

    static func `import`(_ model: AppModel) {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.message = "Choose a CertKeeper configuration file"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let file: ConfigTransfer.File
        do {
            file = try ConfigTransfer.read(try Data(contentsOf: url))
        } catch {
            return show("Couldn't open the configuration", error.localizedDescription, style: .warning)
        }

        var secrets: [(Keychain.Item, String)] = []
        if let encrypted = file.secrets {
            guard let result = askImportPassword(file: file, count: encrypted.count) else { return }
            secrets = result
        }

        let inv = file.inventory, current = model.inventory
        let confirm = NSAlert()
        confirm.alertStyle = .warning
        confirm.messageText = "Replace the current configuration?"
        confirm.informativeText = """
        The file (exported \(file.exportedAt.formatted(date: .abbreviated, time: .shortened))) has \
        \(inv.hosts.count) hosts, \(inv.certificates.count) certificates and \(inv.deployments.count) deployments\
        \(secrets.isEmpty ? ", without secrets" : " and \(secrets.count) secrets").

        It replaces the current \(current.hosts.count) hosts, \(current.certificates.count) certificates and \
        \(current.deployments.count) deployments. The current configuration is saved to a backup file first, \
        and the activity log is kept.
        """
        confirm.addButton(withTitle: "Replace")
        confirm.addButton(withTitle: "Cancel")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        do {
            let backup = try model.importConfiguration(file, secrets: secrets)
            let summary = model.inventory.log.first?.detail ?? ""
            show("Configuration imported", summary.replacingOccurrences(of: backup.lastPathComponent, with: backup.path),
                 style: model.inventory.log.first?.level == .warning ? .warning : .informational)
        } catch {
            show("Couldn't import the configuration", error.localizedDescription, style: .warning)
        }
    }

    /// Returns the decrypted secrets, [] to import without them, or nil if cancelled.
    private static func askImportPassword(file: ConfigTransfer.File, count: Int) -> [(Keychain.Item, String)]? {
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        field.placeholderString = "Password"
        var message = "This file contains \(count) encrypted secrets. Enter the password used to export it."
        while true {
            let alert = NSAlert()
            alert.messageText = "Import Secrets"
            alert.informativeText = message
            alert.accessoryView = field
            alert.addButton(withTitle: "Decrypt")
            alert.addButton(withTitle: "Import Without Secrets")
            alert.addButton(withTitle: "Cancel")
            alert.window.initialFirstResponder = field
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                do { return try ConfigTransfer.decryptSecrets(file, password: field.stringValue) }
                catch { message = "\(error.localizedDescription) Try again, or import without secrets." }
            case .alertSecondButtonReturn:
                return []
            default:
                return nil
            }
        }
    }

    private static func show(_ title: String, _ text: String, style: NSAlert.Style) {
        let alert = NSAlert()
        alert.alertStyle = style
        alert.messageText = title
        alert.informativeText = text
        alert.runModal()
    }
}
