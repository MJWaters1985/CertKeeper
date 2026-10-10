import AppKit
import CertKeeperCore

/// Certificate › Export…: pick a format, choose a folder, write the files.
@MainActor
enum CertExportUI {
    private static let lastFormatKey = "CertExportLastFormat"

    static func export(_ cert: ManagedCertificate, model: AppModel) {
        guard let key = model.secrets.get(.certificateKey(cert.id)) else {
            return show("No private key for \(cert.name)", "Its private key isn't in the Keychain. Reissue the certificate, then export it.")
        }
        let formats = CertExport.Format.allCases
        let options = CertExportAccessory(choices: formats.map {
            .init(title: $0.title, summary: $0.summary, needsPassword: $0.needsPassword)
        })
        if let last = UserDefaults.standard.string(forKey: lastFormatKey),
           let index = formats.firstIndex(where: { $0.rawValue == last }) {
            options.select(index)
        }

        var files: [CertExport.OutputFile] = []
        var format = formats[0]
        while true {
            let alert = NSAlert()
            alert.messageText = "Export \(cert.name)"
            alert.informativeText = "Exports the certificate with its full chain. Private keys are written so only you can read them."
            alert.accessoryView = options.view
            alert.addButton(withTitle: "Export…")
            alert.addButton(withTitle: "Cancel")
            alert.window.initialFirstResponder = options.formatMenu
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            format = formats[options.selectedIndex]
            if format.needsPassword {
                if options.password.stringValue.isEmpty {
                    show("Enter a password", "PKCS#12 files are protected with a password you'll need when importing them."); continue
                }
                if options.password.stringValue != options.confirm.stringValue {
                    show("Passwords don't match", "Type the same password in both fields."); continue
                }
            }
            do {
                files = try CertExport.files(for: cert, keyPEM: key, format: format,
                                             password: format.needsPassword ? options.password.stringValue : nil,
                                             legacy: options.legacy.state == .on)
                break
            } catch {
                return show("Couldn't export \(cert.name)", error.localizedDescription)
            }
        }
        UserDefaults.standard.set(format.rawValue, forKey: lastFormatKey)

        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Export Here"
        panel.message = "Writes " + files.map(\.name).joined(separator: ", ")
        guard panel.runModal() == .OK, let dir = panel.url else { return }

        let urls = files.map { dir.appendingPathComponent($0.name) }
        let existing = urls.filter { FileManager.default.fileExists(atPath: $0.path) }
        if !existing.isEmpty {
            let confirm = NSAlert()
            confirm.alertStyle = .warning
            confirm.messageText = "Replace \(existing.count == 1 ? "an existing file" : "\(existing.count) existing files")?"
            confirm.informativeText = existing.map(\.lastPathComponent).joined(separator: "\n")
            confirm.addButton(withTitle: "Replace")
            confirm.addButton(withTitle: "Cancel")
            guard confirm.runModal() == .alertFirstButtonReturn else { return }
        }
        do {
            for (file, url) in zip(files, urls) {
                try file.data.write(to: url, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: file.secret ? 0o600 : 0o644], ofItemAtPath: url.path)
            }
            model.log(.info, "Exported \(cert.name) (\(format.title))", detail: "\(dir.path): " + files.map(\.name).joined(separator: ", "))
            NSWorkspace.shared.activateFileViewerSelecting(urls)
        } catch {
            show("Couldn't write the files", error.localizedDescription)
        }
    }

    private static func show(_ title: String, _ text: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = text
        alert.runModal()
    }
}
