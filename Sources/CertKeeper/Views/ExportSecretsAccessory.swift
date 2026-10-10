import AppKit

/// The controls under the Export Configuration alert: an "Include secrets" checkbox with a short
/// explanation, and password fields that stay disabled until the box is ticked.
/// Self-contained (AppKit only) so it can be rendered and checked outside the app.
final class ExportSecretsAccessory: NSObject {
    /// The alert places its accessory ~7pt left of its message text, so the controls are inset by that
    /// much to line up with the text, inside a 300pt accessory (the alert's usual width).
    static let inset: CGFloat = 7
    static let width: CGFloat = 300 - 2 * inset

    let include = NSButton(checkboxWithTitle: "Include secrets", target: nil, action: nil)
    let password = NSSecureTextField()
    let confirm = NSSecureTextField()
    let view: NSView

    override init() {
        let note = NSTextField(wrappingLabelWithString:
            "Cloudflare token, ACME key, private keys and host passwords, encrypted with a password you'll need to import them.")
        note.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        note.textColor = .secondaryLabelColor
        note.preferredMaxLayoutWidth = Self.width - 20

        password.placeholderString = "Password (at least 8 characters)"
        confirm.placeholderString = "Confirm password"

        // Indent the note under the checkbox's title, past the box itself.
        let noteRow = NSStackView(views: [note])
        noteRow.edgeInsets = NSEdgeInsets(top: 0, left: 20, bottom: 0, right: 0)

        let stack = NSStackView(views: [include, noteRow, password, confirm])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.setCustomSpacing(12, after: noteRow)
        stack.edgeInsets = NSEdgeInsets(top: 0, left: Self.inset, bottom: 0, right: Self.inset)
        for field in [password, confirm] {
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: Self.width).isActive = true
        }
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: Self.width + 2 * Self.inset).isActive = true
        stack.layoutSubtreeIfNeeded()
        stack.frame = NSRect(origin: .zero, size: stack.fittingSize)
        view = stack

        super.init()
        include.target = self
        include.action = #selector(toggled)
        update()
    }

    var includeSecrets: Bool { include.state == .on }

    @objc private func toggled() {
        update()
        if includeSecrets { password.window?.makeFirstResponder(password) }
    }

    private func update() {
        for field in [password, confirm] {
            field.isEnabled = includeSecrets
            field.alphaValue = includeSecrets ? 1 : 0.4  // disabled fields barely differ in dark mode
            if !includeSecrets { field.stringValue = "" }
        }
    }
}
