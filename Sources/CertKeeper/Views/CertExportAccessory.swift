import AppKit

/// The controls under the certificate Export alert: a format menu with a description of the chosen
/// format, and PKCS#12 password fields plus a legacy-encryption option that are only active for
/// PKCS#12. AppKit only, so it can be rendered and checked outside the app.
final class CertExportAccessory: NSObject {
    /// Same geometry as ExportSecretsAccessory: inset to line up with the alert's text.
    static let inset: CGFloat = 7
    static let width: CGFloat = 300 - 2 * inset

    struct Choice { let title: String; let summary: String; let needsPassword: Bool }

    let formatMenu = NSPopUpButton()
    let summary = NSTextField(wrappingLabelWithString: "")
    let password = NSSecureTextField()
    let confirm = NSSecureTextField()
    let legacy = NSButton(checkboxWithTitle: "Legacy encryption (3DES) for older systems", target: nil, action: nil)
    let view: NSView
    private let choices: [Choice]

    init(choices: [Choice]) {
        self.choices = choices
        formatMenu.addItems(withTitles: choices.map(\.title))
        let smallFont = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        summary.font = smallFont
        summary.textColor = .secondaryLabelColor
        summary.preferredMaxLayoutWidth = Self.width
        password.placeholderString = "Password for the .p12 file"
        confirm.placeholderString = "Confirm password"
        legacy.font = .systemFont(ofSize: NSFont.smallSystemFontSize)

        let stack = NSStackView(views: [formatMenu, summary, password, confirm, legacy])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.setCustomSpacing(12, after: summary)
        stack.edgeInsets = NSEdgeInsets(top: 0, left: Self.inset, bottom: 0, right: Self.inset)
        for control in [formatMenu, password, confirm] as [NSView] {
            control.translatesAutoresizingMaskIntoConstraints = false
            control.widthAnchor.constraint(equalToConstant: Self.width).isActive = true
        }
        // Reserve room for the longest description so the alert doesn't jump as the format changes.
        summary.translatesAutoresizingMaskIntoConstraints = false
        summary.widthAnchor.constraint(equalToConstant: Self.width).isActive = true
        let tallest = choices.map { choice -> CGFloat in
            let probe = NSTextField(wrappingLabelWithString: choice.summary)
            probe.font = smallFont
            probe.preferredMaxLayoutWidth = Self.width
            return probe.fittingSize.height
        }.max() ?? 0
        summary.heightAnchor.constraint(equalToConstant: ceil(tallest)).isActive = true

        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: Self.width + 2 * Self.inset).isActive = true
        view = stack
        super.init()
        formatMenu.target = self
        formatMenu.action = #selector(formatChanged)
        update()
        stack.layoutSubtreeIfNeeded()
        stack.frame = NSRect(origin: .zero, size: stack.fittingSize)
    }

    var selectedIndex: Int { formatMenu.indexOfSelectedItem }

    func select(_ index: Int) {
        formatMenu.selectItem(at: index)
        update()
    }

    @objc private func formatChanged() {
        update()
        if choices[selectedIndex].needsPassword { password.window?.makeFirstResponder(password) }
    }

    private func update() {
        let choice = choices[max(selectedIndex, 0)]
        summary.stringValue = choice.summary
        for control in [password, confirm, legacy] as [NSControl] {
            control.isEnabled = choice.needsPassword
            control.alphaValue = choice.needsPassword ? 1 : 0.4
        }
        if !choice.needsPassword {
            password.stringValue = ""
            confirm.stringValue = ""
            legacy.state = .off
        }
    }
}
