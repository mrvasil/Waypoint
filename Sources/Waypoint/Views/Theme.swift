import SwiftUI

enum Theme {
    static let corner: CGFloat = 16
    static let compactCorner: CGFloat = 11
    static let cardPadding: CGFloat = 16
    static let pageSpacing: CGFloat = 24
    static let contentWidth: CGFloat = 860

    static var surface: Color { Color(nsColor: .controlBackgroundColor) }
    static var elevatedSurface: Color { Color(nsColor: .textBackgroundColor) }
    static var separator: Color { Color(nsColor: .separatorColor) }
    static var accentGreen: Color { Color(nsColor: .systemGreen) }
    static var subtle: Color { Color(nsColor: .tertiaryLabelColor) }
}

struct Card<Content: View>: View {
    private let padding: CGFloat
    @ViewBuilder private let content: Content

    init(padding: CGFloat = Theme.cardPadding, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    var body: some View {
        content
            .padding(padding)
            .background(Theme.surface, in: .rect(cornerRadius: Theme.corner))
            .overlay {
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                    .strokeBorder(Theme.separator.opacity(0.45), lineWidth: 0.5)
            }
    }
}

struct GroupCard<Content: View>: View {
    @ViewBuilder private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .background(Theme.surface, in: .rect(cornerRadius: Theme.corner))
            .clipShape(.rect(cornerRadius: Theme.corner))
            .overlay {
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                    .strokeBorder(Theme.separator.opacity(0.45), lineWidth: 0.5)
            }
    }
}

struct SectionHeader: View {
    let title: String
    var subtitle: String?
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.title3.weight(.semibold))
                if let subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let actionTitle, let action {
                Button(actionTitle, action: action)
            }
        }
    }
}

struct SymbolTile: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 34

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.48, weight: .semibold))
            .symbolRenderingMode(.monochrome)
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(color.gradient, in: .rect(cornerRadius: size * 0.24))
            .overlay {
                RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                    .strokeBorder(.white.opacity(0.18), lineWidth: 0.5)
            }
            .shadow(color: color.opacity(0.18), radius: 2, y: 1)
            .accessibilityHidden(true)
    }
}

struct StatusDot: View {
    let running: Bool

    var body: some View {
        Circle()
            .fill(running ? Theme.accentGreen : Theme.subtle)
            .frame(width: 9, height: 9)
            .overlay {
                if running {
                    Circle()
                        .stroke(Theme.accentGreen.opacity(0.28), lineWidth: 5)
                }
            }
            .animation(.easeInOut(duration: 0.2), value: running)
            .accessibilityHidden(true)
    }
}

extension View {
    @ViewBuilder
    func appGlass(cornerRadius: CGFloat = Theme.corner) -> some View {
        if #available(macOS 26.0, *) {
            glassEffect(
                .regular,
                in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            )
        } else {
            background(.regularMaterial, in: .rect(cornerRadius: cornerRadius))
        }
    }
}
